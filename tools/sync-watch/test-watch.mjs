// Deterministic harness for watch-sync.mjs against synthetic fixtures.
// Never touches the live credential files.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn, execFileSync } from "node:child_process";

const WATCHER = process.argv[2];
const root = fs.mkdtempSync(path.join(os.tmpdir(), "kr-sync-test-"));
const logDir = path.join(root, "logs");
const authPath = path.join(root, "auth.json");
const krPath = path.join(root, "keyrouter.json");
const logPath = path.join(logDir, "sync-watch.ndjson");
const lockPath = path.join(logDir, "sync-watch.lock");

let pass = 0, fail = 0;
const check = (label, ok) => { if (ok) { pass++; console.log("  PASS  " + label); } else { fail++; console.log("  FAIL  " + label); } };

const write = (p, obj) => { const t = p + ".tmp"; fs.writeFileSync(t, JSON.stringify(obj, null, 2) + "\n", "utf-8"); fs.renameSync(t, p); };
const writeInPlace = (p, obj) => fs.writeFileSync(p, JSON.stringify(obj, null, 2) + "\n", "utf-8");
const cred = (access, refresh, expires) => ({ type: "oauth", access, refresh, expires });
const authDoc = (c) => ({ cline: c, google: { type: "api_key", key: "GKEY" } });
const krDoc = (c, active = "acct-a") => ({
  providers: [
    { name: "cline", accounts: [{ name: "acct-a", credential: c }, { name: "acct-b", credential: cred("B_ACC", "REFRESH_B", 500) }], active },
    { name: "tokenharbor", keys: [{ name: "k1", value: "KV1" }], active: "k1" },
  ],
});

write(authPath, authDoc(cred("ACCESS_OLD", "REFRESH_1", 1000)));
write(krPath, krDoc(cred("ACCESS_OLD", "REFRESH_1", 1000)));

const env = { ...process.env, KR_SYNC_AUTH: authPath, KR_SYNC_KEYROUTER: krPath, KR_SYNC_LOG_DIR: logDir,
  KR_SYNC_POLL_MS: "250", KR_SYNC_HEARTBEAT_MS: "700", KR_SYNC_DEBOUNCE_MS: "10" };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const read = () => { try { return fs.readFileSync(logPath, "utf-8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } };
const find = (kind, pred = () => true) => read().filter((e) => e.kind === kind && pred(e));
async function waitFor(desc, pred, timeout = 6000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeout) { if (pred(read())) return true; await sleep(50); }
  console.log("  !! TIMEOUT: " + desc);
  return false;
}
const spawnWatcher = () => { const p = spawn(process.execPath, [WATCHER], { env, stdio: ["ignore", "pipe", "pipe"] });
  p.stdout.on("data", (d) => process.stdout.write("  [w] " + d)); p.stderr.on("data", (d) => process.stdout.write("  [w!] " + d)); return p; };
// Windows has no catchable signal: TerminateProcess runs no handlers at all.
const hardKill = (pid) => { try { execFileSync("taskkill", ["/F", "/PID", String(pid)], { stdio: "ignore" }); } catch {} };
const waitExit = (p) => new Promise((r) => p.on("exit", (code) => r(code)));

console.log("root: " + root);
let w = spawnWatcher();
await waitFor("baseline + armed + scheduler", (e) => e.filter((x) => x.kind === "file.baseline").length >= 2 && e.some((x) => x.kind === "runtime.watch-armed") && e.some((x) => x.kind === "runtime.scheduler-alive"));

// Only events carrying a sequence number belong to the observed timeline. A refused
// instance's notice is deliberately unnumbered, so it is excluded by design.
const numbered = () => read().filter((x) => typeof x.seq === "number");

console.log("\n--- T1 baseline ---");
check("two baselines (auth + keyrouter)", find("file.baseline").length === 2);
check("watch armed for both dirs", find("runtime.watch-armed").length >= 1);
check("no spurious change on startup", find("file.change").length === 0);
check("scheduler proven alive", find("runtime.scheduler-alive").length === 1);
check("start event records resumedFromSeq", find("runtime.start").at(-1)?.resumedFromSeq === 0);

console.log("\n--- T2 pi refreshes auth.json (access rotates, refresh stable) ---");
writeInPlace(authPath, authDoc(cred("ACCESS_NEW", "REFRESH_1", 2000)));
await waitFor("auth change", (e) => e.some((x) => x.kind === "file.change" && x.file === "auth"));
await sleep(250);
{
  const e = find("file.change", (x) => x.file === "auth").at(-1);
  check("detected auth change", Boolean(e));
  check("diff names exactly access+expires: " + JSON.stringify((e?.changed ?? []).map((c) => c.field)), (e?.changed ?? []).map((c) => c.field).sort().join(",") === "cline|access,cline|expires");
  const acc = (e?.changed ?? []).find((c) => c.field === "cline|access");
  check("diff carries raw from/to", acc?.from === "ACCESS_OLD" && acc?.to === "ACCESS_NEW");
  check("diff carries fingerprints", Boolean(acc?.fromFp) && Boolean(acc?.toFp) && acc.fromFp !== acc.toFp);
  check("pair embeds both files whole", e?.pair?.auth?.cline?.access === "ACCESS_NEW" && e?.pair?.keyrouter?.providers?.length === 2);
  const row = (e?.crosscheck ?? []).find((r) => r.provider === "cline");
  check("verdict STALE-ACCESS (got " + row?.verdict + ")", row?.verdict === "STALE-ACCESS");
  check("proves same account via refresh match", row?.sameRefresh === true && row?.sameAccess === false);
  check("reports expires delta + both timestamps", typeof row?.expiresDeltaMs === "number" && row.poolExpiresIso && row.authExpiresIso);
  check("keys-pool row labelled expected", String((e?.crosscheck ?? []).find((r) => r.provider === "tokenharbor")?.verdict).includes("expected"));
  check("raw token recorded verbatim in log file", fs.readFileSync(logPath, "utf-8").includes("ACCESS_NEW"));
}

console.log("\n--- T3 byte-identical rewrite must NOT log a change ---");
write(krPath, krDoc(cred("ACCESS_OLD", "REFRESH_1", 1000)));
await waitFor("no-content-change", (e) => e.some((x) => x.kind === "watch.no-content-change"));
await sleep(200);
check("no keyrouter file.change", find("file.change", (x) => x.file === "keyrouter").length === 0);
check("watch.no-content-change recorded", find("watch.no-content-change").length >= 1);

console.log("\n--- T4 keyrouter moves `active` only (bookkeeping write; access still stale) ---");
write(krPath, krDoc(cred("ACCESS_OLD", "REFRESH_1", 1000), "acct-b"));
await waitFor("keyrouter change", (e) => e.some((x) => x.kind === "file.change" && x.file === "keyrouter"));
await sleep(250);
{
  const e = find("file.change", (x) => x.file === "keyrouter").at(-1);
  check("detected keyrouter change", Boolean(e));
  check("diff is exactly the active field", (e?.changed ?? []).length === 1 && e.changed[0].field === "cline|__active");
  check("detectLagMs is an integer >= 0", Number.isInteger(e?.detectLagMs) && e.detectLagMs >= 0);
  check("verdict DIVERGED", (e?.crosscheck ?? []).find((r) => r.provider === "cline")?.verdict === "DIVERGED");
}

console.log("\n--- T5 keyrouter writes back the refreshed token (correct behaviour) ---");
write(krPath, krDoc(cred("ACCESS_NEW", "REFRESH_1", 2000), "acct-a"));
await waitFor("in-sync", (e) => e.some((x) => x.kind === "file.change" && x.file === "keyrouter" && (x.crosscheck ?? []).some((r) => r.provider === "cline" && r.verdict === "IN-SYNC")));
{
  const row = (find("file.change", (x) => x.file === "keyrouter").at(-1)?.crosscheck ?? []).find((r) => r.provider === "cline");
  check("verdict IN-SYNC after write-back", row?.verdict === "IN-SYNC");
  check("sameAccess and sameRefresh both true", row?.sameAccess === true && row?.sameRefresh === true);
  check("expires delta is 0", row?.expiresDeltaMs === 0);
}

console.log("\n--- T6 heartbeat ---");
await waitFor("heartbeat", (e) => e.some((x) => x.kind === "runtime.heartbeat"));
{
  const h = find("runtime.heartbeat").at(-1);
  check("heartbeat has uptime, counts, targets, memory", typeof h?.uptimeMs === "number" && h?.counts && h?.targets?.length === 2 && typeof h?.memory === "number");
}

console.log("\n--- T7 a second live instance is refused ---");
{
  const before = read().length;
  const second = spawn(process.execPath, [WATCHER], { env, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  second.stdout.on("data", (d) => (out += d));
  const code = await waitExit(second);
  const added = read().slice(before);
  check("second instance exited cleanly", code === 0);
  check("second instance logged no runtime.start", !added.some((x) => x.kind === "runtime.start"));
  check("second instance logged instance-skip", added.some((x) => x.kind === "runtime.instance-skip"));
  check("that notice is unnumbered (it shares the counter with the live owner)", added.filter((x) => x.kind === "runtime.instance-skip").every((x) => x.seq === null));
  check("second instance logged no runtime.exit (never started)", !added.some((x) => x.kind === "runtime.exit"));
  check("second instance printed nothing to stdout", out.trim() === "");
}

console.log("\n--- T8 forced kill (Windows has no catchable signal) ---");
const firstPid = w.pid;
const stopBefore = find("runtime.stop").length;
hardKill(firstPid);
await waitExit(w);
await sleep(300);
check("no runtime.stop recorded", find("runtime.stop").length === stopBefore);
check("stale lock left behind", fs.existsSync(lockPath));
check("lock still names the dead pid", (() => { try { return JSON.parse(fs.readFileSync(lockPath, "utf-8")).pid === firstPid; } catch { return false; } })());
check("log is still valid NDJSON after the kill", (() => {
  const lines = fs.readFileSync(logPath, "utf-8").split("\n").filter(Boolean);
  return lines.every((l) => { try { JSON.parse(l); return true; } catch { return false; } });
})());

console.log("\n--- T9 restart takes over the stale lock and reports whose ---");
let w2 = spawnWatcher();
await waitFor("second start", (e) => e.filter((x) => x.kind === "runtime.start").length >= 2);
{
  const start = find("runtime.start").at(-1);
  check("restart recorded", Boolean(start));
  check("tookOverStaleLock names the killed pid", start?.tookOverStaleLock?.pid === firstPid);
  check("start records resumedFromSeq > 0", typeof start?.resumedFromSeq === "number" && start.resumedFromSeq > 0);
  check("no extra instance-skip from the takeover", find("runtime.instance-skip").length === 1);
  check("lock now names the new pid", (() => { try { return JSON.parse(fs.readFileSync(lockPath, "utf-8")).pid === w2.pid; } catch { return false; } })());
}

console.log("\n--- T10 detection continues after restart ---");
const beforeCount = find("file.change", (x) => x.file === "auth").length;
writeInPlace(authPath, authDoc(cred("ACCESS_AFTER_CRASH", "REFRESH_1", 3000)));
await waitFor("auth change after restart", () => find("file.change", (x) => x.file === "auth").length > beforeCount);
{
  const e = find("file.change", (x) => x.file === "auth").at(-1);
  check("change detected by the restarted instance", e?.changed?.some((c) => c.to === "ACCESS_AFTER_CRASH"));
  check("verdict STALE-ACCESS again (got " + (e?.crosscheck ?? []).find((r) => r.provider === "cline")?.verdict + ")", (e?.crosscheck ?? []).find((r) => r.provider === "cline")?.verdict === "STALE-ACCESS");
  check("mtimeUnchanged flag present", typeof e?.mtimeUnchanged === "boolean");
}

console.log("\n--- T11 seq is monotonic across the crash ---");
{
  const seqs = numbered().map((x) => x.seq);
  const dupes = seqs.filter((s, i) => i > 0 && s <= seqs[i - 1]);
  check("strictly increasing, no reuse after restart (dupes: " + JSON.stringify(dupes) + ")", dupes.length === 0);
}

console.log("\n--- T12 restart itself records no spurious change ---");
{
  const starts = find("runtime.start").length;
  check("every start has a baseline for both files", find("file.baseline").length === starts * 2);
}

w2.kill("SIGTERM");
await waitExit(w2);

const all = read();
const byKind = {};
for (const e of all) byKind[e.kind] = (byKind[e.kind] ?? 0) + 1;
console.log("\n=== SUMMARY ===  pass=" + pass + "  fail=" + fail);
console.log("events: " + all.length + "   log bytes: " + fs.statSync(logPath).size);
console.log(JSON.stringify(byKind, null, 2));
console.log("verdicts exercised: " + JSON.stringify([...new Set(all.flatMap((e) => (e.crosscheck ?? []).map((r) => r.verdict)))]));
console.log("\nDETECTED CHANGES (mtime -> detection):");
for (const e of all.filter((x) => x.kind === "file.change")) {
  const c = (e.changed ?? []).map((d) => d.field + " " + JSON.stringify(d.from) + "->" + JSON.stringify(d.to)).join(", ");
  console.log("  #" + e.seq + " " + e.file.padEnd(9) + " mtime=" + e.mtimeIso.to + " detected=" + e.t + " lag=" + e.detectLagMs + "ms  " + c);
}
console.log("\nExample file.change event verbatim:");
console.log(JSON.stringify(all.find((e) => e.kind === "file.change" && e.crosscheck?.some((r) => r.verdict === "STALE-ACCESS")), null, 2).slice(0, 2600));
console.log("\nRESULT: " + (fail === 0 ? "ALL PASS" : fail + " FAILURES"));
process.exit(fail === 0 ? 0 : 1);