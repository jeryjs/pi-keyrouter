#!/usr/bin/env node
// =============================================================================
// analyze-sync.mjs — turn sync-watch.ndjson into an answer
// =============================================================================
//
// The watcher records everything; this reads it back and answers the actual
// question: does keyrouter.json end up holding the same credential pi has?
//
// The central measurement is the WRITE-BACK LAG. pi rotates the access token in
// auth.json, and keyrouter is supposed to copy that value into the pool entry for
// the active account. So for every auth.json access-token rotation this reports
// how long keyrouter took to match it — or that it never did.
//
// Usage:
//   node analyze-sync.mjs [--log <path>] [--provider <name>] [--since <iso>]
//                        [--full] [--json]
//
// =============================================================================

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
	const out = { log: path.join(SCRIPT_DIR, "logs", "sync-watch.ndjson"), provider: null, since: null, full: false, json: false };
	for (let i = 0; i < argv.length; i += 1) {
		const key = argv[i];
		const next = () => argv[++i];
		if (key === "--log") out.log = next();
		else if (key === "--provider") out.provider = next();
		else if (key === "--since") out.since = next();
		else if (key === "--full") out.full = true;
		else if (key === "--json") out.json = true;
		else if (key === "--help" || key === "-h") out.help = true;
	}
	return out;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
	process.stdout.write(
		[
			"Usage: node analyze-sync.mjs [options]",
			"",
			"  --log <path>        NDJSON log (default: ./logs/sync-watch.ndjson)",
			"  --provider <name>   restrict output to one provider",
			"  --since <iso>       ignore events before this timestamp",
			"  --full              list every change, not just the first N",
			"  --json              emit the computed report as JSON",
			"",
		].join("\n"),
	);
	process.exit(0);
}

if (!fs.existsSync(args.log)) {
	process.stderr.write(`no log at ${args.log}\n`);
	process.exit(1);
}

// -----------------------------------------------------------------------------
// Load
// -----------------------------------------------------------------------------

const events = [];
let malformed = 0;
for (const line of fs.readFileSync(args.log, "utf-8").split("\n")) {
	if (!line.trim()) continue;
	try {
		const event = JSON.parse(line);
		if (args.since && event.t && event.t < args.since) continue;
		events.push(event);
	} catch {
		malformed += 1;
	}
}

const ts = (iso) => (iso ? Date.parse(iso) : null);
const fmtDur = (ms) => {
	if (ms === null || !Number.isFinite(ms)) return "-";
	const s = Math.round(ms / 1000);
	if (s < 60) return `${s}s`;
	if (s < 3600) return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}s`;
	return `${Math.floor(s / 3600)}h${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m`;
};
const short = (iso) => (iso ? iso.replace("T", " ").replace(/\.\d+Z$/, "Z") : "-");
const oneLine = (value, max = 90) => {
	const text = String(value ?? "");
	return text.length <= max ? text : `${text.slice(0, max)}…(${text.length})`;
};

const changes = events.filter((e) => e.kind === "file.change");
const baselines = events.filter((e) => e.kind === "file.baseline");
const starts = events.filter((e) => e.kind === "runtime.start");
const stops = events.filter((e) => e.kind === "runtime.stop");
const exits = events.filter((e) => e.kind === "runtime.exit");
const heartbeats = events.filter((e) => e.kind === "runtime.heartbeat");

// Crosscheck rows, flattened to one record per (event, provider).
const observations = [];
for (const event of events) {
	for (const row of event.crosscheck ?? []) {
		if (args.provider && row.provider !== args.provider) continue;
		observations.push({ t: event.t, seq: event.seq, pid: event.pid, file: event.file, reason: event.reason, ...row });
	}
}

// Last observation per provider at any point in time, so an episode can be said
// to have lasted until the next one contradicts it.
const report = {};

// -----------------------------------------------------------------------------
// Section: coverage
// -----------------------------------------------------------------------------

function coverage() {
	const lines = [];
	const first = events[0];
	const last = events[events.length - 1];
	lines.push(`log            ${args.log}`);
	lines.push(`events         ${events.length}${malformed ? `  (+${malformed} malformed lines)` : ""}${events.length ? `, seq ${first.seq ?? "-"}..${last.seq ?? "-"}` : ""}`);
	if (first && last) lines.push(`window         ${short(first.t)} .. ${short(last.t)}  (${fmtDur(ts(last.t) - ts(first.t))})`);
	lines.push(`watcher runs   ${starts.length} start(s), ${stops.length} clean stop(s), ${exits.length} exit(s)`);

	const pids = [...new Set(events.map((e) => e.pid))];
	lines.push(`processes      ${pids.join(", ")}`);

	// Uptime of the currently-running instance, and gaps where nothing observed.
	lines.push("");
	for (const start of starts) {
		const from = ts(start.t);
		const later = stops.find((s) => s.pid === start.pid && ts(s.t) > from);
		const ended = later ? ts(later.t) : null;
		const lastOfPid = [...events].reverse().find((e) => e.pid === start.pid);
		const to = ended ?? ts(lastOfPid?.t);
		lines.push(
			`  pid ${String(start.pid).padStart(6)}  ${short(start.t)}  ..  ${ended ? short(later.t) : "still running or killed"}` +
				`  (${fmtDur(to - from)})${start.tookOverStaleLock ? `  took over pid ${start.tookOverStaleLock.pid}` : ""}`,
		);
	}

	// Detection gaps: a stretch with no events at all while the watcher claimed to
	// be running means observation was lost, whatever the cause.
	const sample = [...changes, ...heartbeats, ...events.filter((e) => e.kind === "runtime.scheduler-alive")].sort((a, b) => ts(a.t) - ts(b.t));
	const gaps = [];
	for (let i = 1; i < sample.length; i += 1) {
		const delta = ts(sample[i].t) - ts(sample[i - 1].t);
		const threshold = 2 * (starts[0]?.intervals?.heartbeatMs ?? 300_000);
		if (delta > threshold) gaps.push({ from: sample[i - 1].t, to: sample[i].t, ms: delta });
	}
	if (gaps.length) {
		lines.push("");
		lines.push("observation gaps (no events for longer than two heartbeat intervals):");
		for (const gap of gaps) lines.push(`  ${short(gap.from)} .. ${short(gap.to)}  ${fmtDur(gap.ms)}`);
	}
	return lines;
}

// -----------------------------------------------------------------------------
// Section: verdicts
// -----------------------------------------------------------------------------

function verdictSummary() {
	const lines = [];
	const counts = new Map();
	for (const obs of observations) counts.set(obs.verdict, (counts.get(obs.verdict) ?? 0) + 1);
	const oauthRows = observations.filter((o) => o.kind === "accounts");

	lines.push(`observations   ${observations.length}  from ${changes.length} change(s), ${baselines.length} baseline(s)`);
	lines.push("");
	for (const [verdict, count] of [...counts.entries()].sort((a, b) => b[1] - a[1])) lines.push(`  ${String(count).padStart(5)}  ${verdict}`);

	if (oauthRows.length) {
		// Transitions only, so the report is a history rather than a wall of repeats.
		lines.push("");
		lines.push("verdict transitions (OAuth pools):");
		let previous = null;
		for (const obs of oauthRows) {
			if (obs.verdict === previous) continue;
			previous = obs.verdict;
			lines.push(`  ${short(obs.t)}  #${String(obs.seq).padStart(4)}  ${String(obs.provider).padEnd(22)} ${obs.verdict}`);
			if (obs.verdict === "STALE-ACCESS") {
				lines.push(`        same account (refresh matches ${obs.poolRefreshFp}); pool access ${obs.poolAccessFp} != pi access ${obs.authAccessFp}`);
				if (typeof obs.expiresDeltaMs === "number") lines.push(`        pool expires ${short(obs.poolExpiresIso)} vs pi ${short(obs.authExpiresIso)}  (${fmtDur(-obs.expiresDeltaMs)} behind)`);
			} else if (obs.verdict === "DIVERGED") {
				lines.push(`        different account: pool refresh ${obs.poolRefreshFp} vs pi refresh ${obs.authRefreshFp}`);
			}
		}
	}
	return lines;
}

// -----------------------------------------------------------------------------
// Section: write-back lag — the central measurement
//
// For each time pi rotates an access token in auth.json, find the next moment
// keyrouter.json holds that same token. That interval is the write-back lag. If
// it never happens, the rotated token was lost.
// -----------------------------------------------------------------------------

function writeBackLag() {
	const lines = [];
	const byProvider = new Map();
	for (const obs of observations) {
		if (obs.kind !== "accounts") continue;
		if (!byProvider.has(obs.provider)) byProvider.set(obs.provider, []);
		byProvider.get(obs.provider).push(obs);
	}

	for (const [provider, rows] of byProvider) {
		lines.push("");
		lines.push(`── ${provider} ─────────────────────────────────────────────`);

		// ── Access-token rotations, tracked per ACCOUNT ─────────────────────
		//
		// A rotation is only "lost" if the account that received it never adopted
		// it. Tracking the access token alone cannot establish that, because
		// keyrouter switching the active account ALSO changes the access token in
		// auth.json — legitimately. So each rotation is bucketed by the refresh
		// identity present in auth.json when it happened, and judged against that
		// same identity's later pool value.
		//
		// The forward scan runs over the whole history rather than only from an
		// IN-SYNC row, which keeps the answer correct across a restart: the last
		// baseline still carries the pool contents as they were.
		const rotations = [];
		let previousAuthFp = null;
		let previousRefreshFp = null;
		let inSyncCount = 0;

		for (const row of rows) {
			if (row.verdict === "IN-SYNC") inSyncCount += 1;
			const authChanged = row.authAccessFp !== previousAuthFp && previousAuthFp !== null;
			const accountChanged = row.authRefreshFp !== previousRefreshFp && previousRefreshFp !== null;
			if (authChanged) {
				rotations.push({
					t: row.t,
					seq: row.seq,
					refreshFp: row.authRefreshFp,
					previousRefreshFp,
					authFp: row.authAccessFp,
					previousAuthFp,
					sameAccount: !accountChanged,
					matchedAt: row.verdict === "IN-SYNC" ? row.t : null,
					lagMs: row.verdict === "IN-SYNC" ? 0 : null,
				});
			}
			previousAuthFp = row.authAccessFp;
			previousRefreshFp = row.authRefreshFp;
		}

		// Second pass: did each rotation's own account ever hold that access token?
		for (const rotation of rotations) {
			if (rotation.matchedAt) continue;
			for (const row of rows) {
				if (ts(row.t) < ts(rotation.t)) continue;
				if (row.authRefreshFp !== rotation.refreshFp) continue;
				if (row.poolAccessFp !== rotation.authFp) continue;
				rotation.matchedAt = row.t;
				rotation.lagMs = ts(row.t) - ts(rotation.t);
				break;
			}
		}

		if (!rotations.length) {
			lines.push(`  no access-token rotation by pi in this window`);
		} else {
			const lags = rotations.filter((r) => typeof r.lagMs === "number").map((r) => r.lagMs);
			// Only a rotation on an account that stayed put can be called lost. When the
			// account changed as well, the access token differing is expected, not a defect.
			const sameAccount = rotations.filter((r) => r.sameAccount);
			const lost = sameAccount.filter((r) => r.matchedAt === null);
			const switched = rotations.filter((r) => !r.sameAccount);
			lines.push(`  pi rotated the access token ${rotations.length} time(s)`);
			lines.push(`    same account (${sameAccount.length}): ${sameAccount.length - lost.length} written back, ${lost.length} NOT written back`);
			lines.push(`    account switched (${switched.length}): expected, not a defect`);
			if (lags.length) {
				const sorted = [...lags].sort((a, b) => a - b);
				lines.push(`  write-back lag: min ${fmtDur(sorted[0])}  median ${fmtDur(sorted[Math.floor(sorted.length / 2)])}  max ${fmtDur(sorted[sorted.length - 1])}`);
			}
			lines.push(`  observations already in sync: ${inSyncCount}/${rows.length}`);
			lines.push("");
			for (const rotation of rotations) {
				let verdict;
				if (rotation.matchedAt) verdict = `written back after ${fmtDur(rotation.lagMs)}`;
				else if (!rotation.sameAccount) verdict = "account switched at the same instant — not a lost write-back";
				else verdict = "NEVER WRITTEN BACK — this account's pool copy kept the old access token";
				lines.push(`    ${short(rotation.t)}  #${String(rotation.seq).padStart(4)}  account ${rotation.refreshFp ?? "?"}  access ${rotation.previousAuthFp} -> ${rotation.authFp}`);
				lines.push(`        ${verdict}`);
			}
		}

		// Refresh identities: the account fingerprint the user trusts as an id.
		const refreshes = new Map();
		for (const row of rows) {
			for (const [side, fp] of [["pool", row.poolRefreshFp], ["auth", row.authRefreshFp]]) {
				if (!fp) continue;
				if (!refreshes.has(fp)) refreshes.set(fp, { pool: 0, auth: 0, first: row.t, last: row.t });
				const entry = refreshes.get(fp);
				entry[side] += 1;
				entry.last = row.t;
			}
		}
		lines.push(`  refresh-token identities seen: ${refreshes.size}`);
		for (const [fp, entry] of refreshes) {
			lines.push(`    ${fp}  pool=${entry.pool} auth=${entry.auth}  ${short(entry.first)} .. ${short(entry.last)}`);
		}
	}
	return lines;
}

// -----------------------------------------------------------------------------
// Section: change log
// -----------------------------------------------------------------------------

function changeLog() {
	const lines = [];
	const limit = args.full ? changes.length : 40;
	lines.push(`file changes (${changes.length}${limit < changes.length ? `, first ${limit}` : ""}):`);
	for (const change of changes.slice(0, limit)) {
		lines.push("");
		lines.push(`  ${short(change.t)}  #${String(change.seq).padStart(4)}  ${String(change.file).padEnd(9)} ${change.reason ?? ""}  lag=${change.detectLagMs ?? "?"}ms`);
		const changed = change.changed;
		if (Array.isArray(changed)) {
			for (const field of changed) {
				const isToken = /access|refresh/.test(field.field);
				// A token is never truncated in the report: its fingerprint identifies it
				// and the true length is stated, so a reader can correlate with the raw
				// values in the log without them being echoed into this output.
				const from = isToken ? `${field.fromFp} (${String(field.from ?? "").length} chars)` : oneLine(field.from, 70);
				const to = isToken ? `${field.toFp} (${String(field.to ?? "").length} chars)` : oneLine(field.to, 70);
				lines.push(`      ${field.field}`);
				lines.push(`        from ${from}`);
				lines.push(`        to   ${to}`);
			}
		} else {
			lines.push(`      (${changed})`);
		}
		for (const row of change.crosscheck ?? []) {
			if (args.provider && row.provider !== args.provider) continue;
			if (row.kind !== "accounts") continue;
			lines.push(`      verdict ${row.verdict}${row.verdict === "DIVERGED" ? " (active account is not the one pi holds)" : ""}`);
		}
	}
	if (limit < changes.length) lines.push(`\n  … ${changes.length - limit} more (use --full)`);
	return lines;
}

// -----------------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------------

const sections = {
	coverage: coverage(),
	verdicts: verdictSummary(),
	writeback: writeBackLag(),
	changes: changeLog(),
};

if (args.json) {
	process.stdout.write(
		`${JSON.stringify(
			{
				log: args.log,
				events: events.length,
				malformed,
				starts: starts.length,
				changes: changes.length,
				verdicts: observations.reduce((acc, o) => ({ ...acc, [o.verdict]: (acc[o.verdict] ?? 0) + 1 }), {}),
			},
			null,
			2,
		)}\n`,
	);
	process.exit(0);
}

const title = (text) => `\n${"═".repeat(78)}\n${text}\n${"═".repeat(78)}`;
process.stdout.write(`${title("COVERAGE")}\n${sections.coverage.join("\n")}\n`);
process.stdout.write(`${title("VERDICTS")}\n${sections.verdicts.join("\n")}\n`);
process.stdout.write(`${title("WRITE-BACK LAG (does keyrouter record what pi refreshed?)")}\n${sections.writeback.join("\n") || "\n  no OAuth pool observations yet"}\n`);
process.stdout.write(`${title("CHANGE LOG")}\n${sections.changes.join("\n")}\n`);
process.stdout.write("\n");