#!/usr/bin/env node
// =============================================================================
// run.mjs — end-to-end tests for pi-keyrouter against the fake OpenAI server.
// =============================================================================
//
// Boots test/fake-openai-server.mjs, points a THROWAWAY pi instance at it
// (isolated agent dir + isolated keyrouter config, extension loaded with -e),
// runs real `pi --print` requests, and asserts on three independent signals:
//
//   1. server log — which `Authorization` key each request carried. That is the
//      proof rotation actually happened (pi resolved a different key).
//   2. trace log  — what keyrouter decided (PI_KEYROUTER_TRACE); key NAMES only.
//   3. pi output  — whether the turn finally succeeded.
//
// The provider's own models.json key is `sk-models-json-baseline` and is NOT in
// any pool, so if that ever reaches the server, injection silently failed.
//
//   node test/run.mjs                 # all cases
//   node test/run.mjs rotate          # name-substring filter
//   node test/run.mjs --verbose       # trace + timing for every case
//   node test/run.mjs --keep-open     # leave the server listening
//
// Nothing touches ~/.pi.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { OAUTH_ACCOUNTS, OAUTH_ACCOUNTS_3, OAUTH_ACCOUNTS_DEAD_FIRST, OAUTH_ACCOUNTS_EXPIRING_FIRST, oauthCases } from "./oauth-cases.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const FIXTURE = join(HERE, "fixture");
const AGENT_DIR = join(FIXTURE, "agent");
const PI_HOME = join(FIXTURE, "pi-home");
const KEYROUTER_CONFIG = join(PI_HOME, "keyrouter.json");
const ARTIFACTS = join(HERE, "artifacts");
const TRACE = join(ARTIFACTS, "trace.log");
const SERVER_LOG = join(ARTIFACTS, "server.log");
const EXTENSION_ENTRY = join(ROOT, "index.ts");
/** The OAuth-only fixture provider, loaded in addition to the extension. */
const OAUTH_PROVIDER = join(HERE, "fixture", "oauth-provider.ts");
/** Written by the fixture's refreshToken hook ("did pi refresh, and when"). */
const OAUTH_LOG = join(ARTIFACTS, "oauth.log");
/** The REAL user auth.json. The suite asserts this is byte-identical. */
const REAL_AUTH_JSON = join(homedir(), ".pi", "agent", "auth.json");

/** Extra pi CLI options for OAuth cases. */
const OAUTH_RUN_OPTS = {
	extensions: [OAUTH_PROVIDER],
	provider: "kroauth",
	env: { KR_OAUTH_LOG: OAUTH_LOG },
};

/**
 * Read the fixture's oauth log, if the case produced one.
 * Lines are "<iso> refresh access=..."; timestamps are stripped so assertions
 * match on content.
 */
function readOauthLog() {
	if (!existsSync(OAUTH_LOG)) return [];
	return readFileSync(OAUTH_LOG, "utf8")
		.split(/\r?\n/)
		.filter(Boolean)
		.map((line) => line.replace(/^\S+\s+/, "").trim());
}

/** Parse the fixture agent dir's auth.json after a run. */
function readAuthJson() {
	const path = join(AGENT_DIR, "auth.json");
	if (!existsSync(path)) return undefined;
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
}

/**
 * Parse the fixture keyrouter config after a run.
 *
 * This is the OBSERVABLE PROOF that a captured credential was persisted: pi
 * writes a refreshed pair to its own store, and only a write-back puts it in
 * keyrouter's config. Without it the pool would keep installing the access token
 * from an account's last login and every account would look dead.
 */
function readKeyrouterConfig() {
	if (!existsSync(KEYROUTER_CONFIG)) return undefined;
	try {
		return JSON.parse(readFileSync(KEYROUTER_CONFIG, "utf8"));
	} catch {
		return undefined;
	}
}


/**
 * sha256 of a file, or "(absent)". Used to prove the suite never touches the
 * user's real credentials — every case runs in the fixture agent dir.
 */
function fileDigest(path) {
	if (!existsSync(path)) return "(absent)";
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

// How to launch pi: Node cannot spawn the `pi.ps1`/`pi.cmd` shims on Windows,
// so prefer pi's own bundle entry through this Node binary. Resolution order:
// PI_BIN (explicit) > PI_CLI_JS > auto-resolved bundle/cli.js > "pi".
const PI_BIN = process.env.PI_BIN ?? "pi";
const PI_CLI_JS = process.env.PI_BIN ? undefined : (process.env.PI_CLI_JS ?? resolvePiCli());
const PI_CMD = PI_CLI_JS ? process.execPath : PI_BIN;
const PI_PREFIX = PI_CLI_JS ? [PI_CLI_JS] : [];

function resolvePiCli() {
	try {
		// pi's exports map has no "./package.json" subpath and no require condition,
		// so resolve the ESM main entry (dist/index.js) and derive the root from it.
		const main = fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent"));
		const root = dirname(dirname(main));
		const candidate = join(root, "dist", "bundle", "cli.js");
		return existsSync(candidate) ? candidate : undefined;
	} catch {
		return undefined;
	}
}
// Ask the OS for a genuinely free ephemeral port. A random guess in a fixed
// range intermittently lands on a Windows excluded/reserved port, which fails
// as EACCES ("permission denied") rather than EADDRINUSE and looks like a
// mysterious server crash. Binding port 0 cannot collide.
const PORT = Number(process.env.KR_TEST_PORT ?? (await freePort()));
const BASE = `http://127.0.0.1:${PORT}`;
const SERVER_BUILD = "kr-fake-v2";

async function freePort() {
	const { createServer } = await import("node:net");
	return await new Promise((resolve, reject) => {
		const probe = createServer();
		probe.unref();
		probe.on("error", reject);
		probe.listen(0, "127.0.0.1", () => {
			const address = probe.address();
			const port = typeof address === "object" && address ? address.port : 0;
			probe.close(() => (port ? resolve(port) : reject(new Error("no free port"))));
		});
	});
}
const PI_TIMEOUT_MS = Number(process.env.KR_TEST_TIMEOUT ?? 120_000);
const BASELINE_KEY = "sk-models-json-baseline";

const argv = process.argv.slice(2);
const verbose = argv.includes("--verbose");
const keepOpen = argv.includes("--keep-open");
const filters = argv.filter((a) => !a.startsWith("--"));

// ---------------------------------------------------------------------------
// keyrouter configs (written per case)
// ---------------------------------------------------------------------------
const POOL = (...keys) => ({
	providers: [{ name: "krtest", keys: keys.map(([name, value]) => ({ name, value })) }],
	maxRetries: 3,
	cooldownMs: 60_000,
	overloadedCooldownMs: 30_000,
});

/** An OAuth account pool for `kroauth`, the OAuth-only fixture provider. */
const ACCOUNTS = (accounts, extra = {}) => ({
	providers: [{ name: "kroauth", accounts, ...extra }],
	maxRetries: 3,
	cooldownMs: 60_000,
	overloadedCooldownMs: 30_000,
});

const CONFIGS = {
	abc: POOL(["A", "sk-a"], ["B", "sk-b"], ["C", "sk-c"]),
	// Same pool, but explicitly allowed to shadow a stored OAuth login.
	"abc-takeover": {
		...POOL(["A", "sk-a"], ["B", "sk-b"], ["C", "sk-c"]),
		providers: [
			{
				name: "krtest",
				keys: [{ name: "A", value: "sk-a" }, { name: "B", value: "sk-b" }, { name: "C", value: "sk-c" }],
				takeoverOAuth: true,
			},
		],
	},
	// One key only: nothing left to rotate to, so keyrouter must declare the pool
	// exhausted and hand the provider back to pi's own credential.
	single: POOL(["A", "sk-a"]),
	// A valid pool plus a provider id pi does not know.
	"with-ghost": {
		providers: [
			{ name: "krtest", keys: [{ name: "A", value: "sk-a" }, { name: "B", value: "sk-b" }] },
			{ name: "ghost-not-registered", keys: [{ name: "G", value: "sk-g" }] },
		],
	},
	// Keys from the environment, plus a pool referencing a missing variable.
	env: {
		providers: [
			{ name: "krtest", keys: [{ name: "ENVKEY", value: "$KR_TEST_ENV_KEY" }] },
			{ name: "uses-missing-var", keys: [{ name: "M", value: "$KR_TEST_DEFINITELY_NOT_SET" }] },
		],
	},

	// --- OAuth account pools (provider `kroauth`, OAuth-only) ----------------
	accounts: ACCOUNTS(OAUTH_ACCOUNTS),
	"accounts-3": ACCOUNTS(OAUTH_ACCOUNTS_3),
	// Credential shapes that must come from the POOL: the first account is
	// installed at session start, replacing anything seeded into auth.json.
	"accounts-expiring-first": ACCOUNTS(OAUTH_ACCOUNTS_EXPIRING_FIRST),
	"accounts-dead-first": ACCOUNTS(OAUTH_ACCOUNTS_DEAD_FIRST),
	// rotateOnQuota disabled: a quota error must NOT rotate.
	"accounts-no-quota": ACCOUNTS(OAUTH_ACCOUNTS, { rotateOnQuota: false }),
	// Points an account pool at the API-key-only fixture provider. keyrouter must
	// refuse it: installing a blob on a provider with no OAuth auth resolves to
	// nothing, so the pool would silently do harm.
	"accounts-wrong-provider": {
		providers: [{ name: "krtest", accounts: OAUTH_ACCOUNTS }],
	}
};

// ---------------------------------------------------------------------------
// fake server
// ---------------------------------------------------------------------------
let serverProc = null;
let serverOut = "";

function startServer() {
	serverProc = spawn(process.execPath, [join(HERE, "fake-openai-server.mjs"), "--port", String(PORT)], {
		stdio: ["ignore", "pipe", "pipe"],
		windowsHide: true,
	});
	serverProc.on("error", (error) => {
		serverOut += `spawn error: ${error.message}\n`;
	});
	serverProc.stdout.on("data", (d) => {
		serverOut += d;
		if (verbose) process.stdout.write(`    [server] ${String(d).trimEnd()}\n`);
	});
	serverProc.stderr.on("data", (d) => {
		serverOut += d;
		if (verbose) process.stderr.write(`    [server!] ${d}`);
	});
	serverProc.on("exit", (code) => {
		if (code !== 0 && code !== null) serverExitCode = code;
	});
}

// Set when the child exits non-zero, e.g. EADDRINUSE on a reused port.
let serverExitCode = null;

async function waitForHealth(timeoutMs = 10_000) {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (serverExitCode !== null) {
			throw new Error(
				`fake server exited with code ${serverExitCode}. Port ${PORT} is probably taken by an older server — ` +
				`the runner picks a random port unless KR_TEST_PORT is set.\nserver output:\n${serverOut}`,
			);
		}
		try {
			const res = await fetch(`${BASE}/__admin/health`, { signal: AbortSignal.timeout(1000) });
			if (res.ok) {
				const health = await res.json();
				// Refuse a stale build: a leftover server from an older checkout
				// silently mis-plans every case (observed as "unknown step shorthand").
				if (health.build !== SERVER_BUILD) {
					throw new Error(`server on ${PORT} reports build ${JSON.stringify(health.build)}, expected ${SERVER_BUILD}`);
				}
				return true;
			}
		} catch (error) {
			if (error instanceof Error && error.message.startsWith("server on")) throw error;
			// not listening yet
		}
		await sleep(120);
	}
	throw new Error(`fake server never became healthy on ${PORT}\nserver output:\n${serverOut}`);
}

async function admin(path, body) {
	const res = await fetch(`${BASE}${path}`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body ?? {}),
	});
	const text = await res.text();
	if (!res.ok) throw new Error(`POST ${path} -> ${res.status}: ${text}`);
	return text ? JSON.parse(text) : {};
}

async function serverRequestLog() {
	const res = await fetch(`${BASE}/__admin/log`);
	const data = await res.json();
	return data.log ?? [];
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// pi
// ---------------------------------------------------------------------------
/**
 * Run one pi print-mode request.
 *
 * `caseOpts` lets a case add extensions and override the provider, which is how
 * the OAuth cases load test/fixture/oauth-provider.ts and select `kroauth`
 * instead of the api-key `krtest` provider.
 */
async function runPi(extraEnv) {
	const opts = arguments[1] ?? {};
	const args = [
		...PI_PREFIX,
		"-e", EXTENSION_ENTRY,
		...(opts.extensions ?? []).flatMap((path) => ["-e", path]),
		"--no-session",
		"--no-tools",
		"--provider", opts.provider ?? "krtest",
		"--model", opts.model ?? "fake-gpt",
		"--thinking", "off",
		"-p", "Reply with exactly: PONG",
	];
	const env = {
		...process.env,
		PI_CODING_AGENT_DIR: AGENT_DIR,
		PI_KEYROUTER_CONFIG: KEYROUTER_CONFIG,
		PI_KEYROUTER_TRACE: TRACE,
		PI_OFFLINE: "1",
		PI_SKIP_VERSION_CHECK: "1",
		PI_TELEMETRY: "0",
		PI_CACHE_WARMING: "off",
		KR_FAKE_BASE: BASE,
		...(opts.env ?? {}),
		...extraEnv,
	};
	return new Promise((done) => {
		// stdin must be closed, not piped: pi merges stdin content into the prompt
		// (`git diff | pi --print ...`), so an open pipe hangs the child forever.
		const child = spawn(PI_CMD, args, {
			env,
			cwd: FIXTURE,
			windowsHide: true,
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
		}, PI_TIMEOUT_MS);
		child.stdout.on("data", (d) => (stdout += d));
		child.stderr.on("data", (d) => (stderr += d));
		child.on("error", (error) => {
			clearTimeout(timer);
			done({ stdout, stderr: `${stderr}\nspawn error: ${error.message}`, code: -1, timedOut });
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			done({ stdout, stderr, code: code ?? -1, timedOut });
		});
	});
}

function readTrace() {
	if (!existsSync(TRACE)) return [];
	return readFileSync(TRACE, "utf8")
		.split(/\r?\n/)
		.filter(Boolean)
		.map((line) => line.replace(/^\S+\s+/, "").trim());
}

// ---------------------------------------------------------------------------
// assertion helpers
// ---------------------------------------------------------------------------
const keysOf = (log) => log.map((entry) => entry.key);
const statusesOf = (log) => log.map((entry) => entry.status);
const traceHas = (trace, needle) => trace.some((line) => line.includes(needle));
const traceCount = (trace, prefix) => trace.filter((line) => line.startsWith(prefix)).length;
const joined = (pi) => `${pi.stdout}\n${pi.stderr}`;

// Stored OAuth credential for the fixture provider. Expiry is far in the future
// so pi never attempts a refresh (and no network is needed).
const OAUTH_AUTH_JSON = {
	krtest: {
		type: "oauth",
		refresh: "test-refresh-token",
		access: "test-oauth-access",
		expires: Date.now() + 24 * 60 * 60 * 1000,
	},
};

// ---------------------------------------------------------------------------
// cases — expect() returns [label, boolean][]
// ---------------------------------------------------------------------------
const cases = [
	{
		name: "bootstrap-injects-pool-key",
		config: "abc",
		plan: { default: "ok", text: "PONG" },
		expect: ({ keys, statuses, trace, pi }) => [
			["pi printed PONG", pi.code === 0 && /PONG/.test(pi.stdout)],
			["exactly one request", keys.length === 1],
			["that request was 200", statuses.join() === "200"],
			["carried pool key sk-a (injection beat models.json)", keys[0] === "sk-a"],
			[`never carried the baseline key ${BASELINE_KEY}`, !keys.includes(BASELINE_KEY)],
			["trace: bootstrap krtest -> A", traceHas(trace, "bootstrap krtest -> A")],
			["trace: no rotation", traceCount(trace, "rotate") === 0],
			["trace: one clear (shutdown only)", traceCount(trace, "clear") === 1],
		],
	},
	{
		name: "rotate-on-429",
		config: "abc",
		plan: { byKey: { "sk-a": 429 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi }) => [
			["pi recovered and printed PONG", /PONG/.test(pi.stdout)],
			["first request used sk-a", keys[0] === "sk-a"],
			["a later request used sk-b", keys.includes("sk-b")],
			["trace: rotate A -> B", traceHas(trace, "rotate krtest A -> B")],
			["trace: 429 rate-limited", traceHas(trace, "429 rate-limited")],
			["trace: no exhaustion", !traceHas(trace, "exhausted")],
			["trace: B marked ok", traceHas(trace, "success krtest key=B")],
			// 429 is in pi's retryable set, so its own retry used sk-b and the
			// settle-time continuation must not have been needed.
			["no settle continuation for a pi-retryable error", !traceHas(trace, "continue ")],
		],
	},
	{
		name: "rotate-on-401",
		config: "abc",
		// pi does NOT retry 401, so recovery here proves the settle-time
		// continuation: keyrouter rotates the key and asks for one more request.
		plan: { byKey: { "sk-a": 401 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi }) => [
			["pi recovered and printed PONG", /PONG/.test(pi.stdout)],
			["first request used sk-a", keys[0] === "sk-a"],
			["continuation request used sk-b", keys[1] === "sk-b"],
			["trace: 401 unauthorized", traceHas(trace, "401 unauthorized")],
			["trace: rotate A -> B", traceHas(trace, "rotate krtest A -> B")],
			["trace: continuation requested", traceHas(trace, "continue krtest")],
			["exactly one continuation", traceCount(trace, "continue ") === 1],
		],
	},
	{
		name: "rotate-on-403",
		config: "abc",
		plan: { byKey: { "sk-a": 403 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace }) => [
			["rotated to sk-b", keys[1] === "sk-b"],
			["trace: 403 unauthorized", traceHas(trace, "403 unauthorized")],
			["continuation requested (pi never retries 403)", traceHas(trace, "continue krtest")],
		],
	},
	{
		name: "server-500-is-not-a-key-failure",
		config: "abc",
		// 500 is pi-retryable but is NOT a key problem: keyrouter must leave the
		// key alone and let pi's own retry succeed on the same key.
		plan: { sequence: [500, "ok"], default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi }) => [
			["pi recovered via its own retry", pi.code === 0 && /PONG/.test(pi.stdout)],
			["no key rotation for 5xx", traceCount(trace, "rotate") === 0],
			["no continuation requested", !traceHas(trace, "continue ")],
			["ignored as non-rotatable", traceHas(trace, "ignore krtest")],
			["both attempts used the same sk-a", keys.join(",") === "sk-a,sk-a"],
		],
	},
	{
		name: "two-failures-walk-A-B-C",
		config: "abc",
		plan: { byKey: { "sk-a": 429, "sk-b": 401 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace }) => [
			["sk-a then sk-b then sk-c", keys.slice(0, 3).join(",") === "sk-a,sk-b,sk-c"],
			["trace: rotate A -> B", traceHas(trace, "rotate krtest A -> B")],
			["trace: rotate B -> C", traceHas(trace, "rotate krtest B -> C")],
			["exactly two rotations", traceCount(trace, "rotate") === 2],
			["recovered on C", traceHas(trace, "success krtest key=C")],
			// 429 is retried by pi, but the following 401 is not: that leg needs
			// exactly one settle-time continuation to reach sk-c.
			["exactly one continuation", traceCount(trace, "continue ") === 1],
		],
	},
	{
		name: "exhaustion-clears-override",
		config: "single",
		// One key, 429 forever: nothing to rotate to, so keyrouter must hand the
		// provider back to pi's own credential. The proof is pi's later retries
		// carrying the models.json baseline key instead of the pool key.
		plan: { sequence: [429], repeatLast: true },
		expect: ({ keys, trace, pi }) => [
			["pi surfaced an error", pi.code !== 0 || /429|rate.?limit|error/i.test(joined(pi))],
			["first request used pool key sk-a", keys[0] === "sk-a"],
			["later retries fell back to the baseline key", keys.slice(1).length > 0 && keys.slice(1).every((k) => k === BASELINE_KEY)],
			["zero rotations (single-key pool)", traceCount(trace, "rotate") === 0],
			["trace: exhausted", traceHas(trace, "exhausted krtest")],
			["override cleared BEFORE the exhausted line", orderedBefore(trace, "clear krtest", "exhausted krtest")],
			["exactly one clear (exhaustion; shutdown had nothing left)", traceCount(trace, "clear") === 1],
		],
	},
	{
		name: "overloaded-529-cools-provider-no-rotation",
		config: "abc",
		plan: { sequence: [529], repeatLast: true },
		expect: ({ keys, trace, pi }) => [
			["pi reported the error", pi.code !== 0 || /overload/i.test(joined(pi))],
			["same key throughout (no rotation)", keys.length > 0 && keys.every((k) => k === "sk-a")],
			["trace: overload branch", traceHas(trace, "overload krtest")],
			["zero rotations", traceCount(trace, "rotate") === 0],
			["no exhaustion (overload is not a key failure)", !traceHas(trace, "exhausted")],
			["only the shutdown clear ran", traceCount(trace, "clear") === 1],
		],
	},
	{
		name: "quota-402-is-not-rotatable",
		config: "abc",
		// "insufficient_quota" + "quota exceeded" are NON_RETRYABLE in pi: the
		// request is not retried, so keyrouter must not touch the pool.
		plan: { byKey: { "sk-a": 402 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace }) => [
			["exactly one request (pi gave up)", keys.length === 1],
			["still sk-a — no rotation", keys[0] === "sk-a"],
			["trace: ignored as non-rotatable", traceHas(trace, "ignore krtest")],
			["zero rotations", traceCount(trace, "rotate") === 0],
			["zero overloads", traceCount(trace, "overload") === 0],
		],
	},
	{
		name: "sequence-plan-walks-keys",
		config: "abc",
		// Per-request steps rather than per-key: request 1 and 2 fail, 3 works.
		plan: { sequence: [429, 401, "ok"], default: "ok", text: "PONG" },
		expect: ({ keys, trace }) => [
			["keys went A -> B -> C", keys.slice(0, 3).join(",") === "sk-a,sk-b,sk-c"],
			["two rotations", traceCount(trace, "rotate") === 2],
			["succeeded on C", traceHas(trace, "success krtest key=C")],
		],
	},
	{
		name: "unknown-provider-skipped-pool-still-works",
		config: "with-ghost",
		plan: { byKey: { "sk-a": 429 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi }) => [
			["pi works", /PONG/.test(pi.stdout)],
			["valid pool bootstrapped", traceHas(trace, "bootstrap krtest -> A")],
			["ghost reported not-registered", traceHas(trace, "skip ghost-not-registered (provider not registered)")],
			["ghost produced no bootstrap", !traceHas(trace, "bootstrap ghost")],
			["rotation still happened", traceHas(trace, "rotate krtest A -> B")],
			["sk-b served the retry", keys.includes("sk-b")],
		],
	},
	{
		name: "env-keys-expand-missing-var-drops-pool",
		config: "env",
		env: { KR_TEST_ENV_KEY: "sk-b" },
		plan: { byKey: { "sk-a": 429 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi }) => [
			["pi works", /PONG/.test(pi.stdout)],
			["$VAR expanded and used first (sk-b)", keys[0] === "sk-b"],
			["trace: bootstrap krtest -> ENVKEY", traceHas(trace, "bootstrap krtest -> ENVKEY")],
			["pool with a missing env var never bootstraps", !traceHas(trace, "bootstrap uses-missing-var")],
			["no rotation (sk-b was fine)", traceCount(trace, "rotate") === 0],
		],
	},
	{
		name: "malformed-stream-is-not-rotatable",
		config: "abc",
		// 200 headers then garbage: pi reports a parse/stream failure, which is
		// not a key problem, so the pool must stay put.
		plan: { sequence: ["badJson"], repeatLast: true },
		expect: ({ keys, trace }) => [
			["zero rotations", traceCount(trace, "rotate") === 0],
			["key never swapped", keys.length > 0 && keys.every((k) => k === "sk-a")],
			["no exhaustion claim", !traceHas(trace, "exhausted")],
		],
	},
	{
		name: "all-keys-401-budget-stops-loop",
		config: "abc",
		// Every key is bad and pi never retries 401, so each leg depends on a
		// settle-time continuation. The pool walks A -> B -> C, and the pick after
		// C is a *cooled* key, so `pendingContinue` stays false: keyrouter stops
		// asking for more requests instead of looping forever.
		plan: { byKey: { "sk-a": 401, "sk-b": 401, "sk-c": 401 } },
		expect: ({ keys, trace, pi }) => [
			["pi surfaced an error", pi.code !== 0 || /401|unauthorized|Incorrect API/i.test(joined(pi))],
			["pool walked A -> B -> C", keys.slice(0, 3).join(",") === "sk-a,sk-b,sk-c"],
			["exactly three requests (loop stopped)", keys.length === 3],
			["three rotations logged (last one to a cooled key)", traceCount(trace, "rotate") === 3],
			["only two continuations asked (third was suppressed)", traceCount(trace, "continue ") === 2],
			["the suppressed leg was the last one (no request after it)", lastRotateAfterLastContinue(trace)],
			["override cleared in the end", traceHas(trace, "clear krtest")],
		],
	},
	{
		// A stored OAuth credential owns the provider in pi's resolver, so an
		// injected api_key would shadow the user's login. keyrouter must leave it
		// completely alone: no bootstrap, and the request is pi's to fail.
		name: "stored-oauth-login-is-never-shadowed",
		config: "abc",
		auth: OAUTH_AUTH_JSON,
		plan: { default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi }) => [
			["skipped because of the stored OAuth login", traceHas(trace, "skip krtest (using a stored OAuth login)")],
			["no bootstrap", !traceHas(trace, "bootstrap krtest")],
			["no pooled key ever reached the server", !keys.includes("sk-a") && !keys.includes("sk-b") && !keys.includes("sk-c")],
			["no override was ever written", traceCount(trace, "clear") === 0],
			["pi still owns the request (it failed without auth)", !/PONG/.test(pi.stdout)],
		],
	},
	{
		// Same stored login, but the pool opts in with `takeoverOAuth`: now the
		// pooled key must win, proving the flag is the only thing gating this.
		name: "takeoverOAuth-overrides-stored-login",
		config: "abc-takeover",
		auth: OAUTH_AUTH_JSON,
		plan: { default: "ok", text: "PONG" },
			expect: ({ keys, trace, pi }) => [
				["no skip reported", !traceHas(trace, "skip krtest")],
				["pool bootstrapped", traceHas(trace, "bootstrap krtest -> A")],
				["pooled key reached the server", keys[0] === "sk-a"],
				["pi printed PONG", /PONG/.test(pi.stdout)],
				["override cleaned up", traceHas(trace, "clear krtest")],
			],
		},
		...oauthCases,
	];

function orderedBefore(trace, earlier, later) {
	const a = trace.findIndex((line) => line.includes(earlier));
	const b = trace.findIndex((line) => line.includes(later));
	return a !== -1 && b !== -1 && a < b;
}

/**
 * True when the final `rotate` line comes after the final `continue` line: the
 * last rotation was suppressed (cooled key) so it never bought another request.
 */
function lastRotateAfterLastContinue(trace) {
	const lines = trace.join("\n").split("\n");
	let lastRotate = -1;
	let lastContinue = -1;
	lines.forEach((line, i) => {
		if (line.startsWith("rotate")) lastRotate = i;
		if (line.startsWith("continue")) lastContinue = i;
	});
	return lastRotate !== -1 && lastRotate > lastContinue;
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------
async function prepareFixture() {
	mkdirSync(AGENT_DIR, { recursive: true });
	mkdirSync(PI_HOME, { recursive: true });
	const modelsPath = join(AGENT_DIR, "models.json");
	const fixture = {
		providers: {
			krtest: {
				name: "KR Test (fake-openai-server)",
				baseUrl: `${BASE}/v1`,
				api: "openai-completions",
				apiKey: BASELINE_KEY,
				models: [
					{
						id: "fake-gpt",
						name: "Fake GPT",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 128000,
						maxTokens: 1024,
					},
				],
			},
		},
	};
	writeFileSync(modelsPath, JSON.stringify(fixture, null, 2) + "\n", "utf8");
	// Isolated settings: no enabledModels patterns, deterministic trust, short
	// retry backoff so failing cases don't sit in sleep() for a minute.
	writeFileSync(
		join(AGENT_DIR, "settings.json"),
		JSON.stringify({ defaultProjectTrust: "never", retry: { enabled: true, maxRetries: 3, baseDelayMs: 150, maxAgentDelayMs: 1000 } }, null, 2) + "\n",
		"utf8",
	);
	return modelsPath;
}

function writeConfig(name) {
	writeFileSync(KEYROUTER_CONFIG, JSON.stringify(CONFIGS[name], null, 2) + "\n", "utf8");
}

// ---------------------------------------------------------------------------
// driver
// ---------------------------------------------------------------------------
async function main() {
	mkdirSync(ARTIFACTS, { recursive: true });
	if (existsSync(TRACE)) rmSync(TRACE);
	const modelsPath = await prepareFixture();
	// Record the user's REAL credentials before anything runs. Every case must
	// stay inside the fixture agent dir, so this digest must be unchanged at the
	// end — a release blocker if it is not.
	const realAuthBefore = fileDigest(REAL_AUTH_JSON);



	if (!(await probePi())) {
		console.error(`cannot run pi --version (PI_CMD=${PI_CMD}, PI_CLI_JS=${PI_CLI_JS ?? "(none)"}) — set PI_BIN or PI_CLI_JS`);
		process.exit(1);
	}
	startServer();
	if (!(await waitForHealth())) {
		console.error(`fake server never answered on ${BASE}`);
		serverProc?.kill();
		process.exit(1);
	}
	console.log(`extension      ${EXTENSION_ENTRY}`);
	console.log(`fake server    ${BASE}`);
	console.log(`pi agent dir   ${AGENT_DIR}`);
	console.log(`keyrouter cfg  ${KEYROUTER_CONFIG}\n`);

	const selected = filters.length ? cases.filter((c) => filters.some((f) => c.name.includes(f))) : cases;
	if (selected.length === 0) {
		console.error(`no case matches ${filters.join(", ")}`);
		serverProc?.kill();
		process.exit(1);
	}

	const results = [];
	for (const c of selected) {
		writeConfig(c.config);
		if (existsSync(TRACE)) rmSync(TRACE);
		await admin("/__admin/reset");
		await admin("/__admin/plan", c.plan);

		const t0 = Date.now();
		// auth.json is pi's stored-credential file for the isolated agent dir.
		// Set it only for cases that need one so it cannot leak into the next.
		const authPath = join(AGENT_DIR, "auth.json");
		if (c.auth) writeFileSync(authPath, JSON.stringify(c.auth, null, 2) + "\n", "utf8");
		else if (existsSync(authPath)) rmSync(authPath);

		// OAuth cases load the fixture provider that registers `kroauth`, and the
		// fixture's refresh hook writes here. Removed per case so a leftover log
		// cannot make a later case look refreshed.
		if (existsSync(OAUTH_LOG)) rmSync(OAUTH_LOG);
		const pi = await runPi(c.env ?? {}, c.oauth ? OAUTH_RUN_OPTS : undefined);
		const log = await serverRequestLog();
		const trace = readTrace();
		const ctx = {
			log,
			trace,
			keys: keysOf(log),
			statuses: statusesOf(log),
			pi,
			oauthLog: readOauthLog(),
			// Read back AFTER the run so a case can assert on what keyrouter left
			// behind — e.g. that a sibling provider entry survived its writes, or that a
			// refreshed credential was persisted back into the pool config.
			authAfter: readAuthJson(),
			configAfter: readKeyrouterConfig(),
		};

		const problems = [];
		let checks = [];
		try {
			checks = c.expect(ctx);
		} catch (error) {
			problems.push(`expect() threw: ${error.message}`);
		}
		for (const [label, pass] of checks) if (!pass) problems.push(label);

		const secs = ((Date.now() - t0) / 1000).toFixed(1);
		results.push({ ...c, ok: problems.length === 0, problems, ctx, secs });
		if (problems.length === 0) {
			console.log(`PASS  ${c.name}  (${secs}s)`);
			if (verbose) dump(ctx);
		} else {
			console.log(`FAIL  ${c.name}  (${secs}s)`);
			for (const p of problems) console.log(`        x ${p}`);
			dump(ctx);
		}
	}

	writeFileSync(SERVER_LOG, serverOut, "utf8");
	if (keepOpen) console.log(`\nserver left on ${BASE} (pid ${serverProc?.pid}) — server log: ${SERVER_LOG}`);
	else serverProc?.kill();

	// The real user credentials must be untouched. Every case runs against the
	// fixture agent dir, so any difference here means a bug could have logged the
	// user out or overwritten a live credential.
	const realAuthAfter = fileDigest(REAL_AUTH_JSON);
	const realAuthIntact = realAuthBefore === realAuthAfter;
	console.log(`\nreal auth.json ${REAL_AUTH_JSON}`);
	console.log(`  sha256 before ${realAuthBefore}`);
	console.log(`  sha256 after  ${realAuthAfter}`);
	console.log(`  ${realAuthIntact ? "unchanged" : "CHANGED — THE SUITE TOUCHED REAL CREDENTIALS"}`);

	const failed = results.filter((r) => !r.ok);
	console.log(`\n${results.length - failed.length}/${results.length} passed`);
	if (failed.length) console.log(`failed: ${failed.map((f) => f.name).join(", ")}`);
	if (!realAuthIntact) console.log("RELEASE BLOCKER: real auth.json was modified by the suite");
	process.exit(failed.length || !realAuthIntact ? 1 : 0);
}

function dump(ctx) {
	console.log(`        keys=${JSON.stringify(ctx.keys)}`);
	console.log(`        status=${JSON.stringify(ctx.statuses)}`);
	console.log(`        trace=${JSON.stringify(ctx.trace)}`);
	if (verbose || ctx.pi.code !== 0) {
		console.log(`        pi.code=${ctx.pi.code} timedOut=${ctx.pi.timedOut}`);
		console.log(`        pi.out=${JSON.stringify(ctx.pi.stdout.slice(0, 200))}`);
		console.log(`        pi.err=${JSON.stringify(ctx.pi.stderr.slice(0, 400))}`);
	}
}

async function probePi() {
	return new Promise((done) => {
		const child = spawn(PI_CMD, [...PI_PREFIX, "--version"], { stdio: "ignore", windowsHide: true });
		child.on("error", () => done(false));
		child.on("close", (code) => done(code === 0));
	});
}

main().catch((error) => {
	serverProc?.kill();
	console.error(error);
	process.exit(1);
});
