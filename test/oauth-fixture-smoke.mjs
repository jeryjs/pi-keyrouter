#!/usr/bin/env node
// =============================================================================
// oauth-fixture-smoke.mjs — prove the OAuth fixture works WITHOUT keyrouter
// =============================================================================
//
// Step 3 gate for the OAuth-pool work. Before trusting any rotation assertion,
// establish the baseline: with a seeded auth.json and the fixture provider
// registered, pi alone resolves the OAuth credential and sends
// `Authorization: Bearer oauth:<access>`.
//
// This is deliberately keyrouter-free. If it fails, the problem is the fixture
// or the pi API — not the pool logic — which is exactly what makes it a useful
// gate. It also pins the two behaviours the pool depends on:
//
//   1. A credential far from expiry is used as-is, with NO refresh call.
//   2. A credential inside pi's ~5-minute validity window IS refreshed, and pi
//      persists the rotated blob itself.
//
//   node test/oauth-fixture-smoke.mjs

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const OAUTH_PROVIDER = join(HERE, "fixture", "oauth-provider.ts");
const FAKE_SERVER = join(HERE, "fake-openai-server.mjs");

let failures = 0;
const check = (label, condition, detail) => {
	const pass = Boolean(condition);
	if (!pass) failures += 1;
	console.log(`${pass ? "PASS" : "FAIL"}  ${label}${detail === undefined || pass ? "" : `  (${detail})`}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function resolvePiCli() {
	try {
		const main = fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent"));
		const candidate = join(dirname(dirname(main)), "dist", "bundle", "cli.js");
		return existsSync(candidate) ? candidate : undefined;
	} catch {
		return undefined;
	}
}
const PI_CLI_JS = process.env["PI_BIN"] ? undefined : (process.env["PI_CLI_JS"] ?? resolvePiCli());
const PI_CMD = PI_CLI_JS ? process.execPath : (process.env["PI_BIN"] ?? "pi");
const PI_PREFIX = PI_CLI_JS ? [PI_CLI_JS] : [];

const PORT = Number(process.env["KR_TEST_PORT"] ?? 41000 + Math.floor(Math.random() * 18000));
const BASE = `http://127.0.0.1:${PORT}`;
const SERVER_BUILD = "kr-fake-v2";

const work = mkdtempSync(join(tmpdir(), "kr-oauth-smoke-"));
const AGENT_DIR = join(work, "agent");
const OAUTH_LOG = join(work, "oauth.log");
let serverProc;

async function startServer() {
	serverProc = spawn(process.execPath, [FAKE_SERVER, "--port", String(PORT)], {
		stdio: ["ignore", "pipe", "pipe"],
		windowsHide: true,
	});
	let out = "";
	serverProc.stdout.on("data", (d) => (out += d));
	serverProc.stderr.on("data", (d) => (out += d));
	const deadline = Date.now() + 10_000;
	while (Date.now() < deadline) {
		try {
			const res = await fetch(`${BASE}/__admin/health`, { signal: AbortSignal.timeout(800) });
			if (res.ok) {
				const health = await res.json();
				if (health.build !== SERVER_BUILD) throw new Error(`stale server build ${health.build}`);
				return;
			}
		} catch (error) {
			if (error instanceof Error && error.message.startsWith("stale")) throw error;
		}
		await sleep(100);
	}
	throw new Error(`fake server never came up\n${out}`);
}

async function admin(path, body) {
	const res = await fetch(`${BASE}${path}`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body ?? {}),
	});
	return res.ok ? res.json() : Promise.reject(new Error(`${path} -> ${res.status}`));
}

async function serverLog() {
	const res = await fetch(`${BASE}/__admin/log`);
	return (await res.json()).log ?? [];
}

function runPi(env) {
	return new Promise((done) => {
		// stdin closed, not piped: pi merges stdin into the prompt.
		const child = spawn(
			PI_CMD,
			[
				...PI_PREFIX,
				"-e",
				OAUTH_PROVIDER,
				"--no-session",
				"--no-tools",
				"--provider",
				"kroauth",
				"--model",
				"fake-gpt",
				"--thinking",
				"off",
				"-p",
				"Reply with exactly: PONG",
			],
			{
				env: {
					...process.env,
					PI_CODING_AGENT_DIR: AGENT_DIR,
					PI_OFFLINE: "1",
					PI_SKIP_VERSION_CHECK: "1",
					PI_TELEMETRY: "0",
					PI_CACHE_WARMING: "off",
					KR_FAKE_BASE: BASE,
					KR_OAUTH_LOG: OAUTH_LOG,
					...env,
				},
				cwd: work,
				windowsHide: true,
				stdio: ["ignore", "pipe", "pipe"],
			},
		);
		let stdout = "";
		let stderr = "";
		const timer = setTimeout(() => child.kill("SIGTERM"), 60_000);
		child.stdout.on("data", (d) => (stdout += d));
		child.stderr.on("data", (d) => (stderr += d));
		child.on("error", (e) => {
			clearTimeout(timer);
			done({ stdout, stderr: `${stderr}\n${e.message}`, code: -1 });
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			done({ stdout, stderr, code: code ?? -1 });
		});
	});
}

const readLog = () => (existsSync(OAUTH_LOG) ? readFileSync(OAUTH_LOG, "utf8").trim().split(/\r?\n/).filter(Boolean) : []);

try {
	mkdirSync(AGENT_DIR, { recursive: true });
	writeFileSync(
		join(AGENT_DIR, "settings.json"),
		JSON.stringify(
			{ defaultProjectTrust: "never", retry: { enabled: true, maxRetries: 3, baseDelayMs: 150, maxAgentDelayMs: 1000 } },
			null,
			2,
		),
		"utf8",
	);
	// The fixture registers its own models, so models.json only needs to be absent
	// or empty; an empty providers map keeps pi from complaining.
	writeFileSync(join(AGENT_DIR, "models.json"), JSON.stringify({ providers: {} }, null, 2), "utf8");

	await startServer();
	console.log(`fake server    ${BASE}`);
	console.log(`agent dir      ${AGENT_DIR}\n`);
	const authPath = join(AGENT_DIR, "auth.json");

	// -----------------------------------------------------------------------
	// 1. Valid, far-from-expiry credential: used as-is, no refresh.
	// -----------------------------------------------------------------------
	writeFileSync(
		authPath,
		JSON.stringify(
			{
				kroauth: {
					type: "oauth",
					refresh: "refresh-1",
					access: "access-1",
					expires: Date.now() + 24 * 60 * 60 * 1000,
					accountId: "fixture-extra-field",
				},
			},
			null,
			2,
		) + "\n",
		"utf8",
	);
	await admin("/__admin/reset");
	await admin("/__admin/plan", { default: "ok", text: "PONG" });

	const r1 = await runPi();
	const log1 = await serverLog();
	check("pi printed PONG with a seeded OAuth credential", /PONG/.test(r1.stdout), `code=${r1.code} err=${r1.stderr.slice(0, 200)}`);
	check(
		"the server saw the OAuth-derived bearer",
		log1[0]?.key === "oauth:access-1",
		`saw ${JSON.stringify(log1.map((e) => e.key))}`,
	);
	check("exactly one request", log1.length === 1, String(log1.length));

	const oauthLog1 = readLog();
	check("pi did NOT refresh a far-from-expiry credential", oauthLog1.length === 0, JSON.stringify(oauthLog1));

	// The stored blob must be untouched, including the provider-specific field:
	// nothing about the pool's opacity guarantee is meaningful if pi itself
	// rewrites credentials it did not need to touch.
	const after1 = JSON.parse(readFileSync(authPath, "utf8"));
	check("auth.json unchanged after a no-refresh request", after1.kroauth?.access === "access-1");
	check("provider-specific fields survived the round trip", after1.kroauth?.accountId === "fixture-extra-field");

	// -----------------------------------------------------------------------
	// 2. Credential inside pi's 5-minute validity window: pi refreshes it and
	//    persists the rotated blob by itself. This is the behaviour the pool must
	//    copy back, and the reason keyrouter never refreshes anything.
	// -----------------------------------------------------------------------
	rmSync(OAUTH_LOG, { force: true });
	writeFileSync(
		authPath,
		JSON.stringify(
			{ kroauth: { type: "oauth", refresh: "refresh-near", access: "access-near", expires: Date.now() + 60_000 } },
			null,
			2,
		) + "\n",
		"utf8",
	);
	await admin("/__admin/reset");
	await admin("/__admin/plan", { default: "ok", text: "PONG" });

	const r2 = await runPi();
	const log2 = await serverLog();
	check("pi printed PONG after a refresh", /PONG/.test(r2.stdout), `code=${r2.code}`);
	check(
		"the request carried the REFRESHED access token",
		typeof log2[0]?.key === "string" && log2[0].key.startsWith("oauth:refreshed-"),
		`saw ${JSON.stringify(log2.map((e) => e.key))}`,
	);

	const oauthLog2 = readLog();
	check("pi called refreshToken exactly once", oauthLog2.filter((l) => l.includes("refresh access=")).length === 1, JSON.stringify(oauthLog2));

	const after2 = JSON.parse(readFileSync(authPath, "utf8"));
	check(
		"pi PERSISTED the rotated credential itself (keyrouter must not)",
		typeof after2.kroauth?.access === "string" && after2.kroauth.access.startsWith("refreshed-"),
		`access=${after2.kroauth?.access}`,
	);
	check(
		"the rotated refresh token was persisted too",
		typeof after2.kroauth?.refresh === "string" && after2.kroauth.refresh.startsWith("refresh-"),
		`refresh=${after2.kroauth?.refresh}`,
	);

	// -----------------------------------------------------------------------
	// 3. A dead refresh token surfaces as an auth error naming the provider.
	//    keyrouter classifies off this message, so its shape is pinned here.
	// -----------------------------------------------------------------------
	rmSync(OAUTH_LOG, { force: true });
	writeFileSync(
		authPath,
		JSON.stringify(
			{ kroauth: { type: "oauth", refresh: "refresh-dead", access: "access-dead", expires: Date.now() + 30_000 } },
			null,
			2,
		) + "\n",
		"utf8",
	);
	await admin("/__admin/reset");
	await admin("/__admin/plan", { default: "ok", text: "PONG" });

	const r3 = await runPi();
	const combined = `${r3.stdout}\n${r3.stderr}`;
	check("a dead refresh token fails the request", !/PONG/.test(r3.stdout));
	check(
		"the error message names the provider and the refresh failure",
		/OAuth refresh failed/i.test(combined),
		combined.replace(/\s+/g, " ").slice(0, 300),
	);
	console.log(`      error surfaced as: ${combined.replace(/\s+/g, " ").trim().slice(0, 180)}`);
} finally {
	serverProc?.kill();
	rmSync(work, { recursive: true, force: true });
}

console.log(failures === 0 ? "\nOAuth fixture works: pi resolves, refreshes and persists on its own" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);