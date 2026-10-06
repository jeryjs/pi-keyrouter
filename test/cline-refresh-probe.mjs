#!/usr/bin/env node
// =============================================================================
// cline-refresh-probe.mjs — ask Cline's refresh endpoint what it really thinks
// =============================================================================
//
// Read-only with respect to the filesystem: nothing is written, and a rotated
// token returned upstream is NOT saved (its hash is reported so you can see
// whether Cline rotates at all).
//
// This is the only way to distinguish the five candidate explanations for
// "OAuth refresh failed for cline", because pi's error message collapses them
// all into one sentence:
//
//   1. the refresh token is genuinely expired/revoked  -> invalid_grant (terminal)
//   2. the request was malformed (headers/body)        -> 4xx with a schema error
//   3. only a subset of accounts are dead              -> per-account differences
//   4. the token was already consumed                  -> invalid_grant + rotation
//   5. a transient outage                              -> 5xx / 429 (retryable)
//
//   node cline-refresh-probe.mjs            # probe every account in the pool
//   node cline-refresh-probe.mjs --skip-live   # leave the currently-working one alone
//
// Requests mirror pi-free's `attemptClineTokenRefresh` exactly
// (~/.pi/agent/npm/node_modules/pi-free/dist/providers/cline/cline-auth.js).

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const BASE = "https://api.cline.bot/api/v1";
const VERSION = "4.1.10";
const VSCODE_VERSION = "1.109.3";

const h = (s) => (s === undefined ? "-" : createHash("sha256").update(String(s)).digest("hex").slice(0, 10));

function resolve(raw) {
	if (raw && typeof raw === "object") return raw;
	if (typeof raw !== "string") return undefined;
	if (raw.startsWith("@")) {
		try {
			return JSON.parse(readFileSync(raw.slice(1).replace(/^~/, homedir()), "utf8"));
		} catch {
			return undefined;
		}
	}
	let v = raw;
	if (raw.includes("$")) v = raw.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (_, n) => process.env[n] ?? "");
	try {
		return JSON.parse(v);
	} catch {
		return undefined;
	}
}

function headers() {
	return {
		Accept: "application/json",
		"Content-Type": "application/json",
		"User-Agent": `Cline/${VERSION}`,
		"X-PLATFORM": "Visual Studio Code",
		"X-PLATFORM-VERSION": VSCODE_VERSION,
		"X-CLIENT-TYPE": "VSCode Extension",
		"X-CLIENT-VERSION": VERSION,
		"X-CORE-VERSION": VERSION,
	};
}

/** Redact anything that looks like a secret, and cap the length. */
function safe(text) {
	if (typeof text !== "string") return String(text);
	return text
		.replace(/[A-Za-z0-9_-]{20,}/g, "<redacted>")
		.slice(0, 400);
}

const args = process.argv.slice(2);
const skipLive = args.includes("--skip-live");

const cfg = JSON.parse(readFileSync(join(homedir(), ".pi", "keyrouter.json"), "utf8"));
const pool = (cfg.providers ?? []).find((p) => p.name === "cline");
const stored = JSON.parse(readFileSync(join(homedir(), ".pi", "agent", "auth.json"), "utf8"));

const liveRefresh = stored.cline?.refresh;
const accounts = [];
for (const a of pool?.accounts ?? []) {
	const c = resolve(a.credential);
	if (c) accounts.push({ name: a.name, cred: c });
}

console.log(`probing ${BASE}/auth/refresh`);
console.log(`accounts: ${accounts.map((a) => a.name).join(", ")}\n`);

const results = [];
for (const { name, cred } of accounts) {
	const isLive = cred.refresh === liveRefresh;

	if (skipLive && isLive) {
		console.log(`SKIP  ${name.padEnd(14)} (its refresh token is the one pi currently has stored; not consuming it)`);
		results.push({ name, skipped: true });
		continue;
	}

	const before = h(cred.refresh);
	process.stdout.write(`${name.padEnd(14)} refresh#${before} … `);

	let res;
	let bodyText = "";
	let json;
	let networkError;
	try {
		res = await fetch(`${BASE}/auth/refresh`, {
			method: "POST",
			headers: headers(),
			body: JSON.stringify({ refreshToken: cred.refresh, grantType: "refresh_token" }),
			signal: AbortSignal.timeout(20_000),
		});
		bodyText = await res.text();
		try {
			json = JSON.parse(bodyText);
		} catch {
			json = undefined;
		}
	} catch (error) {
		networkError = error instanceof Error ? error.message : String(error);
	}

	if (networkError) {
		console.log(`NETWORK ERROR: ${networkError}`);
		results.push({ name, networkError });
		continue;
	}

	const success = json?.success === true;
	const newAccess = json?.data?.accessToken;
	const newRefresh = json?.data?.refreshToken;
	const rotated = typeof newRefresh === "string" && newRefresh !== cred.refresh;

	console.log(`HTTP ${res.status} success=${success} rotated=${rotated}`);
	console.log(`                 body: ${safe(bodyText)}`);

	if (success) {
		console.log(`                 new access#${h(newAccess)} expires=${json?.data?.expiresAt ?? json?.data?.expires ?? "-"}`);
		if (rotated) console.log(`                 new refresh#${h(newRefresh)}  <-- Cline ROTATES`);
		else console.log(`                 refresh token UNCHANGED  <-- Cline does NOT rotate`);
	}

	results.push({
		name,
		status: res.status,
		success,
		rotated,
		message: json?.error?.message ?? json?.message ?? json?.error ?? undefined,
		code: json?.error?.code ?? json?.code,
	});
}

console.log("\n=== summary ===");
for (const r of results) {
	if (r.skipped) {
		console.log(`  ${r.name.padEnd(14)} SKIPPED (live)`);
	} else if (r.networkError) {
		console.log(`  ${r.name.padEnd(14)} network: ${r.networkError}`);
	} else {
		console.log(
			`  ${r.name.padEnd(14)} HTTP ${r.status} success=${r.success} rotated=${r.rotated}` +
				(r.code ? ` code=${r.code}` : "") +
				(r.message ? ` msg=${safe(String(r.message)).slice(0, 160)}` : ""),
		);
	}
}