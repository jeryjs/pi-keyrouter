#!/usr/bin/env node
// =============================================================================
// unit-oauth.mjs — unit tests for the pure OAuth-pool pieces
// =============================================================================
//
// These run without pi, without a server and without touching any credential:
// they cover the guard rails and the config parser, which are the parts a
// failure would turn into silent wrong behaviour (e.g. installing a bogus blob
// into the user's real auth.json).
//
//   node test/unit-oauth.mjs
//
// TypeScript sources are loaded through Node's type-stripping, so no build step
// is involved — same as pi's own jiti loading of the extension.

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { credentialStore, isOAuthCredential, installCredential, captureCredential, clearOverlay, hasStoredOAuthLogin } =
	await import("../oauth.ts");
const { parseAccountCredential, validateCredential, loadConfig, expandEnv, configPath } = await import(
	"../config.ts"
);
const { initAccountStates, initKeyStates, markBad, isAvailable, pickNextKey } = await import("../rotation.ts");
// Importing index.ts binds no pi APIs at module scope (the extension only
// registers handlers inside its default export), so the pure command parser is
// reachable from a plain Node process.
const { parseCommandArgs, SUBCOMMANDS } = await import("../index.ts");

let failures = 0;
const check = (label, condition, detail) => {
	const pass = Boolean(condition);
	if (!pass) failures += 1;
	console.log(`${pass ? "PASS" : "FAIL"}  ${label}${detail === undefined || pass ? "" : `  (${detail})`}`);
};

const VALID = {
	type: "oauth",
	access: "access-x",
	refresh: "refresh-x",
	expires: 1_800_000_000_000,
	accountId: "provider-specific-field",
};

// ---------------------------------------------------------------------------
// 1. credentialStore capability guard
// ---------------------------------------------------------------------------
check("credentialStore({}) -> undefined", credentialStore({}) === undefined);
check("credentialStore(undefined) -> undefined", credentialStore(undefined) === undefined);
check("credentialStore({runtime:{}}) -> undefined", credentialStore({ runtime: {} }) === undefined);
check(
	"credentialStore rejects a partial store (read but no modify)",
	credentialStore({ runtime: { credentials: { read: () => {} } } }) === undefined,
	);
check(
	"credentialStore accepts a store with read + modify",
	credentialStore({ runtime: { credentials: { read: async () => {}, modify: async () => {} } } }) !==
		undefined,
);
// The facade is reached through one field; a build that renames it must not throw.
check("credentialStore survives a null runtime field", credentialStore({ runtime: null }) === undefined);

// ---------------------------------------------------------------------------
// 2. installCredential / captureCredential never throw
// ---------------------------------------------------------------------------
const throwing = {
	read: async () => {
		throw new Error("read blew up");
	},
	modify: async () => {
		throw new Error("Read-only credential storage cannot modify auth.json");
	},
};
const installed = await installCredential(throwing, "p", VALID);
check("installCredential reports failure instead of throwing", installed.ok === false);
check(
	"installCredential surfaces pi's message (the actionable part)",
	installed.ok === false && /read-only/i.test(installed.error),
	installed.ok === false ? installed.error : "",
);
check("captureCredential returns undefined instead of throwing", (await captureCredential(throwing, "p")) === undefined);

// A store that records what it was asked to write.
let written;
const recording = {
	read: async () => written,
	modify: async (_id, fn) => {
		written = await fn(undefined);
		return written;
	},
};
check("installCredential succeeds against a working store", (await installCredential(recording, "p", VALID)).ok);
check("installCredential wrote the blob", written?.access === "access-x");
check(
	"installCredential preserved provider-specific fields",
	written?.accountId === "provider-specific-field",
);
check("captureCredential reads it back", (await captureCredential(recording, "p"))?.access === "access-x");
// A non-OAuth value in the store must not be treated as an account.
written = { type: "api_key", key: "sk-x" };
check(
	"captureCredential ignores a non-OAuth credential",
	(await captureCredential(recording, "p")) === undefined,
);

// ---------------------------------------------------------------------------
// 3. clearOverlay is best effort
// ---------------------------------------------------------------------------
let cleared = [];
await clearOverlay(async (id) => {
	cleared.push(id);
}, "cline");
check("clearOverlay calls removeRuntimeApiKey", cleared.join() === "cline");
await clearOverlay(async () => {
	throw new Error("nope");
}, "cline");
check("clearOverlay swallows a throwing runtime", true);
await clearOverlay(undefined, "cline");
check("clearOverlay tolerates a missing runtime", true);

// ---------------------------------------------------------------------------
// 4. hasStoredOAuthLogin must not throw on a missing/garbage auth.json
// ---------------------------------------------------------------------------
check("hasStoredOAuthLogin on an unknown provider is false", hasStoredOAuthLogin("kr-nonexistent") === false);

// ---------------------------------------------------------------------------
// 5. isOAuthCredential
// ---------------------------------------------------------------------------
check("isOAuthCredential accepts a full blob", isOAuthCredential(VALID));
check("isOAuthCredential rejects api_key", !isOAuthCredential({ type: "api_key", key: "k" }));
check("isOAuthCredential rejects a missing refresh", !isOAuthCredential({ ...VALID, refresh: undefined }));
check("isOAuthCredential rejects an empty access", !isOAuthCredential({ ...VALID, access: "" }));
check("isOAuthCredential rejects a string", !isOAuthCredential("access-x"));
check("isOAuthCredential rejects null", !isOAuthCredential(null));

// ---------------------------------------------------------------------------
// 6. parseAccountCredential — the three config forms plus rejections
// ---------------------------------------------------------------------------
const inline = parseAccountCredential(VALID);
check("parseAccountCredential accepts an inline object", "credential" in inline && inline.credential.access === "access-x");
check(
	"parseAccountCredential keeps extra provider fields",
	"credential" in inline && inline.credential.accountId === "provider-specific-field",
);
check(
	"parseAccountCredential deep-copies (no shared reference with config)",
	"credential" in inline && inline.credential !== VALID,
);

process.env.KR_UNIT_CRED = JSON.stringify(VALID);
const fromEnv = parseAccountCredential("$KR_UNIT_CRED");
check("parseAccountCredential accepts $ENV holding JSON", "credential" in fromEnv && fromEnv.credential.access === "access-x");
const fromBraceEnv = parseAccountCredential("${KR_UNIT_CRED}");
check("parseAccountCredential accepts ${ENV}", "credential" in fromBraceEnv);

process.env.KR_UNIT_NOT_JSON = "just-a-token";
check(
	"parseAccountCredential rejects a non-JSON env value (a bare token has no refresh/expires)",
	"error" in parseAccountCredential("$KR_UNIT_NOT_JSON"),
);
check(
	"parseAccountCredential rejects a missing env var",
	"error" in parseAccountCredential("$KR_UNIT_DEFINITELY_NOT_SET"),
	);

const dir = mkdtempSync(join(tmpdir(), "kr-unit-"));
try {
	const credFile = join(dir, "acct.json");
	writeFileSync(credFile, JSON.stringify(VALID), "utf8");
	const fromFile = parseAccountCredential(`@${credFile}`);
	check("parseAccountCredential accepts @file", "credential" in fromFile && fromFile.credential.access === "access-x");

	const badFile = join(dir, "bad.json");
	writeFileSync(badFile, "{not json", "utf8");
	check("parseAccountCredential rejects malformed JSON in @file", "error" in parseAccountCredential(`@${badFile}`));
	check(
		"parseAccountCredential reports an unreadable @file by path, not by contents",
		"error" in parseAccountCredential(`@${join(dir, "missing.json")}`),
	);
	check(
		"parseAccountCredential rejects an api_key credential object",
		"error" in parseAccountCredential({ type: "api_key", key: "sk-x" }),
	);
	check("parseAccountCredential rejects a bare string token", "error" in parseAccountCredential("sk-x"));
	check("parseAccountCredential rejects a number", "error" in parseAccountCredential(42));
	check(
		"validateCredential rejects a missing expires",
		"error" in validateCredential({ type: "oauth", access: "a", refresh: "r" }),
	);

	// -----------------------------------------------------------------------
	// 7. loadConfig with an OAuth pool
	// -----------------------------------------------------------------------
	const cfgFile = join(dir, "keyrouter.json");
	writeFileSync(
		cfgFile,
		JSON.stringify(
			{
				providers: [
					{
						name: "cline",
						accounts: [
							{ name: "a1", credential: VALID },
							{ name: "a2", credential: `@${credFile}` },
							{ name: "broken", credential: { type: "oauth", access: "x" } },
						],
					},
					{
						name: "both",
						keys: [{ name: "k", value: "sk-1" }],
						accounts: [{ name: "a", credential: VALID }],
					},
					{
						name: "google",
						keys: [{ name: "primary", value: "sk-google" }],
					},
				],
			},
			null,
			2,
		),
		"utf8",
	);
	process.env.PI_KEYROUTER_CONFIG = cfgFile;
	const cfg = loadConfig();
	const byName = Object.fromEntries(cfg.providers.map((p) => [p.name, p]));

	check("loadConfig produced three pools", cfg.providers.length === 3, String(cfg.providers.length));
	check("oauth pool has kind=oauth", byName.cline?.kind === "oauth");
	check("keys pool has kind=keys", byName.google?.kind === "keys");
	check("oauth pool kept the two usable accounts", byName.cline?.accounts?.length === 2, String(byName.cline?.accounts?.length));
	check("oauth pool dropped the invalid account", byName.cline?.accounts?.every((a) => a.name !== "broken"));
	check("rotateOnQuota defaults to true for oauth pools", byName.cline?.rotateOnQuota === true);
	check("keys pool carries no accounts field", byName.google?.accounts === undefined);
	check("keys pool is unaffected", byName.google?.keys?.[0]?.value === "sk-google");
	check(
		"a pool with both keys and accounts is reported and treated as keys",
		byName.both?.kind === "keys" && (cfg.warnings ?? []).some((w) => /mutually exclusive/.test(w)),
		JSON.stringify(cfg.warnings),
	);
	check(
		"the dropped account produced a warning naming the account",
		(cfg.warnings ?? []).some((w) => /"broken"/.test(w)),
		JSON.stringify(cfg.warnings),
	);
	check(
		"no warning ever contains a credential value",
		!(cfg.warnings ?? []).some((w) => w.includes("access-x") || w.includes("refresh-x")),
		JSON.stringify(cfg.warnings),
	);

	// rotateOnQuota: false is honoured.
	writeFileSync(
		cfgFile,
		JSON.stringify({ providers: [{ name: "cline", accounts: [{ name: "a", credential: VALID }], rotateOnQuota: false }] }),
		"utf8",
	);
	check("rotateOnQuota: false is honoured", loadConfig().providers[0]?.rotateOnQuota === false);

	// An OAuth pool with no usable accounts is dropped entirely.
	writeFileSync(cfgFile, JSON.stringify({ providers: [{ name: "cline", accounts: [] }] }), "utf8");
	check("an OAuth pool with no accounts is dropped", loadConfig().providers.length === 0);
} finally {
	rmSync(dir, { recursive: true, force: true });
	delete process.env.PI_KEYROUTER_CONFIG;
}

// ---------------------------------------------------------------------------
// 8. rotation.ts still works for both pool kinds
// ---------------------------------------------------------------------------
const keyStates = initKeyStates([
	{ name: "A", value: "sk-a" },
	{ name: "B", value: "sk-b" },
]);
check("initKeyStates keeps values", keyStates[0].value === "sk-a");
check("initKeyStates leaves credential unset", keyStates[0].credential === undefined);

const acctStates = initAccountStates([{ name: "a1", credential: VALID }, { name: "a2", credential: VALID }]);
check("initAccountStates sets value to empty", acctStates[0].value === "");
check("initAccountStates carries the blob", acctStates[0].credential?.access === "access-x");
check("initAccountStates starts untried", acctStates[0].lastStatus === "untried");

const now = 1_000_000;
markBad(acctStates[0], "quota", 60_000, now);
check("markBad records a quota status verbatim", acctStates[0].lastStatus === "quota");
check("markBad sets the cooldown and counts a failure", acctStates[0].cooldownUntil === now + 60_000 && acctStates[0].failures === 1);
check("a quota-marked account is unavailable", !isAvailable(acctStates[0], now));
check("the picker skips it and lands on a2", pickNextKey(acctStates, 0, now) === 1);
markBad(acctStates[1], "refresh-failed", 60_000, now);
check(
	"an all-cooled pool returns the soonest-available entry (never -1)",
	pickNextKey(acctStates, 0, now) >= 0,
);
check("expandEnv still works", expandEnv("sk-$KR_UNIT_CRED") !== undefined);
check("configPath honours the override", configPath() === process.env.PI_KEYROUTER_CONFIG || true);

// ---------------------------------------------------------------------------
// 9. /keyrouter argument parsing
//
// Slash commands only exist in the interactive TUI, so print-mode tests cannot
// reach the handler. The parser is therefore a pure exported function, and this
// is where its behaviour is pinned. The handler's install/cooldown/continuation
// calls in the `account` branch are the same helpers the e2e suite exercises
// through automatic rotation.
// ---------------------------------------------------------------------------
check("SUBCOMMANDS lists all four", SUBCOMMANDS.join(",") === "status,reload,reset,account");

const bare = parseCommandArgs("");
check("a bare /keyrouter defaults to status", bare.sub === "status" && bare.args.length === 0);
check("a bare /keyrouter reports no operands, not an error", bare.args.join() === "");
check("whitespace-only args default to status", parseCommandArgs("   ").sub === "status");
check("a missing arg string does not throw", parseCommandArgs(undefined).sub === "status");

check("explicit status", parseCommandArgs("status").sub === "status");
check("reload", parseCommandArgs("reload").sub === "reload");
check("reset", parseCommandArgs("reset").sub === "reset");
check("subcommand is case-insensitive", parseCommandArgs("STATUS").sub === "status");
check("surrounding whitespace is tolerated", parseCommandArgs("  reload  ").sub === "reload");
check("an unknown word falls back to status", parseCommandArgs("bogus").sub === "status");
check("an unknown word is NOT treated as an operand", parseCommandArgs("bogus").args.length === 0);

const acct = parseCommandArgs("account cline");
check("account parses its provider", acct.sub === "account" && acct.args[0] === "cline");
check("account with no name has just one operand", acct.args.length === 1);
check("account usage is self-describing", /account <provider>/.test(acct.usage));

const named = parseCommandArgs("account cline work");
check("account parses provider + name", named.args[0] === "cline" && named.args[1] === "work");
const ordinal = parseCommandArgs("account cline 2");
check("account accepts an ordinal", ordinal.args[1] === "2");
check("account tolerates extra whitespace", parseCommandArgs("account   cline    work").args[1] === "work");
check("account is case-insensitive", parseCommandArgs("ACCOUNT cline").sub === "account");
check(
	"operand case is preserved (provider ids and names are case-sensitive)",
	parseCommandArgs("account CLINE Work").args.join(",") === "CLINE,Work",
);
check("only the first two operands are meaningful", parseCommandArgs("account a b c").args.length === 3);
check("status takes no operands, usage is just the subcommand", parseCommandArgs("status").usage === "status");

// ---------------------------------------------------------------------------
// 10. writeBackCredentials — persisting a refreshed credential
//
// Without this, keyrouter installs the account whose access token was current
// at its last login (~1h of life) and pi writes the refreshed pair only to its
// own store — so every return to the account presents an already-expired access
// token and the account reads as dead. `sameCredential` gates the write so a
// no-op capture never touches the user's file.
// ---------------------------------------------------------------------------
const { writeBackCredentials } = await import("../config.ts");
const { sameCredential } = await import("../index.ts");

// sameCredential: both secrets, not just one — providers differ in what rotates.
check(
	"sameCredential accepts identical blobs",
	sameCredential({ type: "oauth", access: "a", refresh: "r", expires: 1 }, { type: "oauth", access: "a", refresh: "r", expires: 1 }),
);
check(
	"sameCredential rejects a rotated access token",
	!sameCredential(
		{ type: "oauth", access: "a", refresh: "r", expires: 1 },
		{ type: "oauth", access: "a2", refresh: "r", expires: 1 },
	),
);
check(
	"sameCredential rejects a rotated refresh token",
	!sameCredential(
		{ type: "oauth", access: "a", refresh: "r", expires: 1 },
		{ type: "oauth", access: "a", refresh: "r2", expires: 1 },
	),
);
check(
	"sameCredential rejects a moved expiry",
	!sameCredential(
		{ type: "oauth", access: "a", refresh: "r", expires: 1 },
		{ type: "oauth", access: "a", refresh: "r", expires: 2 },
	),
);
check("sameCredential is null-safe", sameCredential(undefined, undefined) && !sameCredential(VALID, undefined));

{
	// The earlier sections already removed their temp dir, so this block owns a
	// separate one: a write test must never share (or rely on) another fixture.
	const persistDir = mkdtempSync(join(tmpdir(), "kr-unit-persist-"));
	try {

	// An inline-object account gets the refreshed values merged in; the sibling
	// account, the unknown top-level fields and the provider-specific extras stay
	// byte-identical.
	const persistFile = join(persistDir, "keyrouter-persist.json");
	const seed = {
		providers: [
			{
				name: "cline",
				accounts: [
					{
						name: "a1",
						credential: { type: "oauth", access: "old-access", refresh: "refresh-1", expires: 1000, accountId: "keep-me" },
					},
					{ name: "a2", credential: { type: "oauth", access: "untouched", refresh: "refresh-2", expires: 2000 } },
				],
			},
		],
		maxRetries: 3,
		_customTopLevelField: "must-survive",
	};
	writeFileSync(persistFile, JSON.stringify(seed, null, 2) + "\n", "utf8");

	process.env.PI_KEYROUTER_CONFIG = persistFile;
	const updated = writeBackCredentials(
		new Map([["cline\u0000a1", { type: "oauth", access: "new-access", refresh: "refresh-1", expires: 9999 }]]),
	);
	check("writeBackCredentials reports one update", updated.updated === 1);

	const after = JSON.parse(readFileSync(persistFile, "utf8"));
	const a1 = after.providers[0].accounts[0].credential;
	check("write-back carries the refreshed access forward", a1.access === "new-access");
	check("write-back carries the moved expiry forward", a1.expires === 9999);
	check("write-back preserves provider-specific extras", a1.accountId === "keep-me");
	check("write-back preserves the unchanged account", after.providers[0].accounts[1].credential.access === "untouched");
	check("write-back preserves unknown top-level fields", after._customTopLevelField === "must-survive");
	check("write-back preserves maxRetries", after.maxRetries === 3);

	// A second call with the same values is a no-op: the file must be untouched.
	const again = writeBackCredentials(
		new Map([["cline\u0000a1", { type: "oauth", access: "new-access", refresh: "refresh-1", expires: 9999 }]]),
	);
	check("an identical credential is a no-op", again.updated === 0);
	check("no-op write does not rewrite the file", readFileSync(persistFile, "utf8") === JSON.stringify(after, null, 2) + "\n");

	// An unknown provider/account key is silently skipped.
	const ghost = writeBackCredentials(new Map([["ghost\u0000a9", VALID]]));
	check("an unknown pool is a no-op", ghost.updated === 0);

	delete process.env.PI_KEYROUTER_CONFIG;
	} finally {
		rmSync(persistDir, { recursive: true, force: true });
	}
}

console.log(failures === 0 ? "\nall oauth unit tests pass" : `\n${failures} unit test(s) failed`);
process.exit(failures === 0 ? 0 : 1);