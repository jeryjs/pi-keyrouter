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

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { credentialStore, isOAuthCredential, installCredential, captureCredential, clearOverlay, hasStoredOAuthLogin } =
	await import("../oauth.ts");
const {
	parseAccountCredential,
	validateCredential,
	loadConfig,
	expandEnv,
	configPath,
	writeBackActive,
	writeBackNotifications,
	writeBackPoolEntry,
	uniquePoolEntryName,
} = await import("../config.ts");
const { initAccountStates, initKeyStates, markBad, isAvailable, pickNextKey } = await import("../rotation.ts");
const {
	notifyRotation,
	notifyOverloaded,
	notifyExhausted,
	rotationIsNotifiable,
	overloadIsNotifiable,
} = await import("../notification.ts");
// Importing index.ts binds no pi APIs at module scope (the extension only
// registers handlers inside its default export), so the pure command parser is
// reachable from a plain Node process.
const {
	parseCommandArgs,
	commandCompletions,
	commandHelpText,
	COMMAND_DESCRIPTION,
	SUBCOMMANDS,
	alreadyUsingMessage,
	planOAuthAddition,
	startupSweepEnabled,
} = await import("../index.ts");

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
	check("a pool with no active reads as undefined", byName.google?.active === undefined);
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

	// `active` — the position a previous session left off at — is read for both
	// pool kinds, and only when it is a string.
	writeFileSync(
		cfgFile,
		JSON.stringify({
			providers: [
				{ name: "google", active: "backup", keys: [{ name: "primary", value: "sk-1" }] },
				{ name: "openai", active: 42, keys: [{ name: "primary", value: "sk-2" }] },
			],
		}),
		"utf8",
	);
	const activeCfg = loadConfig();
	check("active is read back", activeCfg.providers[0]?.active === "backup");
	check("a non-string active is ignored", activeCfg.providers[1]?.active === undefined);

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

	// notifications — which events earn a visible status line. The policy
	// functions are pure; the notify wrappers are exercised with a fake UI so
	// the gating itself is pinned, not just the decision helpers.
	const writeCfg = (value) =>
		writeFileSync(
			cfgFile,
			JSON.stringify({ providers: [{ name: "google", keys: [{ name: "primary", value: "sk-1" }] }], notifications: value }),
			"utf8",
		);
	writeCfg("quiet");
	check("notifications: quiet is read back", loadConfig().notifications === "quiet");
	writeCfg("silent");
	check("notifications: silent is read back", loadConfig().notifications === "silent");
	writeCfg("loud");
	const badLevel = loadConfig();
	check("an unknown notifications value falls back to all", badLevel.notifications === "all");
	check(
		"an unknown notifications value warns (and never breaks the pool)",
		badLevel.providers.length === 1 && (badLevel.warnings ?? []).some((w) => /"notifications"/.test(w)),
		JSON.stringify(badLevel.warnings),
	);
	writeCfg(undefined);
	check("notifications defaults to all when absent", loadConfig().notifications === "all");

	const notified = [];
	const fakeUi = { notify: (message, kind) => notified.push([message, kind]) };
	const rotation = (reason) => ({ provider: "google", fromKey: "A", toKey: "B", reason, status: 429, attempt: 1 });
	check("rotationIsNotifiable: all shows rate-limited", rotationIsNotifiable("all", "rate-limited"));
	check("rotationIsNotifiable: quiet hides rate-limited", !rotationIsNotifiable("quiet", "rate-limited"));
	check("rotationIsNotifiable: quiet keeps unauthorized", rotationIsNotifiable("quiet", "unauthorized"));
	check("rotationIsNotifiable: quiet keeps quota", rotationIsNotifiable("quiet", "quota"));
	check("rotationIsNotifiable: quiet keeps refresh-failed", rotationIsNotifiable("quiet", "refresh-failed"));
	check("rotationIsNotifiable: silent hides unauthorized too", !rotationIsNotifiable("silent", "unauthorized"));
	check("rotationIsNotifiable: an absent level means all", rotationIsNotifiable(undefined, "rate-limited"));
	check("overloadIsNotifiable: only the all level shows it", overloadIsNotifiable("all") && !overloadIsNotifiable("quiet") && !overloadIsNotifiable("silent"));
	check("overloadIsNotifiable: an absent level means all", overloadIsNotifiable(undefined));
	notified.length = 0;
	notifyRotation(fakeUi, rotation("rate-limited"), "quiet");
	check("notifyRotation is silent for a quiet rate-limited rotation", notified.length === 0);
	notifyRotation(fakeUi, rotation("unauthorized"), "quiet");
	check(
		"notifyRotation still notifies for unauthorized in quiet",
		notified.length === 1 && notified[0][1] === "warning" && /unauthorized/.test(notified[0][0]),
	);
	notifyRotation(fakeUi, rotation("unauthorized"), "silent");
	check("notifyRotation is silent in silent mode", notified.length === 1);
	notifyOverloaded(fakeUi, "google", 30_000, "quiet");
	check("notifyOverloaded is silent in quiet", notified.length === 1);
	notifyExhausted(fakeUi, "google", ["A", "B"], "keys");
	check(
		"notifyExhausted always notifies — no level can gate it",
		notified.length === 2 && notified[1][1] === "error" && /exhausted/.test(notified[1][0]),
	);
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
check(
	"SUBCOMMANDS lists all eight",
	SUBCOMMANDS.join(",") === "status,reload,reset,account,strategy,add,remove,notifications",
);

const bare = parseCommandArgs("");
check("a bare /keyrouter requests help", bare.sub === "help" && bare.args.length === 0);
check("a bare /keyrouter reports no operands, not an error", bare.args.join() === "");
check("whitespace-only args request help", parseCommandArgs("   ").sub === "help");
check("a missing arg string does not throw", parseCommandArgs(undefined).sub === "help");
check("--help requests help", parseCommandArgs("--help").sub === "help");
check("--help is case-insensitive", parseCommandArgs("--HELP").sub === "help");
const wordHelp = parseCommandArgs("help");
check(
	"the word help is not a recognized subcommand",
	wordHelp.sub === "status" && wordHelp.args[0] === "help",
);
check("help is absent from the completion subcommands", !SUBCOMMANDS.includes("help"));

check("explicit status", parseCommandArgs("status").sub === "status");
check("reload", parseCommandArgs("reload").sub === "reload");
check("reset", parseCommandArgs("reset").sub === "reset");
check("subcommand is case-insensitive", parseCommandArgs("STATUS").sub === "status");
check("surrounding whitespace is tolerated", parseCommandArgs("  reload  ").sub === "reload");
check("an unknown word becomes a status provider operand", parseCommandArgs("bogus").sub === "status");
check("an unknown word is retained for a clear provider error", parseCommandArgs("bogus").args[0] === "bogus");
check("status parses an optional provider", parseCommandArgs("status cline").args[0] === "cline");

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
check("status usage shows its optional provider operand", parseCommandArgs("status").usage === "status [provider]");

const notificationsCmd = parseCommandArgs("notifications");
check("notifications parses without an operand", notificationsCmd.sub === "notifications" && notificationsCmd.args.length === 0);
check(
	"notifications usage lists every valid level",
	notificationsCmd.usage === "notifications [all|quiet|silent]",
);
const notificationsSet = parseCommandArgs("notifications quiet");
check(
	"notifications parses its level operand",
	notificationsSet.sub === "notifications" && notificationsSet.args[0] === "quiet",
);
check("notifications is case-insensitive", parseCommandArgs("NOTIFICATIONS silent").sub === "notifications");
check(
	"an invalid notifications operand reaches the command boundary unchanged",
	parseCommandArgs("notifications loud").args[0] === "loud",
);

// add / remove: the guided credential-management commands.
const addCmd = parseCommandArgs("add cline");
check("add parses its provider", addCmd.sub === "add" && addCmd.args[0] === "cline");
check("add with no name has just one operand", addCmd.args.length === 1);
check("add usage is self-describing", addCmd.usage === "add <provider> [name]");
check("add accepts a name", parseCommandArgs("add cline work").args[1] === "work");
check("add is case-insensitive", parseCommandArgs("ADD cline").sub === "add");
const removeCmd = parseCommandArgs("remove cline work");
check("remove parses provider + name", removeCmd.sub === "remove" && removeCmd.args[1] === "work");
check("remove accepts an ordinal", parseCommandArgs("remove cline 2").args[1] === "2");
check("remove usage is self-describing", /remove <provider>/.test(removeCmd.usage));
check("remove is case-insensitive", parseCommandArgs("REMOVE cline").sub === "remove");

const helpText = commandHelpText();
check("help lists the filtered status form", helpText.includes("/keyrouter status [provider]"));
check("help lists the add form with an optional name", helpText.includes("/keyrouter add <provider> [name]"));
check("help does not invent a key operand", !helpText.includes("/keyrouter add <provider> [name] [key]"));
check("help explains that key input is interactive", helpText.includes("entered interactively"));
check(
	"help lists the notifications operand syntax",
	helpText.includes("/keyrouter notifications [all|quiet|silent]"),
);
check(
	"the command description exposes the operand syntax",
	COMMAND_DESCRIPTION.includes("/keyrouter status [provider]") &&
		COMMAND_DESCRIPTION.includes("/keyrouter add <provider> [name]") &&
		COMMAND_DESCRIPTION.includes("/keyrouter notifications [all|quiet|silent]"),
);

check(
	"the already-using refusal has the exact required wording",
	alreadyUsingMessage("work") ===
		'🔑 keyrouter: pi is already using "work". Run `/login` to sign in to another account first and then call `/keyrouter add` again.',
);
check(
	"a generated name collision gets the first free numbered suffix",
	uniquePoolEntryName("work", ["work"]).name === "work-2" &&
		uniquePoolEntryName("work", ["work"]).adjusted === true,
);
check(
	"a generated name collision skips an occupied suffix",
	uniquePoolEntryName("work", ["work", "work-2"]).name === "work-3",
);
check(
	"an unused generated name is not adjusted",
	uniquePoolEntryName("work", ["other"]).name === "work" &&
		uniquePoolEntryName("work", ["other"]).adjusted === false,
);

const identityPool = [
	{
		name: "jsjery123",
		credential: {
			type: "oauth",
			access: "old-access",
			refresh: "old-refresh",
			expires: 1000,
			accountId: "account-123",
		},
	},
];
const liveSameIdentity = {
	type: "oauth",
	access: "new-access",
	refresh: "new-refresh",
	expires: 2000,
	accountId: "account-123",
};
const namedIdentityPlan = planOAuthAddition({
	credential: liveSameIdentity,
	accounts: identityPool,
	requestedName: "custom-new-name",
	identityPath: "accountId",
});
check(
	"a requested new name still prompts when the login matches an existing identity",
	namedIdentityPlan.kind === "prompt" && namedIdentityPlan.target.name === "jsjery123",
);
check(
	"the add-as-new choice preserves the explicitly requested name",
	namedIdentityPlan.kind === "prompt" && namedIdentityPlan.addName === "custom-new-name",
);
check(
	"the identity prompt keeps update first and add-as-new second",
	namedIdentityPlan.kind === "prompt" &&
		namedIdentityPlan.updateOption === 'Update existing account "jsjery123"' &&
		namedIdentityPlan.addOption === "Add current login as a new account",
);
check(
	"an explicitly existing target remains an in-place update",
	planOAuthAddition({
		credential: liveSameIdentity,
		accounts: identityPool,
		requestedName: "jsjery123",
		identityPath: "accountId",
	}).kind === "update",
);
check(
	"an exact duplicate elsewhere still refuses before identity prompting",
	planOAuthAddition({
		credential: identityPool[0].credential,
		accounts: identityPool,
		requestedName: "custom-new-name",
		identityPath: "accountId",
	}).kind === "duplicate",
);

// ---------------------------------------------------------------------------
// 10. commandCompletions — the /keyrouter completion menu
//
// pi calls this with the raw text after the command name and replaces that whole
// prefix with the chosen item's `value`, which is why each suggestion carries the
// full line rather than just its own token.
// ---------------------------------------------------------------------------
const POOLS = [
	{
		name: "cline",
		kind: "oauth",
		accounts: [
			{ name: "work", credential: { type: "oauth", access: "oauth-secret" } },
			{ name: "home" },
			{ name: "work-laptop" },
		],
		active: "home",
	},
	{
		name: "tokenharbor",
		kind: "keys",
		keys: [{ name: "primary", value: "key-secret" }, { name: "backup" }],
		active: "primary",
	},
];
const compl = (prefix) => commandCompletions(prefix, POOLS);
const labels = (prefix) => (compl(prefix) ?? []).map((item) => item.label);

// Subcommands.
check(
	"an empty prefix offers every subcommand",
	labels("").join() === "status,reload,reset,account,strategy,add,remove,notifications",
);
check("a partial subcommand narrows the list", labels("re").join() === "reload,reset,remove");
check("subcommands are case-insensitive", labels("RE").join() === "reload,reset,remove");
check("a subcommand suggestion carries a trailing space", compl("st")[0].value === "status ");
check("subcommands carry a description", /pool state/.test(compl("")[0].description ?? ""));
check("no matching subcommand yields null", compl("zzz") === null);

// After a subcommand, only the commands with operands keep suggesting.
check("status offers provider filters", compl("status ").map((i) => i.label).join() === "cline,tokenharbor");
check("status stops after the provider", compl("status cline ") === null);
check("a chosen subcommand offers its pools", compl("account ").map((i) => i.label).join() === "cline,tokenharbor");
check("reload takes no operands", compl("reload ") === null);
check("reset takes no operands", compl("reset x") === null);

// Notification levels.
check(
	"notifications offers all three levels",
	compl("notifications ").map((i) => i.label).join() === "all,quiet,silent",
);
check(
	"notification levels filter by prefix",
	compl("notifications q").map((i) => i.label).join() === "quiet",
);
check(
	"a notification suggestion carries the whole line",
	compl("notifications ").find((i) => i.label === "silent").value === "notifications silent",
);
check(
	"notification suggestions explain their level",
	/notices/.test(compl("notifications ").find((i) => i.label === "silent").description ?? ""),
);
check("notifications stops after its level", compl("notifications quiet ") === null);

// Pool names.
check("pool names filter by prefix", compl("account to").map((i) => i.label).join() === "tokenharbor");
check("pool names are case-insensitive", compl("account CL").map((i) => i.label).join() === "cline");
check("a pool suggestion carries the whole line", compl("account ").find((i) => i.label === "cline").value === "account cline ");
check("pools are labelled by kind", compl("account ").map((i) => i.description).join() === "oauth pool,key pool");
check("an unknown pool yields null", compl("account nope") === null);

// Entries, for either pool kind.
check("add offers the pool names", compl("add ").map((i) => i.label).join() === "cline,tokenharbor");
check(
	"add offers existing account names",
	compl("add cline ").map((i) => i.label).join() === "work,home,work-laptop",
);
check(
	"add offers existing key names",
	compl("add tokenharbor ").map((i) => i.label).join() === "primary,backup",
);
check(
	"an add suggestion carries the whole line",
	compl("add cline wo").find((i) => i.label === "work").value === "add cline work",
);
check(
	"add completions never expose credential values",
	!JSON.stringify(compl("add cline ")).includes("oauth-secret") &&
		!JSON.stringify(compl("add tokenharbor ")).includes("key-secret"),
);
check(
	"remove offers the pool's entries",
	compl("remove cline ").map((i) => i.label).join() === "work,home,work-laptop",
);
check(
	"a remove suggestion carries the whole line",
	compl("remove cline wo").find((i) => i.label === "work").value === "remove cline work",
);
check("entries of an oauth pool", compl("account cline ").map((i) => i.label).join() === "work,home,work-laptop");
check("entries of a keys pool", compl("account tokenharbor ").map((i) => i.label).join() === "primary,backup");
check("entries filter by prefix", compl("account cline wo").map((i) => i.label).join() === "work,work-laptop");
check("entry names are case-insensitive", compl("account cline HO").map((i) => i.label).join() === "home");
check("an entry suggestion carries the whole line", compl("account cline wo").find((i) => i.label === "work").value === "account cline work");
check("no trailing space after the last token", !compl("account cline wo")[0].value.endsWith(" "));
check("the active entry is labelled", compl("account cline ").find((i) => i.label === "home").description === "active");
check("an inactive entry has no label", compl("account cline ").find((i) => i.label === "work").description === undefined);
check("an unknown entry yields null", compl("account cline zz") === null);
check("extra operands stop suggesting", compl("account cline work extra ") === null);

// Must never throw on whatever the editor hands it.
check("a null-ish prefix is safe", commandCompletions("", []).length === SUBCOMMANDS.length);
// Whitespace-only still offers the subcommands: nothing has been chosen yet, and
// offering them is harmless where offering entries for a blank pool name would
// not be.
check(
	"a whitespace-only prefix still offers subcommands",
	labels("  ").join() === "status,reload,reset,account,strategy,add,remove,notifications",
);
check("a tab counts as a separator", compl("account\t").map((i) => i.label).join() === "cline,tokenharbor");
check("an unknown subcommand offers nothing", compl("notacommand ") === null);
check("an empty pool list yields null, not an empty menu", commandCompletions("account ", []) === null);
check("an empty pool list still offers subcommands", commandCompletions("", []).length === SUBCOMMANDS.length);

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
				_customProviderField: "must-survive",
				accounts: [
					{
						name: "a1",
						note: "keep-entry-field",
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

	// --- active: the saved rotation position ------------------------------
	// Written back as a field on the pool itself, so a rotation survives a
	// session: without it every session restarts at entry #1.
	writeFileSync(
		persistFile,
		JSON.stringify(
			{ ...seed, providers: [...seed.providers, { name: "google", keys: [{ name: "primary", value: "sk-g" }] }] },
			null,
			2,
		) + "\n",
		"utf8",
	);
	check("writeBackActive reports success", writeBackActive("cline", "a2").updated === 1);
	let active = JSON.parse(readFileSync(persistFile, "utf8"));
	check("active names the entry", active.providers[0].active === "a2");
	check("active is per-pool (sibling pools untouched)", active.providers[1].active === undefined);
	check(
		"writeBackActive leaves credentials, keys and other fields alone",
		active.providers[0].accounts[0].credential.access === "old-access" &&
			active._customTopLevelField === "must-survive" &&
			active.maxRetries === 3,
	);
	check("an unchanged active is a no-op", writeBackActive("cline", "a2").updated === 0);
	check("an unknown pool is a no-op for active", writeBackActive("ghost", "x").updated === 0);
	check("clearing active forgets it", writeBackActive("cline", undefined).updated === 1);
	active = JSON.parse(readFileSync(persistFile, "utf8"));
	check("clearing leaves no active field", active.providers[0].active === undefined);
	check("clearing an already-unset active is a no-op", writeBackActive("cline", undefined).updated === 0);

	// --- notifications: the top-level status-line volume ----------------
	const notificationFile = join(persistDir, "notifications.json");
	const notificationSeed = {
		providers: [{ name: "google", keys: [{ name: "primary", value: "$GOOGLE_KEY" }] }],
		notifications: "all",
		maxRetries: 3,
		_customTopLevelField: { keep: true },
	};
	writeFileSync(notificationFile, JSON.stringify(notificationSeed, null, 2) + "\n", "utf8");
	process.env.PI_KEYROUTER_CONFIG = notificationFile;

	const setNotifications = writeBackNotifications("quiet");
	check("writeBackNotifications reports one update", setNotifications.updated === 1);
	const quietText = readFileSync(notificationFile, "utf8");
	const quietConfig = JSON.parse(quietText);
	check("write-back sets the notification level", quietConfig.notifications === "quiet");
	check(
		"write-back preserves every other top-level field",
		quietConfig.maxRetries === 3 &&
			quietConfig._customTopLevelField.keep === true &&
			JSON.stringify(quietConfig.providers) === JSON.stringify(notificationSeed.providers),
	);
	check(
		"write-back preserves key order and formatting",
		Object.keys(quietConfig).join() === Object.keys(notificationSeed).join() &&
			quietText === JSON.stringify({ ...notificationSeed, notifications: "quiet" }, null, 2) + "\n",
	);
	check("an unchanged notification level is a no-op", writeBackNotifications("quiet").updated === 0);
	check("a no-op notification write does not rewrite the file", readFileSync(notificationFile, "utf8") === quietText);
	check("write-back can change the notification level", writeBackNotifications("silent").updated === 1);
	check("the changed notification level is persisted", JSON.parse(readFileSync(notificationFile, "utf8")).notifications === "silent");

	const missingNotificationsFile = join(persistDir, "missing-notifications.json");
	process.env.PI_KEYROUTER_CONFIG = missingNotificationsFile;
	const missingNotifications = writeBackNotifications("quiet");
	check(
		"a missing config is reported as a write-back error",
		"error" in missingNotifications && /cannot read/.test(missingNotifications.error),
	);
	check("a missing config is not created", !existsSync(missingNotificationsFile));

	const malformedNotificationsFile = join(persistDir, "malformed-notifications.json");
	writeFileSync(malformedNotificationsFile, '{"privateValue":"must-not-appear"', "utf8");
	process.env.PI_KEYROUTER_CONFIG = malformedNotificationsFile;
	const malformedNotifications = writeBackNotifications("quiet");
	check(
		"malformed JSON is reported as a write-back error",
		"error" in malformedNotifications && /cannot parse/.test(malformedNotifications.error),
	);
	check(
		"a malformed-config error never quotes file contents",
		!("error" in malformedNotifications) || !malformedNotifications.error.includes("must-not-appear"),
	);

	const failedNotificationsFile = join(persistDir, "failed-notifications.json");
	writeFileSync(failedNotificationsFile, JSON.stringify(notificationSeed, null, 2) + "\n", "utf8");
	const failedTemp = `${failedNotificationsFile}.keyrouter.tmp`;
	mkdirSync(failedTemp);
	process.env.PI_KEYROUTER_CONFIG = failedNotificationsFile;
	const failedNotifications = writeBackNotifications("quiet");
	check(
		"a failed atomic write is reported as an error",
		"error" in failedNotifications && /cannot write/.test(failedNotifications.error),
	);
	check(
		"a failed atomic write leaves the original config unchanged",
		readFileSync(failedNotificationsFile, "utf8") === JSON.stringify(notificationSeed, null, 2) + "\n",
	);
	rmSync(failedTemp, { recursive: true, force: true });
	process.env.PI_KEYROUTER_CONFIG = persistFile;

	// --- pool entries: what the guided add/remove commands write ---------
	const addedKey = writeBackPoolEntry("google", "add", { name: "k2", value: "sk-2" });
	check("writeBackPoolEntry reports one update", addedKey.updated === 1);
	let pool = JSON.parse(readFileSync(persistFile, "utf8"));
	check(
		"the key entry is appended",
		pool.providers[1].keys[1].name === "k2" && pool.providers[1].keys[1].value === "sk-2",
	);
	check(
		"a duplicate name is a no-op",
		writeBackPoolEntry("google", "add", { name: "k2", value: "sk-3" }).updated === 0,
	);
	check(
		"an unknown pool is a no-op",
		writeBackPoolEntry("ghost", "add", { name: "x", value: "y" }).updated === 0,
	);
	check(
		"the other pools are untouched",
		JSON.parse(readFileSync(persistFile, "utf8")).providers[0].accounts.length === 2,
	);

	const addedAccount = writeBackPoolEntry("cline", "add", {
		name: "a3",
		credential: { type: "oauth", access: "new-access", refresh: "refresh-3", expires: 3000 },
	});
	check("an account pool accepts an entry", addedAccount.updated === 1);
	pool = JSON.parse(readFileSync(persistFile, "utf8"));
	check(
		"the account entry keeps its credential",
		pool.providers[0].accounts[2].name === "a3" && pool.providers[0].accounts[2].credential.access === "new-access",
	);

	// `update` changes only the named entry's credential. Its position, sibling
	// entries, provider fields, and unknown top-level fields all stay put.
	const updatedAccount = writeBackPoolEntry("cline", "update", {
		name: "a1",
		credential: {
			type: "oauth",
			access: "replacement-access",
			refresh: "replacement-refresh",
			expires: 4000,
			accountId: "replacement-id",
		},
	});
	check("an OAuth account can be updated in place", updatedAccount.updated === 1);
	pool = JSON.parse(readFileSync(persistFile, "utf8"));
	check(
		"the update replaces the targeted credential",
		pool.providers[0].accounts[0].credential.access === "replacement-access" &&
			pool.providers[0].accounts[0].credential.refresh === "replacement-refresh" &&
			pool.providers[0].accounts[0].credential.expires === 4000,
	);
	check(
		"the update preserves the entry's other fields and position",
		pool.providers[0].accounts[0].name === "a1" &&
			pool.providers[0].accounts[0].note === "keep-entry-field",
	);
	check(
		"the update preserves sibling accounts and provider fields",
		pool.providers[0].accounts[1].name === "a2" &&
			pool.providers[0].accounts[2].name === "a3" &&
			pool.providers[0]._customProviderField === "must-survive" &&
			pool._customTopLevelField === "must-survive",
	);
	const beforeNoopUpdate = readFileSync(persistFile, "utf8");
	const noopAccountUpdate = writeBackPoolEntry("cline", "update", {
		name: "a1",
		credential: {
			type: "oauth",
			access: "replacement-access",
			refresh: "replacement-refresh",
			expires: 4000,
			accountId: "replacement-id",
		},
	});
	check("an identical OAuth update is a no-op", noopAccountUpdate.updated === 0);
	check("a no-op OAuth update does not rewrite the file", readFileSync(persistFile, "utf8") === beforeNoopUpdate);

	const updatedKey = writeBackPoolEntry("google", "update", { name: "k2", value: "sk-replaced" });
	check("an API key can be updated in place", updatedKey.updated === 1);
	pool = JSON.parse(readFileSync(persistFile, "utf8"));
	check(
		"the API-key update changes only the value",
		pool.providers[1].keys[1].name === "k2" && pool.providers[1].keys[1].value === "sk-replaced",
	);
	check(
		"an unknown update target is a no-op",
		writeBackPoolEntry("google", "update", { name: "missing", value: "x" }).updated === 0,
	);

	// External-backed entries are refused from the RAW file. The normalized
	// in-memory value has already lost the reference, so the writer is the place
	// where this can be enforced safely.
	const externalSource = join(persistDir, "external-credential.json");
	writeFileSync(externalSource, JSON.stringify(VALID), "utf8");
	const externalConfig = join(persistDir, "external-config.json");
	const externalRaw = {
		providers: [
			{
				name: "ext-oauth",
				accounts: [
					{ name: "env", credential: "$EXT_ACCOUNT" },
					{ name: "braced", credential: "${EXT_ACCOUNT}" },
					{ name: "file", credential: `@${externalSource}` },
				],
			},
			{
				name: "ext-keys",
				keys: [
					{ name: "env", value: "$EXT_KEY" },
					{ name: "braced", value: "${EXT_KEY}" },
					{ name: "file", value: `@${externalSource}` },
				],
			},
		],
	};
	writeFileSync(externalConfig, JSON.stringify(externalRaw, null, 2) + "\n", "utf8");
	process.env.PI_KEYROUTER_CONFIG = externalConfig;
	const externalBefore = readFileSync(externalConfig, "utf8");
	const envAccountUpdate = writeBackPoolEntry("ext-oauth", "update", { name: "env", credential: VALID });
	check(
		"an OAuth environment reference refuses an in-place update",
		"error" in envAccountUpdate && envAccountUpdate.error.includes("EXT_ACCOUNT"),
	);
	const bracedAccountUpdate = writeBackPoolEntry("ext-oauth", "update", { name: "braced", credential: VALID });
	check(
		"a braced OAuth environment reference refuses an in-place update",
		"error" in bracedAccountUpdate && bracedAccountUpdate.error.includes("EXT_ACCOUNT"),
	);
	const fileAccountUpdate = writeBackPoolEntry("ext-oauth", "update", { name: "file", credential: VALID });
	check(
		"an OAuth file reference refuses an in-place update and names the file",
		"error" in fileAccountUpdate && fileAccountUpdate.error.includes(externalSource),
	);
	const envKeyUpdate = writeBackPoolEntry("ext-keys", "update", { name: "env", value: "replacement" });
	check(
		"an API-key environment reference refuses an in-place update",
		"error" in envKeyUpdate && envKeyUpdate.error.includes("EXT_KEY"),
	);
	const bracedKeyUpdate = writeBackPoolEntry("ext-keys", "update", { name: "braced", value: "replacement" });
	check(
		"a braced API-key environment reference refuses an in-place update",
		"error" in bracedKeyUpdate && bracedKeyUpdate.error.includes("EXT_KEY"),
	);
	const fileKeyUpdate = writeBackPoolEntry("ext-keys", "update", { name: "file", value: "replacement" });
	check(
		"an API-key file reference refuses an in-place update and names the file",
		"error" in fileKeyUpdate && fileKeyUpdate.error.includes(externalSource),
	);
	check("external-backed updates leave the raw config unchanged", readFileSync(externalConfig, "utf8") === externalBefore);
	check("external-backed updates leave the external source unchanged", readFileSync(externalSource, "utf8") === JSON.stringify(VALID));
	check(
		"external-reference errors never contain the replacement secret",
		!("error" in envAccountUpdate) || !envAccountUpdate.error.includes("access-x"),
	);
	process.env.PI_KEYROUTER_CONFIG = persistFile;

	writeBackActive("google", "k2");
	check("the entry is removed", writeBackPoolEntry("google", "remove", { name: "k2" }).updated === 1);
	pool = JSON.parse(readFileSync(persistFile, "utf8"));
	check("the removal took effect", pool.providers[1].keys.length === 1);
	check("removing the active entry forgets the position", pool.providers[1].active === undefined);
	check(
		"removing an unknown entry is a no-op",
		writeBackPoolEntry("google", "remove", { name: "nope" }).updated === 0,
	);

	delete process.env.PI_KEYROUTER_CONFIG;
	} finally {
		rmSync(persistDir, { recursive: true, force: true });
	}
}

// ---------------------------------------------------------------------------
// 11. Leases — an exclusive claim on one pool entry
//
// A lease is how two pi processes sharing a pool stay off each other's
// credential: the claim is a file, created exclusively, and another live
// process holding it makes the entry un-pickable. The selection half lives in
// rotation.ts and stays pure, so it is tested here as a plain argument.
// ---------------------------------------------------------------------------
const leaseHome = mkdtempSync(join(tmpdir(), "kr-unit-lease-"));
try {
	const {
		claimLease,
		claimSweepLease,
		releaseLease,
		releaseOwnLeases,
		releaseSweepLease,
		leasedByOthers,
		leaseOwner,
		sweepLeaseOwner,
	} = await import("../lease.ts");
	// The leases live next to the config file, so a test points them at a
	// throwaway config rather than at the user's own ~/.pi.
	const leaseConfig = join(leaseHome, "keyrouter.json");
	const leaseDir = join(leaseHome, "keyrouter-leases");

	check("a fresh entry is free", leaseOwner("p", 0, leaseConfig) === undefined);
	check("claiming succeeds", claimLease("p", 0, leaseConfig) === true);
	check("the claim is ours", leaseOwner("p", 0, leaseConfig) === process.pid);
	check("claiming twice is still ours", claimLease("p", 0, leaseConfig) === true);
	check("our own claim is not another process", !leasedByOthers("p", 3, leaseConfig).has(0));
	releaseLease("p", 0, leaseConfig);
	check("releasing frees the entry", leaseOwner("p", 0, leaseConfig) === undefined);

	// Another LIVE process holds the entry: it must be invisible to us to take,
	// and visible to the picker.
	mkdirSync(leaseDir, { recursive: true });
	writeFileSync(join(leaseDir, "p.1.lease"), `${process.ppid}\n`, "utf8");
	check("another live process holds the entry", leasedByOthers("p", 3, leaseConfig).has(1));
	check("a held entry cannot be claimed", claimLease("p", 1, leaseConfig) === false);
	check("releasing never steals somebody else's claim", (releaseLease("p", 1, leaseConfig), leaseOwner("p", 1, leaseConfig) === process.ppid));

	// A DEAD process's claim is stale and may be taken over.
	writeFileSync(join(leaseDir, "p.2.lease"), "999999999\n", "utf8");
	check("a dead owner's claim is stale", !leasedByOthers("p", 3, leaseConfig).has(2));
	check("a stale claim can be taken over", claimLease("p", 2, leaseConfig) === true);
	check("the taken-over claim is ours", leaseOwner("p", 2, leaseConfig) === process.pid);

	// The selection half: a leased entry is skipped, but a lease never
	// deadlocks the picker.
	const leasedStates = initKeyStates([
		{ name: "a", value: "1" },
		{ name: "b", value: "2" },
	]);
	check("a leased entry is skipped", pickNextKey(leasedStates, 0, Date.now(), new Set([0])) === 1);
	check(
		"a lease never deadlocks the picker",
		pickNextKey(leasedStates, 0, Date.now(), new Set([0, 1])) === 0,
	);
	check(
		"without leases the preferred entry still wins",
		pickNextKey(leasedStates, 0, Date.now()) === 0,
	);

	// Provider-wide sweep claims are separate from entry leases: they guard a
	// whole OAuth provider while its idle accounts are refreshed.
	check("a fresh provider sweep claim is free", sweepLeaseOwner("sweep-provider", leaseConfig) === undefined);
	check("claiming a provider sweep succeeds", claimSweepLease("sweep-provider", leaseConfig) === true);
	check("the provider sweep claim is ours", sweepLeaseOwner("sweep-provider", leaseConfig) === process.pid);
	check("claiming a provider sweep twice is still ours", claimSweepLease("sweep-provider", leaseConfig) === true);
	releaseSweepLease("sweep-provider", leaseConfig);
	check("releasing frees the provider sweep", sweepLeaseOwner("sweep-provider", leaseConfig) === undefined);

	// Another LIVE process holds the provider sweep: it is visible, but cannot
	// be taken or stolen by release.
	writeFileSync(join(leaseDir, "sweep-provider.sweep-lease"), `${process.ppid}\n`, "utf8");
	check("another live process holds the provider sweep", sweepLeaseOwner("sweep-provider", leaseConfig) === process.ppid);
	check("a held provider sweep cannot be claimed", claimSweepLease("sweep-provider", leaseConfig) === false);
	releaseSweepLease("sweep-provider", leaseConfig);
	check("releasing never steals another process's provider sweep", sweepLeaseOwner("sweep-provider", leaseConfig) === process.ppid);

	// A DEAD process's provider sweep is stale and may be taken over.
	writeFileSync(join(leaseDir, "dead-sweep.sweep-lease"), "999999999\n", "utf8");
	check("a dead owner's provider sweep is stale", sweepLeaseOwner("dead-sweep", leaseConfig) === undefined);
	check("a stale provider sweep can be taken over", claimSweepLease("dead-sweep", leaseConfig) === true);
	check("the taken-over provider sweep is ours", sweepLeaseOwner("dead-sweep", leaseConfig) === process.pid);
	releaseSweepLease("dead-sweep", leaseConfig);

	// Sweep claims must not leak into the API-key entry-lease API.
	check("claiming a provider sweep succeeds independently", claimSweepLease("sweep-only", leaseConfig) === true);
	check("a provider sweep is not an entry lease", leasedByOthers("sweep-only", 3, leaseConfig).size === 0);
	check("a provider sweep has no entry owner", leaseOwner("sweep-only", 0, leaseConfig) === undefined);

	// Clean shutdown releases this process's provider sweep too.
	claimSweepLease("cleanup-sweep", leaseConfig);
	releaseOwnLeases(leaseConfig);
	check("own-claims cleanup removes this process's provider sweep", sweepLeaseOwner("cleanup-sweep", leaseConfig) === undefined);

	// A sweep that is STILL RUNNING keeps its claim: releasing it early would
	// let another session sweep the same provider in parallel.
	claimSweepLease("running-sweep", leaseConfig);
	releaseOwnLeases(leaseConfig, new Set(["running-sweep"]));
	check("cleanup keeps the claim of a running sweep", sweepLeaseOwner("running-sweep", leaseConfig) === process.pid);
	releaseSweepLease("running-sweep", leaseConfig);
} finally {
	rmSync(leaseHome, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// 12. startup sweep — temporary internal gate
// ---------------------------------------------------------------------------
check("startup sweep is disabled when the flag is unset", !startupSweepEnabled({}));
check("startup sweep is disabled when the flag is 0", !startupSweepEnabled({ PI_KEYROUTER_SWEEP: "0" }));
check("startup sweep is enabled when the flag is 1", startupSweepEnabled({ PI_KEYROUTER_SWEEP: "1" }));
check(
	"startup sweep is disabled for an arbitrary other flag value",
	!startupSweepEnabled({ PI_KEYROUTER_SWEEP: "enabled" }),
);

console.log(failures === 0 ? "\nall oauth unit tests pass" : `\n${failures} unit test(s) failed`);
process.exit(failures === 0 ? 0 : 1);