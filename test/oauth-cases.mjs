// =============================================================================
// oauth-cases.mjs — OAuth account-pool cases for test/run.mjs
// =============================================================================
//
// Loaded by run.mjs and spread into its `cases` array. Kept in its own file
// because these cases need machinery the API-key cases do not:
//
//   * test/fixture/oauth-provider.ts — an OAuth-ONLY provider (`kroauth`).
//     It has no `apiKey` auth method, so a runtime api_key overlay resolves to
//     NO auth at all (verified against openai-codex in
//     test/verify-runtime-credentials.mjs). Every request therefore proves which
//     account keyrouter installed into pi's credential store.
//   * A seeded auth.json holding one or more accounts.
//   * A per-case oauth log, written by the fixture's `refreshToken` hook, which
//     is how "did pi refresh, and did keyrouter refresh" becomes observable.
//
// Accounts are seeded directly into auth.json (pi's own format) rather than
// through /login, because the tests must never run an interactive flow.

/** Numbers for what the fixture provider turns into `Bearer oauth:<access>`. */
export const ACCESS_1 = "oauth:access-1";
export const ACCESS_2 = "oauth:access-2";
export const ACCESS_3 = "oauth:access-3";

const FAR_FUTURE = () => Date.now() + 24 * 60 * 60 * 1000;

/** One account entry as keyrouter's config sees it. */
const account = (name, access, extra = {}) => ({
	name,
	credential: {
		type: "oauth",
		access,
		refresh: `refresh-${access}`,
		expires: FAR_FUTURE(),
		...extra,
	},
});

/**
 * Accounts whose credential needs a specific shape: a dead refresh token, or one
 * close enough to expiry that pi refreshes it on first use.
 *
 * These MUST live in the pool config rather than the `auth.json` seed. keyrouter
 * installs the pool's FIRST account at session start, so anything seeded into the
 * store is replaced before the first request — a seeded near-expiry or dead
 * credential would never be the one that runs.
 */
export const OAUTH_ACCOUNTS_EXPIRING_FIRST = [
	{
		name: "a1",
		credential: {
			type: "oauth",
			access: "access-1",
			refresh: "refresh-1",
			// Inside pi's ~5 minute validity window, so pi refreshes on first use.
			expires: Date.now() + 60_000,
		},
	},
	account("a2", "access-2"),
];

/** First account's refresh token is dead, so it can never be used. */
export const OAUTH_ACCOUNTS_DEAD_FIRST = [
	{
		name: "a1",
		credential: {
			type: "oauth",
			access: "access-dead",
			refresh: "refresh-dead",
			expires: Date.now() + 30_000,
		},
	},
	account("a2", "access-2"),
];

/** Two healthy accounts. */
export const OAUTH_ACCOUNTS = [account("a1", "access-1"), account("a2", "access-2")];

/** Three healthy accounts, for the walk-the-pool case. */
export const OAUTH_ACCOUNTS_3 = [
	account("a1", "access-1"),
	account("a2", "access-2"),
	account("a3", "access-3"),
];

/**
 * The `auth.json` seed for a run: one stored account, plus an unrelated
 * provider entry that must survive every write keyrouter makes.
 */
export const authJson = (access = "access-1", extra = {}) => ({
	kroauth: {
		type: "oauth",
		access,
		refresh: `refresh-${access}`,
		expires: FAR_FUTURE(),
		...extra,
	},
	// A second provider is what catches a whole-file clobber: pi's store does a
	// read-modify-write of the entire file, so a bug here would destroy a real
	// login that has nothing to do with this pool.
	"unrelated-provider": { type: "api_key", key: "sk-must-survive" },
});

const traceHas = (trace, needle) => trace.some((line) => line.includes(needle));
const traceCount = (trace, prefix) => trace.filter((line) => line.startsWith(prefix)).length;

export const oauthCases = [
	// -------------------------------------------------------------------------
	{
		// The baseline: a pool account is installed and used, with no api-key
		// overlay anywhere near it.
		name: "oauth-installs-first-account",
		config: "accounts",
		oauth: true,
		auth: authJson(),
		plan: { default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi, oauthLog }) => [
			["pi printed PONG", pi.code === 0 && /PONG/.test(pi.stdout)],
			["exactly one request", keys.length === 1],
			["carried the first account's OAuth bearer", keys[0] === ACCESS_1],
			["never carried a pooled api key", !keys.includes("sk-a") && !keys.includes("sk-b")],
			["trace: oauth install kroauth -> a1", traceHas(trace, "oauth install kroauth -> a1")],
			["trace: no rotation", traceCount(trace, "rotate") === 0],
			["trace: no api-key bootstrap for kroauth", !traceHas(trace, "bootstrap kroauth")],
			["no runtime override was written", !traceHas(trace, "clear kroauth")],
			["pi did not need to refresh", (oauthLog ?? []).length === 0],
		],
	},
	// -------------------------------------------------------------------------
	{
		// 429 IS in pi's retryable set, so pi's own retry picks the new account up
		// and no settle continuation is needed.
		name: "oauth-rotate-on-429",
		config: "accounts",
		oauth: true,
		auth: authJson(),
		plan: { byKey: { [ACCESS_1]: 429 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi }) => [
			["pi recovered and printed PONG", /PONG/.test(pi.stdout)],
			["first request used account a1", keys[0] === ACCESS_1],
			["a later request used account a2", keys.includes(ACCESS_2)],
			["trace: rotate a1 -> a2", traceHas(trace, "rotate kroauth a1 -> a2")],
			["trace: 429 rate-limited", traceHas(trace, "429 rate-limited")],
			["no exhaustion", !traceHas(trace, "exhausted")],
			["no settle continuation for a pi-retryable error", !traceHas(trace, "continue ")],
		],
	},
	// -------------------------------------------------------------------------
	{
		// pi does NOT retry 401, so recovery here proves the settle-time
		// continuation works for OAuth pools too.
		name: "oauth-rotate-on-401",
		config: "accounts",
		oauth: true,
		auth: authJson(),
		plan: { byKey: { [ACCESS_1]: 401 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi }) => [
			["pi recovered and printed PONG", /PONG/.test(pi.stdout)],
			["first request used account a1", keys[0] === ACCESS_1],
			["continuation request used account a2", keys[1] === ACCESS_2],
			["trace: 401 unauthorized", traceHas(trace, "401 unauthorized")],
			["trace: rotate a1 -> a2", traceHas(trace, "rotate kroauth a1 -> a2")],
			["trace: continuation requested", traceHas(trace, "continue kroauth")],
			["exactly one continuation", traceCount(trace, "continue ") === 1],
		],
	},
	// -------------------------------------------------------------------------
	{
		// THE contrast case. An account-level limit MUST rotate an OAuth pool
		// (each account is its own subscription) even though the identical error
		// must NOT rotate an API-key pool — see quota-402-is-not-rotatable, which
		// asserts zero rotations for the same quota wording. pi treats quota as
		// non-retryable, so this depends on the continuation.
		name: "oauth-rotate-on-account-quota",
		config: "accounts",
		oauth: true,
		auth: authJson(),
		plan: {
			byKey: {
				[ACCESS_1]: {
					status: 402,
					message: "Monthly usage limit reached: your subscription is out of budget.",
				},
			},
			default: "ok",
			text: "PONG",
		},
		expect: ({ keys, trace, pi }) => [
			["pi recovered and printed PONG", /PONG/.test(pi.stdout)],
			["rotated away from the limited account", keys.includes(ACCESS_2)],
			["trace: rotate a1 -> a2", traceHas(trace, "rotate kroauth a1 -> a2")],
			["trace: classified as quota", traceHas(trace, "402 quota")],
			["continuation requested (quota is non-retryable)", traceHas(trace, "continue kroauth")],
			["exactly one continuation", traceCount(trace, "continue ") === 1],
		],
	},
	// -------------------------------------------------------------------------
	{
		// `rotateOnQuota: false` must suppress the quota rotation, proving the
		// option is wired and not merely documented.
		name: "oauth-quota-rotation-can-be-disabled",
		config: "accounts-no-quota",
		oauth: true,
		auth: authJson(),
		plan: {
			byKey: {
				[ACCESS_1]: {
					status: 402,
					message: "Monthly usage limit reached: your subscription is out of budget.",
				},
			},
			default: "ok",
			text: "PONG",
		},
		expect: ({ keys, trace }) => [
			["zero rotations", traceCount(trace, "rotate") === 0],
			["stayed on account a1", keys.every((k) => k === ACCESS_1)],
			["trace: ignored as non-rotatable", traceHas(trace, "ignore kroauth")],
			["no continuation requested", !traceHas(trace, "continue ")],
		],
	},
	// -------------------------------------------------------------------------
	{
		// A dead refresh token: pi refuses to resolve auth, keyrouter classifies the
		// failure and rotates to a usable account. pi's own refresh attempt is the
		// only refresh here — keyrouter must never add one.
		//
		// The dead credential is account a1's POOL entry, not an auth.json seed:
		// keyrouter installs account a1 at session start, so whatever is in the
		// store beforehand is replaced before the first request.
		name: "oauth-dead-refresh-token-rotates",
		config: "accounts-dead-first",
		oauth: true,
		auth: authJson(),
		plan: { default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi, oauthLog }) => [
			["pi eventually recovered", /PONG/.test(pi.stdout)],
			["pi attempted the refresh of the dead account", (oauthLog ?? []).some((l) => l.includes("refresh access=access-dead"))],
			["trace: classified as a dead credential", traceHas(trace, "401 refresh-failed")],
			["trace: rotated away from it", traceHas(trace, "rotate kroauth a1 -> a2")],
			["a later request used the healthy account", keys.includes(ACCESS_2)],
		],
	},
	// -------------------------------------------------------------------------
	{
		// pi owns refresh, and its rotated tokens MUST reach the pool. pi rotates the
		// refresh token too, so if keyrouter failed to copy the refreshed blob back,
		// a later return to account a1 would install a consumed refresh token and the
		// fixture (which models rotation, like a real provider) would reject it with
		// invalid_grant. So "we came back to a1 and still succeeded" is the proof.
		//
		// The near-expiry credential is account a1's POOL entry, not an auth.json
		// seed: keyrouter installs account a1 at session start.
		name: "oauth-pi-refreshes-and-keyrouter-syncs-back",
		config: "accounts-expiring-first",
		oauth: true,
		auth: authJson(),
		plan: { sequence: [429, 429, 429, "ok"], default: "ok", text: "PONG", repeatLast: true },
			expect: ({ keys, trace, oauthLog }) => {
				const refreshed = (keys ?? []).filter((k) => typeof k === "string" && k.startsWith("oauth:refreshed-"));
				// Request 1 carries the refreshed token: pi refreshed a1 on first use
				// because the pool installed it inside pi's validity window.
				// Request 3 carries the SAME token again, because the pool captured pi's
				// rotated blob when it left a1 and reinstalled it on return. Had the
				// capture been lost, reinstalling would have presented the stale
				// near-expiry credential, pi would have refreshed the already-consumed
				// refresh token, and the fixture would have failed with invalid_grant.
				const refreshedOnce = new Set(refreshed).size === 1;
				return [
					["pi refreshed account a1", (oauthLog ?? []).some((l) => l.includes("refresh access=access-1"))],
					["pi's rotated access token reached the server", refreshed.length > 0],
					["the pool re-installed a1 using pi's ROTATED credential", refreshed.includes(keys[2])],
					["a1 was not refreshed a second time (the captured blob was reused)", refreshedOnce],
					["the stale access token was never sent", !keys.includes(ACCESS_1)],
					["the rotated refresh token was never reused (no invalid_grant)", keys[3] === ACCESS_2],
					["keyrouter never refreshed anything itself", !(oauthLog ?? []).some((l) => /keyrouter/.test(l))],
					["the pool walked a1(refreshed) -> a2 -> a1(refreshed) -> a2", keys[0] === keys[2] && keys[1] === ACCESS_2 && keys[3] === ACCESS_2],
					["at least two rotations happened", traceCount(trace, "rotate") >= 2],
				];
			},

	},
	// -------------------------------------------------------------------------
	{
		// Moving between accounts must never lose a credential: the pool started
		// with three and the third account must be reachable.
		name: "oauth-walks-three-accounts",
		config: "accounts-3",
		oauth: true,
		auth: authJson(),
		plan: { byKey: { [ACCESS_1]: 401, [ACCESS_2]: 401 }, default: "ok", text: "PONG" },
		expect: ({ keys, trace, pi }) => [
			["pi recovered on a3", /PONG/.test(pi.stdout)],
			["walked a1 -> a2 -> a3", keys.slice(0, 3).join(",") === [ACCESS_1, ACCESS_2, ACCESS_3].join(",")],
			["two rotations", traceCount(trace, "rotate") === 2],
			["at most two continuations for two non-retryable legs", traceCount(trace, "continue ") <= 2],
		],
	},
	// -------------------------------------------------------------------------
	{
		// An OAuth pool pointed at a provider without an `oauth` auth method must
		// be skipped: installing a blob there could never resolve.
		name: "oauth-pool-on-krapi-provider-is-skipped",
		config: "accounts-wrong-provider",
		oauth: true,
		auth: authJson(),
		plan: { default: "ok", text: "PONG" },
		expect: ({ trace }) => [
			["reported the provider has no OAuth auth", traceHas(trace, "skip krtest (provider has no OAuth auth method)")],
			["no install attempted", !traceHas(trace, "oauth install krtest")],
			["zero rotations", traceCount(trace, "rotate") === 0],
		],
	},
	// -------------------------------------------------------------------------
	{
		// A pool account must not leak across providers, and the unrelated
		// provider entry in auth.json must be byte-identical afterwards. This is
		// the guard against pi's whole-file read-modify-write clobbering a real
		// login (or against keyrouter writing auth.json out of band).
		name: "oauth-preserves-unrelated-auth-entries",
		config: "accounts",
		oauth: true,
		auth: authJson(),
		plan: { default: "ok", text: "PONG" },
		expect: ({ authAfter, trace }) => [
			["unrelated provider entry survived", authAfter?.["unrelated-provider"]?.key === "sk-must-survive"],
			["the pool provider entry is still an OAuth credential", authAfter?.kroauth?.type === "oauth"],
			["install ran", traceHas(trace, "oauth install kroauth")],
		],
	},
	// -------------------------------------------------------------------------
	{
		// Overload is a provider problem, never an account problem: no rotation,
		// no failure counted, same account retried.
		name: "oauth-overload-cools-provider-no-rotation",
		config: "accounts",
		oauth: true,
		auth: authJson(),
		plan: { sequence: [529], repeatLast: true },
		expect: ({ keys, trace, pi }) => [
			["pi reported the overload", pi.code !== 0 || /overload/i.test(`${pi.stdout}\n${pi.stderr}`)],
			["zero rotations", traceCount(trace, "rotate") === 0],
			["trace: overload branch", traceHas(trace, "overload kroauth")],
			["no exhaustion", !traceHas(trace, "exhausted")],
			["no install churn (one install only)", traceCount(trace, "oauth install") === 1],
		],
	},
];