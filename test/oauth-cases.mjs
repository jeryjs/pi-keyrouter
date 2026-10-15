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

/**
 * One account entry as keyrouter's config sees it.
 *
 * `accountId` doubles as the account's identity: keyrouter reads it through
 * `detectIdentity`, so tests exercise the same identity path a real provider's
 * claims would drive. The fixture's `access` values are opaque on purpose, so
 * without this every capture would report "no readable identity" and the
 * attribution logic would never be reached.
 */
const account = (name, access, extra = {}) => ({
	name,
	credential: {
		type: "oauth",
		access,
		refresh: `refresh-${access}`,
		expires: FAR_FUTURE(),
		accountId: name,
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
			// Identity, for the same reason `account()` carries one: keyrouter reads it
			// to attribute a captured credential to a slot.
			accountId: "a1",
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
			accountId: "a1",
		},
	},
	account("a2", "access-2"),
];

/**
 * The MIRROR of the above: here the dead account is LAST.
 *
 * The shutdown handover must not install a dead credential, and it can only be
 * asked not to when the pool's ACTIVE account is the dead one. With the dead entry
 * first, a rotation walks away from it and the active account ends up healthy, so
 * that guard is never reached. Reaching it requires the dead account to be the one
 * rotation settles on.
 */
export const OAUTH_ACCOUNTS_DEAD_SECOND = [
	account("a1", "access-1"),
	{
		name: "a2",
		credential: {
			type: "oauth",
			access: "access-dead",
			refresh: "refresh-dead",
			expires: Date.now() + 30_000,
			accountId: "a2",
		},
	},
];

/**
 * A pool whose ONLY account is dead, with an already-expired access token.
 *
 * This is the case the shutdown guard exists for. keyrouter installs the account at
 * session start, pi fails to refresh it, and rotation has nowhere to go (one entry),
 * so the active account stays dead. Handing that to the next session guarantees it
 * starts by failing, which is exactly the live symptom.
 */
export const OAUTH_ACCOUNTS_DEAD_ONLY = [
	{
		name: "a1",
		credential: {
			type: "oauth",
			access: "access-dead",
			refresh: "refresh-dead",
			// Already in the PAST, unlike `accounts-dead-first`'s +30s (which exists to make
			// pi refresh on first use). This case needs a credential that CANNOT work, so
			// `expires` must have passed rather than merely be close.
			expires: Date.now() - 60_000,
			accountId: "a1",
		},
	},
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
			["trace: classified as a dead credential (the refresh reason wins over the 401/403 net)", traceHas(trace, "refresh-failed")],
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
		// -------------------------------------------------------------------------
		{
			// THE REGRESSION CASE. pi refreshes lazily and writes the rotated pair only
			// to its own store. keyrouter holds its own copy of each account, so if a
			// capture is not written back, installs keep presenting the access token
			// from an account's LAST LOGIN (~1h of life). After any real use that token
			// is expired and every account in the pool looks dead.
			//
			// The fixture models this exactly: account a1 starts expired, pi refreshes
			// it on first use, and this asserts the refreshed value reached the pool's
			// CONFIG FILE, not just memory.
			name: "oauth-persists-refreshed-credential-to-config",
			config: "accounts-expiring-first",
			oauth: true,
			auth: authJson(),
			plan: { default: "ok", text: "PONG" },
			expect: ({ keys, trace, pi, configAfter }) => {
				const a1 = configAfter?.providers?.[0]?.accounts?.[0]?.credential;
				return [
					["pi recovered", /PONG/.test(pi.stdout)],
					["pi refreshed the expired account", /oauth:refreshed-/.test(String(keys[0]))],
					["the refreshed credential was written back to keyrouter.json", typeof a1?.access === "string" && a1.access.startsWith("refreshed-")],
					["the persisted expiry moved forward, not left at login time", typeof a1?.expires === "number" && a1.expires > Date.now()],
					["the refresh token was carried through", typeof a1?.refresh === "string" && a1.refresh.startsWith("refresh-")],
					["the write was traced", traceHas(trace, "persist kroauth a1")],
				];
			},
		},
		// -------------------------------------------------------------------------
		{
			// The write must not run when nothing changed: pi refreshes lazily, so most
			// captures are no-ops, and a needless write would churn the user's file.
			name: "oauth-does-not-churn-config-when-nothing-changed",
			config: "accounts",
			oauth: true,
			auth: authJson(),
			plan: { default: "ok", text: "PONG" },
			expect: ({ trace, pi }) => [
				["pi recovered", /PONG/.test(pi.stdout)],
				["pi did not need to refresh (credentials are far from expiry)", !traceHas(trace, "refresh")],
				["nothing was persisted", !traceHas(trace, "persist kroauth")],
			],
		},
	// -------------------------------------------------------------------------
	{
		// REGRESSION: a `/login` must reach the pool.
		//
		// pi exposes no login, logout or credential-changed event, so a credential the
		// user creates by hand is only observable by looking. This reaches that state
		// through the fixture's refresh hook, which stamps an identity belonging to a
		// DIFFERENT pool account — exactly what `/login` as another account produces.
		//
		// Without the drift check the pool kept its old copy and then installed it OVER
		// the new login on the next rotation, so the account failed with invalid_grant
		// despite having just been authenticated. Observed live: five `/login`s and not
		// one trace line, with the new refresh token absent from keyrouter.json.
		name: "oauth-login-drift-is-recorded",
		config: "accounts-expiring-first",
		oauth: true,
		auth: authJson(),
		// a1 is the account keyrouter installs, and its near-expiry credential makes pi
		// refresh on first use. The hook then stamps a2's identity onto the result, so pi
		// ends up holding a credential for an account OTHER than the one installed —
		// which is the state a `/login` as another account produces.
		drift: "a2",
		plan: { default: "ok", text: "PONG", repeatLast: true },
		expect: ({ keys, trace, pi, configAfter, oauthLog }) => {
			const accounts = configAfter?.providers?.[0]?.accounts ?? [];
			const a1 = accounts.find((a) => a.name === "a1")?.credential;
			const a2 = accounts.find((a) => a.name === "a2")?.credential;
			return [
				["pi recovered", /PONG/.test(pi.stdout)],
				["pi refreshed, which is what produces the foreign credential", (oauthLog ?? []).length > 0],
				["the drift was attributed to a2, not the installed a1", traceHas(trace, "credential belongs to a2, not a1")],
				["attribution used the credential's own identity", traceHas(trace, "(accountId)")],
				["the credential was persisted to a2's slot", typeof a2?.access === "string" && a2.access.startsWith("refreshed-")],
				["a2's refresh token moved to the new one", typeof a2?.refresh === "string" && a2.refresh.startsWith("refresh-")],
				["a1's own slot was NOT overwritten with someone else's credential", a1?.accountId === "a1"],
				["the tripwire did not have to refuse anything", !traceHas(trace, "identity tripwire kroauth")],
				["a request still carried a working OAuth bearer", keys.some((k) => typeof k === "string" && k.startsWith("oauth:"))],
			];
		},
	},
	// -------------------------------------------------------------------------
	{
		// A drift that resolves to NO pool slot must be reported, never written.
		//
		// pi holding a login the pool does not contain is normal — the user signed into
		// an account they never added — and adding it is their decision, not keyrouter's.
		// The pool WILL overwrite it on the next rotation, so staying quiet would lose a
		// working login without a word.
		name: "oauth-login-drift-into-unknown-account-is-reported",
		config: "accounts-expiring-first",
		oauth: true,
		auth: authJson(),
		drift: "not-a-pool-account",
		plan: { default: "ok", text: "PONG", repeatLast: true },
		expect: ({ pi, trace, configAfter }) => {
			const accounts = configAfter?.providers?.[0]?.accounts ?? [];
			return [
				["pi recovered", /PONG/.test(pi.stdout)],
				["the unknown identity was traced", traceHas(trace, "drift unknown kroauth")],
				["nothing was written into any slot", accounts.every((a) => a.credential.accountId === a.name)],
				["no account was invented", accounts.length === 2],
			];
		},
	},
	// -------------------------------------------------------------------------
	{
		// REGRESSION: shutdown must hand over a credential that can actually work.
		//
		// The session-start credential used to be reinstalled here. It is stale by then
		// — pi rotated the access token in place, and keyrouter swapped accounts several
		// times — so the next session began by 403ing against an expired token. The live
		// case exited holding a credential whose `expires` was three hours in the past.
		name: "oauth-shutdown-hands-over-the-active-account",
		config: "accounts",
		oauth: true,
		auth: authJson(),
		plan: { default: "ok", text: "PONG", repeatLast: true },
		expect: ({ trace, authAfter }) => {
			// pi's own store already holds a credential keyrouter installed, so the handover
			// should keep it rather than swap in a snapshot. What matters is that the
			// credential left behind is one that can actually work.
			return [
				["shutdown recorded what it handed over", /oauth keep kroauth/.test(trace.join("\n"))],
				["the handover names which credential was kept", /oauth keep kroauth \(.+expires in \d+m\)/.test(trace.join("\n"))],
				["and it reports pi's credential, not an old snapshot", traceHas(trace, "pi's credential for a1")],
				["pi's store still holds an OAuth credential", authAfter?.kroauth?.type === "oauth"],
				["the handed-over credential is the one pi held", authAfter?.kroauth?.accountId === "a1"],
				["and it is not expired", typeof authAfter?.kroauth?.expires === "number" && authAfter.kroauth.expires > Date.now()],
				["the unrelated provider entry survived", authAfter?.["unrelated-provider"]?.key === "sk-must-survive"],
			];
		},
	},
	// -------------------------------------------------------------------------
	{
		// A pool whose active account is EXPIRED must not be installed at shutdown.
		//
		// This is the exact live failure: the expired session-start credential was put
		// back, so the next session 403ed before a single request could succeed. Leaving
		// pi's current credential — the one that was just working — is strictly better.
		name: "oauth-shutdown-does-not-install-an-expired-account",
		config: "accounts-dead-only",
		oauth: true,
		auth: authJson(),
		plan: { default: "ok", text: "PONG", repeatLast: true },
		expect: ({ trace, authAfter, configAfter }) => {
			// The pool has one account and it cannot work, so there is nothing safe to
			// hand over. The store must be left alone rather than rewritten with a dead
			// credential, which would look like a successful handover while guaranteeing
			// the next session starts broken.
			const a1 = configAfter?.providers?.[0]?.accounts?.[0]?.credential;
			return [
				["shutdown refused to hand over anything", traceHas(trace, "nothing viable for handing to the next session")],
				["and said why: pi's credential is expired", traceHas(trace, "pi's credential is expired")],
				["the pool's account was recorded as expired too", typeof a1?.expires === "number"],
				["pi's store was left untouched rather than given a dead credential", authAfter?.kroauth?.access === "access-dead"],
			];
		},
	},
];