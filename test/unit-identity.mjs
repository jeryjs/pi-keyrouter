// =============================================================================
// unit-identity.mjs — credential-to-account attribution
// =============================================================================
//
// The regression this file exists for:
//
//   A pool holds slots A and B with distinct logins. pi's credential store holds
//   a credential belonging to A — e.g. the user ran /login for A while the saved
//   `active` still named B. The write-back used to trust the caller's belief that
//   the credential was B's, so it stamped A's refresh token into slot B. B was
//   then aliased onto A, B's own refresh token was orphaned, and B failed with
//   invalid_grant on its next use even though nothing had been wrong with it.
//
//   Every assertion in the "regression" block below fails against the old code.
//
// Run: node test/unit-identity.mjs
// =============================================================================

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const {
	attributeCredential,
	checkTripwire,
	decodeValue,
	detectIdentity,
	identityLabel,
	resolveUserPath,
	validateIdentityPath,
} = await import("../identity.ts");

let checks = 0;
let failures = 0;
const check = (label, ok, detail) => {
	checks += 1;
	if (ok) {
		console.log(`PASS  ${label}`);
	} else {
		failures += 1;
		console.log(`FAIL  ${label}${detail ? `  (${detail})` : ""}`);
	}
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const b64 = (obj) => Buffer.from(JSON.stringify(obj), "utf-8").toString("base64url");
/** A well-formed JWT with an unverifiable signature, like a real access token. */
const jwt = (claims) => `${b64({ alg: "RS256", typ: "JWT" })}.${b64(claims)}.signature`;
const cred = (fields) => ({ type: "oauth", access: "opaque", refresh: "r", expires: 1, ...fields });
const slot = (name, credential) => ({
	name,
	value: "",
	credential,
	lastStatus: "untried",
	cooldownUntil: 0,
	overloadedUntil: 0,
	uses: 0,
	failures: 0,
});

// The two real accounts from the incident, so the regression reads concretely.
const CLINE_CLAIMS_A = { sub: "user_jery99961", email: "jery99961@gmail.com", iss: "https://api.workos.com/user_management/client_x" };
const CLINE_CLAIMS_B = { sub: "user_22btrca061", email: "22btrca061@jainuniversity.ac.in", iss: "https://api.workos.com/user_management/client_x" };
const credA = (refresh = "2fa78665-old", expires = 100) => cred({ access: jwt(CLINE_CLAIMS_A), refresh, expires });
const credB = (refresh = "fa5cfd2c-old", expires = 100) => cred({ access: jwt(CLINE_CLAIMS_B), refresh, expires });

// ---------------------------------------------------------------------------
// 1. validateIdentityPath
// ---------------------------------------------------------------------------

check("a bare field is a valid path", validateIdentityPath("refresh").ok === true);
check("a two-level path is valid", validateIdentityPath("access:email").ok === true);
check("a nested claim path is valid", validateIdentityPath("access:user.email").ok === true);
check("surrounding whitespace is trimmed", validateIdentityPath("  access:email  ").path === "access:email");
check("a leading colon is rejected", validateIdentityPath(":email").ok === false);
check("a trailing colon is rejected", validateIdentityPath("access:").ok === false);
check("an empty string is rejected", validateIdentityPath("").ok === false);
check("a non-string is rejected", validateIdentityPath(42).ok === false);
check("a rejection carries a reason", /colon/.test(validateIdentityPath(":email").reason ?? ""));

// ---------------------------------------------------------------------------
// 2. Decoding — the codec is auto-detected, and ambiguity is refused
// ---------------------------------------------------------------------------

check("a JWT decodes to its claims", decodeValue(jwt({ email: "a@b.c" }))?.email === "a@b.c");
check("JSON decodes", decodeValue('{"email":"a@b.c"}')?.email === "a@b.c");
check("base64-wrapped JSON decodes", decodeValue(b64({ email: "a@b.c" }))?.email === "a@b.c");
check("a bare word is left alone", decodeValue("opaque-token-value") === "opaque-token-value");
check("a non-string is returned unchanged", decodeValue(12345) === 12345);

// The important refusal: most opaque tokens are base64-ish. Decoding one would
// produce mojibake and then report that mojibake as an account identity.
const base64ish = Buffer.from("not json at all, just text").toString("base64url");
check("base64 that is NOT JSON is not decoded", decodeValue(base64ish) === base64ish, `got ${String(decodeValue(base64ish)).slice(0, 40)}`);
check("a 3-part string with a non-JSON payload is not decoded", decodeValue("aaa.bbb.ccc") === "aaa.bbb.ccc");
check("invalid JSON is not decoded", decodeValue("{broken") === "{broken");
check("a JSON array is not treated as a claims object", detectIdentity(cred({ access: "[1,2,3]" })) === undefined);

// ---------------------------------------------------------------------------
// 3. resolveUserPath — the user's override, in all three forms
// ---------------------------------------------------------------------------

const jwtCred = cred({ access: jwt(CLINE_CLAIMS_A), refresh: "REFRESH_TOKEN_VALUE" });

check(
	'"refresh" compares the refresh token itself',
	resolveUserPath(jwtCred, "refresh")?.value === "REFRESH_TOKEN_VALUE",
);
check('"refresh" is reported as an exact refresh match', resolveUserPath(jwtCred, "refresh")?.source === "refresh-token");
check('"access:email" reads a decoded claim', resolveUserPath(jwtCred, "access:email")?.value === "jery99961@gmail.com");
check('"access:sub" reads a different claim', resolveUserPath(jwtCred, "access:sub")?.value === "user_jery99961");
check("a decoded claim is reported as a token claim", resolveUserPath(jwtCred, "access:email")?.source === "token-claim");

// Nested claims, the shape the user described as level2.
const nested = cred({ access: jwt({ user: { email: "nested@example.com", profile: { id: "deep-id" } } }) });
check('a nested claim path resolves', resolveUserPath(nested, "access:user.email")?.value === "nested@example.com");
check('a deeply nested claim path resolves', resolveUserPath(nested, "access:user.profile.id")?.value === "deep-id");

// level1 is any key of the credential, not just `access`.
const blobCred = cred({ accountId: "acct-123", projectId: "proj-9" });
check("a credential field works with no decoding", resolveUserPath(blobCred, "accountId")?.value === "acct-123");
check("a second credential field works", resolveUserPath(blobCred, "projectId")?.value === "proj-9");
check("a decoded credential field works", resolveUserPath(cred({ machineID: jwt({ sub: "machine-7" }) }), "machineID:sub")?.value === "machine-7");
check("a numeric field is usable as an identity", resolveUserPath(cred({ projectId: 12345 }), "projectId")?.value === "12345");

// A whole-token comparison: "access" with no level2.
check('"access" alone compares the whole token', resolveUserPath(jwtCred, "access")?.value === jwtCred.access);

// Non-resolution, which must fall through rather than throw.
check("an absent field does not resolve", resolveUserPath(jwtCred, "nope") === undefined);
check("a claim absent from the token does not resolve", resolveUserPath(jwtCred, "access:missing") === undefined);
check("a claim path into a plain string does not resolve", resolveUserPath(cred({ access: "opaque" }), "access:email") === undefined);
check("a structured value cannot be an identity directly", resolveUserPath(cred({ access: { email: "x@y.z" } }), "access") === undefined);

// ---------------------------------------------------------------------------
// 4. detectIdentity — best effort when nothing is configured
// ---------------------------------------------------------------------------

check("an email claim is detected", detectIdentity(jwtCred)?.value === "jery99961@gmail.com");
check("preferred_username is used when email is absent", detectIdentity(cred({ access: jwt({ preferred_username: "pref@x.y" }) }))?.value === "pref@x.y");
check("sub is used when no name is present", detectIdentity(cred({ access: jwt({ sub: "subject-1" }) }))?.value === "subject-1");
check("an opaque token falls back to accountId", detectIdentity(cred({ access: "opaque", accountId: "acct-9" }))?.value === "acct-9");
check("projectId is used when accountId is absent", detectIdentity(cred({ access: "opaque", projectId: "proj-9" }))?.value === "proj-9");
check("nothing detectable yields undefined", detectIdentity(cred({ access: "opaque" })) === undefined);
check("identityLabel is undefined for a missing credential", identityLabel(undefined) === undefined);
check("identityLabel names a credential", identityLabel(jwtCred) === "jery99961@gmail.com");

// ---------------------------------------------------------------------------
// The regression: attribution must follow the credential, not the caller
// ---------------------------------------------------------------------------

console.log("\n--- regression: the credential decides, not the active pointer ---");

// Pool: slot A and slot B, active = B. pi holds A's credential — what a /login
// for A produces while the saved active still says B.
const pool = [slot("jery99961", credA()), slot("22btrca061", credB())];
const liveIsA = credA("2fa78665-new"); // A, refreshed by pi

const attributed = attributeCredential({
	credential: liveIsA,
	states: pool,
	activeName: "22btrca061",
	expectedName: "22btrca061", // the caller believes it is B — it is NOT
	installedByUs: true,
});

check("attribution returns a match", attributed.kind === "match", `got ${attributed.kind}`);
check(
	"attribution picks slot jery99961 (the credential's real owner)",
	attributed.kind === "match" && attributed.name === "jery99961",
	`got ${attributed.kind === "match" ? attributed.name : attributed.kind}`,
);
check(
	"attribution does NOT pick the active slot 22btrca061 — this is the bug",
	!(attributed.kind === "match" && attributed.name === "22btrca061"),
);
check("the match is explained by the email claim", attributed.kind === "match" && attributed.via === "access:email");
check("the match is not merely an exact refresh-token hit", attributed.kind === "match" && attributed.exact === false);

// The same routing must hold when the caller passes no expectation at all,
// which is the capture-before-leaving path.
const noExpectation = attributeCredential({
	credential: liveIsA,
	states: pool,
	activeName: "22btrca061",
	expectedName: undefined,
	installedByUs: true,
});
check("attribution works with no expectation given", noExpectation.kind === "match" && noExpectation.name === "jery99961");

// And the reverse direction must be symmetric.
const liveIsB = credB("fa5cfd2c-new");
const reverse = attributeCredential({
	credential: liveIsB,
	states: pool,
	activeName: "22btrca061",
	expectedName: "jery99961",
	installedByUs: true,
});
check("the reverse case routes to 22btrca061", reverse.kind === "match" && reverse.name === "22btrca061");

console.log("\n--- regression: the tripwire refuses a cross-account write ---");

// Even if attribution were somehow bypassed, the tripwire must stop the write:
// the live credential is A's, the target slot holds B's.
const trip = checkTripwire({ target: slot("22btrca061", credB()), credential: liveIsA });
check("a cross-account write is refused", trip.ok === false, trip.ok ? "allowed" : "");
check("the refusal names both accounts", /jery99961@gmail\.com/.test(trip.reason ?? "") && /22btrca061@jainuniversity\.ac\.in/.test(trip.reason ?? ""), trip.reason);
check("the refusal explains the source of each value", /via/.test(trip.reason ?? ""));

// Same account: the ordinary write-back must NOT be blocked.
const sameAccount = checkTripwire({ target: slot("22btrca061", credB()), credential: credB("fa5cfd2c-rotated") });
check("a same-account write-back is allowed", sameAccount.ok === true, sameAccount.ok ? "" : sameAccount.reason);
check(
	"a rotated REFRESH token alone does not trip the wire",
	checkTripwire({ target: slot("22btrca061", credB("old")), credential: credB("brand-new") }).ok === true,
);
check(
	"a rotated ACCESS token alone does not trip the wire",
	checkTripwire({ target: slot("x", cred({ access: jwt(CLINE_CLAIMS_B), refresh: "r", expires: 1 })), credential: credB("fa5cfd2c-old") }).ok === true,
);
check("an empty target slot is never a conflict", checkTripwire({ target: slot("x", undefined), credential: liveIsA }).ok === true);
check(
	"an unprovable pair is allowed rather than blocking every opaque provider",
	checkTripwire({ target: slot("x", cred({ access: "opaque-a" })), credential: cred({ access: "opaque-b" }) }).ok === true,
);
check(
	"an identityPath does not weaken the tripwire",
	checkTripwire({ target: slot("22btrca061", credB()), credential: liveIsA, identityPath: "access:email" }).ok === false,
);

// ---------------------------------------------------------------------------
// 5. attribution — the remaining signal orders and outcomes
// ---------------------------------------------------------------------------

console.log("\n--- attribution: signal order and outcomes ---");

// Exact refresh equality matches an opaque credential nothing else can identify.
const opaquePool = [slot("a", cred({ access: "opaque-a", refresh: "R-A" })), slot("b", cred({ access: "opaque-b", refresh: "R-B" }))];
const byRefresh = attributeCredential({
	credential: cred({ access: "opaque-a", refresh: "R-A" }),
	states: opaquePool,
	activeName: "b",
	expectedName: "b",
	installedByUs: true,
});
check("an opaque credential matches by exact refresh token", byRefresh.kind === "match" && byRefresh.name === "a");
check("such a match is flagged exact", byRefresh.kind === "match" && byRefresh.exact === true);

// The user's identityPath outranks automatic detection: here the emails differ
// from the field the user names, so the user's answer must win.
const conflicting = [slot("slot-1", cred({ access: jwt({ email: "one@x.y", sub: "s1" }), refresh: "R1", accountId: "acct-X" }))];
const userPath = attributeCredential({
	credential: cred({ access: jwt({ email: "other@x.y", sub: "s2" }), refresh: "R2", accountId: "acct-X" }),
	states: conflicting,
	activeName: "slot-1",
	expectedName: "slot-1",
	installedByUs: true,
	identityPath: "accountId",
});
check("the user's identityPath is tried before detection", userPath.kind === "match" && userPath.name === "slot-1");
check("and is reported as the user's path", userPath.kind === "match" && userPath.source === "user-path");

// `/keyrouter add` must find the account by identity even when pi refreshed
// the access and refresh tokens. The configured path is authoritative.
const sameAccountDifferentTokens = attributeCredential({
	credential: cred({ accountId: "acct-123", access: "new-access", refresh: "new-refresh" }),
	states: [{ name: "same-account", credential: cred({ accountId: "acct-123", access: "old-access", refresh: "old-refresh" }) }],
	activeName: undefined,
	expectedName: undefined,
	installedByUs: false,
	identityPath: "accountId",
});
check(
	"a unique configured identity match survives token rotation",
	sameAccountDifferentTokens.kind === "match" && sameAccountDifferentTokens.name === "same-account",
);
check(
	"the configured identity match is attributed to the user's path",
	sameAccountDifferentTokens.kind === "match" && sameAccountDifferentTokens.source === "user-path",
);

// Two slots sharing an identity, with nothing to separate them.
const twins = [slot("twin-a", cred({ access: jwt({ email: "same@x.y" }), refresh: "RA" })), slot("twin-b", cred({ access: jwt({ email: "same@x.y" }), refresh: "RB" }))];
const ambiguous = attributeCredential({
	credential: cred({ access: jwt({ email: "same@x.y" }), refresh: "RC" }),
	states: twins,
	activeName: "twin-a",
	expectedName: "twin-a",
	installedByUs: true,
});
check("two slots sharing an identity are reported ambiguous", ambiguous.kind === "ambiguous", `got ${ambiguous.kind}`);
check("both candidates are named", ambiguous.kind === "ambiguous" && ambiguous.names.join(",") === "twin-a,twin-b");
check(
	"ambiguity refuses rather than guessing one",
	!(ambiguous.kind === "match"),
);

// Ambiguity must be resolved by a later, sharper signal when one exists.
const twinsResolvable = [slot("twin-a", cred({ access: jwt({ email: "same@x.y" }), refresh: "RA" })), slot("twin-b", cred({ access: jwt({ email: "same@x.y" }), refresh: "RB" }))];
const resolved = attributeCredential({
	credential: cred({ access: jwt({ email: "same@x.y" }), refresh: "RB" }),
	states: twinsResolvable,
	activeName: "twin-a",
	expectedName: "twin-a",
	installedByUs: true,
});
check("a distinguishing refresh token resolves the ambiguity", resolved.kind === "match" && resolved.name === "twin-b");

// The active pointer is the last resort, and only when it is provably right.
const fallback = attributeCredential({
	credential: cred({ access: "opaque", refresh: "R-new" }),
	states: [slot("b", cred({ access: "opaque-b", refresh: "R-old" }))],
	activeName: "b",
	expectedName: "b",
	installedByUs: true,
});
check("the active pointer is used when keyrouter installed the credential", fallback.kind === "active-fallback", `got ${fallback.kind}`);
check("the fallback names the active slot", fallback.kind === "active-fallback" && fallback.name === "b");

// The guard: WITHOUT install tracking, that same case must refuse. This is the
// difference between the fix and the bug for providers with opaque credentials.
const unguarded = attributeCredential({
	credential: cred({ access: "opaque", refresh: "R-new" }),
	states: [slot("b", cred({ access: "opaque-b", refresh: "R-old" }))],
	activeName: "b",
	expectedName: "b",
	installedByUs: false,
});
check("the fallback is refused when keyrouter did not install it", unguarded.kind === "none", `got ${unguarded.kind}`);
check("and the refusal says why", /not installed by keyrouter/.test(unguarded.kind === "none" ? unguarded.reason : ""), unguarded.kind === "none" ? unguarded.reason : "");

// A pointer naming a different slot than the caller's expectation is not a licence to guess.
const mismatchedPointer = attributeCredential({
	credential: cred({ access: "opaque", refresh: "R-new" }),
	states: [slot("a", cred({ access: "opaque-a", refresh: "R-a" })), slot("b", cred({ access: "opaque-b", refresh: "R-b" }))],
	activeName: "a",
	expectedName: "b",
	installedByUs: true,
});
check("a pointer naming another slot does not authorise the write", mismatchedPointer.kind === "none", `got ${mismatchedPointer.kind}`);

// An empty pool cannot be written to at all.
const emptyPool = attributeCredential({
	credential: liveIsA,
	states: [],
	activeName: undefined,
	expectedName: undefined,
	installedByUs: true,
});
check("an empty pool yields no target", emptyPool.kind === "none");

// ---------------------------------------------------------------------------
// 6. The corruption, replayed against a real config file
//
// Proves the whole point end to end at the unit level: given the incident's
// state, the slot that must be written is A's, and B's credential survives.
// ---------------------------------------------------------------------------

console.log("\n--- replay: the incident's own numbers ---");

const replayDir = mkdtempSync(join(tmpdir(), "kr-identity-"));
try {
	// The pool as it was: four sound accounts, plus slot 22btrca061 last.
	const poolConfig = {
		providers: [
			{
				name: "cline",
				accounts: [
					{ name: "jery99961", credential: credA() },
					{ name: "jsjery123", credential: cred({ access: jwt({ email: "jsjery123@gmail.com" }), refresh: "r-js", expires: 1 }) },
					{ name: "jery2005may", credential: cred({ access: jwt({ email: "jery2005may@gmail.com" }), refresh: "r-j2", expires: 1 }) },
					{ name: "jeryharryvm", credential: cred({ access: jwt({ email: "jeryharryvm@gmail.com" }), refresh: "r-jh", expires: 1 }) },
					{ name: "22btrca061", credential: credB() },
				],
				active: "22btrca061",
			},
		],
	};
	const file = join(replayDir, "keyrouter.json");
	writeFileSync(file, `${JSON.stringify(poolConfig, null, 2)}\n`, "utf-8");

	const states = poolConfig.providers[0].accounts.map((a) => slot(a.name, a.credential));
	const live = credA("2fa78665"); // pi holds jery99961's refreshed pair

	const where = attributeCredential({
		credential: live,
		states,
		activeName: "22btrca061",
		expectedName: "22btrca061",
		installedByUs: true,
	});
	check("replay: the refreshed credential routes to jery99961", where.kind === "match" && where.name === "jery99961", `got ${where.kind === "match" ? where.name : where.kind}`);
	check(
		"replay: 22btrca061 is left holding its own account",
		checkTripwire({ target: slot("22btrca061", credB()), credential: live }).ok === false,
	);

	// And the outcome the bug produced, stated as what must NOT happen.
	const wouldHaveBeen = { ...poolConfig.providers[0].accounts[4], credential: live };
	const wouldHaveIdentity = detectIdentity(wouldHaveBeen.credential)?.value;
	check(
		"replay: stamping it onto 22btrca061 would have made the slot claim jery99961's login",
		wouldHaveIdentity === "jery99961@gmail.com" && wouldHaveBeen.name === "22btrca061",
	);
} finally {
	rmSync(replayDir, { recursive: true, force: true });
}

console.log(`\n${checks - failures}/${checks} identity checks pass`);
if (failures > 0) process.exit(1);