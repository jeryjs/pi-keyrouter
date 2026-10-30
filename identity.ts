// =============================================================================
// identity.ts — decide WHICH pool account a credential belongs to
// =============================================================================
//
// WHY THIS EXISTS
//
// keyrouter writes pi's refreshed credential back into a pool slot. The original
// implementation assumed that slot was "the active one", and that assumption is
// wrong the moment pi's store holds a credential keyrouter did not install — for
// instance after the user runs /login for account A while the persisted `active`
// still names slot B.
//
// The consequence is silent and destructive: A's refresh is written into B, so B
// is aliased onto A and B's own login is orphaned. B's refresh token is then
// stale, and the next time the pool reaches B it fails with invalid_grant even
// though nothing was wrong with it. Two of five accounts were lost this way
// before the cause was found.
//
// So attribution is a SEARCH, not an assumption.
//
// =============================================================================
// `identityPath` — the user's override
// =============================================================================
//
// OAuth credentials do not agree on where an account's identity lives. Rather
// than guess and hope, the user may name it:
//
//     "identityPath": "level1:level2"
//
// `level1`  a key of the credential object (`access`, `refresh`, `accountId`, or
//           a dotted path for a nested field).
// `level2`  a path into `level1`'s value AFTER it has been decoded. Optional:
//           with no colon, `level1`'s own value is compared as-is, which is the
//           "compare the refresh token and nothing else" case.
//
// The decoding of `level1` is automatic and best-effort, because a credential can
// carry JSON, a JWT, a base64-wrapped blob, or nothing encoded at all:
//
//     "refresh"                 compare the refresh token; no decoding
//     "access:email"            decode `access`, read its `email`
//     "access:user.email"       decode `access`, read a nested claim
//     "accountId:sub"           decode `accountId`, read its `sub`
//     "projectId"               compare `projectId` directly
//
// Decoding is ordered JWT -> JSON -> base64-wrapped-JSON and STOPS at the first
// form that yields structure. Two consequences worth knowing:
//
//   - A plain string that merely happens to be base64-decodable is NOT decoded.
//     Most opaque tokens are base64-ish, and decoding one would produce mojibake
//     that would then be reported as an "identity". Only a decode that produces
//     real JSON is accepted.
//   - JSON itself is only attempted on a value that starts with `{` or `[`, so a
//     bare token can never be misread as JSON.
//
// =============================================================================
// Signal order (descending)
// =============================================================================
//
//   1. the user's `identityPath`      authoritative; beats every guess
//   2. exact refresh-token equality   exact, works on opaque credentials
//   3. a claim decoded from a token field
//   4. a known per-account field on the blob
//   5. the `active` pointer           only when provably the right slot
//
// 2 is tried after 3 and 4 rather than before them because a refresh token loses
// its identity once it rotates: Cline does not rotate refresh tokens, but RFC 9700
// providers generally do, which makes exact equality the least STABLE signal, not
// the least reliable one.

import type { KeyState, OAuthCredential } from "./types.ts";

/** Where an identity value came from. Reported so a decision can be explained. */
export type IdentitySource =
	| "user-path" // the `identityPath` the user configured
	| "refresh-token" // exact refresh-token equality
	| "token-claim" // a claim decoded out of a token field
	| "credential-field"; // a field on the credential blob itself

export interface Identity {
	/** The identifying value. */
	value: string;
	source: IdentitySource;
	/**
	 * The path this value came from, expressed so it can be fed straight back to
	 * `resolveUserPath` — `"refresh"`, `"access:email"` or `"accountId"`. That
	 * makes the pool side of a comparison use the identical lookup, so the two
	 * sides can never be read by different rules.
	 */
	via: string;
}

// -----------------------------------------------------------------------------
// Decoding
// -----------------------------------------------------------------------------

/** String fields that may hold an encoded payload, most likely first. */
const DECODED_FIELDS = ["access", "id_token"];

/**
 * Identity keys searched inside a decoded payload, most specific first.
 *
 * A human-facing name comes first because it is what the user would recognise,
 * then the stable subject, then provider-specific account fields.
 */
const CLAIM_KEYS = [
	"email",
	"preferred_username",
	"upn",
	"sub",
	"accountId",
	"userID",
	"machineID",
	"clientId",
	"projectId",
];

/** Credential fields that name an account directly, with no decoding. */
const BLOB_PATHS = ["accountId", "projectId", "userID", "machineID", "clientId"];

/** True when a decoded string is sane text rather than binary. */
function isText(value: string): boolean {
	if (value.length === 0) return false;
	if (value.includes("\uFFFD")) return false;
	for (const ch of value) {
		const code = ch.codePointAt(0) ?? 0;
		// Control characters (other than tab/newline/CR) mean this was binary.
		if (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) return false;
		if (code === 0x7f) return false;
	}
	return true;
}

function tryJson(text: string): unknown {
	const trimmed = text.trim();
	// Guarded so a bare token can never be misread as JSON.
	if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return undefined;
	try {
		return JSON.parse(trimmed) as unknown;
	} catch {
		return undefined;
	}
}

function tryJwt(text: string): unknown {
	if (text.split(".").length !== 3) return undefined;
	try {
		const payload = Buffer.from(text.split(".")[1] ?? "", "base64url").toString("utf-8");
		if (!isText(payload)) return undefined;
		const parsed = tryJson(payload);
		return typeof parsed === "object" && parsed !== null ? parsed : undefined;
	} catch {
		return undefined;
	}
}

/**
 * Accept a base64 payload ONLY when it decodes to JSON.
 *
 * Deliberately strict. Most opaque tokens are base64-ish, so a permissive decode
 * would turn a perfectly good token into mojibake and then report that mojibake as
 * the account's identity. Requiring real JSON on the far side means the only
 * values ever reinterpreted are ones that were genuinely encoded structure.
 */
function tryBase64Json(text: string): unknown {
	try {
		const decoded = Buffer.from(text, "base64url").toString("utf-8");
		if (!isText(decoded)) return undefined;
		return tryJson(decoded);
	} catch {
		return undefined;
	}
}

/**
 * Peel one layer of encoding off a value.
 *
 * Non-strings are returned unchanged — a credential field that is already an
 * object needs no decoding, and one that is a number or boolean is a scalar
 * identity in its own right.
 */
export function decodeValue(value: unknown): unknown {
	if (typeof value !== "string") return value;
	const text = value.trim();
	if (!text) return value;
	return tryJwt(text) ?? tryJson(text) ?? tryBase64Json(text) ?? value;
}

/** Read a dotted path out of an object or array. Undefined if any step is absent. */
function readPath(root: unknown, dotted: string): unknown {
	let node: unknown = root;
	for (const part of dotted.split(".")) {
		if (typeof node !== "object" || node === null) return undefined;
		node = (node as Record<string, unknown>)[part];
	}
	return node;
}

/** Normalize a candidate identity. Rejects values too weak to identify anything. */
function normalize(value: unknown): string | undefined {
	if (typeof value === "string") {
		const trimmed = value.trim();
		return trimmed.length > 0 ? trimmed : undefined;
	}
	if (typeof value === "number" && Number.isFinite(value)) return String(value);
	return undefined;
}

// -----------------------------------------------------------------------------
// Resolving a path
// -----------------------------------------------------------------------------

/**
 * Check an `identityPath` for obvious malformation, at config load.
 *
 * Only structurally impossible forms are rejected here. Whether a path actually
 * resolves depends on a credential that may not exist yet, so that check happens
 * at use time and falls through with a warning.
 */
export function validateIdentityPath(value: unknown): { ok: true; path: string } | { ok: false; reason: string } {
	if (typeof value !== "string") return { ok: false, reason: "must be a string" };
	const spec = value.trim();
	if (!spec) return { ok: false, reason: "must not be empty" };
	const colon = spec.indexOf(":");
	if (colon === 0) return { ok: false, reason: `"${spec}": nothing before the colon` };
	if (colon === spec.length - 1) return { ok: false, reason: `"${spec}": nothing after the colon` };
	return { ok: true, path: spec };
}

/**
 * Resolve an `identityPath` against one credential.
 *
 * Returns undefined when the path does not resolve on this credential — an
 * absent field, an opaque token with no claims, or a claim that is not there.
 * The caller reports that once and then falls through to the built-in signals.
 */
export function resolveUserPath(credential: OAuthCredential, identityPath: string): Identity | undefined {
	const spec = identityPath.trim();
	if (!spec) return undefined;

	const colon = spec.indexOf(":");
	const level1 = colon === -1 ? spec : spec.slice(0, colon).trim();
	const level2 = colon === -1 ? undefined : spec.slice(colon + 1).trim();
	if (!level1) return undefined;

	const raw = readPath(credential, level1);
	if (raw === undefined) return undefined;

	// No `level2`: compare the field's own value. This is "compare the refresh
	// token and nothing else", and equally "compare the accountId directly".
	if (level2 === undefined || level2 === "") {
		// A structured value cannot be compared as an identity; only a scalar can.
		if (typeof raw === "object" && raw !== null) return undefined;
		const value = normalize(raw);
		if (!value) return undefined;
		return { value, source: level1 === "refresh" ? "refresh-token" : "credential-field", via: level1 };
	}

	const decoded = decodeValue(raw);
	if (decoded === undefined) return undefined;
	const found = normalize(readPath(decoded, level2));
	if (!found) return undefined;
	// A decoded string that became structure is a claim; anything else was a
	// plain nested field.
	const source: IdentitySource = typeof raw === "string" && decoded !== raw ? "token-claim" : "credential-field";
	return { value: found, source, via: spec };
}

/** Read one credential's identity through a given path. */
function identityVia(credential: OAuthCredential, via: string): string | undefined {
	return resolveUserPath(credential, via)?.value;
}

// -----------------------------------------------------------------------------
// Automatic detection
// -----------------------------------------------------------------------------

/**
 * The best identity obtainable with no configuration at all.
 *
 * Decoded token fields are checked before blob fields because a claim names the
 * authentication subject directly, whereas a blob field can be a coarser or
 * shared value — a GCP `projectId`, for instance, may cover more than one login,
 * which is why an ambiguous match is treated as a distinct outcome rather than a
 * silent win.
 */
export function detectIdentity(credential: OAuthCredential): Identity | undefined {
	for (const field of DECODED_FIELDS) {
		const raw = credential[field];
		if (typeof raw !== "string" || !raw) continue;
		const payload = decodeValue(raw);
		if (typeof payload !== "object" || payload === null) continue;
		for (const key of CLAIM_KEYS) {
			const value = normalize(readPath(payload, key));
			if (value) return { value, source: "token-claim", via: `${field}:${key}` };
		}
	}
	for (const path of BLOB_PATHS) {
		const value = normalize(readPath(credential, path));
		if (value) return { value, source: "credential-field", via: path };
	}
	return undefined;
}

/** A short human-readable label for a credential, for state and messages. */
export function identityLabel(credential: OAuthCredential | undefined): string | undefined {
	if (!credential) return undefined;
	return detectIdentity(credential)?.value;
}

// -----------------------------------------------------------------------------
// Attribution
// -----------------------------------------------------------------------------

/** Candidate identities for a credential, strongest first. */
function candidates(credential: OAuthCredential, identityPath?: string): Identity[] {
	const list: Identity[] = [];
	if (identityPath) {
		const fromUser = resolveUserPath(credential, identityPath);
		if (fromUser) list.push({ ...fromUser, source: "user-path" });
	}
	const auto = detectIdentity(credential);
	if (auto) list.push(auto);
	// Last: exact equality, which needs no interpretation at all.
	const refresh = normalize(credential.refresh);
	if (refresh) list.push({ value: refresh, source: "refresh-token", via: "refresh" });
	return list;
}

export type Attribution =
	| {
			kind: "match";
			index: number;
			name: string | undefined;
			via: string;
			source: IdentitySource;
			/** True when the match came from exact refresh-token equality. */
			exact: boolean;
	  }
	| {
			kind: "ambiguous";
			indexes: number[];
			names: string[];
			value: string;
			via: string;
	  }
	| { kind: "active-fallback"; index: number; name: string | undefined }
	| { kind: "none"; reason: string };

/**
 * Decide which pool slot a live credential belongs to.
 *
 * `expectedName` is the slot the caller believes the credential came from (the
 * entry it is capturing into). It is used ONLY to validate the final fallback — it
 * never short-circuits the search, because trusting the caller's belief is the
 * original bug.
 */
export function attributeCredential(args: {
	credential: OAuthCredential;
	states: ReadonlyArray<Pick<KeyState, "name" | "credential">>;
	activeName: string | undefined;
	expectedName: string | undefined;
	/** True when keyrouter itself installed the credential currently in pi. */
	installedByUs: boolean;
	identityPath?: string | undefined;
}): Attribution {
	const { credential, states, activeName, expectedName, installedByUs, identityPath } = args;

	let ambiguous: Attribution | undefined;

	for (const candidate of candidates(credential, identityPath)) {
		const matching: number[] = [];
		states.forEach((state, index) => {
			if (!state.credential) return;
			if (identityVia(state.credential, candidate.via) === candidate.value) matching.push(index);
		});

		if (matching.length === 1) {
			const index = matching[0] as number;
			return {
				kind: "match",
				index,
				name: states[index]?.name,
				via: candidate.via,
				source: candidate.source,
				exact: candidate.source === "refresh-token",
			};
		}
		if (matching.length > 1 && !ambiguous) {
			// More than one slot shares this value — two logins to the same account,
			// or a coarse field such as a shared projectId. Remember it and keep
			// going: a later candidate (usually the refresh token) may separate them.
			ambiguous = {
				kind: "ambiguous",
				indexes: matching,
				names: matching.map((i) => states[i]?.name ?? "?"),
				value: candidate.value,
				via: candidate.via,
			};
		}
	}

	if (ambiguous) return ambiguous;

	// No identity matched. Falling back to the active pointer is safe only when
	// BOTH hold:
	//   - the pointer names the very slot being written, so this is not a guess
	//     about some other slot, and
	//   - keyrouter installed the credential currently in pi, so the pointer and
	//     the live credential describe the same thing.
	// Without the second condition, a credential the user installed by hand would
	// be stamped onto whatever slot happened to be marked active.
	if (activeName !== undefined && expectedName !== undefined && activeName === expectedName && installedByUs) {
		const index = states.findIndex((s) => s.name === activeName);
		if (index >= 0) return { kind: "active-fallback", index, name: activeName };
	}

	if (!installedByUs) {
		return {
			kind: "none",
			reason: "no identifying field resolved, and pi's credential was not installed by keyrouter",
		};
	}
	if (expectedName === undefined) {
		return { kind: "none", reason: "no identifying field resolved, and no slot was named to fall back to" };
	}
	return {
		kind: "none",
		reason: `no identifying field resolved, and the active slot does not name ${expectedName}`,
	};
}

/**
 * Refuse to overwrite a slot that holds a DIFFERENT account.
 *
 * The last line of defence. Even if attribution picks a slot, a mismatch between
 * what is already stored there and what is about to be written means one of the
 * two would be destroyed — and it is the stored one that holds an unrecoverable
 * refresh token. Refusing leaves the file consistent and makes the problem loud,
 * which is strictly better than silently aliasing two accounts.
 *
 * Only stable identifiers are compared. The refresh token is deliberately NOT
 * used: it rotates on refresh, so including it would make every legitimate write
 * look like a conflict.
 */
export function checkTripwire(args: {
	target: KeyState;
	credential: OAuthCredential;
	identityPath?: string | undefined;
}): { ok: true } | { ok: false; reason: string } {
	const { target, credential, identityPath } = args;
	// An empty slot cannot be clobbered.
	if (!target.credential) return { ok: true };

	const pick = (from: OAuthCredential): Identity | undefined => {
		if (identityPath) {
			const byPath = resolveUserPath(from, identityPath);
			if (byPath) return byPath;
		}
		return detectIdentity(from);
	};

	const incoming = pick(credential);
	const existing = pick(target.credential);

	// Unprovable is not the same as safe to assume. When either side carries no
	// stable identity there is nothing to compare, so the write proceeds — the
	// alternative would block every provider whose credentials are opaque.
	if (!incoming || !existing) return { ok: true };
	if (incoming.value === existing.value) return { ok: true };

	return {
		ok: false,
		reason: `slot "${target.name}" holds ${existing.value} (via ${existing.via}), but the live credential is ${incoming.value} (via ${incoming.via})`,
	};
}