// =============================================================================
// types.ts — shared types for pi-keyrouter
// =============================================================================

/** A single API key entry. `name` is for logging; `value` is the literal key. */
export interface ApiKey {
	name: string;
	value: string;
}

/**
 * A stored OAuth credential, kept deliberately OPAQUE.
 *
 * keyrouter never reads inside this object beyond the three fields pi's
 * `resolveStoredOAuth` requires. The installed providers each carry their own
 * extra fields — github-copilot has `availableModelIds`, openai-codex has
 * `accountId`, kiro has `clientId`/`clientSecret`/`region`, qoder has
 * `machineID`/`userID` — so inspecting the blob would break at least one of
 * them. The index signature is what keeps provider-specific fields alive
 * through a JSON round trip.
 */
export interface OAuthCredential {
	type: "oauth";
	access: string;
	refresh: string;
	/** Epoch ms. pi refreshes when fewer than ~5 minutes remain. */
	expires: number;
	[key: string]: unknown;
}

/** A named account in an OAuth pool. */
export interface AccountEntry {
	name: string;
	credential?: OAuthCredential;
}

/** Which mechanism a pool uses. Both kinds share the rotation machinery. */
export type PoolKind = "keys" | "oauth";

/** Configuration for a single provider. */
export interface ProviderConfig {
	/** Provider id pi uses: built-in (`google`), a `models.json` id, or another
	 *  extension's id. Matched case-insensitively against pi's known providers. */
	name: string;
	/** Legacy field, accepted and ignored. Rotation is keyed by provider id, not URL. */
	match?: string[];
	/** API-key pool. Mutually exclusive with `accounts`. */
	keys?: ApiKey[];
	/** OAuth account pool. Mutually exclusive with `keys`. */
	accounts?: AccountEntry[];
	/** Derived from which of `keys`/`accounts` was present. */
	kind: PoolKind;
	/**
	 * Inject pooled API keys even when the user has a stored OAuth login for this
	 * provider. Off by default: a runtime api_key shadows the OAuth credential.
	 * Meaningless for `accounts` pools, which install into the credential store.
	 */
	takeoverOAuth?: boolean;
	/**
	 * Rotate on account-level quota/billing errors. Default true for `accounts`
	 * pools. Ignored for `keys` pools, where a quota error is an account-wide
	 * limit that switching keys cannot lift.
	 */
	rotateOnQuota?: boolean;
}

/** Top-level config. */
export interface KeyRouterConfig {
	providers: ProviderConfig[];
	/** Max number of retries across all keys per request. Default 3. */
	maxRetries: number;
	/** How long a key is marked bad after 429 (ms). Default 60_000. */
	cooldownMs: number;
	/** How long to mark the provider as overloaded after a 529/overloaded
	 *  error (ms). Provider-wide — all keys of this provider share the
	 *  same deadline. Not counted as a key failure. Default 30_000. */
	overloadedCooldownMs: number;
	/** Human-readable notes from loading (dropped accounts, ignored fields).
	 *  Not read from disk; produced by `normalize` and reported once. */
	warnings?: string[];
}

/** Last status observed for a pool entry. */
export type KeyStatus =
	| "ok"
	| "rate-limited"
	| "unauthorized"
	| "quota"
	| "refresh-failed"
	| "untried";

/** Internal state for a pool entry (not user-configurable). */
export interface KeyState {
	name: string;
	/** API-key pools: the key. OAuth pools: always "" (never read). */
	value: string;
	/** OAuth pools only — the opaque blob currently held for this entry. */
	credential?: OAuthCredential;
	/** Last status we saw from this entry. */
	lastStatus: KeyStatus;
	/** Epoch ms when this entry's bad-status expires. 0 = available. */
	cooldownUntil: number;
	/** Epoch ms when the provider's overload state expires for this entry.
	 *  0 = not overloaded. Provider-wide: set on ALL entries together when
	 *  any one of them gets an overloaded response. Not a failure. */
	overloadedUntil: number;
	/** How many times this entry has been used (for diagnostics). */
	uses: number;
	/** How many times this entry has returned a rotatable failure. */
	failures: number;
}

/** Reason we rotated to a new pool entry. */
export type RotationReason = "rate-limited" | "unauthorized" | "quota" | "refresh-failed";

/** Reason we observed a provider-level event. Overloaded does NOT cause
 *  rotation — only an overload cooldown on every entry of that provider. */
export type ProviderEventReason = RotationReason | "overloaded";

/** Event payload for `onRotate` callback. */
export interface RotationEvent {
	provider: string;
	fromKey: string;
	toKey: string;
	reason: RotationReason;
	status: number;
	attempt: number;
}