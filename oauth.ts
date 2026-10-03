// =============================================================================
// oauth.ts — install/capture OAuth credentials through pi's credential store
// =============================================================================
//
// keyrouter does NOT implement any part of OAuth. pi owns the flow, the storage,
// the refresh schedule and `/login`. This module only *copies blobs* between a
// pool entry and pi's credential store, so the pool can hold accounts 2..N —
// something pi cannot express, because `auth.json` is
// `Record<providerId, Credential>` with exactly one credential per provider id.
//
// Why not the runtime api_key overlay?
//   `RuntimeCredentials.setRuntimeApiKey` stores a *string*, and pi's resolver
//   returns early on any override. For an OAuth-only provider that means the
//   request resolves to NO auth at all; for a dual-auth provider it means the
//   OAuth credential is frozen out and pi never refreshes it. Verified in
//   test/verify-runtime-credentials.mjs against pi 1.0.0 (openai-codex: with an
//   overlay, `getAuth()` returns undefined while `getProviderAuthStatus()` still
//   cheerfully says source=runtime).
//
// Why go through `modify` rather than writing auth.json with fs?
//   pi's AuthStorage serializes writes with a lockfile, does a whole-file
//   read-modify-write, and caches parsed data in a shared `readState` keyed by
//   the file's revision. Writing the file out of band can clobber a concurrent
//   login and will not be seen by that cache. `modify` keeps all of it coherent.

import { readStoredCredential } from "@earendil-works/pi-coding-agent";
import type { OAuthCredential } from "./types.ts";

export type { OAuthCredential };

/**
 * The subset of pi's credential store that keyrouter uses.
 *
 * Structurally typed on purpose: pi does not export `CredentialStore` from the
 * package root, and the extension must not depend on an unexported class
 * identity. If a future pi renames or reshapes these, the capability check in
 * `credentialStore()` degrades keyrouter to inert instead of crashing it.
 */
export interface CredentialStoreApi {
	read(providerId: string, options?: { signal?: AbortSignal }): Promise<unknown>;
	modify(
		providerId: string,
		fn: (current: unknown) => Promise<unknown>,
		options?: { signal?: AbortSignal },
	): Promise<unknown>;
}

/**
 * Reach pi's live credential store through the `ModelRegistry` facade.
 *
 * `ModelRegistry` is a "synchronous compatibility facade" and deliberately does
 * not expose credentials; the underlying `ModelRuntime` holds them in a plain
 * `runtime` field, and `RuntimeCredentials.modify` delegates to the real store.
 * Capability-checked so a build that moves these fields leaves keyrouter inert
 * with one warning rather than breaking startup.
 */
export function credentialStore(registry: unknown): CredentialStoreApi | undefined {
	const runtime = (registry as { runtime?: { credentials?: Partial<CredentialStoreApi> } } | undefined)
		?.runtime;
	const store = runtime?.credentials;
	if (!store || typeof store.modify !== "function" || typeof store.read !== "function") {
		return undefined;
	}
	return store as CredentialStoreApi;
}

/** True when a value looks like a usable stored OAuth credential. */
export function isOAuthCredential(value: unknown): value is OAuthCredential {
	if (typeof value !== "object" || value === null) return false;
	const candidate = value as Record<string, unknown>;
	return (
		candidate["type"] === "oauth" &&
		typeof candidate["access"] === "string" &&
		candidate["access"].length > 0 &&
		typeof candidate["refresh"] === "string" &&
		typeof candidate["expires"] === "number"
	);
}

/**
 * Install a credential blob. Returns false instead of throwing so callers can
 * degrade to inert on a read-only store or a synchronization failure.
 *
 * `modify` returning the object is what writes it; returning `undefined` would
 * mean "no change", which is why the callback ignores `current` entirely.
 */
export async function installCredential(
	store: CredentialStoreApi,
	providerId: string,
	credential: OAuthCredential,
): Promise<{ ok: true } | { ok: false; error: string }> {
	try {
		await store.modify(providerId, async () => credential);
		return { ok: true };
	} catch (error) {
		return { ok: false, error: error instanceof Error ? error.message : String(error) };
	}
}

/**
 * Read the live credential back, so pi's refreshed tokens are not lost.
 *
 * pi rotates refresh tokens in place, so the copy in the pool must be updated
 * whenever we leave an account. Otherwise returning to it later would install a
 * consumed refresh token and fail — burning an account that was perfectly fine.
 */
export async function captureCredential(
	store: CredentialStoreApi,
	providerId: string,
): Promise<OAuthCredential | undefined> {
	try {
		const current = await store.read(providerId);
		return isOAuthCredential(current) ? current : undefined;
	} catch {
		return undefined;
	}
}

/**
 * True when a stored OAuth login exists for this provider.
 *
 * Uses pi's own `readStoredCredential` so auth.json parsing and location stay
 * pi's business. Reads only — never writes.
 */
export function hasStoredOAuthLogin(providerId: string): boolean {
	try {
		return readStoredCredential(providerId)?.type === "oauth";
	} catch {
		// Unreadable auth.json is pi's problem, not ours: treat as no login.
		return false;
	}
}

/**
 * Remove a runtime api_key overlay so it cannot shadow the OAuth credential.
 *
 * A leftover override from an earlier API-key configuration is the one way an
 * OAuth pool could silently break: on an OAuth-only provider it makes auth
 * resolve to nothing, and on a dual-auth provider it freezes the token. The
 * runtime API is passed in rather than imported so this module stays testable.
 */
export async function clearOverlay(
	removeRuntimeApiKey: ((providerId: string) => Promise<void>) | undefined,
	providerId: string,
): Promise<void> {
	if (!removeRuntimeApiKey) return;
	try {
		await removeRuntimeApiKey(providerId);
	} catch {
		// Best effort: nothing persisted means nothing corrupted.
	}
}