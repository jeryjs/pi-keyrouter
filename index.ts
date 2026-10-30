// =============================================================================
// index.ts — pi-keyrouter extension entry point (native runtime key injection)
// =============================================================================
//
// HOW IT WORKS (native integration, no fetch hacks, no custom providers):
//
// 1. pi makes a request with the current API key
// 2. Provider returns 429 (rate-limited) or 401/403 (unauthorized)
// 3. `message_end` fires with the assistant error message
// 4. We set the next pooled key as a *runtime* credential override for that
//    provider id (pi's `ModelRuntime.setRuntimeApiKey`)
// 5. pi's BUILT-IN retry logic kicks in → next attempt uses the new key
// 6. Repeat until a key succeeds or we exhaust our key pool
//
// keyrouter NEVER registers a provider. It only writes into pi's runtime
// credential overlay for provider ids that already exist — built-in providers,
// `models.json` providers, and providers registered by other extensions such as
// cx-providers. pi owns everything below that: auth resolution, refresh,
// headers, `/login`, OAuth, retries.
//
// The overlay is what `pi --api-key` uses (`main.js`), and it wins over
// auth.json and env vars because `RuntimeCredentials.read()` short-circuits the
// store when an override exists. It is NOT persisted, so clearing it restores
// whatever the user had configured.
//
// Providers whose auth has no api-key method (OAuth/subscription-only, e.g. a
// ChatGPT/Claude Pro login) are left completely alone: injecting an api_key
// there would shadow the stored OAuth credential and fail the request.
//
// Usage:
//   pi install npm:pi-keyrouter      # or: pi -e <path-to-this-folder>
//   # create ~/.pi/keyrouter.json with your provider keys
//   /reload

import { readStoredCredential } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI, ExtensionContext, ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import { appendFileSync, existsSync } from "node:fs";
import {
	loadConfig,
	configPath,
	writeBackCredentials,
	writeBackActive,
	writeBackNotifications,
	writeBackStrategy,
	writeBackPoolEntry,
	uniquePoolEntryName,
	normalizeStrategy,
	STRATEGIES,
} from "./config.ts";
import {
	notifyRotation,
	notifyOverloaded,
	notifyExhausted,
	notifyOAuthUnsupported,
	rotationIsNotifiable,
} from "./notification.ts";
import {
	captureCredential,
	clearOverlay,
	credentialStore,
	installCredential,
	isOAuthCredential,
	type CredentialStoreApi,
} from "./oauth.ts";
import {
	attributeCredential,
	checkTripwire,
	detectIdentity,
	identityLabel,
	resolveUserPath,
} from "./identity.ts";
import {
	claimLease,
	leaseOwner,
	leasedByOthers,
	releaseLease,
	releaseOwnLeases,
} from "./lease.ts";
import {
	initAccountStates,
	initKeyStates,
	isAvailable,
	markBad,
	markOk,
	markOverloaded,
	pickNextKey,
	pickStrategyNext,
	recordUse,
} from "./rotation.ts";
import type {
	AccountEntry,
	KeyRouterConfig,
	KeyState,
	NotificationLevel,
	OAuthCredential,
	PoolKind,
	ProviderConfig as ProviderPoolConfig,
	RotationEvent,
	RotationReason,
	RotationStrategy,
} from "./types.ts";
/**
 * Optional trace sink. Set `PI_KEYROUTER_TRACE=/path/to/log` to record pool
 * decisions (key NAMES only, never values) for debugging or headless runs where
 * `ui.notify` has no terminal to print to.
 */
const tracePath = process.env["PI_KEYROUTER_TRACE"] || undefined;

/**
 * TEMPORARY/INTERNAL: the session-start sweep is disabled by default for testing.
 * `PI_KEYROUTER_SWEEP=1` is the only opt-in. This flag must not be documented
 * publicly and should be removed once the sweep is safe to run again.
 */
export function startupSweepEnabled(env?: Record<string, string | undefined>): boolean {
	return env?.["PI_KEYROUTER_SWEEP"] === "1";
}

/**
 * `ui.notify` before a UI context exists is a silent no-op, so a warning raised during
 * bootstrap has to be queued. `deepEqual` is its own exported helper.
 *
 * Same-credential captures are suppressed entirely. pi refreshes lazily, so a capture
 * fires on every rotation attempt, and without this the queue would fill with repeats
 * of one refusal and bury the first one — which is the only one that matters, because
 * it is the one that names which account was nearly overwritten.
 */
function warn(ui: ExtensionUIContext | undefined, queue: string[], message: string, kind: "warning" | "error" | "info" = "warning"): void {
	if (ui) {
		ui.notify(message, kind);
		return;
	}
	if (queue.length === 0 || queue[queue.length - 1] !== message) queue.push(message);
}

function trace(message: string): void {
	if (!tracePath) return;
	try {
		appendFileSync(tracePath, `${new Date().toISOString()} ${message}\n`, "utf8");
	} catch {
		// tracing must never break a request
	}
}

/** Regex matching overloaded-style errors. Covers Anthropic 429 + "overloaded",
 *  standard HTTP 529, and "service overloaded" variants. Case-insensitive. */
const OVERLOADED_RE = /\boverloaded\b|\b529\b/i;

/** Regex matching rate-limit style errors (entry-specific failures). */
const RATE_LIMITED_RE = /\b429\b|rate.?limit|too many requests/i;

/** Regex matching auth errors (entry-specific failures). */
const UNAUTHORIZED_RE = /\b40[13]\b|unauthorized|forbidden|invalid_api_key/i;

/**
 * Account-level limit / billing errors.
 *
 * For an API-key pool these are NOT rotatable: every key belongs to the same
 * account, so switching keys cannot lift an account-wide limit.
 *
 * For an OAuth pool they ARE rotatable by default (`rotateOnQuota`): each
 * account is a separate subscription, so this is exactly the case where the
 * next account is wanted. pi marks these non-retryable, so the rotation only
 * takes effect through the settle-time continuation.
 */
const QUOTA_RE = /quota exceeded|insufficient_quota|usage limit|available balance|out of budget|billing|subscription_sharing_usage_limit_exceeded/i;

/**
 * Dead-credential errors: a refresh token that can never be redeemed.
 *
 * pi surfaces these as `OAuth refresh failed for <provider>: ...` (pinned by
 * test/oauth-fixture-smoke.mjs). Only meaningful for OAuth pools — the
 * credential itself is unusable, so the account must be rotated away from.
 */
const REFRESH_FAILED_RE = /OAuth refresh failed|re-?authenticate|invalid_grant|token has been revoked|refresh token/i;
/**
 * pi's runtime credential overlay, reached through the `ModelRegistry` facade.
 *
 * NOT part of the public extension API: `ModelRegistry` is documented as a
 * "synchronous compatibility facade" and deliberately does not expose
 * `setRuntimeApiKey`/`removeRuntimeApiKey` (they live on `ModelRuntime`, which
 * is what `pi --api-key` uses internally). The facade stores its runtime in a
 * plain `runtime` field, so we read it here and capability-check before use.
 * If a future pi removes the field, keyrouter degrades to inert with one clear
 * warning instead of crashing pi on startup.
 */
interface RuntimeCredentialApi {
	setRuntimeApiKey(providerId: string, apiKey: string): Promise<void>;
	removeRuntimeApiKey(providerId: string): Promise<void>;
}

function runtimeCredentials(
	registry: ExtensionContext["modelRegistry"],
): RuntimeCredentialApi | undefined {
	const candidate = (registry as unknown as { runtime?: Partial<RuntimeCredentialApi> }).runtime;
	if (
		!candidate ||
		typeof candidate.setRuntimeApiKey !== "function" ||
		typeof candidate.removeRuntimeApiKey !== "function"
	) {
		return undefined;
	}
	return candidate as RuntimeCredentialApi;
}

interface ProviderRuntime {
	/** Provider id as pi knows it (the credential-overlay key). */
	providerId: string;
	/**
	 * The provider name exactly as written in keyrouter.json. Needed to find the
	 * config entry again when writing a refreshed credential back: the resolved id
	 * may be a canonicalized form (`z-ai` -> `zai`) and the config file is never
	 * rewritten to match it.
	 */
	configName: string;
	/** Which mechanism this pool uses. `keys` = string overlay, `oauth` = store. */
	kind: PoolKind;
	/**
	 * OAuth pools: rotate on account-level quota/billing errors. Always false for
	 * keys pools, where a quota error is account-wide and switching cannot lift it.
	 */
	rotateOnQuota: boolean;
	/** How the next entry is picked at each turn boundary (per-pool setting). */
	strategy: RotationStrategy;
	/** Entries for both kinds: the shared rotation machinery operates on these. */
	keys: KeyState[];
	/**
	 * Index of the entry currently in effect.
	 * - keys pool:  the index installed in the runtime overlay.
	 * - oauth pool: the index installed in pi's credential store.
	 * -1 = none set yet.
	 */
	currentIndex: number;
	/** Index this session bootstraps from: the pool's `active` entry, else 0. */
	resumeIndex: number;
	/**
	 * True once we have written into pi for this provider.
	 * - keys pool:  an override is installed (needs removing on shutdown).
	 * - oauth pool: a pool account is installed in the credential store.
	 */
	injecting: boolean;
	/**
	 * Where this provider's account identity lives, from the config's
	 * `identityPath`. Unset means "use the built-in detection".
	 */
	identityPath?: string | undefined;
	/**
	 * Set after a rotation that no request has used yet. pi does not retry
	 * 401/403 (or quota/refresh failures), so `agent_before_settle` must ask for
	 * the one more request that makes the swap useful. Cleared when consumed.
	 */
	pendingContinue: boolean;
	/**
	 * Continuations already requested since this provider last succeeded.
	 * Bounds the settle-time retry: a pool whose entries are all bad would
	 * otherwise keep cycling through `pickNextKey`'s soonest-available branch.
	 * Reset by any non-error assistant response.
	 */
	continuations: number;
	/**
	 * The pool entry this process holds a lease on (-1 = none).
	 *
	 * A lease is an exclusive claim on one entry, visible to other pi processes
	 * through the lease directory, so two processes sharing a pool do not pile
	 * onto the same credential. Only API-key pools use it: pi's OAuth store
	 * holds ONE credential per provider id, shared by every process, so there
	 * is no slot to lease there.
	 */
	claimed: number;
	/**
	 * Pool entries serving an in-flight provider request in THIS process,
	 * oldest first.
	 *
	 * A request holds its entry for as long as it runs, so a rotation never
	 * walks onto a credential that is already serving one. Released when the
	 * response arrives, and cleared at the turn boundary as a backstop.
	 */
	busy: number[];
}

/** Hidden custom-message type used to request the extra retry turn. */
const CONTINUATION_CUSTOM_TYPE = "pi-keyrouter.retry";

export default function keyRouterExtension(pi: ExtensionAPI): void {
	let config: KeyRouterConfig | undefined;
	const runtimes = new Map<string, ProviderRuntime>();
	/** Api-key overlays we set in THIS process; cleared on shutdown. */
	const injected = new Set<string>();
	/** OAuth pools that installed an account in THIS process. */
	const installedAccounts = new Set<string>();
	/**
	 * Providers with a startup-sweep refresh exchange in flight. Consulted by
	 * `advanceForStrategy` so a turn-boundary swap never installs an account
	 * whose refresh the sweep is mid-way through — see `sweepIdleAccounts`.
	 */
	const sweepingProviders = new Set<string>();
	let uiCtx: ExtensionUIContext | undefined;
	/** Providers whose config error we have already reported once. */
	const skipReported = new Set<string>();
	/**
	 * Warnings raised before a UI context exists.
	 *
	 * An OAuth pool bootstraps during `before_agent_start`, which runs BEFORE `ui.notify`
	 * is usable — `uiCtx` is only assigned later in that same function. Anything warned
	 * during bootstrap was therefore discarded, and the identity refusals below happen at
	 * exactly that moment. Buffering them and flushing once the UI is ready is the
	 * difference between a loud refusal and a silent one.
	 */
	const earlyWarnings: string[] = [];
	/** Providers that can never be managed (OAuth-only): stop re-checking. */
	const permanentSkip = new Set<string>();
	let activationNotified = false;
	let credentialApi: RuntimeCredentialApi | undefined;
	let credentialApiChecked = false;
	/** pi's credential store (OAuth pools). Probed once, like the overlay API. */
	let storeApi: CredentialStoreApi | undefined;
	let storeApiChecked = false;
	let lastErrorNotified = false;
	/** Config warnings are reported once per config load. */
	let warningsReported = false;
	let persistNotifyErrorNotified = false;
	// `identityConflictNotified` was removed: refusals are now collapsed by `warn`,
	// which suppresses a repeat of the immediately preceding message. A single
	// boolean could only ever report the first refusal across ALL providers, so a
	// second provider's problem was silently swallowed.
	/** Providers whose configured `identityPath` did not resolve, reported once each. */
	const identityPathReported = new Set<string>();

	/**
	 * Get-or-create the runtime for a provider, keyed by the real provider id.
	 * Both pool kinds produce the same shape, so every downstream branch is on
	 * `kind`, never on which config field was present.
	 */
	function ensureRuntime(providerId: string, providerCfg: ProviderPoolConfig): ProviderRuntime {
		let rt = runtimes.get(providerId);
		if (rt) return rt;
		rt = {
			providerId,
			// The name as the user wrote it. Persisting a refreshed credential has to
			// find the config entry by this, because `resolveProviderId` may have
			// canonicalized it (`z-ai` -> `zai`) and the config is never rewritten to
			// the canonical form.
			configName: providerCfg.name,
			// Only a `accounts` pool can carry one, and only it can use one.
			identityPath: providerCfg.identityPath,
			kind: providerCfg.kind,
			// Only meaningful for OAuth pools; false for keys pools by construction.
			rotateOnQuota: providerCfg.kind === "oauth" && providerCfg.rotateOnQuota !== false,
			strategy: providerCfg.strategy ?? "failover",
			keys:
				providerCfg.kind === "oauth"
					? initAccountStates(providerCfg.accounts ?? [])
					: initKeyStates(providerCfg.keys ?? []),
			currentIndex: -1,
			// Resume where the last session left off. Kept apart from `currentIndex`
			// because that field's -1 is the "nothing installed yet" sentinel
			// `activate` tests before bootstrapping.
			resumeIndex: Math.max(
				0,
				(providerCfg.keys ?? providerCfg.accounts ?? []).findIndex(
					(entry) => entry.name === providerCfg.active,
				),
			),
			injecting: false,
			pendingContinue: false,
			continuations: 0,
			claimed: -1,
			busy: [],
		};
		runtimes.set(providerId, rt);
		return rt;
	}

	/** One-time capability probe, with a single actionable warning. */
	function credentialsApi(
		registry: ExtensionContext["modelRegistry"],
		ui: ExtensionUIContext,
	): RuntimeCredentialApi | undefined {
		if (credentialApiChecked) return credentialApi;
		credentialApiChecked = true;
		credentialApi = runtimeCredentials(registry);
		if (!credentialApi) {
			ui.notify(
				"🔑 keyrouter: this pi build does not expose runtime credential " +
					"overrides to extensions — keyrouter is inert and provider auth is untouched.",
				"warning",
			);
		}
		return credentialApi;
	}

	/**
	 * One-time capability probe for pi's credential store, used by OAuth pools.
	 * Separate from the overlay probe: a build could expose one and not the
	 * other, and OAuth pools must stay inert without affecting API-key pools.
	 */
	function credentialsStore(
		registry: ExtensionContext["modelRegistry"],
		ui: ExtensionUIContext,
	): CredentialStoreApi | undefined {
		if (storeApiChecked) return storeApi;
		storeApiChecked = true;
		storeApi = credentialStore(registry);
		if (!storeApi) {
			notifyOAuthUnsupported(ui, "its credential store is not reachable through the model registry");
		}
		return storeApi;
	}

	/**
	 * Why keyrouter cannot manage this provider, or undefined when it can.
	 * `oauth`, `oauth-login` and `oauth-unsupported` are permanent for the
	 * session; `missing` is retried on later turns because another extension may
	 * register the provider after us.
	 *
	 * The two pool kinds have DIFFERENT requirements, and conflating them is the
	 * single easiest way to break this extension:
	 *   - a `keys` pool needs `auth.apiKey`, because it installs an api_key;
	 *   - an `oauth` pool needs `auth.oauth`, and must NOT require `auth.apiKey`
	 *     (the OAuth-only providers, e.g. openai-codex, are precisely the ones
	 *     whose accounts are worth pooling).
	 */
	function skipReason(
		registry: ExtensionContext["modelRegistry"],
		providerId: string,
		pool: ProviderPoolConfig,
	): "missing" | "oauth" | "oauth-login" | "oauth-unsupported" | undefined {
		const provider = registry.getProvider(providerId);
		if (!provider) return "missing";

		if (pool.kind === "oauth") {
			// The provider must understand OAuth credentials for an installed blob to
			// resolve at all.
			return provider.auth?.oauth ? undefined : "oauth-unsupported";
		}

		// OAuth/subscription-only providers have no apiKey auth method; an injected
		// api_key credential would be dropped by pi's resolver and fail the request.
		if (!provider.auth?.apiKey) return "oauth";
		// A provider can accept both. Injecting a runtime key shadows whatever is
		// stored, including a signed-in OAuth token, so leave logins alone unless
		// the pool explicitly opts in with `takeoverOAuth`.
		if (pool.takeoverOAuth !== true && storedCredentialIsOAuth(providerId)) return "oauth-login";
		return undefined;
	}


	/**
	 * True when the user has an OAuth credential stored for this provider.
	 * Uses pi's own `readStoredCredential` so auth.json parsing and location
	 * stay pi's business.
	 */
	function storedCredentialIsOAuth(providerId: string): boolean {
		try {
			return readStoredCredential(providerId)?.type === "oauth";
		} catch {
			// Unreadable auth.json is pi's problem, not ours: treat as no login.
			return false;
		}
	}

	function reportSkip(
		providerId: string,
		reason: "missing" | "oauth" | "oauth-login" | "oauth-unsupported",
	): void {
		if (skipReported.has(providerId)) return;
		skipReported.add(providerId);
		const detail =
			reason === "missing"
				? "provider not registered"
				: reason === "oauth"
					? "OAuth/subscription-only, no api-key auth"
					: reason === "oauth-unsupported"
						? "provider has no OAuth auth method"
						: "using a stored OAuth login";
		trace(`skip ${providerId} (${detail})`);
		const text =
			reason === "missing"
				? `🔑 keyrouter: provider "${providerId}" is not registered — check the name in ${configPath()}.`
				: reason === "oauth"
					? `🔑 keyrouter: "${providerId}" is OAuth/subscription-only — leaving it on pi's own login.`
					: reason === "oauth-unsupported"
						? `🔑 keyrouter: "${providerId}" has no OAuth auth method, so an account pool cannot be installed — leaving it alone.`
						: `🔑 keyrouter: "${providerId}" has a stored OAuth login — keeping it. Set "takeoverOAuth": true on the pool to use pooled keys instead.`;
		if (uiCtx) uiCtx.notify(text, reason === "missing" ? "warning" : "info");
	}

	/** Write a pooled key into pi's runtime overlay. Never throws. */
	async function applyKey(
		providerId: string,
		key: string,
		ctx: ExtensionContext,
	): Promise<boolean> {
		if (!credentialApi) return false;
		try {
			await credentialApi.setRuntimeApiKey(providerId, key);
			injected.add(providerId);
			const rt = runtimes.get(providerId);
			if (rt) rt.injecting = true;
			return true;
		} catch (error) {
			const detail = error instanceof Error ? error.message : String(error);
			if (!lastErrorNotified) {
				lastErrorNotified = true;
				ctx.ui.notify(`🔑 keyrouter: setRuntimeApiKey(${providerId}) failed — ${detail}`, "error");
			}
			return false;
		}
	}

	/** Drop our override so pi falls back to auth.json / env / OAuth. */
	async function clearKey(providerId: string): Promise<void> {
		if (!credentialApi) return;
		try {
			await credentialApi.removeRuntimeApiKey(providerId);
			trace(`clear ${providerId} (override removed)`);
		} catch {
			// Best effort: nothing persisted means nothing corrupted.
		}
		injected.delete(providerId);
		const rt = runtimes.get(providerId);
		if (rt) rt.injecting = false;
	}

	// -----------------------------------------------------------------------
	// Leases: an exclusive claim on one entry of a pool.
	// -----------------------------------------------------------------------

	/**
	 * The pool entries that must not be picked right now: the ones serving an
	 * in-flight request in this process, plus the ones another live pi process
	 * has leased.
	 *
	 * The cross-process half is read from the lease directory, so it is only
	 * consulted for API-key pools — pi's OAuth credential store holds a single
	 * credential per provider id that every process shares, so an OAuth entry
	 * cannot be leased away from another process.
	 */
	function leasedIndices(rt: ProviderRuntime): ReadonlySet<number> {
		const leased = new Set<number>(rt.busy);
		if (rt.kind === "keys") {
			for (const index of leasedByOthers(rt.providerId, rt.keys.length)) leased.add(index);
		}
		return leased;
	}

	/**
	 * Move this process's lease onto the entry it just installed.
	 *
	 * The claim is what keeps another pi process off the same credential. A
	 * claim that cannot be taken (another process got there first) is not
	 * fatal: the entry is still usable, so the request goes out and the next
	 * pick prefers a different entry.
	 */
	function takeLease(rt: ProviderRuntime, index: number): void {
		if (rt.kind !== "keys" || index < 0) return;
		if (rt.claimed >= 0 && rt.claimed !== index) releaseLease(rt.providerId, rt.claimed);
		rt.claimed = claimLease(rt.providerId, index) ? index : -1;
		if (rt.claimed < 0) trace(`lease ${rt.providerId} entry ${index} (held by another process)`);
	}

	/**
	 * Drop every claim this process holds.
	 *
	 * Called when the pools are handed back to pi (reset, reload, shutdown):
	 * the entries are no longer in use, so another process may take them.
	 */
	function releaseLeases(): void {
		for (const rt of runtimes.values()) {
			releaseLease(rt.providerId, rt.claimed);
			rt.claimed = -1;
		}
	}

	// -----------------------------------------------------------------------
	// OAuth pools: install / capture / restore through pi's credential store.
	// keyrouter NEVER refreshes a token — pi owns refresh, and these helpers
	// only copy blobs in and out of the store.
	// -----------------------------------------------------------------------

	/**
	 * Install a pool account into pi's credential store.
	 * Returns false (never throws) so a read-only store degrades instead of
	 * failing a turn. One warning per process, like the overlay API.
	 */
	async function applyAccount(
		providerId: string,
		entry: KeyState,
		ctx: ExtensionContext,
	): Promise<boolean> {
		if (!storeApi) return false;
		const credential = entry.credential;
		if (!credential) {
			trace(`oauth skip ${providerId} ${entry.name} (no credential in pool entry)`);
			return false;
		}
		const result = await installCredential(storeApi, providerId, credential);
		if (!result.ok) {
			trace(`oauth install failed ${providerId} ${entry.name} (${result.error})`);
			if (!lastErrorNotified) {
				lastErrorNotified = true;
				ctx.ui.notify(
					`🔑 keyrouter: cannot write the credential store for ${providerId} — ${result.error}. ` +
						`OAuth pools are inert; API-key pools are unaffected.`,
					"error",
				);
			}
			return false;
		}
		installedAccounts.add(providerId);
		const rt = runtimes.get(providerId);
		if (rt) rt.injecting = true;
		return true;
	}

	/**
	 * Read the live credential back into the pool, writing it to whichever slot the
	 * credential actually belongs to.
	 *
	 * pi rotates tokens in place, so a stale pool copy would install a consumed
	 * refresh token on a later return to that account — burning an account that was
	 * perfectly healthy. This is why capture happens both before swapping away and
	 * after installing.
	 *
	 * `entry` is the slot the CALLER BELIEVES owns this credential. It is used only
	 * to validate the last-resort fallback, never to short-circuit attribution:
	 * assuming the caller is right is what corrupted two accounts. When pi's store
	 * holds a credential keyrouter did not install — after `/login` for account A
	 * while the saved `active` still names slot B — writing to `entry` aliases B
	 * onto A and orphans B's refresh token, which is unrecoverable.
	 *
	 * IMPORTANT: capturing into memory is not enough on its own. pi refreshes a
	 * credential in place, but when keyrouter later installs a DIFFERENT account it
	 * overwrites what pi stored — so the refreshed pair only survives if it is
	 * written back to the config. Without that, a return to this account would
	 * present the access token from its last login (~1h of life) and look dead.
	 */
	/**
	 * Read the live credential back into the pool, writing it to whichever slot the
	 * credential actually belongs to.
	 *
	 * pi rotates tokens in place, so a stale pool copy would install a consumed
	 * refresh token on a later return to that account — burning an account that was
	 * perfectly healthy. This is why capture happens both before swapping away and
	 * after installing.
	 *
	 * `entry` is the slot the CALLER BELIEVES owns this credential. Its identity is
	 * consulted FIRST, because the caller is right in every ordinary case (pi can only
	 * hand back what was installed), while the attribution search exists for the case
	 * where it is NOT — a `/login` under a stale `active` slot. Preference, not
	 * assumption: the caller's slot is used only when the credential's own identity
	 * agrees it belongs there.
	 *
	 * IMPORTANT: capturing into memory is not enough on its own. pi refreshes a
	 * credential in place, but when keyrouter later installs a DIFFERENT account it
	 * overwrites what pi stored — so the refreshed pair only survives if it is
	 * written back to the config. Without that, a return to this account would
	 * present the access token from its last login (~1h of life) and look dead.
	 */
	async function captureAccount(
		rt: ProviderRuntime,
		entry: KeyState | undefined,
		persist = true,
	): Promise<void> {
		if (!storeApi) return;
		const live = await captureCredential(storeApi, rt.providerId);
		if (!live) return;

		// A configured `identityPath` that resolves nowhere is almost always a typo.
		// Report it once, then let the built-in detection take over: a typo must not
		// stop refreshes from being persisted.
		if (rt.identityPath && !identityPathReported.has(rt.providerId)) {
			const path = rt.identityPath;
			const resolves =
				resolveUserPath(live, path) !== undefined ||
				rt.keys.some((k) => k.credential !== undefined && resolveUserPath(k.credential, path) !== undefined);
			if (!resolves) {
				identityPathReported.add(rt.providerId);
				trace(`identityPath unresolved ${rt.providerId} "${path}"`);
				warn(
					uiCtx,
					earlyWarnings,
					`🔑 keyrouter: identityPath "${path}" does not resolve for ${rt.providerId}. ` +
						"Falling back to automatic detection — check the field name and the claim path.",
				);
			}
		}

		// ── Which slot does this credential belong to? ───────────────────────────
		//
		// The order below is the fix for two separate failures:
		//
		//   1. The slot pi installed, when the credential's identity agrees it belongs
		//      there. The ordinary case, and it must win.
		//   2. Any slot the identity matches, for a credential pi holds that keyrouter
		//      never installed.
		//   3. The active pointer, only when provably the right slot.
		//
		// NOT trying step 1 first is what killed a healthy account. Every rotation
		// captured the just-refreshed credential, an identity match sent it to a
		// DIFFERENT slot, the source slot kept its expired token, the tripwire refused
		// the foreign write, and nothing was persisted at all — so the account looked
		// dead on the next lap and the pool looped forever. Preferring the installed
		// slot records an ordinary refresh while still refusing to write one account's
		// credential into another's.
		const liveIdentity =
			detectIdentity(live) ?? (rt.identityPath ? resolveUserPath(live, rt.identityPath) : undefined);
		const entryIdentity = entry?.credential
			? (detectIdentity(entry.credential) ??
				(rt.identityPath ? resolveUserPath(entry.credential, rt.identityPath) : undefined))
			: undefined;
		let target: KeyState;
		let via: string;

		// 1. The slot pi installed, when the credential's identity agrees it belongs
		//    there. Inlined rather than pre-computed as a boolean so the compiler can
		//    see `entry` is defined on this branch.
		if (
			entry !== undefined &&
			installedAccounts.has(rt.providerId) &&
			(liveIdentity === undefined || entryIdentity === undefined || liveIdentity.value === entryIdentity.value)
		) {
			target = entry;
			via = "installed";
		} else {
			// 2 and 3: a credential pi holds that keyrouter did not install. Find it
			// by identity, and only then fall back to the active pointer.
			const attribution = attributeCredential({
				credential: live,
				states: rt.keys,
				activeName: rt.keys[rt.currentIndex]?.name,
				expectedName: entry?.name,
				installedByUs: installedAccounts.has(rt.providerId),
				identityPath: rt.identityPath,
			});
			const picked =
				attribution.kind === "match" || attribution.kind === "active-fallback"
					? rt.keys[attribution.index]
					: undefined;
			if (!picked) {
				const where =
					attribution.kind === "ambiguous"
						? `ambiguous: ${attribution.names.join(", ")} share ${attribution.via}=${attribution.value}`
						: attribution.kind === "none"
							? attribution.reason
							: "no attributable slot";
				// Ambiguity is surfaced because a write was actively declined to avoid
				// hitting the wrong login. A plain non-match is ordinary bookkeeping —
				// it happens on every capture before pi holds anything usable.
				trace(`identity skip ${rt.providerId} (${where})`);
				if (attribution.kind === "ambiguous") {
					warn(
						uiCtx,
						earlyWarnings,
						`🔑 keyrouter: not saving a refreshed ${rt.providerId} credential — ${where}. ` +
							"Two pool accounts share that identity, so writing could overwrite the wrong one. " +
							"Nothing was written; set \"identityPath\" for this provider to tell them apart.",
					);
				}
				return;
			}
			target = picked;
			via = attribution.kind === "match" ? attribution.via : "active-fallback";
		}

		// Last line of defence: never overwrite a slot holding a DIFFERENT account.
		const tripwire = checkTripwire({ target, credential: live, identityPath: rt.identityPath });
		if (!tripwire.ok) {
			trace(`identity tripwire ${rt.providerId} (${tripwire.reason})`);
			warn(
				uiCtx,
				earlyWarnings,
				`🔑 keyrouter: refused to save a refreshed ${rt.providerId} credential — ${tripwire.reason}. ` +
					"Overwriting would have replaced that account's login. Nothing was written. " +
					"Run /keyrouter account ${rt.providerId} <name> to point the pool at what pi holds.",
			);
			return;
		}

		// Skip the write when nothing moved: most captures happen inside a single
		// token lifetime, and a no-op must never touch the user's config file.
		const changed = !target.credential || !sameCredential(target.credential, live);
		const moved = Boolean(entry) && entry !== target;
		target.credential = live;
		if (moved) {
			trace(`identity ${rt.providerId}: credential belongs to ${target.name}, not ${entry?.name} (${via})`);
		}
		if (persist && changed) persistCredential(rt, target.name, live);
	}

	/**
	 * Write a refreshed credential back into keyrouter.json.
	 *
	 * Best effort by design: persistence is an optimization, so a failure warns
	 * once and the session continues. The pool still holds the fresh value in
	 * memory for as long as keyrouter runs.
	 */
	function persistCredential(rt: ProviderRuntime, name: string, credential: KeyState["credential"]): void {
		if (!credential) return;
		const result = writeBackCredentials(
			new Map([[`${rt.configName}\u0000${name}`, credential]]),
		);
		if ("error" in result) {
			trace(`persist failed ${rt.providerId} ${name} (${result.error})`);
			if (!persistNotifyErrorNotified) {
				persistNotifyErrorNotified = true;
				uiCtx?.notify(
					`🔑 keyrouter: could not write refreshed credentials to ${configPath()} — ${result.error}. ` +
						`Refreshes still work this session; the fix is to restore the file's permissions.`,
					"warning",
				);
			}
			return;
		}
		if (result.updated > 0) trace(`persist ${rt.providerId} ${name} (refreshed credential written back)`);
	}

	/**
	 * Make an entry the active one, in memory and in the config.
	 *
	 * Every change of `currentIndex` goes through here, so no rotation path can
	 * forget to save the position: becoming active IS the save. Written at the
	 * mutation rather than at handler exit, so a session that dies mid-rotation
	 * still leaves the right position behind.
	 *
	 * Best effort, like the credential write-back: a failure warns once and
	 * rotation continues. Only the entry NAME is written, never a credential.
	 */
	function setActive(rt: ProviderRuntime, idx: number): void {
		rt.currentIndex = idx;
		const result = writeBackActive(rt.configName, idx >= 0 ? rt.keys[idx]?.name : undefined);
		if ("error" in result) {
			trace(`persist active failed ${rt.providerId} (${result.error})`);
			if (!persistNotifyErrorNotified) {
				persistNotifyErrorNotified = true;
				uiCtx?.notify(
					`🔑 keyrouter: could not save the active key to ${configPath()} — ${result.error}. ` +
						"Rotation still works; the next session will start at the first key.",
					"warning",
				);
			}
			return;
		}
		if (result.updated > 0) trace(`persist active ${rt.providerId} -> ${rt.keys[idx]?.name ?? "(none)"}`);
	}

	/**
	 * Leave the credential pi should carry into the next session.
	 *
	 * WHAT THIS REPLACES: the session-start credential used to be reinstalled here.
	 * That is only correct if pi's store still holds it — and it usually does not. pi
	 * rotates the access token in place during the session, a `/login` may have
	 * replaced the account entirely, and keyrouter has by now swapped the active
	 * account several times. Reinstalling a credential captured hours ago therefore
	 * put a STALE token back into `auth.json`, so the next session began by 403ing:
	 * the account looked dead before a single request could succeed. Removing the
	 * restore by itself would only invert the problem — leaving an account nobody
	 * asked for — so what replaces it is the credential pi should actually resume
	 * with: the pool's ACTIVE account, which is the account rotation last settled on
	 * and the one the saved `active` field names.
	 *
	 * The expiry guard matters as much as the choice of account. A pool can hold a
	 * login that is expired and whose refresh token is dead; installing one of those
	 * at shutdown recreates the original failure exactly. Leaving pi's current
	 * credential in place is strictly better — it is the one that was just working.
	 * A stale access token is fine here, because pi refreshes it from the refresh
	 * token, which Cline does not rotate.
	 */
	async function restoreSessionStartAccount(
		providerId: string,
		rt: ProviderRuntime,
	): Promise<void> {
		if (!storeApi) return;
		const active = rt.currentIndex >= 0 ? rt.keys[rt.currentIndex] : undefined;
		// Capture pi's live credential into the pool FIRST. Installing anything below
		// discards whatever pi holds now, and the pool's copy is what a later return to
		// this account will install — so an uncaptured refresh would be lost for good.
		await captureAccount(rt, active);
		// And record a `/login` the pool has not seen. Same reason: the install below
		// would otherwise overwrite a credential the user created by hand.
		await captureDrift(rt);

		// What pi holds right now is the freshest credential in existence for whichever
		// account it belongs to, so that is what the handover reports and installs. An
		// untouched snapshot of the ACTIVE account would be older by definition — pi
		// refreshes in place and may have switched accounts entirely — and the previous
		// implementation reinstalled the credential from SESSION START, which is how the
		// next session ended up 403ing against a token three hours past its expiry.
		const live = await captureCredential(storeApi, providerId);
		const purpose = "handing to the next session";

		// ── What is safe to leave installed? ────────────────────────────────────
		//
		// pi's current credential is the first choice, but it is only better than the
		// pool's if it can still WORK. When the whole pool is dead and pi's refresh
		// failed, pi's credential is an expired access token backed by a revoked refresh
		// token — and leaving that installed is precisely the "next session 403s before
		// it can do anything" failure this function exists to prevent. So it is tested
		// the same way the pool's copy is, and the pool's copy is the fallback rather
		// than being skipped.
		const viable = (credential: KeyState["credential"]): credential is NonNullable<KeyState["credential"]> =>
			credential !== undefined && credential.expires > Date.now();

		let chosen = live;
		let choice = live ? `pi's credential${identityLabel(live) ? ` for ${identityLabel(live)}` : ""}` : "";
		if (!viable(chosen) && viable(active?.credential)) {
			chosen = active.credential;
			choice = `active pool account ${active.name}`;
		}

		if (!viable(chosen)) {
			// Nothing can be handed over safely, so pi's store is left exactly as it is.
			// Rewriting it with a credential that cannot work would only look like a
			// successful handover while guaranteeing the next session starts broken.
			trace(
				`oauth keep ${providerId} (nothing viable for ${purpose}; ` +
					`pi's credential ${live ? "is expired" : "is absent"} and no pool account can replace it — leaving pi's store untouched)`
			);
			installedAccounts.delete(providerId);
			rt.injecting = false;
			return;
		}

		const remaining = chosen.expires - Date.now();
		const result = await installCredential(storeApi, providerId, chosen);
		if (result.ok) {
			trace(`oauth keep ${providerId} (${choice}, expires in ${Math.round(remaining / 60_000)}m)`);
		} else {
			trace(`oauth keep failed ${providerId} (${result.error})`);
		}
		installedAccounts.delete(providerId);
		rt.injecting = false;
	}

	/**
	 * Which of two credentials for the SAME account is the newer one.
	 *
	 * `expires` is the arbiter, because it is the only field that orders two
	 * credentials. Both secrets rotate, so neither can be compared for age: a
	 * different refresh token means a different LOGIN, not necessarily a newer one,
	 * and a different access token merely means one side refreshed.
	 *
	 * That distinction is what keeps a hand-edited config safe. "pi is always
	 * fresher" is nearly true and still wrong in both directions:
	 *
	 *   live.expires > stored.expires   pi is newer — a `/login`, or a refresh that
	 *                                   happened while keyrouter was not watching
	 *   stored.expires > live.expires   the POOL is newer — the user pasted fresh
	 *                                   credentials into keyrouter.json by hand, and
	 *                                   replacing them with pi's older copy would
	 *                                   destroy the only good credential there is
	 *   equal, different refresh        same age, different login: take pi's, since
	 *                                   pi's is the one actually in use
	 */
	function isNewer(incoming: KeyState["credential"], incumbent: KeyState["credential"]): boolean {
		if (!incoming) return false;
		if (!incumbent) return true;
		const a = typeof incoming.expires === "number" ? incoming.expires : 0;
		const b = typeof incumbent.expires === "number" ? incumbent.expires : 0;
		if (a !== b) return a > b;
		return incoming.refresh !== incumbent.refresh;
	}

	/**
	 * Notice that pi's stored credential is not the pool's copy for that account, and
	 * record pi's version.
	 *
	 * WHY THIS EXISTS: pi exposes no login, logout or credential-changed event, so a
	 * `/login` is invisible to an extension until something looks. Without this the
	 * pool keeps a stale copy and then does the worst possible thing with it — the
	 * next rotation installs that stale copy OVER the freshly logged-in one, because
	 * the pool's copy is what gets written to pi's store. The account then fails with
	 * invalid_grant despite having just been authenticated by hand.
	 *
	 * Only fires when the account's identity can be established. `captureAccount`
	 * refuses to guess where a credential belongs, and a `/login` produces exactly
	 * that situation — a credential keyrouter did not install — so a provider whose
	 * identity cannot be read cannot be tracked this way. Refusing is deliberate: the
	 * alternative is stamping it onto whichever slot looks active, which is what
	 * aliased two accounts in the first place.
	 */
	async function captureDrift(rt: ProviderRuntime): Promise<void> {
		if (!storeApi || rt.kind !== "oauth" || !installedAccounts.has(rt.providerId)) return;
		const live = await captureCredential(storeApi, rt.providerId);
		if (!live) return;
		const identity =
			detectIdentity(live) ?? (rt.identityPath ? resolveUserPath(live, rt.identityPath) : undefined);
		if (!identity) {
			// Not an error: nothing can be attributed, so nothing is touched.
			trace(`drift skip ${rt.providerId} (credential carries no readable identity)`);
			return;
		}
		const slot = rt.keys.find((k) => {
			if (!k.credential) return false;
			const other =
				detectIdentity(k.credential) ?? (rt.identityPath ? resolveUserPath(k.credential, rt.identityPath) : undefined);
			return other?.value === identity.value;
		});
		if (!slot) {
			// pi holds a login no pool slot represents. Capturing is the wrong response —
			// adding accounts is the user's decision — so say so once and leave the file
			// alone. Worth saying because the pool WILL overwrite this on the next
			// rotation, which is a silent loss otherwise.
			trace(`drift unknown ${rt.providerId} (pi holds ${identity.value}, no pool slot has it)`);
			warn(
				uiCtx,
				earlyWarnings,
				`🔑 keyrouter: pi is signed in as ${identity.value} for ${rt.providerId}, but no pool account has that identity. ` +
					"The pool will overwrite it on the next rotation. Add it as an account, or /login as a pooled one.",
			);
			return;
		}
		// Take pi's copy only when it is genuinely newer. `expires` decides that (see
		// `isNewer`), so a credential pasted into keyrouter.json by hand is left
		// alone rather than replaced by pi's older one.
		if (!isNewer(live, slot.credential)) return;
		// The tripwire still applies: an identity resolving to a slot whose stored
		// credential names a DIFFERENT account is refused rather than overwritten.
		const tripwire = checkTripwire({ target: slot, credential: live, identityPath: rt.identityPath });
		if (!tripwire.ok) {
			trace(`drift refused ${rt.providerId} (${tripwire.reason})`);
			return;
		}
		trace(`drift ${rt.providerId}: pi holds a newer credential for ${slot.name} (via ${identity.via})`);
		slot.credential = live;
		persistCredential(rt, slot.name, live);
	}

	/**
	 * Reconcile every OAuth pool against pi's store.
	 *
	 * Called BEFORE anything is installed, which is the only moment it can work. On
	 * `session_start` the bootstrap installs a pool credential over whatever pi had,
	 * so a check running afterwards finds keyrouter's own copy and has nothing to
	 * notice. What it is there to catch:
	 *
	 *   - a `/login` from a session that was force-killed, where no shutdown ran
	 *   - any credential change made outside a session, including pi's own rotation
	 *
	 * A no-op unless pi's credential is genuinely newer for the SAME account, so it
	 * neither churns the config nor overrides a hand-edited pool.
	 */
	async function reconcileCredentials(): Promise<void> {
		if (!storeApi) return;
		for (const rt of runtimes.values()) {
			if (rt.kind !== "oauth") continue;
			try {
				await captureDrift(rt);
			} catch (error) {
				trace(`drift error ${rt.providerId} (${error instanceof Error ? error.message : String(error)})`);
			}
		}
	}

	/**
	 * Perform the actual swap to a chosen entry, shared by failure rotation and
	 * strategy advancement so the two paths can never drift apart. The
	 * capture-before-leave → install → capture-after-install sequence is what
	 * keeps pool copies correct; it must stay identical everywhere it runs.
	 *
	 * Returns the entry that became active, or undefined when the install failed
	 * — in which case nothing was changed and the caller must not behave as if a
	 * rotation had happened.
	 */
	async function swapToEntry(
		rt: ProviderRuntime,
		idx: number,
		ctx: ExtensionContext,
	): Promise<KeyState | undefined> {
		const entry = rt.keys[idx];
		if (!entry) return undefined;
		if (rt.kind === "oauth") {
			// 1. Preserve whatever pi refreshed for the account we are leaving.
			await captureAccount(rt, rt.keys[rt.currentIndex]);
			// 2. Install the next account.
			if (!(await applyAccount(rt.providerId, entry, ctx))) return undefined;
			setActive(rt, idx);
			recordUse(entry);
			// 3. Read it back: pi may normalize or merge the blob, and this copy is
			//    what a later return to this account will install.
			await captureAccount(rt, entry);
		} else {
			if (!(await applyKey(rt.providerId, entry.value, ctx))) return undefined;
			setActive(rt, idx);
			recordUse(entry);
			// The entry is now the one this process uses: hold the lease on it.
			takeLease(rt, idx);
		}
		return entry;
	}

	/**
	 * Advance a pool to the entry its strategy picks for the coming turn.
	 *
	 * Runs at `before_agent_start` — pi's turn boundary, the only moment a swap
	 * is safe. Within a turn, every request must go out on the entry installed
	 * when that turn started; swapping mid-turn would churn credential installs
	 * under a live agent loop and split one logical unit of work across accounts.
	 * (pi's sessions run one request loop at a time — subagent turns happen
	 * while their parent is blocked in a tool call — so a turn boundary never
	 * coincides with an in-flight request of the same session.)
	 *
	 * Not a rotation: nothing failed, so there is no notification and no retry
	 * turn to request. The swap itself is exactly the failure path's, via
	 * `swapToEntry`. Cooldowns still bind — a strategy spreads load; it never
	 * walks the pool onto an entry known to be bad.
	 *
	 * Skipped while `pendingContinue` is set: a failure rotation is waiting for
	 * its retry to run on the entry it just installed, and advancing again would
	 * discard that choice before it was ever used. Also skipped while a
	 * startup-sweep refresh is in flight for the pool (`sweepingProviders`):
	 * installing a mid-refresh account would double-consume its refresh token
	 * on providers that rotate it.
	 */
	async function advanceForStrategy(ctx: ExtensionContext): Promise<void> {
		if (!config) return;
		const now = Date.now();
		for (const rt of runtimes.values()) {
			if (rt.strategy === "failover") continue;
			if (rt.currentIndex < 0 || rt.keys.length < 2) continue; // not bootstrapped / nothing to advance to
			if (rt.pendingContinue) continue;
			if (rt.kind === "oauth" && !storeApi) continue;
			if (sweepingProviders.has(rt.providerId)) {
				// A startup-sweep exchange is in flight for this pool; installing a
				// mid-refresh account would double-consume its refresh token on
				// rotating providers. One turn of delay is harmless.
				trace(`advance skip ${rt.providerId} (startup sweep in flight)`);
				continue;
			}
			const idx = pickStrategyNext(rt.keys, rt.currentIndex, rt.strategy, now, leasedIndices(rt));
			const entry = idx >= 0 ? rt.keys[idx] : undefined;
			if (!entry || idx === rt.currentIndex || !isAvailable(entry, now)) continue;
			const previousName = rt.keys[rt.currentIndex]?.name ?? "(none)";
			const swapped = await swapToEntry(rt, idx, ctx);
			if (!swapped) continue;
			trace(`advance ${rt.providerId} ${previousName} -> ${swapped.name} (${rt.strategy})`);
		}
	}

	/**
	 * Refresh the credentials of IDLE pool accounts at session start, so an
	 * account that has not served a request in weeks is not discovered dead
	 * mid-task.
	 *
	 * pi refreshes only the credential it holds, lazily, at request time. An
	 * account sitting unused in the pool never goes through that path, so its
	 * copy keeps an expired access token and an unexercised refresh token —
	 * whether that token still redeems weeks later is purely provider policy.
	 * This sweep is the fix for the pool's idle entries, and it uses pi's own
	 * refresh implementation (the provider's `oauth.refresh`, the same function
	 * pi's request path calls), so keyrouter still owns no part of OAuth.
	 *
	 * Mimics pi's request-path refresh exactly (pi-ai `auth/resolve.js`): same
	 * threshold (refresh when fewer than ~5 minutes of validity remain), same
	 * 15-second cap on the exchange, and the returned credential replaces the
	 * pool copy wholesale — pi's own refreshers rebuild the blob, and the
	 * config write-back merges it over the stored form, preserving
	 * provider-specific fields such as `accountId`.
	 *
	 * The ACTIVE account is skipped on purpose. pi owns it: it is refreshed at
	 * request time and captured when keyrouter leaves it. Sweeping its pool copy
	 * as well would race pi's own refresh of the same token — and for providers
	 * that rotate the refresh token on every exchange (openai-codex), the two
	 * exchanges would each consume the other's token.
	 *
	 * Non-blocking by design: fired without awaiting from `session_start`,
	 * because it only reads and writes the pool and `keyrouter.json` — never
	 * pi's credential store — so it cannot interfere with the first turn.
	 * It is serialized against strategy advancement per provider
	 * (`sweepingProviders`), so the two writers never target the same account.
	 *
	 * A failed exchange marks the entry exactly like a request-time refresh
	 * failure (status + cooldown) and says so once: reviving a dead login needs
	 * an interactive /login only the user can perform. Persistence follows the
	 * usual write-back rules, so an account sourced from `$ENV`/`@file` is
	 * refreshed in memory for this session while the user's indirection is left
	 * alone on disk.
	 */
	async function sweepIdleAccounts(ctx: ExtensionContext): Promise<void> {
		if (!config) return;
		// pi's own expiry window and exchange timeout — see pi-ai auth/resolve.js:
		// DEFAULT_OAUTH_MINIMUM_VALIDITY_MS / DEFAULT_OAUTH_REFRESH_TIMEOUT_MS.
		const MIN_VALIDITY_MS = 5 * 60 * 1000;
		const REFRESH_TIMEOUT_MS = 15_000;
		const now = Date.now();
		for (const rt of runtimes.values()) {
			if (rt.kind !== "oauth" || rt.currentIndex < 0) continue;
			// pi's own refresh implementation, reached exactly the way `skipReason`
			// reads the provider: through the registry facade, capability-checked.
			// The registry-facing contract is `refresh` — pi-ai's OAuthAuth — for
			// built-in AND extension-registered providers: pi's provider composer
			// adapts a registration's `refreshToken` hook into it
			// (`refresh: (c, s) => config.refreshToken(c, s)`), which is why the
			// e2e fixture's `refreshToken` hook is refreshed through `refresh` here.
			const oauth = ctx.modelRegistry.getProvider(rt.providerId)?.auth?.oauth;
			if (typeof oauth?.refresh !== "function") {
				trace(`sweep skip ${rt.providerId} (no OAuth refresh available)`);
				continue;
			}
			// Serialize with turn-boundary swaps: while an exchange for this provider
			// is in flight, `advanceForStrategy` skips the pool, so a round-robin/
			// random advancement can never install an account whose refresh the
			// sweep is mid-way through — on rotating providers, two exchanges of one
			// refresh token each consume the other. Failure rotation cannot be
			// blocked (a failing turn needs a replacement now); its narrower residual
			// is handled inside the loop, right after the exchange.
			sweepingProviders.add(rt.providerId);
			try {
				for (const entry of rt.keys) {
					if (entry === rt.keys[rt.currentIndex]) continue; // pi owns the active one
					const credential = entry.credential;
					if (!credential || typeof credential.expires !== "number") continue;
					if (now + MIN_VALIDITY_MS < credential.expires) continue; // still has life
					try {
						const fresh = await oauth.refresh(credential, AbortSignal.timeout(REFRESH_TIMEOUT_MS));
						if (!isOAuthCredential(fresh)) {
							trace(`sweep skip ${rt.providerId} ${entry.name} (refresh returned no usable credential)`);
							continue;
						}
						// The exchange awaited, so rotation may have landed on this entry
						// while it ran. If it became active, pi owns it now: write nothing, so
						// the capture machinery stays the only writer for the active account.
						// (When failure rotation installed the pre-sweep blob, that one
						// request may still fail its lazy refresh and rotate away once — then
						// the swept credential serves the later return. Self-healing, and the
						// same behavior as picking any stale account.)
						if (entry === rt.keys[rt.currentIndex]) {
							trace(`sweep skip persist ${rt.providerId} ${entry.name} (became active mid-exchange)`);
							continue;
						}
						entry.credential = fresh;
						persistCredential(rt, entry.name, fresh);
						trace(
							`sweep refreshed ${rt.providerId} ${entry.name} ` +
								`(expires in ${Math.round((fresh.expires - Date.now()) / 60_000)}m)`,
						);
					} catch (error) {
						const detail = error instanceof Error ? error.message : String(error);
						markBad(entry, "refresh-failed", config.cooldownMs, Date.now());
						trace(`sweep refresh failed ${rt.providerId} ${entry.name} (${detail})`);
						// Needs the user to act, exactly like a request-time refresh failure:
						// visible at "all" and "quiet", hidden at "silent".
						if (rotationIsNotifiable(config.notifications, "refresh-failed")) {
							warn(
								uiCtx,
								earlyWarnings,
								`🔑 keyrouter: ${rt.providerId} account "${entry.name}" could not be refreshed at startup — ` +
									`the login is likely dead. Rotation will skip it; /login that account to revive it.`,
							);
						}
					}
				}
			} finally {
				sweepingProviders.delete(rt.providerId);
			}
		}
	}

	/**
	 * Activate the router: load config (once), bootstrap all providers, and set
	 * the first key of each pool. Idempotent — safe on every before_agent_start.
	 */
	async function activate(ctx: ExtensionContext): Promise<void> {
		// Load config once (reload clears it)
		if (!config) {
			config = loadConfig(ctx.cwd);
		}
		if (config.providers.length === 0) return;
		uiCtx = ctx.ui;
		// Flush anything raised while there was no UI to notify. An OAuth bootstrap
		// installs (and therefore captures) before this assignment, so a refusal there
		// would otherwise be lost entirely — the user would never learn that a refreshed
		// credential was declined. Delivered oldest-first so the earliest warning, usually
		// the one naming the cause, is seen first.

		// Report config warnings once (dropped accounts, mutually exclusive fields).
		if (!warningsReported && config.warnings && config.warnings.length > 0) {
			warningsReported = true;
			for (const w of config.warnings) trace(`config warning ${w}`);
			ctx.ui.notify(`🔑 keyrouter: config\n  ${config.warnings.join("\n  ")}`, "warning");
		}
		for (const message of earlyWarnings.splice(0)) ctx.ui.notify(message, "warning");

		// Capability probes. Each pool kind degrades independently: a build without
		// the credential store must still rotate API keys, and vice versa.
		const hasOverlay = credentialsApi(ctx.modelRegistry, ctx.ui) !== undefined;
		const hasStore = credentialsStore(ctx.modelRegistry, ctx.ui) !== undefined;

		let newlyBootstrapped = 0;
		let accounted = 0;
		for (const p of config.providers) {
			const providerId = resolveProviderId(ctx.modelRegistry, p.name);
			// Skip providers we've already bootstrapped or permanently rejected
			if (runtimes.has(providerId) || permanentSkip.has(providerId)) continue;
			const reason = skipReason(ctx.modelRegistry, providerId, p);
			if (reason) {
				if (reason !== "missing") permanentSkip.add(providerId);
				reportSkip(providerId, reason);
				continue;
			}
			// Capability gate per kind. Reported once by the probe helpers.
			if (p.kind === "oauth" ? !hasStore : !hasOverlay) continue;

			const rt = ensureRuntime(providerId, p);
			if (rt.currentIndex >= 0 || rt.keys.length === 0) continue;

			// An OAuth pool must never leave an api_key overlay in place: on an
			// OAuth-only provider it would make auth resolve to NOTHING, and on a
			// dual-auth provider it would freeze the token so pi never refreshes it.
			// A leftover override from an earlier `keys` configuration is the one way
			// this could happen.
			if (p.kind === "oauth") {
				await clearOverlay(credentialApi?.removeRuntimeApiKey.bind(credentialApi), providerId);
				injected.delete(providerId);
			}

			const idx = pickNextKey(rt.keys, rt.resumeIndex, Date.now(), leasedIndices(rt));
			if (idx < 0) continue;
			const key = rt.keys[idx];
			if (!key) continue;

			if (p.kind === "oauth") {
				setActive(rt, idx);
				recordUse(key);
				if (await applyAccount(providerId, key, ctx)) {
					// Capture again: pi may have merged or normalized the blob, and this is
					// the copy a later return to this account will install.
					await captureAccount(rt, key);
					accounted++;
					trace(`oauth install ${providerId} -> ${key.name} (${rt.keys.length} account(s))`);
				}
				continue;
			}

			setActive(rt, idx);
			recordUse(key);
			// This is the fix for the old bug: the initial key actually gets set.
			if (await applyKey(providerId, key.value, ctx)) {
				newlyBootstrapped++;
				// Hold the lease on the entry this process just took.
				takeLease(rt, idx);
				trace(`bootstrap ${providerId} -> ${key.name}`);
			}
		}
		// Only notify on first activation (when we installed anything)
		if ((newlyBootstrapped > 0 || accounted > 0) && !activationNotified) {
			activationNotified = true;
			const totalKeys = config.providers.reduce((a, p) => a + (p.keys?.length ?? 0), 0);
			const totalAccounts = config.providers.reduce((a, p) => a + (p.accounts?.length ?? 0), 0);
			const parts: string[] = [];
			if (totalKeys > 0) parts.push(`${totalKeys} key(s)`);
			if (totalAccounts > 0) parts.push(`${totalAccounts} account(s)`);
			ctx.ui.notify(
				`🔑 keyrouter: active (${config.providers.length} provider(s), ${parts.join(", ")})`,
				"info",
			);
		}
	}

	/**
	 * Re-read the config file and re-activate every pool.
	 *
	 * Shared by `/keyrouter reload` and by the commands that change the config
	 * file (`add`, `remove`), so a change is always picked up the same way:
	 * hand pi back its own credentials, drop the runtime state, load the file
	 * again, and bootstrap from it.
	 */
	async function reloadAll(ctx: ExtensionContext): Promise<void> {
		if (credentialApi) {
			for (const providerId of [...injected]) await clearKey(providerId);
		}
		for (const providerId of [...installedAccounts]) {
			const rt = runtimes.get(providerId);
			if (rt) await restoreSessionStartAccount(providerId, rt);
		}
		injected.clear();
		installedAccounts.clear();
		// The claims go with the entries they were taken for.
		releaseLeases();
		config = loadConfig(ctx.cwd);
		runtimes.clear();
		skipReported.clear();
		permanentSkip.clear();
		activationNotified = false;
		warningsReported = false;
		persistNotifyErrorNotified = false;
		credentialApiChecked = false;
		credentialApi = undefined;
		storeApiChecked = false;
		storeApi = undefined;
		lastErrorNotified = false;
		await activate(ctx);
	}

	pi.on("session_start", async (_event, ctx) => {
		// Reconcile BEFORE the bootstrap installs anything. The install replaces
		// whatever pi holds, so a `/login` left behind by a force-killed session — one
		// where no shutdown handler ever ran — would be destroyed before anything could
		// notice it. This is the only moment in the session when pi's credential is
		// still observable on its own.
		await activate(ctx);
		await reconcileCredentials();
		await activate(ctx);
		// Keep idle pool accounts alive without holding up the session: the sweep
		// never touches pi's store, so it cannot race the first turn.
		if (startupSweepEnabled(process.env)) {
			void sweepIdleAccounts(ctx).catch((error) => {
				trace(`sweep error ${error instanceof Error ? error.message : String(error)}`);
			});
		} else {
			trace("startup sweep skipped (PI_KEYROUTER_SWEEP is not set to 1)");
		}
	});

	// Lazy bootstrap: also fire on every turn. This handles /reload (which
	// does NOT re-fire session_start) and config changes mid-session.
	// activate() is idempotent — only bootstraps once per provider.
	pi.on("before_agent_start", async (_event, ctx) => {
		await activate(ctx);
		// Then reconcile the pool against pi's store. This is the only place a `/login`
		// can be noticed at all: pi exposes no login, logout or credential-changed
		// event, so the change is observable only by looking. Doing it here rather than
		// inside `activate` matters — `activate` short-circuits for every already-
		// bootstrapped provider, and `/login` is exactly the case that got skipped.
		await reconcileCredentials();
		// Non-failover strategies pick their entry for the coming turn here, at the
		// only boundary where a swap is safe.
		await advanceForStrategy(ctx);
	});

	// A provider request holds its pool entry for as long as it is in flight, so
	// a rotation never walks onto a credential that is already serving one.
	pi.on("before_provider_request", async (_event, ctx) => {
		const providerId = activeProviderId(ctx);
		if (!providerId) return;
		const rt = runtimes.get(providerId);
		if (!rt || rt.currentIndex < 0) return;
		rt.busy.push(rt.currentIndex);
	});

	// Success clears a key's cooldown without touching rotation position, so a
	// rate-limited key can re-enter the pool instead of being stuck forever.
	pi.on("after_provider_response", async (event, ctx) => {
		// The request is done with the credential: its lease is released. The
		// turn-end backstop covers a request that never produced a response.
		const leaseProvider = activeProviderId(ctx);
		if (leaseProvider) {
			const leased = runtimes.get(leaseProvider);
			if (leased && leased.busy.length > 0) leased.busy.shift();
		}
		if (!config || !event.status || event.status >= 400) return;
		const providerId = activeProviderId(ctx);
		if (!providerId) return;
		const rt = runtimes.get(providerId);
		if (!rt || rt.currentIndex < 0) return;
		const key = rt.keys[rt.currentIndex];
		if (!key || (key.lastStatus === "ok" && key.cooldownUntil === 0)) return;
		markOk(key);
		trace(`success ${providerId} key=${key.name} (cooldown cleared)`);
	});

	pi.on("message_end", async (event, ctx) => {
		if (!config) return;
		const msg = event.message;
		// Only intercept assistant error messages
		if (msg.role !== "assistant") return;
		if (msg.stopReason !== "error") {
			// A successful response means the current key already served: no retry
			// is owed, so drop any pending continuation request.
			const okProvider = messageProviderId(msg) ?? activeProviderId(ctx);
			const okRuntime = okProvider ? runtimes.get(okProvider) : undefined;
			if (okRuntime) {
				okRuntime.pendingContinue = false;
				okRuntime.continuations = 0;
			}
			return;
		}
		const errMsg = msg.errorMessage ?? "";
		if (!errMsg) return;

		// Attribute the failure to the provider that ACTUALLY served the request:
		// the assistant message names the physical provider, while `ctx.model` can
		// name a virtual model (whose provider is the router's, not the key holder's).
		const providerId = messageProviderId(msg) ?? activeProviderId(ctx);
		if (!providerId) return;
		const rt = runtimes.get(providerId);
		if (!rt) return; // not a managed provider

		// Overload branch: provider-wide cooldown, NO rotation, NO failure
		// counter bump. Marks every key of this provider so pickNextKey
		// skips them until the window expires.
		if (OVERLOADED_RE.test(errMsg)) {
			const now = Date.now();
			for (const k of rt.keys) markOverloaded(k, config.overloadedCooldownMs, now);
			trace(`overload ${providerId} (provider-wide ${config.overloadedCooldownMs}ms, no rotation)`);
			if (uiCtx) notifyOverloaded(uiCtx, providerId, config.overloadedCooldownMs, config.notifications);
			return;
		}

		// The refresh-failure test comes FIRST, and deliberately.
		//
		// pi wraps a refresh failure as `OAuth refresh failed for <id>: ...`, and
		// when the upstream HTTP status was 401 that wrapper text contains "401" —
		// which UNAUTHORIZED_RE matches. Ordering it after that check mislabels a
		// dead-refresh-token error as a plain unauthorized one, hitting the same
		// pool entry but reporting the wrong cause. A refresh failure is strictly
		// more specific, so it wins.
		let reason: RotationReason | null = null;
		let status = 0;
		if (rt.kind === "oauth" && REFRESH_FAILED_RE.test(errMsg)) {
			reason = "refresh-failed";
			status = errMsg.includes("401") ? 401 : 403;
		} else if (RATE_LIMITED_RE.test(errMsg)) {
			reason = "rate-limited";
			status = 429;
		} else if (UNAUTHORIZED_RE.test(errMsg)) {
			reason = "unauthorized";
			status = errMsg.includes("401") ? 401 : 403;
		} else if (rt.kind === "oauth" && rt.rotateOnQuota && QUOTA_RE.test(errMsg)) {
			reason = "quota";
			status = 402;
		}
		if (!reason) {
			// Not an entry problem: leave the pool alone and let pi surface the error
			// rather than burning every credential we hold.
			trace(`ignore ${providerId} (non-rotatable error: ${errMsg.slice(0, 120)})`);
			return;
		}

		// Mark the entry we are leaving as bad.
		const currentKey = rt.currentIndex >= 0 ? rt.keys[rt.currentIndex] : undefined;
		if (currentKey) {
			markBad(currentKey, reason, config.cooldownMs, Date.now());
		}

		// Find the next available entry (different from the current one).
		const nextIdx = pickNextKey(rt.keys, rt.currentIndex + 1, Date.now(), leasedIndices(rt));
		if (nextIdx < 0 || nextIdx === rt.currentIndex) {
			// Everything is exhausted.
			const failed = rt.keys.filter((k) => k.failures > 0).map((k) => k.name);
			if (rt.kind === "oauth") {
				// Leave the active account installed: it is still a valid login, and
				// logging the user out mid-session helps nobody. pi surfaces the error.
				trace(`exhausted ${providerId} accounts=[${failed.join(", ")}]`);
			} else {
				// Keys pool: drop the override so pi falls back to the user's own
				// credential, then let pi surface the real error.
				if (rt.injecting) await clearKey(providerId);
				trace(`exhausted ${providerId} failed=[${failed.join(", ")}]`);
			}
			if (uiCtx) notifyExhausted(uiCtx, providerId, failed, rt.kind);
			return;
		}

		const nextKey = rt.keys[nextIdx];
		if (!nextKey) return;
		const previousName = currentKey?.name ?? "(none)";

		// Whether pi will retry this error class itself. 429 is retryable; 401/403
		// and quota/refresh failures are not, so those need the settle-time
		// continuation to ever use the credential we are about to install.
		// Only ask when the picked entry is genuinely available: `pickNextKey`
		// returns the soonest-to-clear entry even while cooled, and retrying into
		// another cooldown is not worth an extra request.
		const wantsContinue = isAvailable(nextKey, Date.now());

		const swapped = await swapToEntry(rt, nextIdx, ctx);
		if (!swapped) return;
		rt.pendingContinue = wantsContinue;
		trace(`rotate ${providerId} ${previousName} -> ${swapped.name} (${status} ${reason})`);

		// Notify with a single themeable line (falls back silently without UI)
		if (uiCtx) {
			const rotation: RotationEvent = {
				provider: providerId,
				fromKey: previousName,
				toKey: nextKey.name,
				reason,
				status,
				attempt: rt.keys.reduce((a, k) => a + k.failures, 0),
			};
			notifyRotation(uiCtx, rotation, config.notifications);
		}
	});

	// pi stops retrying once an error looks non-transient (401/403 are absent from
	// its retry pattern), so a key rotated for one of those would never be used.
	// `agent_before_settle` is the actionable boundary that adds exactly one more
	// request. The appended hidden message is what makes that valid: pi only
	// allows continuing when the last transcript message is not an assistant turn.
	//
	// Each provider may ask for at most `maxRetries` continuations before its
	// next success, so an all-bad pool cannot loop.
	pi.on("agent_before_settle", async (event) => {
		if (!config) return undefined;
		const pending = [...runtimes.values()].find((rt) => rt.pendingContinue);
		for (const rt of runtimes.values()) rt.pendingContinue = false;
		if (!pending) return undefined;
		if (event.context.canContinue) return undefined; // another extension already continues
		if (pending.continuations >= config.maxRetries) {
			trace(`continue skipped ${pending.providerId} (budget ${config.maxRetries} used)`);
			return undefined;
		}
		pending.continuations += 1;
		trace(`continue ${pending.providerId} (retry with the rotated key, ${pending.continuations}/${config.maxRetries})`);
		return {
			entries: [
				...event.entries,
				{
					type: "custom_message" as const,
					customType: CONTINUATION_CUSTOM_TYPE,
					content: "Retrying.",
					display: false,
				},
			],
			continue: true,
		};
	});

	// Backstop: the turn is over, so none of its requests is in flight any
	// more. Anything left in a busy list (a request that never produced a
	// response) is released here.
	pi.on("turn_end", async () => {
		for (const rt of runtimes.values()) rt.busy.length = 0;
	});

	pi.on("session_shutdown", async () => {
		// Everything keyrouter wrote is a change to pi's live state, so undo it
		// explicitly — this process may be reloaded rather than exited.
		//
		//   keys pool:  drop the runtime override. Not persisted, so removal alone
		//              restores the user's own key/env/OAuth credential.
		//   oauth pool: restore the credential that was stored at session start, so
		//              pi is left exactly as keyrouter found it.
		if (credentialApi) {
			for (const providerId of [...injected]) await clearKey(providerId);
		}
		for (const providerId of [...installedAccounts]) {
			const rt = runtimes.get(providerId);
			if (rt) await restoreSessionStartAccount(providerId, rt);
		}
		injected.clear();
		installedAccounts.clear();
		// The lease claims belong to this process alone: release them so another
		// pi process may use those entries.
		releaseLeases();
		releaseOwnLeases();
		runtimes.clear();
		skipReported.clear();
		permanentSkip.clear();
		config = undefined;
		uiCtx = undefined;
		activationNotified = false;
		warningsReported = false;
		persistNotifyErrorNotified = false;
		credentialApi = undefined;
		credentialApiChecked = false;
		storeApi = undefined;
		storeApiChecked = false;
		lastErrorNotified = false;
	});

	pi.registerCommand("keyrouter", {
		description: COMMAND_DESCRIPTION,
		getArgumentCompletions: (prefix) =>
			commandCompletions(prefix, config?.providers ?? loadConfig().providers),
		handler: async (args, ctx) => {
			const parsed = parseCommandArgs(args);
			const sub = parsed.sub;
			if (sub === "help") {
				// Help is strictly observational. In particular, do not fall through
				// to status: status may activate the pools, while a help request must
				// not touch credentials or keyrouter.json.
				ctx.ui.notify(commandHelpText(), "info");
				return;
			}
			if (sub === "status") {
				const wanted = parsed.args[0];
				let statusProviderId: string | undefined;
				let statusPoolName: string | undefined;
				if (wanted) {
					// Validate the provider against the config before activation so an
					// unknown operand fails clearly and non-destructively.
					if (!config) config = loadConfig(ctx.cwd);
					const found = findPool(ctx, config, wanted);
					if (!found) {
						const names = (config?.providers ?? []).map((pool) => pool.name);
						ctx.ui.notify(
							`🔑 keyrouter: no provider named "${wanted}" in ${configPath()}. ` +
								(names.length > 0
									? `Pools: ${names.join(", ")}.`
									: "No pools are configured."),
							"warning",
						);
						return;
					}
					statusProviderId = found.providerId;
					statusPoolName = found.pool.name;
				}
				// Use the same on-demand activation fallback as unfiltered status. This
				// ensures a filtered view shows the normal runtime state even when
				// session_start/before_agent_start have not fired yet.
				if (!config || runtimes.size === 0) {
					await activate(ctx);
				}
				if (statusProviderId && !runtimes.has(statusProviderId)) {
					ctx.ui.notify(
						`🔑 keyrouter: provider "${statusPoolName}" is configured but has no active runtime state.`,
						"warning",
					);
					return;
				}
				if (!config || config.providers.length === 0) {
					ctx.ui.notify(
						`🔑 keyrouter: not active — no ~/.pi/keyrouter.json found ` +
							`(expected at ${configPath()}). Config is user-level only, never project-scoped.`,
						"warning",
					);
					return;
				}
				if (!credentialApi) {
					// A filtered status may run before activation has probed the API.
					// Probe it read-only so the warning below is accurate.
					if (!credentialApiChecked) credentialsApi(ctx.modelRegistry, ctx.ui);
					if (!credentialApi) {
						ctx.ui.notify(
							"🔑 keyrouter: runtime credential overrides unavailable in this pi build — inert.",
							"warning",
						);
					}
				}
				// The reminder matters only when the level is not the default: it is the
				// answer to "why do I no longer see rotation lines?".
				const levelSuffix =
					config.notifications && config.notifications !== "all"
						? ` (notifications: ${config.notifications})`
						: "";
				const lines: string[] = [`🔑 keyrouter: active${levelSuffix}`];
				for (const [providerId, rt] of runtimes) {
					if (statusProviderId && providerId !== statusProviderId) continue;
					const current = rt.currentIndex >= 0 ? rt.keys[rt.currentIndex] : undefined;
					// `source` is pi's own vocabulary (runtime / stored / environment).
					// "runtime" is the only reliable signal that an api_key overlay is
					// installed, and it tells the two pool kinds apart at a glance.
					const auth = ctx.modelRegistry.getProviderAuthStatus(providerId);
					const installed = rt.kind === "oauth" ? rt.injecting : auth.source === "runtime";
					lines.push("");
					// Strategy only when it is not the default, so pools that never asked
					// for one keep the status line they have always had.
					const strategySuffix = rt.strategy !== "failover" ? `, strategy: ${rt.strategy}` : "";
					lines.push(
						`  ${providerId} (${rt.kind}, active: ${current?.name ?? "(none)"}, ` +
							`installed: ${installed ? "yes" : "no"}, source: ${auth.source ?? "none"}${strategySuffix})`,
					);
					for (let ki = 0; ki < rt.keys.length; ki++) {
						const k = rt.keys[ki];
						if (!k) continue;
						const marker = k === current ? "→" : "•";
						const avail = isAvailable(k, Date.now()) ? "" : " (cooldown)";
						// Show when the credential expires, never the token itself. OAuth
						// pools only — an API-key pool has no `expires` to report.
						let expiry = "";
						if (rt.kind === "oauth") {
							const expires = k.credential?.expires;
							if (typeof expires === "number") {
								const ms = expires - Date.now();
								expiry =
									ms <= 0
										? " expires=expired"
										: ` expires=in ${Math.max(1, Math.round(ms / 60_000))}m`;
							} else {
								expiry = " expires=unknown";
							}
						}
						// Who is using this entry right now. A lease is an exclusive
						// claim: "this-session" is this process, a pid is another pi
						// process, "in-flight" is one of our requests still running.
						const inFlight = rt.busy.filter((index) => index === ki).length;
						const owner = rt.kind === "keys" ? leaseOwner(rt.providerId, ki) : undefined;
						const lease =
							inFlight > 0
								? ` lease=in-flight(${inFlight})`
								: owner === process.pid
									? " lease=this-session"
									: owner !== undefined
										? ` lease=pid ${owner}`
										: "";
						lines.push(
							`    ${marker} ${k.name}  uses=${k.uses} fails=${k.failures} status=${k.lastStatus}${avail}${expiry}${lease}`,
						);
					}
				}
				ctx.ui.notify(lines.join("\n"), "info");
				return;
			}
			if (sub === "reload") {
				await reloadAll(ctx);
				ctx.ui.notify(
					`🔑 keyrouter: reloaded (${config?.providers.length ?? 0} provider(s))`,
					"info",
				);
				return;
			}
			if (sub === "reset") {
				// Hand every provider back to pi's own auth. Stays off until the next
				// turn re-activates the pools.
				if (credentialApi) {
					for (const providerId of [...injected]) await clearKey(providerId);
				}
				for (const providerId of [...installedAccounts]) {
					const rt = runtimes.get(providerId);
					if (rt) await restoreSessionStartAccount(providerId, rt);
				}
				// The claims go with the entries: pi is using the user's own
				// credentials again, so this process holds no pool entry.
				releaseLeases();
				// Forget the saved position too, or the next session would resume
				// straight back onto the key this command just handed back.
				for (const rt of runtimes.values()) setActive(rt, -1);
				injected.clear();
				installedAccounts.clear();
				activationNotified = false;
				ctx.ui.notify(
					runtimes.size > 0
						? "🔑 keyrouter: overrides cleared — pi is using your own credentials again. keyrouter stays off until you call /keyrouter reload (or start a new session)."
						: "🔑 keyrouter: nothing to reset (not active).",
					"info",
				);
				return;
			}
			if (sub === "account") {
				// Manual pin: use a specific pool credential until the next rotation
				// moves off it. Applies to either pool kind.
				if (!config || runtimes.size === 0) await activate(ctx);
				const wanted = parsed.args[0];
				const label = parsed.args[1];
				if (!wanted) {
					ctx.ui.notify(
						`🔑 keyrouter: usage — /keyrouter ${parsed.usage}`,
						"warning",
					);
					return;
				}

				const providerId = resolveProviderId(ctx.modelRegistry, wanted);
				const rt = runtimes.get(providerId);
				if (!rt) {
					const known = [...runtimes.keys()];
					ctx.ui.notify(
						`🔑 keyrouter: "${wanted}" is not an active pool. ` +
							(known.length > 0 ? `Active: ${known.join(", ")}.` : "No pools are active."),
						"warning",
					);
					return;
				}

				// Report the pool instead of guessing when no entry is named.
				if (!label) {
					const names = rt.keys.map((k) => k.name);
					const active = rt.currentIndex >= 0 ? rt.keys[rt.currentIndex]?.name : undefined;
					ctx.ui.notify(
						`🔑 keyrouter: ${providerId} (${rt.kind}) — active: ${active ?? "(none)"}\n` +
							`Choose one: /keyrouter account ${providerId} <${names.join("|")}>`,
						"info",
					);
					return;
				}

				// Exact name first, then case-insensitive, then ordinal (1-based).
				let idx = rt.keys.findIndex((k) => k.name === label);
				if (idx < 0) {
					const lower = label.toLowerCase();
					idx = rt.keys.findIndex((k) => k.name.toLowerCase() === lower);
				}
				if (idx < 0 && /^\d+$/.test(label)) {
					const ordinal = Number(label) - 1;
					if (ordinal >= 0 && ordinal < rt.keys.length) idx = ordinal;
				}
				if (idx < 0) {
					const names = rt.keys.map((k) => k.name);
					ctx.ui.notify(
						`🔑 keyrouter: no entry "${label}" in ${providerId}. Available: ${names.join(", ")}`,
						"warning",
					);
					return;
				}

				const entry = rt.keys[idx];
				if (!entry) return;
				const previous = rt.currentIndex >= 0 ? rt.keys[rt.currentIndex]?.name : undefined;
				if (idx === rt.currentIndex) {
					ctx.ui.notify(`🔑 keyrouter: ${providerId} is already using ${entry.name}.`, "info");
					return;
				}

				// Install through the same helpers rotation uses, so a manual switch is
				// subject to the same capture/clear rules as an automatic one.
				if (rt.kind === "oauth") {
					await captureAccount(rt, rt.currentIndex >= 0 ? rt.keys[rt.currentIndex] : undefined);
					if (!(await applyAccount(providerId, entry, ctx))) {
						ctx.ui.notify(`🔑 keyrouter: could not install ${entry.name} for ${providerId}.`, "error");
						return;
					}
					await captureAccount(rt, entry);
				} else {
					if (!(await applyKey(providerId, entry.value, ctx))) {
						ctx.ui.notify(`🔑 keyrouter: could not install ${entry.name} for ${providerId}.`, "error");
						return;
					}
				}

				// A manual pick is deliberate, so clear any cooldown rather than leaving
				// a chosen entry that the picker would immediately skip, and drop any
				// pending continuation — the user is not waiting on a retry.
				markOk(entry);
				setActive(rt, idx);
				rt.pendingContinue = false;
				recordUse(entry);
				const noun = rt.kind === "oauth" ? "account" : "key";
				trace(`manual ${providerId} ${previous ?? "(none)"} -> ${entry.name} (/${noun})`);
				ctx.ui.notify(
					`🔑 keyrouter: ${providerId} now using ${noun} ${entry.name}` +
						(idx === 0 ? " (pool default)" : "") +
						`. Rotation continues from here.`,
					"info",
				);
				return;
			}
			if (sub === "strategy") {
				// Show or change a pool's rotation strategy. A change never rotates
				// immediately — strategies act at turn boundaries — it only re-points
				// what the next boundary will do.
				if (!config || runtimes.size === 0) await activate(ctx);
				const wanted = parsed.args[0];
				const token = parsed.args[1]?.toLowerCase();
				if (!wanted) {
					// No argument: one line per pool, a strategy-only status.
					const lines: string[] = [];
					for (const [providerId, rt] of runtimes) {
						lines.push(`  ${providerId} (${rt.kind}): ${rt.strategy}`);
					}
					ctx.ui.notify(
						lines.length > 0
							? `🔑 keyrouter: strategies\n${lines.join("\n")}\n` +
								`Set one: /keyrouter strategy <provider> <${[...STRATEGIES].join("|")}>`
							: "🔑 keyrouter: no pools are active.",
						"info",
					);
					return;
				}

				const providerId = resolveProviderId(ctx.modelRegistry, wanted);
				const rt = runtimes.get(providerId);
				if (!rt) {
					const known = [...runtimes.keys()];
					ctx.ui.notify(
						`🔑 keyrouter: "${wanted}" is not an active pool. ` +
							(known.length > 0 ? `Active: ${known.join(", ")}.` : "No pools are active."),
						"warning",
					);
					return;
				}

				// Report the pool instead of guessing when no strategy is named.
				if (!token) {
					ctx.ui.notify(
						`🔑 keyrouter: ${providerId} (${rt.kind}) — strategy: ${rt.strategy}\n` +
							`Choose one: /keyrouter strategy ${providerId} <${[...STRATEGIES].join("|")}>`,
						"info",
					);
					return;
				}

				if (!STRATEGIES.has(token)) {
					ctx.ui.notify(
						`🔑 keyrouter: "${token}" is not a strategy. Valid: ${[...STRATEGIES].join(", ")}.`,
						"warning",
					);
					return;
				}

				// Reuse the loader's own resolution so the command degrades
				// "stalest-first" on a keys pool exactly like a config reload — and
				// persists the EFFECTIVE value, so a later reload does not re-warn.
				const warnings: string[] = [];
				// The pool's WRITTEN name, matching the loader's own warnings (config
				// vocabulary), not the possibly-canonicalized id.
				const effective = normalizeStrategy(token, rt.kind, rt.configName, warnings);
				for (const w of warnings) ctx.ui.notify(`🔑 keyrouter: ${w}`, "warning");

				const previous = rt.strategy;
				if (effective === previous) {
					// No-op set: report it instead of claiming a change, exactly like
					// `account` short-circuits "already using X".
					ctx.ui.notify(`🔑 keyrouter: ${providerId} is already on strategy ${effective}.`, "info");
					return;
				}
				rt.strategy = effective;
				// Find the config entry by the name the user WROTE, not the resolved id —
				// `resolveProviderId` may have canonicalized it (`z-ai` -> `zai`) and the
				// config file is never rewritten to match (same rule as `writeBackActive`).
				const pool = config?.providers.find((p) => p.name === rt.configName);
				if (pool) pool.strategy = effective;

				const result = writeBackStrategy(rt.configName, effective);
				if ("error" in result) {
					ctx.ui.notify(
						`🔑 keyrouter: could not save the strategy to ${configPath()} — ${result.error}. ` +
							"The change applies to this session only.",
						"warning",
					);
				}

				trace(`strategy ${providerId} ${previous} -> ${effective} (/strategy)`);
				ctx.ui.notify(
					`🔑 keyrouter: ${providerId} strategy: ${previous} -> ${effective} ` +
						"(applies from the next turn boundary).",
					"info",
				);
				return;
			}
			if (sub === "notifications") {
				// Show or change the top-level notification level. The config is read
				// directly here so viewing the level never activates a pool.
				const file = configPath();
				const fileExists = existsSync(file);
				const requested = parsed.args[0];
				if (!requested) {
					// Do not cache the default when there is no file: the user may
					// create one before the next turn, and activation should still
					// load it normally.
					if (!config && fileExists) config = loadConfig(ctx.cwd);
					const current = config?.notifications ?? "all";
					ctx.ui.notify(
						fileExists
							? `🔑 keyrouter: notification level: ${current} — ${NOTIFICATION_DESCRIPTIONS[current]}`
							: `🔑 keyrouter: notification level: ${current}${config ? "" : " (default)"}; no config file found at ${file} — ${NOTIFICATION_DESCRIPTIONS[current]}`,
						fileExists ? "info" : "warning",
					);
					return;
				}
				if (parsed.args.length !== 1 || !isNotificationLevel(requested)) {
					// Do not echo an unknown operand: it may be something the user
					// accidentally pasted.
					ctx.ui.notify(
						"🔑 keyrouter: invalid notification level. Valid values: all, quiet, silent.",
						"warning",
					);
					return;
				}
				if (!existsSync(file)) {
					ctx.ui.notify(
						`🔑 keyrouter: could not set the notification level — no config file found at ${file}.`,
						"error",
					);
					return;
				}
				if (!config) config = loadConfig(ctx.cwd);
				const result = writeBackNotifications(requested);
				if ("error" in result) {
					ctx.ui.notify(
						`🔑 keyrouter: could not save the notification level to ${file} — ${result.error}. The level was not changed.`,
						"error",
					);
					return;
				}
				// Apply it to the live config now; waiting for /reload would leave the
				// current session using the old notification policy.
				config.notifications = requested;
				ctx.ui.notify(
					`🔑 keyrouter: notification level: ${requested}${result.updated === 0 ? " (unchanged)" : ""} — ${NOTIFICATION_DESCRIPTIONS[requested]}`,
					"info",
				);
				return;
			}
			if (sub === "add" || sub === "remove") {
				// Guided credential management.
				//
				// Adding an API key asks for the secret here — keyrouter never runs a
				// login of its own. Adding an OAuth account captures the credential pi
				// is holding right now, so the user signs in with pi's own /login and
				// keyrouter takes a copy afterwards. Removing asks for confirmation,
				// because the credential is deleted from the config file.
				if (!config || runtimes.size === 0) await activate(ctx);
				const wanted = parsed.args[0];
				if (!wanted) {
					ctx.ui.notify(`🔑 keyrouter: usage — /keyrouter ${parsed.usage}`, "warning");
					return;
				}
				const found = findPool(ctx, config, wanted);
				if (!found) {
					const names = (config?.providers ?? []).map((candidate) => candidate.name);
					ctx.ui.notify(
						`🔑 keyrouter: no pool named "${wanted}" in ${configPath()}. ` +
							(names.length > 0 ? `Pools: ${names.join(", ")}.` : "No pools are configured."),
						"warning",
					);
					return;
				}
				const { providerId, pool } = found;
				const entries: { name: string }[] =
					pool.kind === "oauth" ? (pool.accounts ?? []) : (pool.keys ?? []);

				if (sub === "remove") {
					const label = parsed.args[1];
					if (!label) {
						ctx.ui.notify(
							`🔑 keyrouter: usage — /keyrouter ${parsed.usage}\n` +
								`Entries in ${pool.name}: ${entries.map((entry) => entry.name).join(", ") || "(none)"}`,
							"warning",
						);
						return;
					}
					const entry = matchEntry(entries, label);
					if (!entry) {
						ctx.ui.notify(
							`🔑 keyrouter: no entry "${label}" in ${pool.name}. ` +
								`Available: ${entries.map((candidate) => candidate.name).join(", ") || "(none)"}`,
							"warning",
						);
						return;
					}
					const confirmed = await ctx.ui.confirm(
						`Remove ${entry.name} from ${pool.name}?`,
						"The credential is deleted from keyrouter.json. pi's own login is not touched.",
					);
					if (!confirmed) {
						ctx.ui.notify("🔑 keyrouter: nothing removed.", "info");
						return;
					}
					const removed = writeBackPoolEntry(pool.name, "remove", { name: entry.name });
					if ("error" in removed) {
						ctx.ui.notify(
							`🔑 keyrouter: could not update ${configPath()} — ${removed.error}.`,
							"warning",
						);
						return;
					}
					await reloadAll(ctx);
					trace(`remove ${pool.name} ${entry.name}`);
					ctx.ui.notify(`🔑 keyrouter: removed ${entry.name} from ${pool.name}.`, "info");
					return;
				}

				// add
				const requestedName = parsed.args[1]?.trim() || undefined;
				let value: string | undefined;
				if (pool.kind === "keys") {
					const entered = await ctx.ui.input(
						`API key for ${pool.name}${requestedName ? `/${requestedName}` : ""}`,
						"paste the key — it is stored in keyrouter.json",
					);
					if (entered === undefined) {
						ctx.ui.notify("🔑 keyrouter: cancelled — nothing was added.", "info");
						return;
					}
					value = entered.trim();
					if (!value) {
						ctx.ui.notify("🔑 keyrouter: cancelled — the key was empty.", "info");
						return;
					}

					// An explicit existing name means UPDATE THAT ENTRY IN PLACE.
					const existing = requestedName
						? (pool.keys ?? []).find((entry) => entry.name === requestedName)
						: undefined;
					if (existing) {
						const updated = writeBackPoolEntry(pool.name, "update", {
							name: existing.name,
							value,
						});
						if ("error" in updated) {
							ctx.ui.notify(
								`🔑 keyrouter: could not update ${configPath()} — ${updated.error}.`,
								"warning",
							);
							return;
						}
						if (updated.updated === 0) {
							ctx.ui.notify(
								`🔑 keyrouter: "${existing.name}" in ${pool.name} is already up to date.`,
								"info",
							);
							return;
						}
						await reloadAll(ctx);
						trace(`update ${pool.name} ${existing.name}`);
						ctx.ui.notify(`🔑 keyrouter: updated ${existing.name} in ${pool.name}.`, "info");
						return;
					}

					const base = requestedName ?? `key-${entries.length + 1}`;
					const generated = uniquePoolEntryName(
						base,
						entries.map((entry) => entry.name),
					);
					const added = writeBackPoolEntry(pool.name, "add", {
						name: generated.name,
						value,
					});
					if ("error" in added) {
						ctx.ui.notify(
							`🔑 keyrouter: could not update ${configPath()} — ${added.error}.`,
							"warning",
						);
						return;
					}
					if (added.updated === 0) {
						ctx.ui.notify(`🔑 keyrouter: nothing was added to ${pool.name}.`, "info");
						return;
					}
					await reloadAll(ctx);
					if (generated.adjusted) {
						ctx.ui.notify(
							`🔑 keyrouter: adjusted the generated name to "${generated.name}" because "${base}" is already in use.`,
							"warning",
						);
					}
					trace(`add ${pool.name} ${generated.name}`);
					ctx.ui.notify(
						`🔑 keyrouter: added ${generated.name} to ${pool.name}. It joins the pool on the next turn.`,
						"info",
					);
					return;
				}

				// OAuth: pi owns the login, so the credential is taken from pi.
				if (!storeApi) {
					ctx.ui.notify(
						"🔑 keyrouter: pi's credential store is unavailable in this build — cannot capture an account.",
						"warning",
					);
					return;
				}
				const credential = await captureCredential(storeApi, providerId);
				if (!credential) {
					ctx.ui.notify(
						`🔑 keyrouter: pi has no login for ${providerId}. Run /login first, then /keyrouter add ${pool.name}.`,
						"warning",
					);
					return;
				}

				const addAccount = async (explicitName?: string): Promise<void> => {
					const label = identityLabel(credential);
					const base =
						explicitName ??
						(label && /^[A-Za-z0-9._@+-]{1,40}$/.test(label)
							? label
							: `account-${entries.length + 1}`);
					const generated = uniquePoolEntryName(
						base,
						entries.map((entry) => entry.name),
					);
					const added = writeBackPoolEntry(pool.name, "add", {
						name: generated.name,
						credential,
					});
					if ("error" in added) {
						ctx.ui.notify(
							`🔑 keyrouter: could not update ${configPath()} — ${added.error}.`,
							"warning",
						);
						return;
					}
					if (added.updated === 0) {
						ctx.ui.notify(`🔑 keyrouter: nothing was added to ${pool.name}.`, "info");
						return;
					}
					await reloadAll(ctx);
					if (generated.adjusted) {
						ctx.ui.notify(
							`🔑 keyrouter: adjusted the generated name to "${generated.name}" because "${base}" is already in use.`,
							"warning",
						);
					}
					trace(`add ${pool.name} ${generated.name}`);
					ctx.ui.notify(
						`🔑 keyrouter: added ${generated.name} to ${pool.name}. It joins the pool on the next turn.`,
						"info",
					);
				};

				const updateAccount = async (target: {
					name: string;
					credential?: OAuthCredential;
				}): Promise<void> => {
					// An explicit retarget is allowed, but only after the user confirms
					// that the named account really has a different identity.
					const targetState = initAccountStates([target])[0];
					if (!targetState) return;
					const tripwire = checkTripwire({
						target: targetState,
						credential,
						identityPath: pool.identityPath,
					});
					if (!tripwire.ok) {
						const confirmed = await ctx.ui.confirm(
							`Replace account "${target.name}" in ${pool.name}?`,
							"pi's current login has a different account identity. Confirming replaces that entry with pi's current credential.",
						);
						if (!confirmed) {
							ctx.ui.notify("🔑 keyrouter: nothing changed.", "info");
							return;
						}
					}
					const updated = writeBackPoolEntry(pool.name, "update", {
						name: target.name,
						credential,
					});
					if ("error" in updated) {
						ctx.ui.notify(
							`🔑 keyrouter: could not update ${configPath()} — ${updated.error}.`,
							"warning",
						);
						return;
					}
					if (updated.updated === 0) {
						ctx.ui.notify(
							`🔑 keyrouter: "${target.name}" in ${pool.name} is already up to date.`,
							"info",
						);
						return;
					}
					await reloadAll(ctx);
					trace(`update ${pool.name} ${target.name}`);
					ctx.ui.notify(`🔑 keyrouter: updated ${target.name} in ${pool.name}.`, "info");
				};

				const accounts = pool.accounts ?? [];
				const plan = planOAuthAddition({
					credential,
					accounts,
					requestedName,
					identityPath: pool.identityPath,
				});
				if (plan.kind === "update") {
					await updateAccount(plan.target);
					return;
				}

				if (plan.kind === "duplicate") {
					ctx.ui.notify(alreadyUsingMessage(plan.name), "warning");
					return;
				}
				if (plan.kind === "ambiguous") {
					ctx.ui.notify(
						`🔑 keyrouter: pi's current login for ${providerId} matches more than one account (${plan.names.join(", ")}). ` +
							"Name the account to update explicitly, or set identityPath for this provider.",
						"warning",
					);
					return;
				}
				if (plan.kind === "prompt") {
					const choice = await ctx.ui.select(
						`pi's current ${pool.name} login matches account "${plan.target.name}". What should /keyrouter add do?`,
						[plan.updateOption, plan.addOption, plan.cancelOption],
					);
					if (choice === plan.updateOption) {
						await updateAccount(plan.target);
						return;
					}
					if (choice === plan.addOption) {
						await addAccount(plan.addName);
						return;
					}
					ctx.ui.notify("🔑 keyrouter: cancelled — nothing was added.", "info");
					return;
				}

				await addAccount(plan.name);
			}
			ctx.ui.notify(`Usage: /keyrouter [${SUBCOMMANDS.join("|")}]`, "info");
		},
	});
}



/**
 * Find the configured pool the user meant.
 *
 * The pool is matched by the name written in `keyrouter.json` first, then by
 * the provider id pi resolves that name to — the two differ when a provider id
 * is canonicalized (`z-ai` -> `zai`), and the config file is never rewritten
 * to the canonical form.
 */
function findPool(
	ctx: ExtensionContext,
	config: KeyRouterConfig | undefined,
	wanted: string,
): { providerId: string; pool: ProviderPoolConfig } | undefined {
	if (!config) return undefined;
	const exact = config.providers.find((pool) => pool.name === wanted);
	if (exact) {
		return { providerId: resolveProviderId(ctx.modelRegistry, exact.name), pool: exact };
	}
	const providerId = resolveProviderId(ctx.modelRegistry, wanted);
	const pool = config.providers.find(
		(candidate) => resolveProviderId(ctx.modelRegistry, candidate.name) === providerId,
	);
	return pool ? { providerId, pool } : undefined;
}

/**
 * Match a pool entry by exact name, then case-insensitively, then by its
 * 1-based position in the pool.
 */
function matchEntry<T extends { name: string }>(entries: readonly T[], label: string): T | undefined {
	const exact = entries.find((entry) => entry.name === label);
	if (exact) return exact;
	const lower = label.toLowerCase();
	const insensitive = entries.find((entry) => entry.name.toLowerCase() === lower);
	if (insensitive) return insensitive;
	if (/^\d+$/.test(label)) {
		const ordinal = Number(label) - 1;
		return ordinal >= 0 && ordinal < entries.length ? entries[ordinal] : undefined;
	}
	return undefined;
}

/** The decision made after `/keyrouter add` captures pi's live OAuth credential. */
export type OAuthAdditionPlan =
	| { kind: "update"; target: AccountEntry }
	| { kind: "duplicate"; name: string }
	| {
			kind: "prompt";
			target: AccountEntry;
			updateOption: string;
			addOption: string;
			cancelOption: string;
			/** The name to use if the user chooses add-as-new. */
			addName: string | undefined;
	  }
	| { kind: "ambiguous"; names: string[] }
	| { kind: "add"; name: string | undefined };

/**
 * Plan an OAuth addition without touching the TUI.
 *
 * The order is deliberate: an explicitly named existing entry is updated; an
 * exact credential elsewhere is refused; then identity attribution runs even
 * when the requested name is new. That last step is what prevents a named
 * addition from silently duplicating an account identity.
 */
export function planOAuthAddition(args: {
	credential: OAuthCredential;
	accounts: ReadonlyArray<AccountEntry>;
	requestedName?: string | undefined;
	identityPath?: string | undefined;
}): OAuthAdditionPlan {
	const { credential, accounts, requestedName, identityPath } = args;
	const explicitTarget = requestedName
		? accounts.find((account) => account.name === requestedName)
		: undefined;
	if (explicitTarget) return { kind: "update", target: explicitTarget };

	const duplicate = accounts.find((account) => sameCredential(account.credential, credential));
	if (duplicate) return { kind: "duplicate", name: duplicate.name };

	const attribution = attributeCredential({
		credential,
		states: accounts,
		activeName: undefined,
		expectedName: undefined,
		installedByUs: false,
		identityPath,
	});
	if (attribution.kind === "ambiguous") {
		return { kind: "ambiguous", names: attribution.names };
	}
	if (attribution.kind === "match") {
		const target = accounts[attribution.index];
		if (target) {
			return {
				kind: "prompt",
				target,
				updateOption: `Update existing account "${target.name}"`,
				addOption: "Add current login as a new account",
				cancelOption: "Cancel",
				addName: requestedName,
			};
		}
	}
	return { kind: "add", name: requestedName };
}

/** Subcommands accepted by `/keyrouter`, in usage order. */
export const SUBCOMMANDS = [
	"status",
	"reload",
	"reset",
	"account",
	"strategy",
	"add",
	"remove",
	"notifications",
] as const;

/** One line of the full `/keyrouter` command help. */
export const COMMAND_HELP = [
	{
		usage: "status [provider]",
		description: "show live pool state, optionally filtered to one provider",
	},
	{ usage: "reload", description: "re-read the config file" },
	{ usage: "reset", description: "hand providers back to pi's own credentials" },
	{
		usage: "account <provider> [name|index]",
		description: "pin a specific key or account",
	},
	{
		usage: "strategy <provider> [strategy]",
		description: "show or set a pool's rotation strategy",
	},
	{
		usage: "add <provider> [name]",
		description:
			"add or update a key/account; API key values are entered interactively",
	},
	{
		usage: "remove <provider> <name|index>",
		description: "remove a key or an account from a pool",
	},
	{
		usage: "notifications [all|quiet|silent]",
		description: "show or set keyrouter's notification level",
	},
] as const;

/** Description shown for `/keyrouter` in pi's command autocomplete. */
export const COMMAND_DESCRIPTION =
	"manage credential pools — /keyrouter status [provider], /keyrouter reload, " +
	"/keyrouter reset, /keyrouter account <provider> [name|index], " +
	"/keyrouter strategy <provider> [strategy], /keyrouter add <provider> [name], " +
	"/keyrouter remove <provider> <name|index], " +
	"/keyrouter notifications [all|quiet|silent]";

/** The full command help shown by bare `/keyrouter` and `/keyrouter --help`. */
export function commandHelpText(): string {
	return [
		"🔑 keyrouter: command help",
		...COMMAND_HELP.map((entry) => `  /keyrouter ${entry.usage} — ${entry.description}`),
	].join("\n");
}

/**
 * Parse `/keyrouter` arguments into a subcommand plus its operands.
 *
 * Extracted from the handler so the argument handling is a pure, testable unit:
 * slice commands cannot be driven from print mode, so this is what the test suite
 * can actually exercise (`test/unit-oauth.mjs`).
 *
 * `args` is the raw text after `/keyrouter`. Extra whitespace is collapsed. A
 * bare command and `--help` request the help list; an unrecognised word is
 * treated as a `status` provider operand so the handler can report that the
 * provider does not exist instead of silently showing every pool.
 */
export function parseCommandArgs(args: string): {
	sub: string;
	/** Operands after the subcommand: [provider?] for `status`,
	 * [provider, entryName?] for `account`, [provider, strategy?] for `strategy`,
	 * [level?] for `notifications`, and [provider, entryName?] for `add`. */
	args: string[];
	/** The exact `/keyrouter …` form to show the user for this subcommand. */
	usage: string;
} {
	const tokens = (args ?? "").trim().split(/\s+/).filter(Boolean);
	const first = tokens[0]?.toLowerCase() ?? "";
	if (!first || first === "--help") {
		return { sub: "help", args: [], usage: "help" };
	}
	const known = (SUBCOMMANDS as readonly string[]).includes(first);
	const sub = known ? first : "status";
	const rest = known ? tokens.slice(1) : tokens;
	const usage =
		sub === "status"
			? "status [provider]"
			: sub === "account"
				? "account <provider> [name|index]"
				: sub === "strategy"
					? "strategy <provider> [strategy]"
					: sub === "notifications"
						? "notifications [all|quiet|silent]"
						: sub === "add"
							? "add <provider> [name]"
							: sub === "remove"
								? "remove <provider> <name|index>"
								: sub;
	return { sub, args: rest, usage };
}

/** The notification levels accepted by `/keyrouter notifications`. */
const NOTIFICATION_LEVELS = ["all", "quiet", "silent"] as const satisfies readonly NotificationLevel[];

/** True when a command operand is a valid notification level. */
function isNotificationLevel(value: string): value is NotificationLevel {
	return (NOTIFICATION_LEVELS as readonly string[]).includes(value);
}

/** Short explanations shown with the current or newly selected level. */
const NOTIFICATION_DESCRIPTIONS: Record<NotificationLevel, string> = {
	all: "show every keyrouter event",
	quiet: "hide routine events; keep alerts that need action",
	silent: "hide rotation and overload notices (pool exhaustion still notifies)",
};

/** Descriptions shown next to each subcommand in the completion menu. */
const SUBCOMMAND_DESCRIPTIONS: Record<string, string> = {
	status: "[provider] — show live pool state, optionally filtered",
	reload: "reload — re-read the config file",
	reset: "reset — hand providers back to pi's own credentials",
	account: "<provider> [name|index] — pin a specific key or account",
	strategy: "<provider> [strategy] — show or set a pool's rotation strategy",
	add: "<provider> [name] — add/update a key or account; key input is interactive",
	remove: "<provider> <name|index> — remove a key or an account from a pool",
	notifications: "[all|quiet|silent] — show or set keyrouter's notification level",
};

/** Descriptions shown next to each strategy value in the completion menu. */
const STRATEGY_DESCRIPTIONS: Record<string, string> = {
	failover: "stay on the current entry until it fails",
	"round-robin": "advance one entry at every turn boundary",
	"stalest-first": "pick the account whose token expires soonest",
	random: "pick a uniformly random available entry",
};

/**
 * Completions for the text after `/keyrouter`.
 *
 * Pure and exported for the same reason `parseCommandArgs` is: a completion menu
 * only exists in the interactive TUI, so this is what the unit suite can drive.
 *
 * Offers the subcommands, then — for `account` or `strategy` — the configured
 * pool names, then that pool's entries (`account`) or the strategy values valid
 * for its kind (`strategy`). `notifications` offers its three level values.
 * Suggestions carry the whole command line in `value` because pi replaces the
 * whole argument prefix, so the earlier tokens have to be echoed back. Returns
 * null once the line is complete, which is how pi is told to stop suggesting.
 */
export function commandCompletions(
	prefix: string,
	pools: readonly ProviderPoolConfig[],
): { value: string; label: string; description?: string }[] | null {
	// Split into the tokens already finished and the one being typed. A trailing
	// space is what says a token was finished — pi hands us the raw prefix, and
	// "/keyrouter account " must offer pool names, not entries.
	const parts = prefix.split(/\s+/);
	const typing = !/\s$/.test(prefix) && prefix.length > 0;
	// An empty prefix splits to [""], which must count as no finished token.
	const done = (typing ? parts.slice(0, -1) : parts).filter(Boolean);
	const current = (typing ? (parts[parts.length - 1] ?? "") : "").toLowerCase();
	const items = (matches: { value: string; label: string; description?: string }[]) =>
		matches.length > 0 ? matches : null;

	// No token finished yet: completing the subcommand.
	if (done.length === 0) {
		return items(
			SUBCOMMANDS.filter((candidate) => candidate.startsWith(current)).map((candidate) => ({
				value: `${candidate} `,
				label: candidate,
				description: SUBCOMMAND_DESCRIPTIONS[candidate],
			})),
		);
	}

	// Only these take operands; the rest are complete on their own.
	const sub = done[0]?.toLowerCase();
	if (sub === "notifications") {
		if (done.length > 1) return null;
		return items(
			NOTIFICATION_LEVELS.filter((value) => value.startsWith(current)).map((value) => ({
				value: `notifications ${value}`,
				label: value,
				description: NOTIFICATION_DESCRIPTIONS[value],
			})),
		);
	}
	if (
		sub !== "status" &&
		sub !== "account" &&
		sub !== "strategy" &&
		sub !== "add" &&
		sub !== "remove"
	) {
		return null;
	}
	if (done.length > 2) return null;

	// First operand, shared by all of them: the pool names.
	if (done.length === 1) {
		return items(
			pools
				.filter((pool) => pool.name.toLowerCase().startsWith(current))
				.map((pool) => ({
					value: `${sub} ${pool.name} `,
					label: pool.name,
					description: pool.kind === "oauth" ? "oauth pool" : "key pool",
				})),
		);
	}

	// Second operand, once the pool is named.
	const pool = pools.find((candidate) => candidate.name === done[1]);
	if (!pool) return null;

	if (sub === "status") return null;

	if (sub === "strategy") {
		// `stalest-first` is not offered for a keys pool: it orders by token
		// expiry, which keys do not have, so the menu never suggests a choice
		// that would only degrade (see `normalizeStrategy`).
		return items(
			[...STRATEGIES]
				.filter((value) => !(value === "stalest-first" && pool.kind === "keys"))
				.filter((value) => value.startsWith(current))
				.map((value) => ({
					value: `strategy ${pool.name} ${value}`,
					label: value,
					description: STRATEGY_DESCRIPTIONS[value],
				})),
		);
	}

	// `add`, `account`, and `remove`: the entries of the pool named in
	// `done[1]`. Only names are exposed — never key values or credential blobs.
	const entries = pool.kind === "oauth" ? (pool.accounts ?? []) : (pool.keys ?? []);
	return items(
		entries
			.filter((entry) => entry.name.toLowerCase().startsWith(current))
			// No trailing space: this is the last token, and a space would only
			// invite a fourth one that means nothing.
			.map((entry) => ({
				value: `${sub} ${pool.name} ${entry.name}`,
				label: entry.name,
				description:
					sub === "add"
						? pool.kind === "oauth"
							? "existing account"
							: "existing key"
						: pool.active === entry.name
							? "active"
							: undefined,
			})),
	);
}

/** The exact refusal shown when pi already holds a credential from the pool. */
export function alreadyUsingMessage(name: string): string {
	return `🔑 keyrouter: pi is already using "${name}". Run \`/login\` to sign in to another account first and then call \`/keyrouter add\` again.`;
}

/**
 * True when two credentials carry the same secrets and expiry.
 *
 * Used to avoid rewriting the user's config file on every capture: pi refreshes
 * lazily, so most captures return exactly what the pool already holds, and a
 * needless write would churn the file (and its mtime) for nothing.
 *
 * Both secrets are compared because providers differ in which one rotates —
 * Cline rotates neither, some providers rotate only the access token, and others
 * rotate the refresh token too. Comparing only one would silently drop the other
 * half of a rotated pair. Values are compared, never logged.
 */
export function sameCredential(a: KeyState["credential"], b: KeyState["credential"]): boolean {
	if (!a || !b) return a === b;
	return a.access === b.access && a.refresh === b.refresh && a.expires === b.expires;
}
/** Provider id recorded on an assistant message (the physical provider). */
function messageProviderId(msg: { provider?: string }): string | undefined {
	return typeof msg.provider === "string" && msg.provider.length > 0 ? msg.provider : undefined;
}

/**
 * Best available provider id when no message names one: the provider of the
 * selected model. The empty-string guard keeps a keyless virtual router id out
 * of the rotation path.
 */
function activeProviderId(ctx: ExtensionContext): string | undefined {
	const provider = ctx.model?.provider;
	return provider && provider.length > 0 ? provider : undefined;
}

/**
 * Resolve the provider id pi uses for credentials.
 *
 * The config uses whatever name the user typed; pi's provider ids are exact
 * (e.g. `zai`, `openrouter`, or another extension's id). We match
 * case-insensitively against ids pi actually knows and keep the canonical form,
 * so `z-ai`/`Z.AI` map to the real id when one exists and unknown names pass
 * through unchanged for `acceptsApiKey()` to report.
 */
function resolveProviderId(
	registry: ExtensionContext["modelRegistry"],
	displayName: string,
): string {
	const known = new Set<string>();
	for (const model of registry.getAll()) known.add(model.provider);
	for (const id of registry.getRegisteredProviderIds()) known.add(id);
	if (known.has(displayName)) return displayName;
	const lower = displayName.toLowerCase();
	for (const id of known) {
		if (id.toLowerCase() === lower) return id;
	}
	return displayName;
}
