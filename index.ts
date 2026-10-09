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
import { appendFileSync } from "node:fs";
import { loadConfig, configPath, writeBackCredentials, writeBackActive } from "./config.ts";
import {
	notifyRotation,
	notifyOverloaded,
	notifyExhausted,
	notifyOAuthUnsupported,
} from "./notification.ts";
import {
	captureCredential,
	clearOverlay,
	credentialStore,
	installCredential,
	type CredentialStoreApi,
} from "./oauth.ts";
import {
	initAccountStates,
	initKeyStates,
	isAvailable,
	markBad,
	markOk,
	markOverloaded,
	pickNextKey,
	recordUse,
} from "./rotation.ts";
import type {
	KeyRouterConfig,
	KeyState,
	PoolKind,
	ProviderConfig as ProviderPoolConfig,
	RotationEvent,
	RotationReason,
} from "./types.ts";
/**
 * Optional trace sink. Set `PI_KEYROUTER_TRACE=/path/to/log` to record pool
 * decisions (key NAMES only, never values) for debugging or headless runs where
 * `ui.notify` has no terminal to print to.
 */
const tracePath = process.env["PI_KEYROUTER_TRACE"] || undefined;

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
	 * OAuth pools only: the credential that was in the store when this session
	 * started, so it can be restored on clean shutdown. `undefined` means the
	 * provider had no stored credential, in which case shutdown leaves the pool's
	 * active account installed rather than logging the user out.
	 */
	sessionStartCredential?: KeyState["credential"];
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
	let uiCtx: ExtensionUIContext | undefined;
	/** Providers whose config error we have already reported once. */
	const skipReported = new Set<string>();
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
	/** Reported once if refreshed credentials cannot be written back to disk. */
	let persistNotifyErrorNotified = false;

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
			kind: providerCfg.kind,
			// Only meaningful for OAuth pools; false for keys pools by construction.
			rotateOnQuota: providerCfg.kind === "oauth" && providerCfg.rotateOnQuota !== false,
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
	 * Read the live credential back into the pool entry we are leaving.
	 *
	 * pi rotates refresh tokens in place, so a stale pool copy would install a
	 * consumed refresh token on a later return to that account — burning an
	 * account that was perfectly healthy. This is why capture happens both before
	 * swapping away and after installing.
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
		if (!storeApi || !entry) return;
		const live = await captureCredential(storeApi, rt.providerId);
		if (!live) return;
		// Skip the write when nothing moved: most captures happen inside a single
		// token lifetime, and a no-op must never touch the user's config file.
		const changed = !entry.credential || !sameCredential(entry.credential, live);
		entry.credential = live;
		if (persist && changed) persistCredential(rt, entry.name, live);
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
	 * Hand the provider back to whatever it had before this session started.
	 *
	 * Only a credential that was actually present at session start is restored.
	 * If there was none, leaving the active pool account installed is the
	 * friendlier outcome: it is a valid login, and logging the user out would
	 * turn a clean shutdown into a broken one.
	 */
	async function restoreSessionStartAccount(
		providerId: string,
		rt: ProviderRuntime,
	): Promise<void> {
		if (!storeApi) return;
		const active = rt.currentIndex >= 0 ? rt.keys[rt.currentIndex] : undefined;
		// Preserve pi's refreshed tokens for the account we are leaving.
		await captureAccount(rt, active);

		const original = rt.sessionStartCredential;
		if (!original) {
			trace(`oauth restore ${providerId} (no session-start credential; leaving ${active?.name ?? "(none)"} installed)`);
			return;
		}
		const result = await installCredential(storeApi, providerId, original);
		if (result.ok) {
			trace(`oauth restore ${providerId} -> session-start credential`);
		} else {
			trace(`oauth restore failed ${providerId} (${result.error})`);
		}
		installedAccounts.delete(providerId);
		rt.injecting = false;
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

		// Report config warnings once (dropped accounts, mutually exclusive fields).
		if (!warningsReported && config.warnings && config.warnings.length > 0) {
			warningsReported = true;
			for (const w of config.warnings) trace(`config warning ${w}`);
			ctx.ui.notify(`🔑 keyrouter: config\n  ${config.warnings.join("\n  ")}`, "warning");
		}

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

			const idx = pickNextKey(rt.keys, rt.resumeIndex, Date.now());
			if (idx < 0) continue;
			const key = rt.keys[idx];
			if (!key) continue;

			if (p.kind === "oauth") {
				// Remember what the provider had before us, so a clean shutdown can put
				// it back. Read-only, best effort — a read failure just means we treat
				// it as "no stored credential".
				rt.sessionStartCredential = storeApi
					? await captureCredential(storeApi, providerId)
					: undefined;
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

	pi.on("session_start", async (_event, ctx) => {
		await activate(ctx);
	});

	// Lazy bootstrap: also fire on every turn. This handles /reload (which
	// does NOT re-fire session_start) and config changes mid-session.
	// activate() is idempotent — only bootstraps once per provider.
	pi.on("before_agent_start", async (_event, ctx) => {
		await activate(ctx);
	});

	// Success clears a key's cooldown without touching rotation position, so a
	// rate-limited key can re-enter the pool instead of being stuck forever.
	pi.on("after_provider_response", async (event, ctx) => {
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
			if (uiCtx) notifyOverloaded(uiCtx, providerId, config.overloadedCooldownMs);
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
		const nextIdx = pickNextKey(rt.keys, rt.currentIndex + 1, Date.now());
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

		if (rt.kind === "oauth") {
			// 1. Preserve whatever pi refreshed for the account we are leaving.
			await captureAccount(rt, currentKey);
			// 2. Install the next account.
			if (!(await applyAccount(providerId, nextKey, ctx))) return;
			setActive(rt, nextIdx);
			recordUse(nextKey);
			// 3. Read it back: pi may normalize or merge the blob, and this copy is
			//    what a later return to this account will install.
			await captureAccount(rt, nextKey);
			rt.pendingContinue = wantsContinue;
			trace(`rotate ${providerId} ${previousName} -> ${nextKey.name} (${status} ${reason})`);
		} else {
			if (!(await applyKey(providerId, nextKey.value, ctx))) return;
			setActive(rt, nextIdx);
			recordUse(nextKey);
			rt.pendingContinue = wantsContinue;
			trace(`rotate ${providerId} ${previousName} -> ${nextKey.name} (${status} ${reason})`);
		}

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
			notifyRotation(uiCtx, rotation);
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
					content:
						"pi-keyrouter: the API key was rotated after the last failed request. " +
						"Retry the previous turn using the new credentials.",
					display: false,
				},
			],
			continue: true,
		};
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
		description: "manage credential pools (status, reload, reset, account)",
		handler: async (args, ctx) => {
			const parsed = parseCommandArgs(args);
			const sub = parsed.sub;
			if (sub === "status") {
				// On-demand activation in case session_start/before_agent_start
				// haven't fired yet (e.g. user ran /keyrouter status right after
				// /reload without sending a prompt).
				if (!config || runtimes.size === 0) {
					await activate(ctx);
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
					ctx.ui.notify(
						"🔑 keyrouter: runtime credential overrides unavailable in this pi build — inert.",
						"warning",
					);
				}
				const lines: string[] = [`🔑 keyrouter: active`];
				for (const [providerId, rt] of runtimes) {
					const current = rt.currentIndex >= 0 ? rt.keys[rt.currentIndex] : undefined;
					// `source` is pi's own vocabulary (runtime / stored / environment).
					// "runtime" is the only reliable signal that an api_key overlay is
					// installed, and it tells the two pool kinds apart at a glance.
					const auth = ctx.modelRegistry.getProviderAuthStatus(providerId);
					const installed = rt.kind === "oauth" ? rt.injecting : auth.source === "runtime";
					lines.push("");
					lines.push(
						`  ${providerId} (${rt.kind}, active: ${current?.name ?? "(none)"}, ` +
							`installed: ${installed ? "yes" : "no"}, source: ${auth.source ?? "none"})`,
					);
					for (const k of rt.keys) {
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
						lines.push(
							`    ${marker} ${k.name}  uses=${k.uses} fails=${k.failures} status=${k.lastStatus}${avail}${expiry}`,
						);
					}
				}
				ctx.ui.notify(lines.join("\n"), "info");
				return;
			}
			if (sub === "reload") {
				if (credentialApi) {
					for (const providerId of [...injected]) await clearKey(providerId);
				}
				for (const providerId of [...installedAccounts]) {
					const rt = runtimes.get(providerId);
					if (rt) await restoreSessionStartAccount(providerId, rt);
				}
				injected.clear();
				installedAccounts.clear();
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
				ctx.ui.notify(
					`🔑 keyrouter: reloaded (${config.providers.length} provider(s))`,
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
				// Forget the saved position too, or the next session would resume
				// straight back onto the key this command just handed back.
				for (const rt of runtimes.values()) setActive(rt, -1);
				injected.clear();
				installedAccounts.clear();
				activationNotified = false;
				ctx.ui.notify(
					runtimes.size > 0
						? "🔑 keyrouter: overrides cleared — pi is using your own credentials again."
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
			ctx.ui.notify(`Usage: /keyrouter [${SUBCOMMANDS.join("|")}]`, "info");
		},
	});
}



/** Subcommands accepted by `/keyrouter`, in usage order. */
export const SUBCOMMANDS = ["status", "reload", "reset", "account"] as const;

/**
 * Parse `/keyrouter` arguments into a subcommand plus its operands.
 *
 * Extracted from the handler so the argument handling is a pure, testable unit:
 * slice commands cannot be driven from print mode, so this is what the test suite
 * can actually exercise (`test/unit-oauth.mjs`).
 *
 * `args` is the raw text after `/keyrouter`. Extra whitespace is collapsed, and
 * a missing or unrecognised subcommand falls back to `status` — the friendly
 * default for a bare `/keyrouter`.
 */
export function parseCommandArgs(args: string): {
	sub: string;
	/** Operands after the subcommand: [provider, entryName?] for `account`. */
	args: string[];
	/** The exact `/keyrouter …` form to show the user for this subcommand. */
	usage: string;
} {
	const tokens = (args ?? "").trim().split(/\s+/).filter(Boolean);
	const first = tokens[0]?.toLowerCase() ?? "";
	const sub = (SUBCOMMANDS as readonly string[]).includes(first) ? first : "status";
	// A bare `/keyrouter` or an unknown word behaves as `status` with no operands:
	// the unknown word was a subcommand guess, not an argument.
	const rest = (SUBCOMMANDS as readonly string[]).includes(first) ? tokens.slice(1) : [];
	const usage =
		sub === "account" ? "account <provider> [name|index]" : sub;
	return { sub, args: rest, usage };
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
