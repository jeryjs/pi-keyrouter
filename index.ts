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
import { loadConfig, configPath } from "./config.ts";
import { notifyRotation, notifyOverloaded, notifyExhausted } from "./notification.ts";
import {
	initKeyStates,
	isAvailable,
	markBad,
	markOk,
	markOverloaded,
	pickNextKey,
	recordUse,
} from "./rotation.ts";
import type { KeyRouterConfig, RotationEvent, KeyState } from "./types.ts";
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

/** Regex matching rate-limit style errors (key-specific failures). */
const RATE_LIMITED_RE = /\b429\b|rate.?limit|too many requests/i;

/** Regex matching auth errors (key-specific failures). */
const UNAUTHORIZED_RE = /\b40[13]\b|unauthorized|forbidden/i;

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
	keys: KeyState[];
	/** Index of the key currently in the runtime overlay. -1 = none set yet. */
	currentIndex: number;
	/** True once we have written an override for this provider. */
	injecting: boolean;
	/**
	 * Set after a rotation that no request has used yet. pi does not retry
	 * 401/403, so `agent_before_settle` must ask for the one more request that
	 * makes the swap useful. Cleared when it is consumed.
	 */
	pendingContinue: boolean;
	/**
	 * Continuations already requested since this provider last succeeded.
	 * Bounds the settle-time retry: a pool whose keys are all bad would
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
	/** Providers we set in THIS process; cleared on shutdown. */
	const injected = new Set<string>();
	let uiCtx: ExtensionUIContext | undefined;
	/** Providers whose config error we have already reported once. */
	const skipReported = new Set<string>();
	/** Providers that can never be managed (OAuth-only): stop re-checking. */
	const permanentSkip = new Set<string>();
	let activationNotified = false;
	let credentialApi: RuntimeCredentialApi | undefined;
	let credentialApiChecked = false;
	let lastErrorNotified = false;

	/**
	 * Get-or-create the runtime for a provider, keyed by the real provider id.
	 */
	function ensureRuntime(
		providerId: string,
		providerCfg: { keys: ReadonlyArray<{ name: string; value: string }> },
	): ProviderRuntime {
		let rt = runtimes.get(providerId);
		if (rt) return rt;
		rt = {
			providerId,
			keys: initKeyStates(providerCfg.keys),
			currentIndex: -1,
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
	 * Why keyrouter cannot manage this provider, or undefined when it can.
	 * `oauth` and `oauth-login` are permanent for the session; `missing` is
	 * retried on later turns because another extension may register the
	 * provider after us.
	 */
	function skipReason(
		registry: ExtensionContext["modelRegistry"],
		providerId: string,
		allowOAuthTakeover: boolean,
	): "missing" | "oauth" | "oauth-login" | undefined {
		const provider = registry.getProvider(providerId);
		if (!provider) return "missing";
		// OAuth/subscription-only providers have no apiKey auth method; an injected
		// api_key credential would be dropped by pi's resolver and fail the request.
		if (!provider.auth?.apiKey) return "oauth";
		// A provider can accept both. Injecting a runtime key shadows whatever is
		// stored, including a signed-in OAuth token, so leave logins alone unless
		// the pool explicitly opts in with `takeoverOAuth`.
		if (!allowOAuthTakeover && storedCredentialIsOAuth(providerId)) return "oauth-login";
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

	function reportSkip(providerId: string, reason: "missing" | "oauth" | "oauth-login"): void {
		if (skipReported.has(providerId)) return;
		skipReported.add(providerId);
		const detail =
			reason === "missing"
				? "provider not registered"
				: reason === "oauth"
					? "OAuth/subscription-only, no api-key auth"
					: "using a stored OAuth login";
		trace(`skip ${providerId} (${detail})`);
		const text =
			reason === "missing"
				? `🔑 keyrouter: provider "${providerId}" is not registered — check the name in ${configPath()}.`
				: reason === "oauth"
					? `🔑 keyrouter: "${providerId}" is OAuth/subscription-only — leaving it on pi's own login.`
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

		if (!credentialsApi(ctx.modelRegistry, ctx.ui)) return;

		let newlyBootstrapped = 0;
		for (const p of config.providers) {
			const providerId = resolveProviderId(ctx.modelRegistry, p.name);
			// Skip providers we've already bootstrapped or permanently rejected
			if (runtimes.has(providerId) || permanentSkip.has(providerId)) continue;
			const reason = skipReason(ctx.modelRegistry, providerId, p.takeoverOAuth === true);
			if (reason) {
				if (reason !== "missing") permanentSkip.add(providerId);
				reportSkip(providerId, reason);
				continue;
			}
			const rt = ensureRuntime(providerId, p);
			if (rt.currentIndex >= 0 || rt.keys.length === 0) continue;
			const idx = pickNextKey(rt.keys, 0, Date.now());
			if (idx < 0) continue;
			const key = rt.keys[idx];
			if (!key) continue;
			rt.currentIndex = idx;
			recordUse(key);
			// This is the fix for the old bug: the initial key actually gets set.
			if (await applyKey(providerId, key.value, ctx)) {
				newlyBootstrapped++;
				trace(`bootstrap ${providerId} -> ${key.name}`);
			}
		}
		// Only notify on first activation (when we bootstrapped at least one)
		if (newlyBootstrapped > 0 && !activationNotified) {
			activationNotified = true;
			ctx.ui.notify(
				`🔑 keyrouter: active (${config.providers.length} provider(s), ${config.providers.reduce((a, p) => a + p.keys.length, 0)} keys)`,
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

		// Rotation branch: 429 (key-rate-limited) or 401/403 (key-bad).
		let reason: "rate-limited" | "unauthorized" | null = null;
		let status = 0;
		if (RATE_LIMITED_RE.test(errMsg)) {
			reason = "rate-limited";
			status = 429;
		} else if (UNAUTHORIZED_RE.test(errMsg)) {
			reason = "unauthorized";
			status = errMsg.includes("401") ? 401 : 403;
		}
		if (!reason) {
			// Not a key problem (billing/quota/unknown): leave the key in place and
			// let pi surface the error rather than burning the whole pool.
			trace(`ignore ${providerId} (non-rotatable error: ${errMsg.slice(0, 120)})`);
			return;
		}

		// Mark current key as bad
		const currentKey = rt.currentIndex >= 0 ? rt.keys[rt.currentIndex] : undefined;
		if (currentKey) {
			markBad(currentKey, reason, config.cooldownMs, Date.now());
		}

		// Find next available key (different from current)
		const nextIdx = pickNextKey(rt.keys, rt.currentIndex + 1, Date.now());
		if (nextIdx < 0 || nextIdx === rt.currentIndex) {
			// All keys exhausted — clear our override so pi falls back to the
			// user's own credential, then let pi surface the real error.
			const failed = rt.keys.filter((k) => k.failures > 0).map((k) => k.name);
			if (rt.injecting) await clearKey(providerId);
			trace(`exhausted ${providerId} failed=[${failed.join(", ")}]`);
			if (uiCtx) notifyExhausted(uiCtx, providerId, failed);
			return;
		}

		const nextKey = rt.keys[nextIdx];
		if (!nextKey) return;

		// Set the new runtime key. pi retries 429/5xx itself, so that retry already
		// picks the new key up. For errors pi does NOT retry (401/403), the flag
		// lets `agent_before_settle` ask for the one request that uses it.
		// Only ask when the picked key is genuinely available: `pickNextKey`
		// returns the soonest-to-clear key even while cooled, and retrying into
		// another cooldown is not worth an extra request.
		if (!(await applyKey(providerId, nextKey.value, ctx))) return;
		const previousName = currentKey?.name ?? "(none)";
		rt.currentIndex = nextIdx;
		recordUse(nextKey);
		rt.pendingContinue = isAvailable(nextKey, Date.now());
		trace(`rotate ${providerId} ${previousName} -> ${nextKey.name} (${status} ${reason})`);

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
		// Runtime overrides are not persisted, but this process may be reloaded
		// rather than exited, so drop them explicitly. pi restores whatever the
		// user had configured (auth.json key, env var, or OAuth credential).
		if (credentialApi) {
			for (const providerId of [...injected]) await clearKey(providerId);
		}
		injected.clear();
		runtimes.clear();
		skipReported.clear();
		permanentSkip.clear();
		config = undefined;
		uiCtx = undefined;
		activationNotified = false;
		credentialApi = undefined;
		credentialApiChecked = false;
		lastErrorNotified = false;
	});

	pi.registerCommand("keyrouter", {
		description: "manage key rotation (status, reload, reset)",
		handler: async (args, ctx) => {
			const sub = args.trim().split(/\s+/)[0] ?? "status";
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
					const auth = ctx.modelRegistry.getProviderAuthStatus(providerId);
					lines.push("");
					lines.push(
						`  ${providerId} (current: ${current?.name ?? "(none)"}, ` +
							`override: ${rt.injecting ? "on" : "off"}, configured: ${auth.configured ? "yes" : "no"})`,
					);
					for (const k of rt.keys) {
						const marker = k === current ? "→" : "•";
						const avail = isAvailable(k, Date.now()) ? "" : " (cooldown)";
						lines.push(
							`    ${marker} ${k.name}  uses=${k.uses} fails=${k.failures} status=${k.lastStatus}${avail}`,
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
				injected.clear();
				config = loadConfig(ctx.cwd);
				runtimes.clear();
				skipReported.clear();
				permanentSkip.clear();
				activationNotified = false;
				credentialApiChecked = false;
				credentialApi = undefined;
				lastErrorNotified = false;
				await activate(ctx);
				ctx.ui.notify(
					`🔑 keyrouter: reloaded (${config.providers.length} provider(s))`,
					"info",
				);
				return;
			}
			if (sub === "reset") {
				// Hand every provider back to pi's own auth. Stays off until the
				// next turn re-activates the pools.
				if (credentialApi) {
					for (const providerId of [...injected]) await clearKey(providerId);
				}
				for (const rt of runtimes.values()) rt.currentIndex = -1;
				injected.clear();
				activationNotified = false;
				ctx.ui.notify(
					runtimes.size > 0
						? "🔑 keyrouter: overrides cleared — pi is using your own credentials again."
						: "🔑 keyrouter: nothing to reset (not active).",
					"info",
				);
				return;
			}
			ctx.ui.notify("Usage: /keyrouter [status|reload|reset]", "info");
		},
	});
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
