// =============================================================================
// notification.ts — user-facing notifications for key-router events
// =============================================================================
//
// Compact, theme-friendly notifications via `ui.notify(message, severity)`.
// We do NOT paint raw ANSI backgrounds and we do NOT stack a Box widget
// over the editor — both were too loud. Rotations and overloads are
// informational; a single warning-level line that the TUI can theme
// (background tint per severity) reads cleanly in light and dark mode.
//
// Severity map:
//   rotation   -> "warning"  (we just swapped a key, not a failure)
//   overload   -> "warning"  (provider-wide, no key change)
//   exhaustion -> "error"    (all keys failed; pi will surface the real error)
//
// Volume is controlled by the `notifications` config setting (see types.ts).
// The policy lives here, next to the writers, so a new call site cannot
// forget it: every notify wrapper takes the level and gates itself.
// Pool exhaustion is deliberately UNGATED — it is the one event where the
// user's request actually dies, so it shows at every level.

import type { ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import type { NotificationLevel, RotationEvent, RotationReason } from "./types.ts";

const ROTATION_WIDGET_KEY = "keyrouter-rotation";

/**
 * Whether a rotation deserves a visible line at this notification level.
 * `undefined` means the setting was absent — the historical "all".
 *
 * The split is deliberate. A rate-limited rotation is the tool doing its job:
 * the entry cools down and rejoins the pool on its own, so in quiet mode it is
 * exactly the noise worth hiding. An unauthorized, quota or refresh-failed
 * rotation means a credential that will not heal — the key must be replaced,
 * the account topped up, the login redone — so quiet keeps it visible.
 * `silent` drops both; only the exhaustion notice survives (see above).
 */
export function rotationIsNotifiable(
	level: NotificationLevel | undefined,
	reason: RotationReason,
): boolean {
	const resolved = level ?? "all";
	if (resolved === "silent") return false;
	if (resolved === "quiet") return reason !== "rate-limited";
	return true;
}

/**
 * Whether a provider-wide overload notice is visible. Purely informational in
 * every mode — no rotation happens and pi retries on its own — so only the
 * default "all" level shows it.
 */
export function overloadIsNotifiable(level: NotificationLevel | undefined): boolean {
	return (level ?? "all") === "all";
}

/**
 * Show a one-line notification for a key rotation event — unless the
 * `notifications` level says this reason is not worth a line.
 *
 * Format: "🔑 keyrouter: <provider> <fromKey> → <toKey> (HTTP <status>, <reason>)"
 */
export function notifyRotation(
	ui: ExtensionUIContext,
	event: RotationEvent,
	level: NotificationLevel | undefined = "all",
): void {
	if (!rotationIsNotifiable(level, event.reason)) return;
	const text =
		`🔑 keyrouter: ${event.provider} ${event.fromKey} → ${event.toKey} ` +
		`(HTTP ${event.status}, ${event.reason})`;
	try {
		ui.notify(text, "warning");
	} catch {
		// no UI available (print mode, headless) — silent
	}
}

/**
 * Show a one-line notification for a provider-wide overload event —
 * hidden everywhere except the default "all" level. No rotation occurred —
 * just a heads-up that the provider is busy, which pi's own retry covers.
 *
 * Format: "🔑 keyrouter: <provider> overloaded — retrying in <N>s (no key change)"
 */
export function notifyOverloaded(
	ui: ExtensionUIContext,
	provider: string,
	cooldownMs: number,
	level: NotificationLevel | undefined = "all",
): void {
	if (!overloadIsNotifiable(level)) return;
	const seconds = Math.max(1, Math.ceil(cooldownMs / 1000));
	const text =
		`🔑 keyrouter: ${provider} overloaded — retrying in ${seconds}s (no key change)`;
	try {
		ui.notify(text, "warning");
	} catch {
		// silent
	}
}

/**
 * Notify that all entries of a pool have been exhausted.
 * Kept on the same path as the other notifications so the user sees
 * one consistent surface. `kind` only changes the wording — `accounts` for
 * OAuth pools, `keys` for API-key pools.
 *
 * NOT gated by `notifications`, at any level: this is the event where the
 * request the user is waiting on actually fails, and hiding it would only
 * make the provider's own error look unexplained.
 */
export function notifyExhausted(
	ui: ExtensionUIContext,
	provider: string,
	failedKeys: ReadonlyArray<string>,
	kind: "keys" | "oauth" = "keys",
): void {
	const list = failedKeys.length > 0 ? failedKeys.join(", ") : "(none)";
	const noun = kind === "oauth" ? "accounts" : "keys";
	const text = `🔑 keyrouter: ${provider} — all ${noun} exhausted (${list}). Surfacing original error.`;
	try {
		ui.notify(text, "error");
	} catch {
		// silent
	}
}

/**
 * One-time notice that a credential-store capability is missing, so OAuth
 * pools are inert while API-key pools keep working. Kept distinct from the
 * generic inactive notice because the remedies differ.
 *
 * Not rotation noise and not gated by `notifications`: it fires once at
 * startup, and it says the user's `accounts` config is not being applied at
 * all — silencing a capability problem would hide a broken setup.
 */
export function notifyOAuthUnsupported(ui: ExtensionUIContext, detail: string): void {
	try {
		ui.notify(
			`🔑 keyrouter: OAuth account pools are unavailable in this pi build — ${detail}. ` +
				`API-key pools are unaffected.`,
			"warning",
		);
	} catch {
		// silent
	}
}

/**
 * Clear the rotation widget if it exists. Kept as a no-op for backward
 * compatibility with callers that previously expected a Box widget
 * here. New code should not rely on a widget — use ui.notify instead.
 */
export function clearRotationWidget(_ui: ExtensionUIContext): void {
	try {
		_ui.setWidget(ROTATION_WIDGET_KEY, undefined);
	} catch {
		// ignore — session may have ended, or setWidget may not exist on
		// this ExtensionUIContext variant
	}
}
