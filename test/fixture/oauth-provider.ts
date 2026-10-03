// =============================================================================
// oauth-provider.ts — fixture provider for pi-keyrouter's OAuth-pool tests
// =============================================================================
//
// Registered with `-e` alongside the extension under test. It deliberately has
// NO `apiKey` auth method, so it reproduces the real constraint that makes OAuth
// pools hard: pi's resolver stores exactly one credential per provider id, and
// an `api_key` credential or runtime overlay on an OAuth-only provider resolves
// to NO auth at all (verified in test/verify-runtime-credentials.mjs against
// openai-codex). If keyrouter's OAuth path ever regressed to using
// `setRuntimeApiKey`, every request here would fail auth.
//
// The fake server sees whatever `getApiKey` returns, so requests prove which
// account is installed: `Authorization: Bearer oauth:<access>`.
//
// The refresh hook is where pi's ownership of OAuth becomes observable:
//   - pi calls it only when a credential is within ~5 minutes of expiry.
//   - `access: "access-dead"` makes it throw, simulating a revoked refresh token.
//   - otherwise it rotates both `access` and `refresh` and pushes `expires` out,
//     exactly like a real provider. keyrouter must copy the ROTATED blob back
//     into the pool, or a later return to this account would install a consumed
//     refresh token.

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { appendFileSync } from "node:fs";

/**
 * Append to `KR_OAUTH_LOG` when set. Test assertions read this to prove pi
 * refreshed (or did not refresh) a credential. Records the account's `access`
 * only — never a real secret, and never the refresh token.
 */
function log(message: string): void {
	const path = process.env["KR_OAUTH_LOG"];
	if (!path) return;
	try {
		appendFileSync(path, `${new Date().toISOString()} ${message}\n`, "utf8");
	} catch {
		// Logging must never break a request.
	}
}

const FAKE_BASE = process.env["KR_FAKE_BASE"] ?? "http://127.0.0.1:8787";

/**
 * Refresh tokens this process has already redeemed.
 *
 * Real providers ROTATE refresh tokens: redeeming one invalidates it. Modelling
 * that is what makes a lost rotation FATAL rather than merely wasteful. If
 * keyrouter fails to copy pi's rotated blob back into the pool, the next install
 * of that account presents a consumed refresh token and the request fails with
 * invalid_grant. A fixture that accepted a reused token could not tell those two
 * situations apart, so the test would pass either way.
 */
const consumedRefreshTokens = new Set<string>();

export default function oauthFixtureProvider(pi: ExtensionAPI): void {
	pi.registerProvider("kroauth", {
		name: "KR OAuth Test",
		baseUrl: `${FAKE_BASE}/v1`,
		api: "openai-completions",
		models: [
			{
				id: "fake-gpt",
				name: "Fake GPT (oauth)",
				reasoning: false,
				input: ["text"],
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
				contextWindow: 128000,
				maxTokens: 1024,
			},
		],
		oauth: {
			name: "KR OAuth",
			async login() {
				// Never exercised: keyrouter installs credentials directly, and the
				// tests must not run an interactive flow.
				throw new Error("kroauth login is not exercised by tests");
			},
			async refreshToken(credential) {
				const refresh = String(credential.refresh ?? "");
				log(`refresh access=${String(credential.access)} refresh=${refresh}`);
				if (credential.access === "access-dead" || refresh.includes("dead")) {
					// Mirrors a revoked refresh token. pi wraps this in a
					// ModelsError("oauth", `OAuth refresh failed for <id>`), which is
					// the message keyrouter classifies as a dead account.
					throw new Error("OAuth refresh failed: invalid_grant (the refresh token was revoked)");
				}
				// Refresh-token rotation: redeeming a token consumes it, as real
				// providers do. This is what makes a lost rotation observable — a
				// reused token is rejected instead of silently working.
				if (consumedRefreshTokens.has(refresh)) {
					throw new Error(
						`OAuth refresh failed: invalid_grant (refresh token ${refresh} was already used)`,
					);
				}
				consumedRefreshTokens.add(refresh);
				const now = Date.now();
				log(`refresh-rotated from=${String(credential.access)} to=refreshed-${now}`);
				return {
					...credential,
					type: "oauth",
					access: `refreshed-${now}`,
					refresh: `refresh-${now}`,
					expires: now + 3_600_000,
				};
			},
			getApiKey(credential) {
				// The bearer the fake server observes. `oauth:` makes it obvious in
				// the request log that this came through the OAuth path and not from
				// a runtime api_key overlay.
				return `oauth:${String(credential.access)}`;
			},
		},
	});
}