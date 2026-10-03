// =============================================================================
// config.ts — load key router config from disk
// =============================================================================
//
// Config is GLOBAL (user-level), never project-scoped. API keys are personal
// credentials that do not belong inside a project directory (risk of leaking
// via git, shared repos, etc.).
//
// Single location: ~/.pi/keyrouter.json
//   - Windows: %USERPROFILE%\.pi\keyrouter.json
//   - macOS/Linux: ~/.pi/keyrouter.json
//
// Schema:
// {
//   "providers": [
//     {
//       "name": "google",
//       "keys": [
//         { "name": "primary", "value": "$GEMINI_API_KEY" },
//         { "name": "backup",  "value": "$GEMINI_API_KEY_2" }
//       ]
//     }
//   ],
//   "maxRetries": 3,
//   "cooldownMs": 60000,
//   "overloadedCooldownMs": 30000
// }
//
// `value` may be a literal key, or reference environment variables with
// `$NAME` / `${NAME}` (same syntax pi uses in models.json). Prefer env refs so
// secrets never sit on disk. A value that still references a missing variable
// after expansion is dropped.
// `name` is the provider id pi uses — built-in (`google`, `anthropic`), a
// `models.json` id, or another extension's id. `match` is accepted and ignored
// for backward compatibility.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { ApiKey, KeyRouterConfig, ProviderConfig as ProviderPool } from "./types.ts";

/**
 * Expand `$NAME` / `${NAME}` from the environment. `$$` is a literal `$`.
 * Unresolved names are left as `$NAME` so the caller can drop the key.
 */
export function expandEnv(value: string): string {
	if (!value.includes("$")) return value;
	return value.replace(
		/\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
		(match, braced, bare) => {
			if (match === "$$") return "$";
			const name: string = braced ?? bare;
			return process.env[name] ?? `$${name}`;
		},
	);
}

/** True when an expanded value still contains an unresolved `$NAME` reference. */
function hasUnresolvedRef(value: string): boolean {
	return /\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/.test(value);
}

export function defaultConfig(): KeyRouterConfig {
	return {
		providers: [],
		maxRetries: 3,
		cooldownMs: 60_000,
		overloadedCooldownMs: 30_000,
	};
}

/**
 * Resolve the config path. Default is `~/.pi/keyrouter.json` — always under
 * the user profile, never project-scoped (keys are global credentials).
 * `PI_KEYROUTER_CONFIG` overrides it, which is what the test suite uses.
 *
 * @param _cwd ignored — config is always user-level
 * @param home override home dir (for testing)
 */
export function configPath(_cwd?: string, home?: string): string {
	const override = process.env["PI_KEYROUTER_CONFIG"] || undefined;
	if (override) return override;
	const homeDir = home ?? os.homedir();
	return path.join(homeDir, ".pi", "keyrouter.json");
}

/**
 * Path displayed in error messages / /keyrouter status so the user can see
 * exactly where we're looking.
 */
export function configSearchPaths(): string[] {
	return [configPath()];
}

export function loadConfig(_cwd?: string, home?: string): KeyRouterConfig {
	const file = configPath(undefined, home);
	if (!fs.existsSync(file)) return defaultConfig();
	try {
		const raw = fs.readFileSync(file, "utf-8");
		const parsed = JSON.parse(raw) as Partial<KeyRouterConfig>;
		return normalize(parsed);
	} catch {
		// bad config — fall through to default
		return defaultConfig();
	}
}

function normalize(input: Partial<KeyRouterConfig>): KeyRouterConfig {
	const providers = (input.providers ?? [])
		.map((p): ProviderPool | undefined => {
			if (typeof p?.name !== "string" || !p.name || !Array.isArray(p.keys)) return undefined;
			const keys = p.keys
				.map((k): ApiKey | undefined => {
					if (typeof k?.name !== "string" || typeof k?.value !== "string") return undefined;
					const value = expandEnv(k.value);
					if (!value || hasUnresolvedRef(value)) return undefined; // missing env var
					return { name: k.name, value };
				})
				.filter((k): k is ApiKey => k !== undefined);
			if (keys.length === 0) return undefined;
			return { name: p.name, keys, takeoverOAuth: p.takeoverOAuth === true };
		})
		.filter((p): p is ProviderPool => p !== undefined);
	return {
		providers,
		maxRetries: typeof input.maxRetries === "number" ? input.maxRetries : 3,
		cooldownMs: typeof input.cooldownMs === "number" ? input.cooldownMs : 60_000,
		overloadedCooldownMs:
			typeof input.overloadedCooldownMs === "number" ? input.overloadedCooldownMs : 30_000,
	};
}

