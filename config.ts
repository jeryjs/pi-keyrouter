// =============================================================================
// config.ts — load key router config from disk
// =============================================================================
//
// Config is GLOBAL (user-level), never project-scoped. API keys and OAuth
// credentials are personal credentials that do not belong inside a project
// directory (risk of leaking via git, shared repos, etc.).
//
// Single location: ~/.pi/keyrouter.json
//   - Windows: %USERPROFILE%\.pi\keyrouter.json
//   - macOS/Linux: ~/.pi/keyrouter.json
//
// Schema — API-key pool:
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
// Schema — OAuth account pool (mutually exclusive with `keys`):
// {
//   "providers": [
//     {
//       "name": "cline",
//       "accounts": [
//         { "name": "work", "credential": { "type": "oauth", "access": "...", "refresh": "...", "expires": 1234567890 } },
//         { "name": "home", "credential": "$CLINE_ACCOUNT_2" },
//         { "name": "third", "credential": "@~/.pi/accounts/cline3.json" }
//       ],
//       "rotateOnQuota": true
//     }
//   ]
// }
//
// `value` may be a literal key, or reference environment variables with
// `$NAME` / `${NAME}` (same syntax pi uses in models.json). Prefer env refs so
// secrets never sit on disk. A value that still references a missing variable
// after expansion is dropped.
//
// `credential` accepts, for an OAuth account:
//   - an inline object
//   - `$NAME` / `${NAME}` where the environment variable holds a JSON string
//   - `@path` (leading `@`, `~` expanded) pointing at a JSON file with one object
// A credential is used only if it has type "oauth", a non-empty string `access`,
// a string `refresh`, and a numeric `expires`. Anything else is dropped with a
// warning naming the account — never the value.
//
// `name` is the provider id pi uses — built-in (`google`, `anthropic`), a
// `models.json` id, or another extension's id. `match` is accepted and ignored
// for backward compatibility.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type {
	AccountEntry,
	ApiKey,
	KeyRouterConfig,
	OAuthCredential,
	PoolKind,
	ProviderConfig as ProviderPool,
} from "./types.ts";

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

/** Expand a leading `~` to the home directory. */
function expandHome(value: string): string {
	if (value === "~") return os.homedir();
	if (value.startsWith("~/") || value.startsWith("~\\")) {
		return path.join(os.homedir(), value.slice(2));
	}
	return value;
}

/**
 * Validate an already-parsed value as an OAuth credential. Returns a shallow
 * copy restricted to JSON-safe data, or undefined with a reason.
 *
 * The blob is otherwise passed through untouched: provider-specific fields
 * (accountId, projectId, clientId, machineID, availableModelIds, ...) must
 * survive, so nothing here enumerates or drops them.
 */
export function validateCredential(
	value: unknown,
): { credential: OAuthCredential } | { error: string } {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return { error: "not a JSON object" };
	}
	const raw = value as Record<string, unknown>;
	if (raw["type"] !== "oauth") {
		return { error: `type is ${JSON.stringify(raw["type"])}, expected "oauth"` };
	}
	if (typeof raw["access"] !== "string" || raw["access"].length === 0) {
		return { error: "missing or empty `access`" };
	}
	if (typeof raw["refresh"] !== "string") {
		return { error: "missing `refresh`" };
	}
	if (typeof raw["expires"] !== "number" || !Number.isFinite(raw["expires"])) {
		return { error: "missing numeric `expires`" };
	}
	// Round-trip through JSON so only serializable data is carried into the pool
	// and no live object (or prototype) is shared with the config file.
	let clone: OAuthCredential;
	try {
		clone = JSON.parse(JSON.stringify(raw)) as OAuthCredential;
	} catch {
		return { error: "not JSON-serializable" };
	}
	clone.type = "oauth";
	return { credential: clone };
}

/**
 * Resolve one `credential` field from config into an OAuth credential.
 *
 * Accepts an inline object, `$ENV` holding a JSON string, or `@file`.
 * Secrets are never included in the returned error text.
 */
export function parseAccountCredential(
	raw: unknown,
): { credential: OAuthCredential } | { error: string } {
	// 1. Inline object.
	if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
		return validateCredential(raw);
	}
	if (typeof raw !== "string" || raw.length === 0) {
		return { error: `expected an object, "$VAR", or "@file"` };
	}

	// 2. `@path` — a JSON file holding one credential object.
	if (raw.startsWith("@")) {
		const filePath = expandHome(raw.slice(1).trim());
		if (!filePath) return { error: "empty @file path" };
		let text: string;
		try {
			text = fs.readFileSync(filePath, "utf-8");
		} catch (error) {
			// Report the path (the user needs it) but never file contents.
			const code = (error as NodeJS.ErrnoException)?.code ?? "read error";
			return { error: `cannot read ${filePath} (${code})` };
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch {
			return { error: `${filePath} is not valid JSON` };
		}
		return validateCredential(parsed);
	}

	// 3. `$ENV` / bare env name holding a JSON string.
	const expanded = expandEnv(raw);
	if (hasUnresolvedRef(expanded)) {
		return { error: "references an environment variable that is not set" };
	}
	const trimmed = expanded.trim();
	if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
		// A bare token (e.g. an access token) cannot carry `refresh`/`expires`,
		// so it is never a usable OAuth credential.
		return { error: "environment value is not a JSON object" };
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(trimmed);
	} catch {
		return { error: "environment value is not valid JSON" };
	}
	return validateCredential(parsed);
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
	const warnings: string[] = [];
	const providers: ProviderPool[] = [];

	for (const raw of input.providers ?? []) {
		if (typeof raw?.name !== "string" || !raw.name) continue;
		const hasKeys = Array.isArray(raw.keys);
		const hasAccounts = Array.isArray(raw.accounts);

		if (hasKeys && hasAccounts) {
			warnings.push(
				`"${raw.name}": both "keys" and "accounts" are present — these are mutually exclusive; ignoring "accounts".`,
			);
		}

		// API-key pool.
		if (hasKeys) {
			const keys = (raw.keys as unknown[])
				.map((k): ApiKey | undefined => {
					const entry = k as Partial<ApiKey> | undefined;
					if (typeof entry?.name !== "string" || typeof entry?.value !== "string") {
						return undefined;
					}
					const value = expandEnv(entry.value);
					if (!value || hasUnresolvedRef(value)) return undefined; // missing env var
					return { name: entry.name, value };
				})
				.filter((k): k is ApiKey => k !== undefined);
			if (keys.length === 0) {
				warnings.push(`"${raw.name}": no usable keys after expansion — pool dropped.`);
				continue;
			}
			providers.push({
				name: raw.name,
				match: Array.isArray(raw.match) ? raw.match : [],
				keys,
				kind: "keys" satisfies PoolKind,
				takeoverOAuth: raw.takeoverOAuth === true,
			});
			continue;
		}

		// OAuth account pool.
		if (hasAccounts) {
			const accounts: AccountEntry[] = [];
			for (const entry of raw.accounts as unknown[]) {
				const item = entry as Partial<AccountEntry> | undefined;
				const label =
					typeof item?.name === "string" && item.name ? item.name : `(account ${accounts.length + 1})`;
				if (typeof item?.name !== "string" || !item.name) {
					warnings.push(`"${raw.name}": an account is missing "name" — skipped.`);
					continue;
				}
				const parsed = parseAccountCredential(item.credential);
				if ("error" in parsed) {
					warnings.push(`"${raw.name}" account "${label}": ${parsed.error} — skipped.`);
					continue;
				}
				accounts.push({ name: item.name, credential: parsed.credential });
			}
			if (accounts.length === 0) {
				warnings.push(`"${raw.name}": no usable accounts — pool dropped.`);
				continue;
			}
			providers.push({
				name: raw.name,
				match: Array.isArray(raw.match) ? raw.match : [],
				accounts,
				kind: "oauth" satisfies PoolKind,
				// Each OAuth account is a separate subscription, so an account-level
				// limit is exactly when the next account is wanted. Default true.
				rotateOnQuota: raw.rotateOnQuota !== false,
			});
			continue;
		}

		if (raw.name) {
			warnings.push(`"${raw.name}": needs either "keys" or "accounts" — skipped.`);
		}
	}

	return {
		providers,
		maxRetries: typeof input.maxRetries === "number" ? input.maxRetries : 3,
		cooldownMs: typeof input.cooldownMs === "number" ? input.cooldownMs : 60_000,
		overloadedCooldownMs:
			typeof input.overloadedCooldownMs === "number" ? input.overloadedCooldownMs : 30_000,
		warnings,
	};
}