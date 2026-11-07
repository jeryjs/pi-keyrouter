// =============================================================================
// config.ts — load key router config from disk
// =============================================================================
//
// Config is GLOBAL (user-level), never project-scoped. API keys and OAuth
// credentials are personal credentials that do not belong inside a project
// directory (risk of leaking via git, shared repos, etc.).
//
// Single location: pi's agent dir (getAgentDir(), so PI_CODING_AGENT_DIR is
//   honoured) — Windows: %USERPROFILE%\.pi\agent\pi-keyrouter.json,
//   macOS/Linux: ~/.pi/agent/pi-keyrouter.json
// A config still at the pre-migration location ~/.pi/keyrouter.json is moved
// there on the first start (see migrateLegacyConfig below).
//
// The optional `$schema` reference below enables IDE completion and validation.
// Existing configuration files do not need it and are never migrated.
// Schema — API-key pool:
// {
//   "$schema": "https://raw.githubusercontent.com/jeryjs/pi-keyrouter/refs/heads/main/schema.json",
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
//   "overloadedCooldownMs": 30000,
//   "notifications": "all",  // "all" | "quiet" | "silent" — status-line volume
//   "strategy": "failover"  // per-provider: "failover" | "round-robin" |
//                           //   "stalest-first" | "random" — see README
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
//       "rotateOnQuota": true,
//       "strategy": "stalest-first" // per-provider: "failover" | "round-robin" |
//                               //   "stalest-first" | "random" — see README
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
//
// `notifications` tones the status lines down without losing events that matter:
//   all     (default) every event notifies
//   quiet   routine rate-limited rotations and overload notices go silent;
//           rotations that need the user to act (unauthorized key, account
//           quota, dead refresh token) still notify
//   silent  all rotation and overload notices go silent
// Pool exhaustion notifies in every mode — it is the one event where the
// request actually fails. An unknown value warns and falls back to "all".

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import type {
	AccountEntry,
	ApiKey,
	KeyRouterConfig,
	NotificationLevel,
	OAuthCredential,
	PoolKind,
	ProviderConfig as ProviderPool,
	RotationStrategy,
} from "./types.ts";
import { validateIdentityPath } from "./identity.ts";

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

// =============================================================================
// One writer at a time, across processes
// =============================================================================
//
// Every write-back below is a read-modify-write of the same file: read
// `keyrouter.json`, change ONE field, rename a temp file over it. Two pi
// processes doing that at once both read the same bytes, and the second rename
// throws the first process's change away. The file stays valid — the temp name
// carries the pid, so the bytes cannot interleave — but one update is lost.
//
// The lock closes that window: for every other process, the read and the rename
// become one step. It is a file because it has to be visible to other processes,
// and it lives in the lease directory rather than beside the config so that
// nothing a lock does can touch the file the user hand-edits. The create uses
// `wx`, which the filesystem makes atomic: two processes cannot both create it,
// so no further protocol is needed to pick a winner.
//
// The lock is held for microseconds, so one older than CONFIG_LOCK_TTL_MS was
// left by a writer that died. If it still cannot be taken after a short wait the
// writer goes ahead without it: a config write must never block a session, and
// an unlocked write is still atomic.

/** How long the write lock may exist before it is treated as abandoned. */
const CONFIG_LOCK_TTL_MS = 5_000;

/** How long a writer waits for the lock before writing without it. */
const CONFIG_LOCK_WAIT_MS = 10;

/** Re-entrancy depth per lock file, so a writer may call another writer. */
const writeLockDepth = new Map<string, number>();

/** Block this thread briefly, without a timer and without spinning. */
function sleepSync(ms: number): void {
	try {
		Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
	} catch {
		// No shared memory available: skip the wait. The caller's deadline still
		// bounds how long it tries.
	}
}

/** The lock file that guards config writes. It lives in the lease directory. */
function writeLockFile(): string {
	return path.join(leaseDir(), "config.lock");
}

/**
 * Take the write lock.
 *
 * False means "go on without it": the caller still writes atomically, it just
 * cannot promise that no concurrent update was lost.
 */
function acquireWriteLock(lock: string): boolean {
	try {
		fs.mkdirSync(path.dirname(lock), { recursive: true, mode: 0o700 });
	} catch {
		return false; // no lease directory: the writers stay atomic but unlocked
	}
	const deadline = Date.now() + CONFIG_LOCK_WAIT_MS;
	for (;;) {
		try {
			fs.writeFileSync(lock, `${process.pid}\n`, { encoding: "utf-8", flag: "wx", mode: 0o600 });
			return true;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") return false;
		}
		let age: number;
		try {
			age = Date.now() - fs.statSync(lock).mtimeMs;
		} catch {
			continue; // released between the create and the stat: try again
		}
		if (age > CONFIG_LOCK_TTL_MS) {
			// Its writer is gone. Removing is best effort; if it fails the next
			// attempt simply sees EEXIST again.
			try {
				fs.rmSync(lock, { force: true });
			} catch {
				return false;
			}
			continue;
		}
		if (Date.now() >= deadline) return false; // busy: write without it
		sleepSync(1);
	}
}

/** Release the lock, but never somebody else's. */
function releaseWriteLock(lock: string): void {
	try {
		if (fs.readFileSync(lock, "utf-8").trim() !== String(process.pid)) return;
	} catch {
		return; // already gone
	}
	try {
		fs.rmSync(lock, { force: true });
	} catch {
		// Best effort: a leftover lock is reclaimed once it ages past the TTL.
	}
}

/**
 * Run `fn` while holding the cross-process write lock for the config at `file`.
 *
 * Re-entrant within this process, so a write-back may call another write-back
 * without deadlocking on its own lock file.
 */
function withConfigWriteLock<T>(_file: string, fn: () => T): T {
	const lock = writeLockFile();
	const depth = writeLockDepth.get(lock) ?? 0;
	if (depth === 0 && !acquireWriteLock(lock)) return fn();
	writeLockDepth.set(lock, depth + 1);
	try {
		return fn();
	} finally {
		const left = (writeLockDepth.get(lock) ?? 1) - 1;
		if (left > 0) {
			writeLockDepth.set(lock, left);
		} else {
			writeLockDepth.delete(lock);
			releaseWriteLock(lock);
		}
	}
}


/**
 * Write a refreshed OAuth credential back into `keyrouter.json`, in place.
 *
 * WHY THIS EXISTS: pi owns refresh and persists the rotated access/refresh pair
 * to `auth.json`. keyrouter keeps its own copy of each account, and when it
 * installs account #2 it OVERWRITES what pi had stored — so a token pi refreshed
 * is lost unless the pool copy is updated first. Without this, every return to an
 * account would present the access token that was current at the last LOGIN
 * (typically ~1 hour of life), which after any real use is already expired, and
 * the account would appear dead.
 *
 * Note this matters even though Cline does not rotate refresh tokens: the
 * ACCESS token is what expires, and it is the access token that must be carried
 * forward.
 *
 * Rules that keep this safe:
 *   - Only accounts written as an INLINE OBJECT are eligible. An `@file` or
 *     `$ENV` credential is the user's own indirection, so leave it alone.
 *   - Only the four credential fields are touched. Every other field — including
 *     provider-specific ones such as `accountId` or `projectId` — is preserved,
 *     as is the rest of the file, its key order, and its 2-space formatting.
 *   - The write is atomic (temp file + rename) so an interrupted write cannot
 *     truncate a file holding live credentials.
 *   - The write is skipped when nothing changed, so a no-op load never rewrites
 *     the user's config.
 *   - A write failure is reported, never thrown: persistence is an optimization,
 *     and losing it must not break a session.
 *
 * @returns the number of accounts updated (0 when there was nothing to do)
 */
export function writeBackCredentials(
	updates: ReadonlyMap<string, OAuthCredential>,
	home?: string,
): { updated: number } | { error: string } {
	return withConfigWriteLock(configPath(undefined, home), () =>
		writeBackCredentialsNow(updates, home),
	);
}

function writeBackCredentialsNow(
	updates: ReadonlyMap<string, OAuthCredential>,
	home?: string,
): { updated: number } | { error: string } {
	if (updates.size === 0) return { updated: 0 };
	if (!configPath(undefined, home)) return { updated: 0 };
	const file = configPath(undefined, home);

	let rawText: string;
	let parsed: { providers?: Array<Record<string, unknown>> } & Record<string, unknown>;
	try {
		rawText = fs.readFileSync(file, "utf-8");
		parsed = JSON.parse(rawText) as typeof parsed;
	} catch (error) {
		return { error: `cannot read ${file}: ${(error as Error).message}` };
	}

	let updated = 0;
	for (const provider of parsed.providers ?? []) {
		if (typeof provider?.name !== "string") continue;
		const providerId = provider.name;
		const accounts = provider.accounts;
		if (!Array.isArray(accounts)) continue;
		for (const account of accounts) {
			if (typeof account !== "object" || account === null) continue;
			const entry = account as Record<string, unknown>;
			if (typeof entry.name !== "string") continue;
			const incoming = updates.get(`${providerId}\u0000${entry.name}`);
			if (!incoming) continue;
			// Only rewrite an inline object. A string form is the user's own `$ENV`
			// or `@file` reference, which must keep working the way they chose.
			const current = entry.credential;
			if (typeof current !== "object" || current === null || Array.isArray(current)) {
				continue;
			}
			const merged = { ...(current as Record<string, unknown>), ...incoming };
			if (JSON.stringify(merged) === JSON.stringify(current)) continue;
			entry.credential = merged;
			updated += 1;
		}
	}

	if (updated === 0) return { updated: 0 };

	// Atomic replace: write beside the target, then rename over it, so a crash
		// mid-write cannot leave a truncated file holding live credentials.
	// The temp name carries the pid: two pi processes writing the same config
	// must not share one temp file, or one of them renames the other's bytes.
	const temp = `${file}.${process.pid}.keyrouter.tmp`;
	const serialized = `${JSON.stringify(parsed, null, 2)}\n`;
	try {
		fs.writeFileSync(temp, serialized, { encoding: "utf-8", mode: 0o600 });
		fs.renameSync(temp, file);
	} catch (error) {
		try {
			fs.rmSync(temp, { force: true });
		} catch {
			// best effort cleanup
		}
		return { error: `cannot write ${file}: ${(error as Error).message}` };
	}
	return { updated };
}

/**
 * Write the active entry's name back into `keyrouter.json`, in place.
 *
 * This is what makes rotation survive a session: without it every session
 * restarts on entry #1 and has to rediscover the failures that moved the pool off
 * it. Same safety rules as `writeBackCredentials` — only the one field changes,
 * the rest of the file keeps its order and formatting, the write is atomic, it is
 * skipped when nothing moved, and a failure is reported rather than thrown.
 *
 * A NAME, not an index: the user edits this file, and reordering or inserting
 * entries shifts every index after it. An entry that has since been renamed or
 * deleted simply fails to match at read time and the pool starts at the first
 * entry, which is the correct fallback.
 *
 * @returns the number of pools updated (0 when there was nothing to do)
 */
export function writeBackActive(
	providerName: string,
	entryName: string | undefined,
	home?: string,
): { updated: number } | { error: string } {
	return withConfigWriteLock(configPath(undefined, home), () =>
		writeBackActiveNow(providerName, entryName, home),
	);
}

function writeBackActiveNow(
	providerName: string,
	entryName: string | undefined,
	home?: string,
): { updated: number } | { error: string } {
	const file = configPath(undefined, home);
	let rawText: string;
	let parsed: { providers?: Array<Record<string, unknown>> } & Record<string, unknown>;
	try {
		rawText = fs.readFileSync(file, "utf-8");
		parsed = JSON.parse(rawText) as typeof parsed;
	} catch (error) {
		return { error: `cannot read ${file}: ${(error as Error).message}` };
	}

	let updated = 0;
	for (const provider of parsed.providers ?? []) {
		if (provider?.name !== providerName) continue;
		if (entryName === undefined) {
			// Forget the position (`/keyrouter reset`) rather than store a null, so the
			// field only ever holds a real entry name.
			if (provider.active === undefined) continue;
			delete provider.active;
		} else {
			if (provider.active === entryName) continue;
			provider.active = entryName;
		}
		updated += 1;
		// Only the FIRST pool with this name is edited — see writeBackPoolEntry.
		break;
	}
	if (updated === 0) return { updated: 0 };

	// The temp name carries the pid: two pi processes writing the same config
	// must not share one temp file, or one of them renames the other's bytes.
	const temp = `${file}.${process.pid}.keyrouter.tmp`;
	try {
		fs.writeFileSync(temp, `${JSON.stringify(parsed, null, 2)}\n`, { encoding: "utf-8", mode: 0o600 });
		fs.renameSync(temp, file);
	} catch (error) {
		try {
			fs.rmSync(temp, { force: true });
		} catch {
			// best effort cleanup
		}
		return { error: `cannot write ${file}: ${(error as Error).message}` };
	}
	return { updated };
}

/**
 * Write a pool's `strategy` back into `keyrouter.json`, in place.
 *
 * `/keyrouter strategy` persists here because a strategy is only useful if the
 * next session starts with it — a change that dies with the process would make
 * the command a lie. Setting `"failover"` DELETES the field rather than writing
 * the word: absent already means failover (`normalizeStrategy`), so the file
 * keeps only what the user actually chose. Same safety rules as the other
 * write-backs — only this one field changes, the write is atomic and skipped
 * when nothing moved, and a failure is reported rather than thrown.
 *
 * @returns the number of pools updated (0 when there was nothing to do)
 */
export function writeBackStrategy(
	providerName: string,
	strategy: RotationStrategy,
	home?: string,
): { updated: number } | { error: string } {
	return withConfigWriteLock(configPath(undefined, home), () =>
		writeBackStrategyNow(providerName, strategy, home),
	);
}

function writeBackStrategyNow(
	providerName: string,
	strategy: RotationStrategy,
	home?: string,
): { updated: number } | { error: string } {
	const file = configPath(undefined, home);
	let rawText: string;
	let parsed: { providers?: Array<Record<string, unknown>> } & Record<string, unknown>;
	try {
		rawText = fs.readFileSync(file, "utf-8");
		parsed = JSON.parse(rawText) as typeof parsed;
	} catch (error) {
		return { error: `cannot read ${file}: ${(error as Error).message}` };
	}

	let updated = 0;
	for (const provider of parsed.providers ?? []) {
		if (provider?.name !== providerName) continue;
		if (strategy === "failover") {
			if (provider.strategy === undefined) continue;
			delete provider.strategy;
		} else {
			if (provider.strategy === strategy) continue;
			provider.strategy = strategy;
		}
		updated += 1;
		// Only the FIRST pool with this name is edited — see writeBackPoolEntry.
		break;
	}
	if (updated === 0) return { updated: 0 };

	// The temp name carries the pid: two pi processes writing the same config
	// must not share one temp file, or one of them renames the other's bytes.
	const temp = `${file}.${process.pid}.keyrouter.tmp`;
	try {
		fs.writeFileSync(temp, `${JSON.stringify(parsed, null, 2)}\n`, { encoding: "utf-8", mode: 0o600 });
		fs.renameSync(temp, file);
	} catch (error) {
		try {
			fs.rmSync(temp, { force: true });
		} catch {
			// best effort cleanup
		}
		return { error: `cannot write ${file}: ${(error as Error).message}` };
	}
	return { updated };
}

/**
 * Write the top-level `notifications` level back into `keyrouter.json`.
 *
 * Same safety rules as the other write-backs: only this one field changes,
 * the rest of the file keeps its order and 2-space formatting, the write is
 * atomic, it is skipped when nothing moved, and a failure is reported rather
 * than thrown.
 *
 * @returns 1 when the level changed, 0 when it was already current
 */
export function writeBackNotifications(
	level: NotificationLevel,
	home?: string,
): { updated: number } | { error: string } {
	return withConfigWriteLock(configPath(undefined, home), () =>
		writeBackNotificationsNow(level, home),
	);
}

function writeBackNotificationsNow(
	level: NotificationLevel,
	home?: string,
): { updated: number } | { error: string } {
	const file = configPath(undefined, home);
	let rawText: string;
	try {
		rawText = fs.readFileSync(file, "utf-8");
	} catch (error) {
		return { error: `cannot read ${file}: ${(error as Error).message}` };
	}

	let parsed: Record<string, unknown>;
	try {
		const value: unknown = JSON.parse(rawText);
		if (typeof value !== "object" || value === null || Array.isArray(value)) {
			return { error: `${file} is not a JSON object` };
		}
		parsed = value as Record<string, unknown>;
	} catch {
		// Do not include the parser's message: it may quote part of the file,
		// which can contain credentials.
		return { error: `cannot parse ${file} as JSON` };
	}

	if (parsed.notifications === level) return { updated: 0 };
	parsed.notifications = level;

	// The temp name carries the pid: two pi processes writing the same config
	// must not share one temp file, or one of them renames the other's bytes.
	const temp = `${file}.${process.pid}.keyrouter.tmp`;
	try {
		fs.writeFileSync(temp, `${JSON.stringify(parsed, null, 2)}\n`, { encoding: "utf-8", mode: 0o600 });
		fs.renameSync(temp, file);
	} catch (error) {
		try {
			fs.rmSync(temp, { force: true });
		} catch {
			// best effort cleanup
		}
		return { error: `cannot write ${file}: ${(error as Error).message}` };
	}
	return { updated: 1 };
}

type ExternalPoolReference =
	| { kind: "environment"; target: string }
	| { kind: "file"; target: string };

/**
 * Detect an external source in a RAW pool field.
 *
 * The normalized config has already expanded these references, so this check is
 * deliberately done against the string still present in the file. An OAuth
 * credential may be stored in `$ENV` / `${ENV}` / `@file`; an API-key value may
 * use the same environment-variable forms. Those sources belong to the user and
 * must not be replaced with an inline secret by an in-place update.
 */
function externalPoolReference(raw: unknown): ExternalPoolReference | undefined {
	if (typeof raw !== "string") return undefined;
	const trimmed = raw.trim();
	if (trimmed.startsWith("@")) {
		return { kind: "file", target: trimmed.slice(1).trim() || trimmed };
	}
	// Match one environment reference, but not the escaped `$$NAME` form.
	const match = /(?<!\$)\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/.exec(trimmed);
	const variable = match?.[1] ?? match?.[2];
	return variable ? { kind: "environment", target: variable } : undefined;
}

/** Explain why an external-backed entry cannot be updated in place. */
function externalReferenceError(
	providerName: string,
	entryName: string,
	field: "value" | "credential",
	reference: ExternalPoolReference,
): string {
	const source =
		reference.kind === "environment"
			? `environment variable "${reference.target}"`
			: `file "${reference.target}"`;
	const action = reference.kind === "environment" ? "update that environment variable instead" : "update that file instead";
	return `refusing to update "${entryName}" in "${providerName}": ${field} is stored in ${source}; ${action}`;
}

/**
 * Choose a unique name for a generated pool entry.
 *
 * A readable identity can already be in use. Keep the readable base and add the
 * first free numeric suffix (`name-2`, `name-3`, ...) rather than silently
 * replacing or skipping the generated name.
 */
export function uniquePoolEntryName(
	base: string,
	existingNames: readonly string[],
): { name: string; adjusted: boolean } {
	const wanted = base.trim() || "entry";
	// Names that differ only in case are the same name to the user, so they
	// collide: adding "Work" next to "work" would make every later lookup
	// ambiguous.
	const taken = new Set(existingNames.map((name) => name.toLowerCase()));
	const wantedKey = wanted.toLowerCase();
	if (!taken.has(wantedKey)) return { name: wanted, adjusted: false };
	let suffix = 2;
	while (taken.has(`${wantedKey}-${suffix}`)) suffix += 1;
	return { name: `${wanted}-${suffix}`, adjusted: true };
}

/**
 * Add, update, or remove ONE entry of a pool, in place.
 *
 * This is what the guided `/keyrouter add` and `/keyrouter remove` commands
 * write through. Same safety rules as the other write-backs: only the pool's
 * own entry list changes, every other field keeps its value and its order (the
 * file is written back as two-space JSON), the write is atomic, it is skipped
 * when nothing changed, and a failure is reported rather than thrown.
 *
 * The entry is written in the form the pool already uses: a `keys` pool gets
 * `{name, value}`, an `accounts` pool gets `{name, credential}`. A pool with
 * neither list is left alone — a command does not invent a pool that the
 * config file does not have. An `update` changes only the named entry's value
 * or credential; an external `$ENV` / `${ENV}` / `@file` source is refused.
 *
 * @returns the number of pools updated (0 when there was nothing to do)
 */
export function writeBackPoolEntry(
	providerName: string,
	action: "add" | "update" | "remove",
	entry: { name: string; value?: string; credential?: OAuthCredential },
	home?: string,
): { updated: number } | { error: string } {
	return withConfigWriteLock(configPath(undefined, home), () =>
		writeBackPoolEntryNow(providerName, action, entry, home),
	);
}

function writeBackPoolEntryNow(
	providerName: string,
	action: "add" | "update" | "remove",
	entry: { name: string; value?: string; credential?: OAuthCredential },
	home?: string,
): { updated: number } | { error: string } {
	const file = configPath(undefined, home);
	let rawText: string;
	let parsed: { providers?: Array<Record<string, unknown>> } & Record<string, unknown>;
	try {
		rawText = fs.readFileSync(file, "utf-8");
		parsed = JSON.parse(rawText) as typeof parsed;
	} catch (error) {
		return { error: `cannot read ${file}: ${(error as Error).message}` };
	}

	let updated = 0;
	for (const provider of parsed.providers ?? []) {
		if (provider?.name !== providerName) continue;
		const keys = Array.isArray(provider.keys)
			? (provider.keys as Array<Record<string, unknown>>)
			: undefined;
		const accounts = Array.isArray(provider.accounts)
			? (provider.accounts as Array<Record<string, unknown>>)
			: undefined;
		const list = keys ?? accounts;
		if (!list) continue;

		if (action === "add") {
			if (list.some((item) => item?.name === entry.name)) continue;
			if (keys) {
				if (typeof entry.value !== "string") continue;
				list.push({ name: entry.name, value: entry.value });
			} else {
				if (!entry.credential) continue;
				list.push({ name: entry.name, credential: entry.credential });
				// An account captured from pi's own store becomes the pool's active
				// account: the user signed into it on purpose, and the reload that
				// follows must not switch pi back to the account it had before.
				provider.active = entry.name;
			}
		} else if (action === "update") {
			const item = list.find((candidate) => candidate?.name === entry.name);
			if (!item) continue;
			if (keys) {
				if (typeof entry.value !== "string") continue;
				if (typeof item.value !== "string") {
					return { error: `entry "${entry.name}" in "${providerName}" has no inline value to update` };
				}
				const reference = externalPoolReference(item.value);
				if (reference) {
					return { error: externalReferenceError(providerName, entry.name, "value", reference) };
				}
				if (item.value === entry.value) continue;
				item.value = entry.value;
			} else {
				if (!entry.credential) continue;
				const reference = externalPoolReference(item.credential);
				if (reference) {
					return { error: externalReferenceError(providerName, entry.name, "credential", reference) };
				}
				if (typeof item.credential !== "object" || item.credential === null || Array.isArray(item.credential)) {
					return { error: `entry "${entry.name}" in "${providerName}" has no inline credential to update` };
				}
				if (JSON.stringify(item.credential) === JSON.stringify(entry.credential)) continue;
				item.credential = entry.credential;
				// Same for an account whose credential was just refreshed: pi is
				// logged into it right now, so it stays the active one.
				provider.active = entry.name;
			}
		} else {
			const index = list.findIndex((item) => item?.name === entry.name);
			if (index < 0) continue;
			list.splice(index, 1);
			// The saved position may have pointed at the entry that just went away:
			// forget it rather than leave a name that resolves to nothing.
			if (provider.active === entry.name) delete provider.active;
		}
		updated += 1;
		// Only the FIRST pool with this name is edited. Two pools sharing a name
		// are a config mistake, and touching both would change a pool the user
		// did not name.
		break;
	}
	if (updated === 0) return { updated: 0 };

	// The temp name carries the pid: two pi processes writing the same config
	// must not share one temp file, or one of them renames the other's bytes.
	const temp = `${file}.${process.pid}.keyrouter.tmp`;
	try {
		fs.writeFileSync(temp, `${JSON.stringify(parsed, null, 2)}\n`, { encoding: "utf-8", mode: 0o600 });
		fs.renameSync(temp, file);
	} catch (error) {
		try {
			fs.rmSync(temp, { force: true });
		} catch {
			// best effort cleanup
		}
		return { error: `cannot write ${file}: ${(error as Error).message}` };
	}
	return { updated };
}

export function defaultConfig(): KeyRouterConfig {
	return {
		providers: [],
		maxRetries: 3,
		cooldownMs: 60_000,
		overloadedCooldownMs: 30_000,
		notifications: "all" satisfies NotificationLevel,
	};
}

/**
 * Resolve the config path. Default is pi's agent dir (`getAgentDir()`, so
 * `PI_CODING_AGENT_DIR` is honoured) — user-level, never project-scoped (keys
 * are global credentials). `PI_KEYROUTER_CONFIG` overrides it, which is what
 * the test suite uses.
 *
 * @param _cwd ignored — config is always user-level
 * @param _home ignored — the path follows pi's agent dir; override it with
 *   `PI_KEYROUTER_CONFIG` instead
 */
export function configPath(_cwd?: string, _home?: string): string {
	const override = process.env["PI_KEYROUTER_CONFIG"] || undefined;
	if (override) return override;
	return path.join(getAgentDir(), "pi-keyrouter.json");
}

/** Directory (inside pi's extensions dir) that holds the lease files. */
const LEASE_DIR_NAME = ".pi-keyrouter-leases";

/**
 * The directory that holds the lease files (entry claims, provider sweep
 * claims, and the config write lock).
 *
 * It lives inside pi's extensions directory under a dot-prefixed name: hidden
 * by default, and ignored by pi's extension discovery (it holds no entry
 * points), so the agent dir root stays pi's own. The leases describe the same
 * pool as the config, so they follow the same agent dir — `PI_CODING_AGENT_DIR`
 * moves both, while `PI_KEYROUTER_CONFIG` moves only the config file.
 */
export function leaseDir(): string {
	return path.join(getAgentDir(), "extensions", LEASE_DIR_NAME);
}

/** The config location before the move into pi's agent dir. */
export function legacyConfigPath(home?: string): string {
	return path.join(home ?? os.homedir(), ".pi", "keyrouter.json");
}

/**
 * True when a config still sits at the legacy location and the current one has
 * no file yet — i.e. `migrateLegacyConfig` has something to move.
 *
 * `PI_KEYROUTER_CONFIG` opts out entirely: an explicit override means "use
 * exactly this file", so the legacy file is never touched. This is also what
 * keeps the test suite hermetic.
 *
 * @param home override home dir (for testing)
 */
export function needsLegacyConfigMigration(home?: string): boolean {
	if (process.env["PI_KEYROUTER_CONFIG"]) return false;
	if (fs.existsSync(configPath())) return false;
	return fs.existsSync(legacyConfigPath(home));
}

/**
 * Move the config from the legacy location to the current one, so an updated
 * install keeps its pools without a hand edit. A rename keeps every file
 * property; paths on different filesystems (a `PI_CODING_AGENT_DIR` on another
 * mount) cannot rename, so that falls back to a copy and leaves the original
 * in place. Returns true when the config sits at the new location afterwards.
 *
 * @param home override home dir (for testing)
 */
export function migrateLegacyConfig(home?: string): boolean {
	if (!needsLegacyConfigMigration(home)) return false;
	const from = legacyConfigPath(home);
	const to = configPath();
	try {
		fs.mkdirSync(path.dirname(to), { recursive: true });
		try {
			fs.renameSync(from, to);
		} catch {
			// Cross-device rename failed: copy instead. The copy cannot inherit the
			// original's mode, so tighten it the way keyrouter's own writes do.
			fs.copyFileSync(from, to);
			fs.chmodSync(to, 0o600);
		}
		return true;
	} catch {
		return false;
	}
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

export const STRATEGIES: ReadonlySet<string> = new Set([
	"failover",
	"round-robin",
	"stalest-first",
	"random",
]);

/**
 * Resolve a pool's `strategy`. The default is "failover" — the historical
 * behavior — so an absent or mistyped value never changes rotation for a pool
 * whose owner did not ask for it. `stalest-first` orders accounts by token
 * expiry, which a `keys` pool does not have; rather than silently keeping the
 * default, it degrades to the closest intent (spread usage) with a warning.
 */
export function normalizeStrategy(
	raw: unknown,
	kind: PoolKind,
	poolName: string,
	warnings: string[],
): RotationStrategy {
	if (raw === undefined) return "failover";
	if (typeof raw === "string" && STRATEGIES.has(raw)) {
		if (raw === "stalest-first" && kind === "keys") {
			warnings.push(
				`"${poolName}": "stalest-first" orders accounts by token expiry, which a "keys" pool does not have — using "round-robin".`,
			);
			return "round-robin";
		}
		return raw as RotationStrategy;
	}
	warnings.push(
		`"${poolName}": ${JSON.stringify(raw)} is not one of "failover", "round-robin", "stalest-first", "random" — using "failover".`,
	);
	return "failover";
}

function normalize(input: Partial<KeyRouterConfig>): KeyRouterConfig {
	const warnings: string[] = [];
	const providers: ProviderPool[] = [];
	// Pool names are provider ids, and provider ids are matched case-
	// insensitively, so two pools whose names differ only in case are the same
	// pool. The first one wins; the rest are reported and ignored.
	const seenNames = new Set<string>();

	for (const raw of input.providers ?? []) {
		if (typeof raw?.name !== "string" || !raw.name) continue;
		const nameKey = raw.name.toLowerCase();
		if (seenNames.has(nameKey)) {
			warnings.push(
				`"${raw.name}": duplicate pool name — only the first pool with this name is used.`,
			);
			continue;
		}
		seenNames.add(nameKey);
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
				// The pool is KEPT, not dropped: an empty pool is how a pool looks
				// before its first entry is added, and `/keyrouter add` has to be
				// able to find it there. It installs nothing until it has a key.
				warnings.push(`"${raw.name}": no usable keys after expansion — the pool is empty.`);
			}
			if (raw.identityPath !== undefined) {
				// Identity attribution only ever happens for an OAuth pool, where a
				// credential is written back into a named account. An api-key pool has
				// no such write, so the field is meaningless — say so rather than
				// silently accepting a setting that changes nothing.
				warnings.push(`"${raw.name}": "identityPath" applies only to "accounts" pools — ignored.`);
			}
			if (raw.sweepRefresh !== undefined) {
				// The idle-account sweep exchanges OAuth refresh tokens. An api-key
				// pool has no tokens, so the option cannot mean anything here.
				warnings.push(`"${raw.name}": "sweepRefresh" applies only to "accounts" pools — ignored.`);
			}
			providers.push({
				name: raw.name,
				match: Array.isArray(raw.match) ? raw.match : [],
				keys,
				kind: "keys" satisfies PoolKind,
				takeoverOAuth: raw.takeoverOAuth === true,
				strategy: normalizeStrategy(raw.strategy, "keys" satisfies PoolKind, raw.name, warnings),
				sweepRefresh: false,
				active: typeof raw.active === "string" ? raw.active : undefined,
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
				// Kept, not dropped — see the keys branch above: an empty pool is
				// where `/keyrouter add` puts the first account.
				warnings.push(`"${raw.name}": no usable accounts — the pool is empty.`);
			}

			// Where this provider's account identity lives. Checked for structural
			// sanity here; whether it RESOLVES depends on a credential that may not
			// exist yet, so that check happens at use time and falls through with a
			// warning rather than dropping the pool.
			const identityPath = validateIdentityPath(raw.identityPath);
			if (raw.identityPath !== undefined && !identityPath.ok) {
				warnings.push(`"${raw.name}": "identityPath" ${identityPath.reason} — ignored.`);
			}
			providers.push({
				name: raw.name,
				match: Array.isArray(raw.match) ? raw.match : [],
				accounts,
				kind: "oauth" satisfies PoolKind,
				// Each OAuth account is a separate subscription, so an account-level
				// limit is exactly when the next account is wanted. Default true.
			rotateOnQuota: raw.rotateOnQuota !== false,
			strategy: normalizeStrategy(raw.strategy, "oauth" satisfies PoolKind, raw.name, warnings),
			// The idle-account sweep is opt-in per pool. Off unless the config
			// says so: see TODO.md for what still has to be fixed before it can be
			// recommended.
			sweepRefresh: raw.sweepRefresh === true,
			identityPath: identityPath.ok ? identityPath.path : undefined,
			active: typeof raw.active === "string" ? raw.active : undefined,
		});
			continue;
		}

		if (raw.name) {
			warnings.push(`"${raw.name}": needs either "keys" or "accounts" — skipped.`);
		}
	}

	// Status-line volume. Unknown values warn rather than break: a typo must
	// not silently stop the user's rotation notices from appearing.
	let notifications: NotificationLevel = "all";
	if (input.notifications !== undefined) {
		if (
			input.notifications === "all" ||
			input.notifications === "quiet" ||
			input.notifications === "silent"
		) {
			notifications = input.notifications;
		} else {
			warnings.push(
				`"notifications": ${JSON.stringify(input.notifications)} is not one of "all", "quiet", "silent" — using "all".`,
			);
		}
	}

	return {
		providers,
		maxRetries: typeof input.maxRetries === "number" ? input.maxRetries : 3,
		cooldownMs: typeof input.cooldownMs === "number" ? input.cooldownMs : 60_000,
		overloadedCooldownMs:
			typeof input.overloadedCooldownMs === "number" ? input.overloadedCooldownMs : 30_000,
		notifications,
		warnings,
	};
}