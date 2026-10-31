/**
 * Credential leases: exclusive claims on pool entries and provider sweeps.
 *
 * WHAT THIS IS
 * An entry lease says "this process is using this pool entry right now". It
 * exists so two pi processes that share a pool do not pile onto the same
 * credential: the first process to install an entry claims it, and the second
 * one sees the claim and picks a different entry instead.
 *
 * A provider sweep claim says "this process is refreshing the idle accounts
 * for this OAuth provider right now". It prevents two sessions from exchanging
 * the same refresh token or racing their whole-config write-back.
 *
 * WHY A FILE
 * The claim has to be visible to OTHER processes, so it cannot live in memory.
 * A file per claim is used rather than a lock file around the config, because:
 *   - the claim is created with an EXCLUSIVE create (`wx`), which the
 *     filesystem makes atomic: two processes racing for the same entry cannot
 *     both win, and no lock protocol is needed;
 *   - a claim is released by removing the file, which is equally atomic;
 *   - the user's own `keyrouter.json` stays untouched — this lives in its own
 *     directory, so nothing a lease does can corrupt a hand-edited config.
 *
 * WHY ENTRY LEASES ARE API-KEY ONLY
 * pi's OAuth credential store holds exactly ONE credential per provider id
 * (`auth.json` is `{ [providerId]: credential }`), and every process reads the
 * same file. Two processes therefore cannot hold two different accounts for
 * one provider — there is no slot to lease. OAuth pool entries do not use
 * entry leases; spreading OAuth accounts across processes needs a distinct
 * provider id per account, which is a different architecture (see the README).
 *
 * The idle-account sweep is different: it does not install anything into pi's
 * credential store. It refreshes a pool account directly and writes the shared
 * config, so OAuth providers use a separate provider-scoped sweep claim. That
 * claim is not visible to the entry-lease API.
 *
 * STALE CLAIMS
 * A process that dies without releasing leaves its claim behind. A claim is
 * stale when its owner process is gone (`kill(pid, 0)`), or when the file is
 * older than the TTL (which also covers a recycled pid). A stale claim is
 * removed and may be taken over.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { configPath } from "./config.ts";

/** Directory (under the agent dir) that holds the lease files. */
const LEASE_DIR_NAME = "keyrouter-leases";

/**
 * How long a claim may live before it is treated as abandoned.
 *
 * A live process keeps its claim for as long as it uses the entry, which can
 * be days. The TTL only exists to catch a recycled pid — Linux hands pids out
 * cyclically, so a pid alone is not proof that its owner is still there — so
 * it is generous: long enough that no real session is ever cut short, short
 * enough that a leftover claim does not block the entry forever.
 */
const LEASE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * How long a provider sweep claim may live before it is treated as abandoned.
 *
 * The sweep renews its claim before every account, and each refresh exchange
 * has a 15-second cap. This leaves ample room for a legitimate sweep while
 * ensuring that a claim whose pid was recycled cannot block the provider for
 * long. A claim whose owner is already gone is reclaimed immediately.
 */
const SWEEP_LEASE_TTL_MS = 5 * 60 * 1000;

/**
 * The directory that holds the lease files.
 *
 * It sits NEXT TO the config file, in a directory of its own: the leases
 * describe the same pool as `keyrouter.json`, so they share its scope (and
 * its `PI_KEYROUTER_CONFIG` override), and they never touch the config file
 * the user hand-edits. A sibling directory rather than a subdirectory of
 * `~/.pi` keeps the two artifacts apart.
 */
export function leaseDir(configFile?: string): string {
	const file = configFile ?? configPath();
	return path.join(path.dirname(path.resolve(file)), LEASE_DIR_NAME);
}

/**
 * A file-name-safe form of a provider id.
 *
 * Provider ids are provider-controlled strings, so they may contain a slash
 * (which would create a directory) or characters a file system dislikes. Only
 * the safe alphabet is kept; everything else is percent-encoded.
 */
function safeName(value: string): string {
	return value.replace(/[^A-Za-z0-9._-]/g, (char) => {
		return `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`;
	});
}

/** The file that holds the claim for one pool entry. */
function leaseFile(providerId: string, index: number, configFile?: string): string {
	return path.join(leaseDir(configFile), `${safeName(providerId)}.${index}.lease`);
}

/** The file that holds the provider-wide sweep claim. */
function sweepLeaseFile(providerId: string, configFile?: string): string {
	return path.join(leaseDir(configFile), `${safeName(providerId)}.sweep-lease`);
}

/** The pid recorded in a claim file, or undefined when it cannot be read. */
function readOwner(file: string): number | undefined {
	try {
		const raw = fs.readFileSync(file, "utf-8").trim();
		const pid = Number(raw);
		return Number.isInteger(pid) && pid > 0 ? pid : undefined;
	} catch {
		return undefined;
	}
}

/** True when a process with this pid is still running. */
function pidAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		// EPERM means the process exists but belongs to another user.
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
}

/** True when a claim is abandoned and may be taken over. */
function isStale(file: string, owner: number | undefined, ttlMs = LEASE_TTL_MS): boolean {
	if (owner === undefined) return true; // unreadable or empty: nobody can own it
	if (!pidAlive(owner)) return true;
	try {
		const age = Date.now() - fs.statSync(file).mtimeMs;
		return age > ttlMs;
	} catch {
		return true; // the file vanished under us
	}
}

/**
 * Claim one pool entry for this process.
 *
 * Returns true when this process holds the claim afterwards — either because
 * it created it, or because it already held it. False means another live
 * process owns the entry; the caller may still use it (a lease must never
 * block a request), but it should prefer a different one.
 */
export function claimLease(providerId: string, index: number, configFile?: string): boolean {
	const file = leaseFile(providerId, index, configFile);
	const payload = `${process.pid}\n`;
	try {
		fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
	} catch {
		return false; // no lease directory: the feature degrades to "no leases"
	}
	try {
		// `wx` fails when the file exists, and the create itself is atomic.
		fs.writeFileSync(file, payload, { encoding: "utf-8", flag: "wx", mode: 0o600 });
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") return false;
	}
	const owner = readOwner(file);
	if (owner === process.pid) {
		// Already ours. Refresh the timestamp, so a session that stays on one
		// entry for days does not eventually look abandoned.
		try {
			const now = new Date();
			fs.utimesSync(file, now, now);
		} catch {
			// Best effort: the claim itself is intact.
		}
		return true;
	}
	if (!isStale(file, owner)) return false; // someone else is using it
	// The claim is abandoned: take it over. The window between the removal and
	// the create is the only race, and it is harmless — the loser simply does
	// not get a claim and keeps using the entry.
	try {
		fs.rmSync(file, { force: true });
		fs.writeFileSync(file, payload, { encoding: "utf-8", flag: "wx", mode: 0o600 });
		return true;
	} catch {
		return false;
	}
}

/**
 * Release a claim held by this process.
 *
 * A claim owned by another process is never removed: releasing must not steal
 * somebody else's entry.
 */
export function releaseLease(providerId: string, index: number, configFile?: string): void {
	if (index < 0) return;
	const file = leaseFile(providerId, index, configFile);
	const owner = readOwner(file);
	if (owner !== undefined && owner !== process.pid) return;
	try {
		fs.rmSync(file, { force: true });
	} catch {
		// Best effort: a leftover claim is reclaimed once its owner is gone.
	}
}

/**
 * Claim the provider-wide idle-account sweep for this process.
 *
 * Returns true when this process holds the claim afterwards — either because
 * it created it, or because it already held it. False means another live
 * process owns the provider sweep. Claiming an existing claim of ours renews
 * its timestamp, so a long sweep can keep it fresh.
 */
export function claimSweepLease(providerId: string, configFile?: string): boolean {
	const file = sweepLeaseFile(providerId, configFile);
	const payload = `${process.pid}\n`;
	try {
		fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
	} catch {
		return false; // no lease directory: the feature degrades to "no sweep claims"
	}
	try {
		// `wx` fails when the file exists, and the create itself is atomic.
		fs.writeFileSync(file, payload, { encoding: "utf-8", flag: "wx", mode: 0o600 });
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") return false;
	}
	const owner = readOwner(file);
	if (owner === process.pid) {
		// Already ours. Refresh the timestamp so a sweep that visits many
		// accounts does not eventually look abandoned.
		try {
			const now = new Date();
			fs.utimesSync(file, now, now);
		} catch {
			// Best effort: the claim itself is intact.
		}
		// Re-read the owner: if the file was replaced between the read above and
		// the timestamp refresh, the claim is gone and somebody else owns it now.
		return readOwner(file) === process.pid;
	}
	if (!isStale(file, owner, SWEEP_LEASE_TTL_MS)) return false;
	// The claim is abandoned: take it over. The window between the removal and
	// the create is the only race, and it is harmless — the loser simply does
	// not get a claim and skips the provider.
	try {
		fs.rmSync(file, { force: true });
		fs.writeFileSync(file, payload, { encoding: "utf-8", flag: "wx", mode: 0o600 });
		return true;
	} catch {
		return false;
	}
}

/**
 * Release a provider sweep claim held by this process.
 *
 * A claim owned by another process is never removed: releasing must not let a
 * second session start sweeping the same provider.
 */
export function releaseSweepLease(providerId: string, configFile?: string): void {
	const file = sweepLeaseFile(providerId, configFile);
	const owner = readOwner(file);
	if (owner !== undefined && owner !== process.pid) return;
	try {
		fs.rmSync(file, { force: true });
	} catch {
		// Best effort: a leftover claim is reclaimed once its owner is gone.
	}
}

/**
 * The pid holding the provider-wide sweep claim.
 *
 * `undefined` means the provider is free (or the claim is stale).
 */
export function sweepLeaseOwner(providerId: string, configFile?: string): number | undefined {
	const file = sweepLeaseFile(providerId, configFile);
	const owner = readOwner(file);
	if (owner === undefined) return undefined;
	if (isStale(file, owner, SWEEP_LEASE_TTL_MS)) return undefined;
	return owner;
}

/**
 * Release every entry lease and provider sweep claim this process holds.
 *
 * `keepSweepProviders` names the providers whose sweep is STILL RUNNING in this
 * process. Their sweep claim is left alone: the sweep releases it when it
 * finishes, and releasing it early would let another session start sweeping
 * the same provider while this one is still exchanging refresh tokens.
 */
export function releaseOwnLeases(configFile?: string, keepSweepProviders?: ReadonlySet<string>): void {
	let names: string[];
	try {
		names = fs.readdirSync(leaseDir(configFile));
	} catch {
		return;
	}
	const keep = new Set<string>();
	for (const providerId of keepSweepProviders ?? []) {
		keep.add(path.basename(sweepLeaseFile(providerId, configFile)));
	}
	for (const name of names) {
		if (!name.endsWith(".lease") && !name.endsWith(".sweep-lease")) continue;
		if (name.endsWith(".sweep-lease") && keep.has(name)) continue; // the sweep is still running
		const file = path.join(leaseDir(configFile), name);
		if (readOwner(file) === process.pid) {
			try {
				fs.rmSync(file, { force: true });
			} catch {
				// Best effort.
			}
		}
	}
}

/**
 * The entries of a pool that another LIVE process is using.
 *
 * Used by the picker to avoid walking onto a credential that is already in
 * use elsewhere. Claims this process holds are excluded: its own entry is the
 * one it is coming from, not a conflict.
 */
export function leasedByOthers(
	providerId: string,
	count: number,
	configFile?: string,
): Set<number> {
	const leased = new Set<number>();
	const dir = leaseDir(configFile);
	let names: string[];
	try {
		names = fs.readdirSync(dir);
	} catch {
		return leased;
	}
	const prefix = `${safeName(providerId)}.`;
	for (const name of names) {
		if (!name.startsWith(prefix) || !name.endsWith(".lease")) continue;
		const index = Number(name.slice(prefix.length, -".lease".length));
		if (!Number.isInteger(index) || index < 0 || index >= count) continue;
		const file = path.join(dir, name);
		const owner = readOwner(file);
		if (owner === process.pid) continue;
		if (isStale(file, owner)) {
			try {
				fs.rmSync(file, { force: true });
			} catch {
				// Best effort.
			}
			continue;
		}
		leased.add(index);
	}
	return leased;
}

/**
 * The pid holding a claim on one entry, for the status display.
 *
 * `undefined` means the entry is free (or the claim is stale).
 */
export function leaseOwner(
	providerId: string,
	index: number,
	configFile?: string,
): number | undefined {
	const file = leaseFile(providerId, index, configFile);
	const owner = readOwner(file);
	if (owner === undefined) return undefined;
	if (isStale(file, owner)) return undefined;
	return owner;
}
