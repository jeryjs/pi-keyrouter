#!/usr/bin/env node
// =============================================================================
// watch-sync.mjs — passive observer for keyrouter.json vs pi's auth.json
// =============================================================================
//
// WHY THIS IS A SEPARATE PROCESS
//
// keyrouter only ever writes its own `keyrouter.json`. pi writes `auth.json`.
// To find out whether the two stay in step, something has to watch BOTH files
// from outside. Instrumenting the extension can only report what keyrouter
// *intended* to do; it cannot report what pi did independently, and it cannot
// catch keyrouter being wrong about its own bookkeeping. A third-party observer
// is also the only version of this that cannot perturb what it measures.
//
// WHAT IT RECORDS
//
// One append-only NDJSON stream. Every line is one event with a monotonic `seq`
// and both a wall-clock (`t`) and monotonic (`hr`) timestamp, so the order of an
// auth.json write and a keyrouter.json write is provable rather than assumed.
//
//   runtime.start / runtime.baseline / runtime.watch-armed / runtime.heartbeat
//   runtime.instance-skip / runtime.watch-error / runtime.error / runtime.stop
//   file.baseline / file.change
//
// Each `file.change` carries:
//   - `changed`    field-level from/to diff, RAW values plus 8-hex fingerprints
//   - `pair`       both files' full parsed content at that instant
//   - `crosscheck` per OAuth pool: is the active account identical to what
//                  auth.json holds right now? Emits a `verdict`.
//
// The `verdict` field is the answer to the actual question. `STALE-ACCESS` means
// the refresh token matches (so it is the same account) but the access token in
// keyrouter.json is not the one pi has — i.e. a refresh was lost.
//
// DETECTION
//
// Two independent mechanisms, because neither alone is sufficient:
//   1. fs.watch on each file's PARENT DIRECTORY, filtered by basename. Directory
//      watching survives the temp-file+rename that keyrouter uses to write
//      atomically; watching the file itself would lose the handle on replace.
//      Latency: sub-millisecond.
//   2. A poll of both files every few seconds. Catches anything the watcher
//      missed (handle invalidation, event coalescing) and doubles as the tick
//      for heartbeats. A change missed by (1) is still caught here.
//
// SECURITY
//
// Raw access and refresh tokens are written to this log verbatim, because
// proving "the same value" by inspection is the point. The log therefore IS a
// credential dump. It lives in a gitignored directory and must be deleted when
// the investigation is over.
//
// =============================================================================

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { fileURLToPath } from "node:url";

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const HOME = os.homedir();

const intEnv = (name, fallback) => {
	const n = Number.parseInt(process.env[name] ?? "", 10);
	return Number.isFinite(n) && n > 0 ? n : fallback;
};

// Two targets. Overridable so the watcher can be tested against copies without
// ever touching the live credential files.
const TARGETS = [
	{
		label: "auth",
		desc: "pi credential store (pi owns this file)",
		path: process.env["KR_SYNC_AUTH"] ?? path.join(HOME, ".pi", "agent", "auth.json"),
	},
	{
		label: "keyrouter",
		desc: "keyrouter pool config (extension owns this file)",
		path: process.env["KR_SYNC_KEYROUTER"] ?? path.join(HOME, ".pi", "keyrouter.json"),
	},
];

const LOG_DIR = process.env["KR_SYNC_LOG_DIR"] ?? path.join(SCRIPT_DIR, "logs");
const LOG_PATH = path.join(LOG_DIR, "sync-watch.ndjson");
const LOCK_PATH = path.join(LOG_DIR, "sync-watch.lock");

const POLL_MS = intEnv("KR_SYNC_POLL_MS", 2_000);
const HEARTBEAT_MS = intEnv("KR_SYNC_HEARTBEAT_MS", 300_000);
const DEBOUNCE_MS = intEnv("KR_SYNC_DEBOUNCE_MS", 10);
const MAX_BYTES = intEnv("KR_SYNC_MAX_BYTES", 32 * 1024 * 1024);
const KEEP_ROTATIONS = 3;

const STARTED_WALL = new Date();
const STARTED_HR = process.hrtime.bigint();

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------

const SLEEP_CELL = new Int32Array(new SharedArrayBuffer(4));
function sleepSync(ms) {
	Atomics.wait(SLEEP_CELL, 0, 0, ms);
}

function fingerprint(value) {
	if (typeof value !== "string") return null;
	return crypto.createHash("sha256").update(value, "utf-8").digest("hex").slice(0, 8);
}

function byteFingerprint(buffer) {
	return crypto.createHash("sha256").update(buffer).digest("hex");
}

function iso(ms) {
	return typeof ms === "number" && Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function uptimeMs() {
	return Number((process.hrtime.bigint() - STARTED_HR) / 1_000_000n);
}

// -----------------------------------------------------------------------------
// Log writer
//
// appendFileSync per line: open, write, close. A crash can lose at most the line
// being written, and there is no buffered state to flush. Rotation is checked
// against a running byte counter rather than a stat per line.
// -----------------------------------------------------------------------------

// `seq` continues from the events already on disk when the log exists, so it stays
// monotonic across a crash and restart. Without that, a second run reuses the same
// numbers and two unrelated events appear to share an identity.
let seq = 0;
// Highest sequence number seen on disk. `emit` will not produce anything at or
// below it, so a duplicate is impossible even on a path that skipped recovery.
let recoveredSeq = 0;
let logBytes = 0;
const counts = Object.create(null);

function rotateIfNeeded() {
	if (logBytes < MAX_BYTES) return;
	try {
		for (let i = KEEP_ROTATIONS - 1; i >= 1; i -= 1) {
			const from = `${LOG_PATH}.${i}`;
			const to = `${LOG_PATH}.${i + 1}`;
			if (fs.existsSync(from)) fs.renameSync(from, to);
		}
		fs.renameSync(LOG_PATH, `${LOG_PATH}.1`);
	} catch (error) {
		process.stderr.write(`[sync-watch] rotation failed: ${error.message}\n`);
	}
	logBytes = 0;
}

/**
 * Append one event. The only writer. Takes `kind` separately from `fields` so a
 * field named `kind` cannot silently overwrite the event's own type.
 */
function emit(kind, fields = {}) {
	return emitUnlocked({ kind, ...fields });
}

/**
 * Append one event with no prior state required.
 *
 * Separate from `emit` because the instance-skip notice is written BEFORE the lock
 * is taken (see `recoverLogState`), so at that point the counters this log normally
 * owns are not yet trusted. Serialization failure is handled the same way either
 * way, so the two paths cannot drift apart.
 */
function emitUnlocked(record, options = {}) {
	// Only the process holding the lock may number the observed timeline. A refused
	// instance consumes no sequence number at all: it shares one counter with the
	// lock owner, so if it numbered anything, the owner would later emit that same
	// number and two unrelated events would collide — destroying the ordering
	// evidence the numbering exists to provide. Such a record still carries `t` and
	// `pid`, which is enough to place it in time.
	let number = null;
	if (options.numbered !== false) {
		// A duplicate is the one unrecoverable failure; recovery runs before the lock
		// is taken, and the floor is re-asserted so no path can break it.
		if (seq < recoveredSeq) seq = recoveredSeq;
		seq += 1;
		number = seq;
	}
	counts[record.kind ?? "unknown"] = (counts[record.kind ?? "unknown"] ?? 0) + 1;
	const entry = {
		seq: number,
		t: new Date().toISOString(),
		hr: process.hrtime.bigint().toString(),
		pid: process.pid,
		...record,
	};
	let line;
	try {
		line = `${JSON.stringify(entry)}\n`;
	} catch (error) {
		line = `${JSON.stringify({
			seq: number,
			t: entry.t,
			pid: process.pid,
			kind: "runtime.error",
			message: `could not serialize ${record.kind ?? "event"}: ${error.message}`,
		})}\n`;
	}
	if (logBytes >= MAX_BYTES) rotateIfNeeded();
	try {
		fs.appendFileSync(LOG_PATH, line, "utf-8");
		logBytes += Buffer.byteLength(line, "utf-8");
	} catch (error) {
		process.stderr.write(`[sync-watch] write failed: ${error.message}\n`);
	}
	return entry;
}

// -----------------------------------------------------------------------------
// Flattening and diffing
//
// Both files are reduced to a flat `path -> leaf` map so a change anywhere has
// one uniform representation. Leaves are stringified; objects (for example
// github-copilot's availableModelIds array) become compact JSON.
// -----------------------------------------------------------------------------

function leaf(value) {
	if (value === null || value === undefined) return value === null ? "null" : "<undefined>";
	if (typeof value === "object") return JSON.stringify(value);
	return String(value);
}

function flattenAuth(json) {
	const out = new Map();
	for (const [provider, credential] of Object.entries(json ?? {})) {
		if (!credential || typeof credential !== "object" || Array.isArray(credential)) {
			out.set(`${provider}|<value>`, leaf(credential));
			continue;
		}
		for (const [field, value] of Object.entries(credential)) {
			out.set(`${provider}|${field}`, leaf(value));
		}
	}
	return out;
}

function flattenKeyrouter(json) {
	const out = new Map();
	for (const provider of json?.providers ?? []) {
		const name = provider?.name ?? "?";
		out.set(`${name}|__active`, provider?.active === undefined ? "<undefined>" : String(provider.active));
		if (Array.isArray(provider?.keys)) {
			out.set(`${name}|__kind`, "keys");
			for (const key of provider.keys ?? []) out.set(`${name}|key|${key?.name}|value`, leaf(key?.value));
		}
		if (Array.isArray(provider?.accounts)) {
			out.set(`${name}|__kind`, "accounts");
			out.set(`${name}|__rotateOnQuota`, String(provider?.rotateOnQuota !== false));
			for (const account of provider.accounts ?? []) {
				const credential = account?.credential;
				if (credential && typeof credential === "object" && !Array.isArray(credential)) {
					for (const [field, value] of Object.entries(credential)) {
						out.set(`${name}|account|${account?.name}|${field}`, leaf(value));
					}
				} else {
					out.set(`${name}|account|${account?.name}|<ref>`, leaf(credential));
				}
			}
		}
	}
	return out;
}

function diffMaps(before, after) {
	const changes = [];
	const fields = new Set([...before.keys(), ...after.keys()]);
	for (const field of [...fields].sort()) {
		const from = before.get(field);
		const to = after.get(field);
		if (from === to) continue;
		changes.push({
			field,
			from: from ?? null,
			to: to ?? null,
			fromFp: fingerprint(from),
			toFp: fingerprint(to),
		});
	}
	return changes;
}

// -----------------------------------------------------------------------------
// Cross-check
//
// The comparison that answers the question. keyrouter's `active` entry is the
// one it believes is installed into pi right now, so that is the entry that must
// equal auth.json's entry. Refresh token identifies the account (it only changes
// on /login); access token is the thing pi refreshes.
// -----------------------------------------------------------------------------

function crosscheck(authJson, keyrouterJson) {
	const rows = [];
	for (const provider of keyrouterJson?.providers ?? []) {
		const name = provider?.name ?? "?";
		const isKeys = Array.isArray(provider?.keys);
		const isAccounts = Array.isArray(provider?.accounts);
		const auth = authJson?.[name];
		const authPresent = Boolean(auth) && typeof auth === "object" && !Array.isArray(auth);

		const row = {
			provider: name,
			kind: isKeys ? "keys" : isAccounts ? "accounts" : "?",
			active: provider?.active ?? null,
			authPresent,
			authType: authPresent ? (auth.type ?? null) : null,
		};

		if (isAccounts) {
			const entry = (provider.accounts ?? []).find((a) => a?.name === row.active);
			const credential = entry?.credential;
			if (!entry || !credential || typeof credential !== "object") {
				row.verdict = entry ? "ACTIVE-CREDENTIAL-UNUSABLE" : "ACTIVE-ENTRY-MISSING";
			} else if (!authPresent) {
				row.verdict = "NO-AUTH-ENTRY";
			} else {
				row.sameRefresh = typeof credential.refresh === "string" && credential.refresh === auth.refresh;
				row.sameAccess = typeof credential.access === "string" && credential.access === auth.access;
				row.poolRefreshFp = fingerprint(credential.refresh);
				row.authRefreshFp = fingerprint(auth.refresh);
				row.poolAccessFp = fingerprint(credential.access);
				row.authAccessFp = fingerprint(auth.access);
				row.poolExpires = typeof credential.expires === "number" ? credential.expires : null;
				row.authExpires = typeof auth.expires === "number" ? auth.expires : null;
				row.poolExpiresIso = iso(row.poolExpires);
				row.authExpiresIso = iso(row.authExpires);
				row.expiresDeltaMs =
					row.poolExpires !== null && row.authExpires !== null ? row.poolExpires - row.authExpires : null;
				// The account identity (refresh) matching but the access token not
				// matching is precisely "pi refreshed, keyrouter did not record it".
				if (row.sameAccess && row.sameRefresh) row.verdict = "IN-SYNC";
				else if (!row.sameRefresh) row.verdict = "DIVERGED";
				else row.verdict = "STALE-ACCESS";
			}
		} else if (isKeys) {
			const entry = (provider.keys ?? []).find((k) => k?.name === row.active);
			if (!authPresent) {
				// Expected: an API-key pool is injected as an in-memory runtime
				// overlay and never written to auth.json.
				row.verdict = "NO-AUTH-ENTRY (expected for keys pool)";
			} else {
				row.sameKey = entry?.value === auth.key;
				row.verdict = row.sameKey ? "IN-SYNC" : "OVERLAY-DIFFERS (expected for keys pool)";
			}
		}
		rows.push(row);
	}
	return rows;
}

// -----------------------------------------------------------------------------
// Reading
// -----------------------------------------------------------------------------

function readTarget(target, attempt = 0) {
	const base = { label: target.label, path: target.path };
	let stat;
	try {
		stat = fs.statSync(target.path);
	} catch (error) {
		if (error.code === "ENOENT") return { ...base, exists: false };
		return { ...base, exists: false, statError: `${error.code ?? ""} ${error.message}`.trim() };
	}

	let buffer;
	try {
		buffer = fs.readFileSync(target.path);
	} catch (error) {
		return {
			...base,
			exists: true,
			size: stat.size,
			mtimeMs: stat.mtimeMs,
			mtimeIso: iso(stat.mtimeMs),
			readError: `${error.code ?? ""} ${error.message}`.trim(),
		};
	}

	const snapshot = {
		...base,
		exists: true,
		size: stat.size,
		mtimeMs: stat.mtimeMs,
		mtimeIso: iso(stat.mtimeMs),
		sha256: byteFingerprint(buffer),
		json: null,
		parseError: null,
	};

	const text = buffer.toString("utf-8");
	if (text.trim() === "") {
		snapshot.parseError = "file is empty";
	} else {
		try {
			snapshot.json = JSON.parse(text);
		} catch (error) {
			// pi may write in place, so a read can land mid-write. Retry a couple
			// of times before recording a genuine parse failure.
			if (attempt < 2) {
				sleepSync(20);
				return readTarget(target, attempt + 1);
			}
			snapshot.parseError = error.message;
			snapshot.rawText = text.slice(0, 4_000);
		}
	}
	return snapshot;
}

function sameSnapshot(a, b) {
	if (!a || !b) return false;
	if (a.exists !== b.exists) return false;
	if (!a.exists) return true;
	return a.sha256 === b.sha256;
}

function brief(snapshot) {
	if (!snapshot) return null;
	return {
		exists: snapshot.exists,
		size: snapshot.size ?? null,
		mtimeIso: snapshot.mtimeIso ?? null,
		sha256: snapshot.sha256 ?? null,
		parseError: snapshot.parseError ?? null,
		statError: snapshot.statError ?? null,
		readError: snapshot.readError ?? null,
	};
}

// -----------------------------------------------------------------------------
// State
// -----------------------------------------------------------------------------

const snapshots = new Map();

function pairPayload() {
	return {
		auth: snapshots.get("auth")?.json ?? null,
		keyrouter: snapshots.get("keyrouter")?.json ?? null,
	};
}

function checkTarget(label, reason) {
	const target = TARGETS.find((t) => t.label === label);
	if (!target) return;
	const next = readTarget(target);
	const before = snapshots.get(label);
	snapshots.set(label, next);

	if (!before) {
		// The baseline carries a crosscheck too, so the log states the sync condition
		// as of process start rather than only after the first write. Without it the
		// opening state of the investigation would be the one thing not recorded.
		const pair = pairPayload();
		emit("file.baseline", {
			file: label,
			path: next.path,
			reason,
			snapshot: brief(next),
			pair,
			crosscheck: crosscheck(pair.auth, pair.keyrouter),
		});
		return false;
	}
	if (sameSnapshot(before, next)) return false;

	const detectLagMs = typeof next.mtimeMs === "number" ? Math.round(Date.now() - next.mtimeMs) : null;
	let changed = "unavailable";
	let note = null;
	if (before.json && next.json) {
		changed =
			label === "auth"
				? diffMaps(flattenAuth(before.json), flattenAuth(next.json))
				: diffMaps(flattenKeyrouter(before.json), flattenKeyrouter(next.json));
	} else {
		note = before.json ? "previous state unparseable" : "new state unparseable";
	}

	const pair = pairPayload();
	const fields = {
		file: label,
		path: next.path,
		reason,
		detectLagMs,
		size: { from: before.size ?? null, to: next.size ?? null },
		mtimeIso: { from: before.mtimeIso ?? null, to: next.mtimeIso ?? null },
		sha256: { from: before.sha256 ?? null, to: next.sha256 ?? null },
		mtimeUnchanged: before.mtimeMs === next.mtimeMs,
		changed,
		changedCount: Array.isArray(changed) ? changed.length : null,
		note,
		pair,
	};
	// Computed for EVERY change, not only keyrouter's: divergence first becomes
	// observable the instant pi rewrites auth.json. Waiting for keyrouter's next
	// write would delay the verdict by however long that takes.
	fields.crosscheck = crosscheck(pair.auth, pair.keyrouter);
	emit("file.change", fields);
	return true;
}

// -----------------------------------------------------------------------------
// Triggers
// -----------------------------------------------------------------------------

const pending = new Set();
let pendingReason = null;
let pendingTimer = null;

function scheduleCheck(labels, reason) {
	for (const label of labels) pending.add(label);
	pendingReason = reason;
	if (pendingTimer) return;
	pendingTimer = setTimeout(() => {
		pendingTimer = null;
		const batch = [...pending];
		pending.clear();
		const changedLabels = [];
		for (const label of batch) {
			if (checkTarget(label, pendingReason ?? "unknown")) changedLabels.push(label);
		}
		if (pendingReason?.startsWith("watch") && changedLabels.length === 0) {
			// A fs.watch event that produced no content change (touch, metadata
			// write). Worth knowing about: it means a writer touched the file
			// without changing bytes.
			emit("watch.no-content-change", { batch, reason: pendingReason });
		}
	}, DEBOUNCE_MS);
}

const watchers = [];

function armWatchers() {
	const directories = [...new Set(TARGETS.map((t) => path.dirname(t.path)))];
	for (const dir of directories) {
		const labelsHere = TARGETS.filter((t) => path.dirname(t.path) === dir).map((t) => t.label);
		const basenames = new Set(TARGETS.map((t) => path.basename(t.path).toLowerCase()));
		try {
			// Watch the directory, not the file: keyrouter writes via temp+rename,
			// which replaces the inode and silently kills a file-level watch.
			const watcher = fs.watch(dir, { persistent: true }, (eventType, filename) => {
				const name = filename === null ? null : String(filename).toLowerCase();
				if (name !== null && !basenames.has(name)) return;
				scheduleCheck(
					name === null ? labelsHere : TARGETS.filter((t) => path.basename(t.path).toLowerCase() === name).map((t) => t.label),
					`watch:${eventType}`,
				);
			});
			watcher.on("error", (error) => {
				emit("runtime.watch-error", { dir, message: error?.message ?? String(error), code: error?.code ?? null });
			});
			watchers.push({ dir, watcher });
			emit("runtime.watch-armed", { dir, labels: labelsHere });
		} catch (error) {
			emit("runtime.watch-error", { dir, message: error?.message ?? String(error), code: error?.code ?? null });
		}
	}
}

// -----------------------------------------------------------------------------
// Heartbeat
// -----------------------------------------------------------------------------

let lastHeartbeat = Date.now();

function heartbeat() {
	const now = Date.now();
	if (now - lastHeartbeat < HEARTBEAT_MS) return;
	lastHeartbeat = now;
	emit("runtime.heartbeat", {
		uptimeMs: uptimeMs(),
		counts: { ...counts },
		logBytes,
		targets: TARGETS.map((t) => {
			const snapshot = snapshots.get(t.label);
			return { label: t.label, path: t.path, exists: Boolean(snapshot?.exists), mtimeIso: snapshot?.mtimeIso ?? null, sha256: snapshot?.sha256 ?? null };
		}),
		memory: process.memoryUsage().rss,
	});
}

// -----------------------------------------------------------------------------
// Single-instance lock
//
// A repeated trigger can start this a second time while the first is alive. Only
// one instance may append to the log, or the stream interleaves and the seq
// ordering becomes untrustworthy.
// -----------------------------------------------------------------------------

function processAlive(pid) {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return error.code === "EPERM";
	}
}

function acquireLock() {
	let stale = null;
	for (let attempt = 0; attempt < 3; attempt += 1) {
		try {
			const fd = fs.openSync(LOCK_PATH, "wx");
			fs.writeSync(fd, JSON.stringify({ pid: process.pid, startedAt: STARTED_WALL.toISOString() }));
			fs.closeSync(fd);
			return { ok: true, tookOver: stale };
		} catch (error) {
			if (error.code !== "EEXIST") return { ok: true, warning: error.message };
			let held = null;
			try {
				held = JSON.parse(fs.readFileSync(LOCK_PATH, "utf-8"));
			} catch {
				held = null;
			}
			if (typeof held?.pid === "number" && held.pid !== process.pid && processAlive(held.pid)) {
				// A live holder owns the log. Two running watchers would interleave
				// duplicate events and every count in the log would be doubled, so
				// refuse and let the caller exit quietly.
				return { ok: false, heldByPid: held.pid, heldSince: held.startedAt ?? null };
			}
			// Stale lock: its owner is gone. Clear it and take over, recording whose
			// lock this replaces. This is how a restart after a crash or a forced kill
			// becomes visible in the log — the killed process could not report anything
			// itself, because Windows TerminateProcess runs no handlers at all.
			stale = { pid: held?.pid ?? null, startedAt: held?.startedAt ?? null };
			try {
				fs.rmSync(LOCK_PATH, { force: true });
			} catch {
				/* best effort */
			}
		}
	}
	return { ok: false, heldByPid: null };
}

// Set only once this instance owns the log. The exit handler stays silent when it
// does not, because an instance that never took the lock has nothing to report.
let lockHeld = false;
let started = false;
function releaseLock() {
	if (!lockHeld) return;
	try {
		fs.rmSync(LOCK_PATH, { force: true });
	} catch {
		/* best effort */
	}
	lockHeld = false;
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

let shuttingDown = false;
/**
 * Stop cleanly: record the outcome, tear down the watchers, release the lock,
 * then run `exit`. Shared by the signal and error paths.
 */
function stopWithOutcome(reason, exit) {
	if (shuttingDown) {
		exit();
		return;
	}
	shuttingDown = true;
	emit("runtime.stop", { reason, uptimeMs: uptimeMs(), counts: { ...counts } });
	for (const { watcher } of watchers) {
		try {
			watcher.close();
		} catch {
			/* best effort */
		}
	}
	releaseLock();
	exit();
}

/**
 * Establish the sequence floor and the byte counter from the log already on disk.
 *
 * Runs BEFORE the lock is acquired. An instance that finds the lock held still
 * writes a notice, and it must not number that notice from 1 while the lock owner
 * is numbering from 9000: the stream would then contain two competing counters and
 * the ordering evidence this log exists to provide would be worthless.
 */
function recoverLogState() {
	for (let attempt = 0; attempt < 5; attempt += 1) {
		try {
			logBytes = fs.statSync(LOG_PATH).size;
			break;
		} catch (error) {
			if (error.code !== "ENOENT") break;
			sleepSync(10);
		}
	}
	if (logBytes === 0) return;
	try {
		// Tail only: the log can grow to tens of megabytes.
		const tail = fs.readFileSync(LOG_PATH, "utf-8").slice(-65_536).split("\n");
		for (let i = tail.length - 1; i >= 0; i -= 1) {
			if (!tail[i]) continue;
			try {
				const previous = JSON.parse(tail[i]);
				if (typeof previous?.seq === "number") {
					recoveredSeq = previous.seq;
					seq = previous.seq;
					break;
				}
			} catch {
				// A partial trailing line after a hard kill is expected here.
			}
		}
	} catch {
		// Log unreadable; numbering from 0 is the best answer available.
	}
}

function start() {
	fs.mkdirSync(LOG_DIR, { recursive: true });
	recoverLogState();

	const lock = acquireLock();
	if (!lock.ok) {
		// Another instance owns the log and is numbering the timeline, so this one
		// records a single unnumbered notice and stops. Numbering it would collide with
		// a number the owner is yet to emit.
		emitUnlocked(
			{
			kind: "runtime.instance-skip",
			heldByPid: lock.heldByPid,
			heldSince: lock.heldSince ?? null,
			note: "another watcher instance owns the log; this instance recorded only this notice and stopped",
		}, { numbered: false });
		return false;
	}
	lockHeld = true;
	// A poll interval that fails on its first tick and is never re-armed is the one
	// failure mode that would leave a log looking healthy while recording nothing.
	// Arm it before the start event so the ordering proves it was set up, and prove
	// the event loop is actually being serviced rather than assuming it.
	const pollTimer = setInterval(() => {
		try {
			for (const target of TARGETS) checkTarget(target.label, "poll");
			heartbeat();
		} catch (error) {
			emit("runtime.error", { where: "poll", message: error?.message ?? String(error), stack: error?.stack ?? null });
		}
	}, POLL_MS);
	pollTimer.unref?.();

	// If this never appears, the process is wedged and an empty log means something
	// specific rather than merely quiet.
	setTimeout(() => emit("runtime.scheduler-alive", { afterMs: POLL_MS }), POLL_MS).unref?.();

	emit("runtime.start", {
		script: fileURLToPath(import.meta.url),
		scriptDir: SCRIPT_DIR,
		node: process.version,
		platform: `${process.platform} ${os.release()}`,
		hostname: os.hostname(),
		cwd: process.cwd(),
		startedWall: STARTED_WALL.toISOString(),
		tookOverStaleLock: lock.tookOver ?? null,
		logPath: LOG_PATH,
		logBytesAtStart: logBytes,
		resumedFromSeq: seq,
		lock: lock.warning ? { warning: lock.warning } : "acquired",
		intervals: { pollMs: POLL_MS, heartbeatMs: HEARTBEAT_MS, debounceMs: DEBOUNCE_MS },
		maxBytes: MAX_BYTES,
		targets: TARGETS.map((t) => ({ label: t.label, desc: t.desc, path: t.path, exists: fs.existsSync(t.path) })),
	});
	emit("runtime.warning", {
		message: "raw access/refresh tokens are recorded verbatim in this log; delete it when the investigation ends",
	});

	for (const target of TARGETS) checkTarget(target.label, "startup");
	armWatchers();
	return true;
}

process.on("uncaughtException", (error) => {
	emit("runtime.error", { where: "uncaughtException", message: error?.message ?? String(error), stack: error?.stack ?? null });
	stopWithOutcome("uncaughtException", () => process.exit(1));
});
process.on("unhandledRejection", (reason) => {
	emit("runtime.error", { where: "unhandledRejection", message: reason instanceof Error ? reason.message : String(reason), stack: reason instanceof Error ? reason.stack : null });
});
// POSIX delivers these; Windows does not — see the exit handler below.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"]) {
	process.on(signal, () => stopWithOutcome(`signal:${signal}`, () => process.exit(0)));
}
process.on("exit", (code) => {
	// Windows sends no catchable signal for taskkill /F or a closed console window,
	// so on that platform this is the only stop notification the process ever gets.
	// Appending from an exit handler is safe: the log is opened and closed per write
	// and nothing here needs to be scheduled. A file change with no matching
	// runtime.stop is therefore positive evidence the process was killed, not an
	// unexplained gap in the data.
	if (!started) return; // never acquired the log; the owner is already recording
	try {
		releaseLock();
	} catch {
		/* best effort */
	}
	emit("runtime.exit", {
		code,
		cleanStop: shuttingDown,
		note: shuttingDown
			? "stopped after a recorded runtime.stop"
			: "ended with no catchable stop signal (crash or forced kill)",
		uptimeMs: uptimeMs(),
		counts: { ...counts },
	});
});

if (start()) {
	started = true;
	process.stdout.write(`[sync-watch] logging to ${LOG_PATH} (pid ${process.pid})\n`);
} else {
	process.exit(0);
}