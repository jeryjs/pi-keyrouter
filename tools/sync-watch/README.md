# sync-watch — credential sync instrumentation

Observes `~/.pi/keyrouter.json` and `~/.pi/agent/auth.json` and records every
change, to answer one question:

> When pi refreshes an OAuth access token in `auth.json`, does keyrouter record
> that same value in its own pool copy — and how quickly?

This directory is outside the published package. `.gitignore` excludes it because
the log records raw tokens verbatim.

## Why this is a separate process

keyrouter only ever writes its own config; **pi** writes `auth.json`. Nothing
inside the extension can observe what pi did independently, and an extension
cannot be a trustworthy witness to its own bookkeeping. A third-party watcher is
also the only version that cannot perturb what it measures.

## Layout

| File | Purpose |
|---|---|
| `watch-sync.mjs` | The observer. Appends NDJSON events; never writes either watched file. |
| `analyze-sync.mjs` | Reads the log and reports verdicts and write-back lag. |
| `test-watch.mjs` | 45-case regression suite, run against synthetic fixtures in a temp dir. |
| `run-watcher.cmd` | Launcher used by the scheduled task. |
| `logs/sync-watch.ndjson` | The log. **Contains live credentials.** |

## Running

The scheduled task `pi-keyrouter-sync-watch` starts the watcher at logon and runs
it hidden. It is configured to run whether the user is logged on or not, which is
what makes it windowless; `ExecutionTimeLimit` is unbounded, because the default
three-day limit would silently kill a long-running watcher.

Manually:

```powershell
node watch-sync.mjs      # foreground; Ctrl-C stops it
node test-watch.mjs watch-sync.mjs
node analyze-sync.mjs
node analyze-sync.mjs --provider cline --full
node analyze-sync.mjs --since 2026-10-16T00:00:00Z
```

Environment overrides: `KR_SYNC_AUTH`, `KR_SYNC_KEYROUTER`, `KR_SYNC_LOG_DIR`,
`KR_SYNC_POLL_MS`, `KR_SYNC_HEARTBEAT_MS`, `KR_SYNC_DEBOUNCE_MS`,
`KR_SYNC_MAX_BYTES`.

## Reading the log

One JSON object per line. Every observed event carries a monotonic `seq`, a
wall-clock `t`, and a monotonic `hr`, so the order of an `auth.json` write and a
`keyrouter.json` write is provable rather than assumed.

| Kind | Meaning |
|---|---|
| `runtime.start` | Process start. Carries `resumedFromSeq` and `tookOverStaleLock`. |
| `runtime.scheduler-alive` | One-shot proof the event loop is serviced. |
| `runtime.heartbeat` | Every 5 min: uptime, counts, per-target mtime, RSS. |
| `file.baseline` | Initial state of each file, with a `crosscheck`. |
| `file.change` | A real change. Carries `changed`, `pair`, `crosscheck`. |
| `watch.no-content-change` | A writer touched the file without changing bytes. |
| `runtime.stop` / `runtime.exit` | Clean stop, and the last record before exit. |
| `runtime.instance-skip` | A second instance declined to log. Unnumbered. |

`file.change.changed` gives field-level from/to for both raw values *and* 8-hex
fingerprints, so "is this the same token?" is answered by direct comparison.
`pair` embeds both files whole at that instant. `crosscheck` reports, per OAuth
pool, whether the active entry equals what `auth.json` holds:

| Verdict | Meaning |
|---|---|
| `IN-SYNC` | Same refresh *and* same access token. correct. |
| `STALE-ACCESS` | Same refresh, different access. **pi refreshed; keyrouter kept the old token.** |
| `DIVERGED` | Different refresh. A different account is installed than keyrouter thinks. |
| `NO-AUTH-ENTRY` | Nothing in `auth.json` for it. Expected for `keys` pools (runtime overlay). |
| `OVERLAY-DIFFERS` | Expected for `keys` pools; the overlay is never written to `auth.json`. |

## Survivability, and what its absence means

- **Killed hard** (Task Manager, console close): Windows runs no handlers, so the
  process cannot record its own death. The next start reports
  `tookOverStaleLock`, naming the pid whose lock it replaced. That is the crash
  signature — it is recorded after the fact, by the successor.
- **Clean stop**: `runtime.stop` then `runtime.exit`.
- **Sequence numbers** continue from the log on disk, so a restart never reuses a
  number. A number is only ever issued by the instance holding the lock; a
  refused second instance writes `runtime.instance-skip` with `seq: null`, since
  it would otherwise collide with the owner's counter.
- **No `runtime.stop` and no successor's `tookOverStaleLock`**: observation simply
  stopped. Treat any unexplained gap as missing data, not as "nothing happened".

## Verifying the watcher itself

`test-watch.mjs` drives the real script through 45 cases using temp-directory
fixtures and never touches the live files: baseline correctness, a pi refresh, a
byte-identical rewrite that must *not* be logged, an `active`-only write, a
correct write-back, heartbeats, refusal of a second live instance, a hard kill,
stale-lock takeover, post-crash detection, and sequence monotonicity.

## When you are done investigating

Delete `logs/`. It holds every account's access and refresh tokens in plain text.
Then remove the scheduled task:

```powershell
Unregister-ScheduledTask -TaskName 'pi-keyrouter-sync-watch' -Confirm
```