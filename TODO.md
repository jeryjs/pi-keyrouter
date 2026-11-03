# TODO

Deferred work, with enough context to pick it up without re-deriving it. Each item
names where it lives and what "done" looks like.

## OAuth idle-account sweep — the races (next release)

The session-start sweep refreshes the accounts of a pool that no request has touched
for a while, using pi's own `oauth.refresh`. It is **opt-in per pool** (`"sweepRefresh":
true` in that provider's config) and off everywhere else, because the exchange is not
race-free yet. `PI_KEYROUTER_SWEEP=1` remains an internal override that sweeps every
OAuth pool.

Where it lives: `sweepIdleAccounts` in `index.ts`; the provider-wide claim in
`lease.ts` (`claimSweepLease` / `releaseSweepLease`).

Open items:

- **A refresh token can be lost when the entry becomes active mid-exchange.** The
  exchange awaits, and while it runs the pool may rotate onto that very entry. The
  current code then writes nothing ("became active mid-exchange"), but on providers
  that rotate the refresh token on every exchange the token that came back has
  already consumed the stored one — the pool copy is left holding a token that the
  provider has retired. *Done when* the fresh credential is persisted even when the
  entry became active, and the active account's copy is re-read from pi's store
  afterwards so the capture machinery stays the only writer for the active account.

- **A refresh failure can mark a good account bad.** If the exchange fails because
  pi refreshed the same account concurrently (its request-time refresh won the race),
  the sweep marks the entry `refresh-failed` and puts it on cooldown — even though the
  account is alive and the newer token is already on disk. *Done when* a failed
  exchange re-reads the stored credential first and only marks the account bad when
  the newer token is also dead.

- **A rotated refresh token is lost when the write-back fails, or when the credential
  is an external reference.** The write-back to `keyrouter.json` is a separate step
  from the exchange: if it fails, the rotated token exists only in memory. A
  credential stored as `$ENV` / `${ENV}` / `@file` has nowhere to be written back to
  at all, so the rotated token is dropped on the floor. *Done when* a failed
  write-back is reported and the in-memory copy keeps the rotated token for the rest
  of the session, and an external reference is reported as "cannot persist a rotated
  token" instead of being silently refreshed in memory only.

- **The sweep is not coordinated with `reloadAll()` or with session shutdown.** A
  reload rebuilds the runtime while an exchange may be in flight, and the sweep's
  write-back can land on a config file that was just rewritten.

When these are fixed, the per-pool opt-in can become the recommended setting and the
`PI_KEYROUTER_SWEEP` override can go.

## Lease takeover: stale claims and pid reuse

A claim is stale when its owner process is gone, or when the file is older than the
7-day TTL. Two edges remain:

- The takeover deletes the claim file after checking that it is stale. A live owner
  whose claim just aged past the TTL can refresh it in between, and its fresh claim
  is deleted. A lease is a preference, never a lock, so the worst case is two
  processes preferring the same entry.
- A dead owner's pid can be reused by an unrelated process, which makes the claim
  look live until the TTL expires.

*Done when* the takeover re-checks the owner immediately before removing the file,
and a claim records something that outlives a pid (a start time, or a per-process
token) so a reused pid cannot keep a claim alive.
