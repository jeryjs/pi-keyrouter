# 🔑 pi-keyrouter

**Credential pools for [pi](https://pi.dev) — injected into providers you already have.**

Multiple API keys **or multiple OAuth logins** per provider · automatic 429/401/403 failover ·
no custom providers, no fetch hacks.

Built for **pi 1.0.0**. Auth, retries, OAuth, refresh, storage and headers stay entirely inside pi;
this extension only chooses which credential pi resolves.

> Originally created by [lowern1ght](https://github.com/lowern1ght). Forked, maintained, and substantially improved by [jeryjs](https://github.com/jeryjs).
>
> Release notes for every version, including the original `0.1.0` – `0.4.0` line, are in
> [CHANGELOG.md](./CHANGELOG.md).

```bash
pi install npm:@jeryjs/pi-keyrouter
# create ~/.pi/keyrouter.json with your keys or accounts
/reload
```

Want to stay on top of the latest changes? `pi install git:github.com/jeryjs/pi-keyrouter` works too.

---

## What it does

`~/.pi/keyrouter.json` declares a **pool** per provider id. There are two kinds:

- **`keys`** — several API keys. keyrouter puts the active key into pi's *runtime credential
  overlay*, the same mechanism `pi --api-key` uses. The overlay wins over `auth.json` and
  environment variables, so every request for that provider carries your pooled key.
- **`accounts`** — several stored OAuth logins. keyrouter installs the active one into pi's
  **credential store**, because `auth.json` holds exactly one credential per provider id and pi
  has nowhere to keep the rest. pi still owns the OAuth flow, the refresh, and the headers.

When a request fails, keyrouter reads the error off the assistant message (`message_end`), marks
the active credential bad, and installs the next one. pi's own retry then uses it — and for error
classes pi refuses to retry (401/403, quota), keyrouter asks for one extra request at pi's
`agent_before_settle` boundary.

**It never registers a provider.** Pools point at provider ids that already exist — built-ins like
`google` or `anthropic`, ids from `models.json`, and ids owned by **other extensions** such as
`cx-providers`. Nothing is shadowed, merged, or unregistered, so it cannot stomp on another
extension's provider config.

```
user prompt
   → pi resolves auth for provider "tokenharbor"   → pool key A (runtime overlay)
   → provider answers 429
   → message_end: mark A bad, install pool key B  → overlay updated
   → pi's built-in retry                          → request uses B

user prompt
   → pi resolves auth for provider "cline"        → pool account #1 (credential store)
   → provider answers 401 (pi will not retry this)
   → message_end: capture pi's refreshed blob, install account #2
   → agent_before_settle: one extra request       → request uses account #2
```

---

## Configuration

**`~/.pi/keyrouter.json` only** — user-level, never project-scoped, because API keys are personal
credentials that must not be overridable by a repo you clone.

```json5
{
  "providers": [
    {
      // Provider id as pi knows it: built-in ("google"), models.json, or
      // another extension's id. Matched case-insensitively.
      "name": "tokenharbor",
      "keys": [
        // Literal, or an env reference. Prefer env refs so secrets stay off disk.
        { "name": "primary", "value": "$TOKENHARBOR_API_KEY" },
        { "name": "backup",  "value": "thk_live_..." }
      ],
      // Optional: inject pooled keys even when pi has a stored OAuth login.
      "takeoverOAuth": false,
      // Optional: how the next entry is picked at each turn boundary.
      // "failover" (default) | "round-robin" | "stalest-first" | "random" — see Strategies.
      "strategy": "failover",
      // Written and updated by keyrouter — the entry the last session ended on, so
      // the next one resumes here instead of restarting at "primary".
      // See "Resuming across sessions". Leave it out; it is not yours to set.
      "active": "backup"
    }
  ],
  "maxRetries": 3,            // rotations per provider before giving up
  "cooldownMs": 60000,        // how long a failed key stays bad
  "overloadedCooldownMs": 30000, // provider-wide pause on "overloaded"/529
  "notifications": "all"      // status-line volume: "all" | "quiet" | "silent"
}
```

`$NAME` / `${NAME}` expand from the environment at load time. A key whose variable is missing is
dropped; if that empties the pool, the provider is skipped with a warning.

Each provider takes **either** `keys` (API keys) **or** `accounts` (OAuth logins) — see
[OAuth](#2-rotating-between-several-oauth-logins-accounts-pools) for the `accounts` form.

Set `PI_KEYROUTER_CONFIG=/path/to/file` to use a different config path (the test suite relies on it).

---

## Rotation rules

The classification is deliberate, because pi only *retries* some failures.

| Signal | Detected from | `keys` pool | `accounts` pool |
|---|---|---|---|
| `429` / "rate limit" / "too many requests" | assistant error message | cooldown, **rotate** | cooldown, **rotate** |
| `401` / `403` / "unauthorized" / "forbidden" | assistant error message | cooldown, **rotate** | cooldown, **rotate** |
| "quota exceeded" / "insufficient_quota" / billing | assistant error message | **ignored** | **rotate** (if `rotateOnQuota`) |
| "OAuth refresh failed" / `invalid_grant` | assistant error message | n/a | cooldown, **rotate** |
| `529` / "overloaded" | assistant error message | provider-wide cooldown, **no rotation** | same |
| `500` / `502` / `503` | assistant error message | **ignored** — pi retries the same key | same |
| any 2xx | `after_provider_response` | entry marked ok, its cooldown cleared |

The differing quota row is the point: an API key for an account that has hit its limit cannot help,
whereas a different OAuth account is a different subscription — so the same error wording
**rotates** one pool kind and is **ignored** by the other.

Two consequences of pi's retry policy worth knowing:

- **401/403 and quota errors are not in pi's retryable set.** pi stops immediately. To keep
  rotation useful for those, keyrouter uses `agent_before_settle` — pi's actionable boundary that
  may add exactly one more request — and appends a hidden message so the continuation is valid.
  The extra request then runs with the rotated key or account. Capped at `maxRetries` per provider
  until that provider succeeds again, so an all-bad pool cannot loop. (429 *is* retryable, so that
  leg needs no continuation.)
- **Failed requests are not visible to `after_provider_response`.** The OpenAI SDK throws on non-2xx,
  so pi's response hook never fires. That is why errors are read from `message_end`.

### Strategies

By default a pool is a **failover** pool: keyrouter stays on the current entry until it fails,
and only an error moves the pool on. Set `strategy` per provider to change *which entry serves each
turn* — rotation on failure is unaffected and still applies on top of every strategy. It can
also be changed live with `/keyrouter strategy` (see [Commands](#commands)).

| `strategy` | Behavior |
|---|---|
| `"failover"` (default) | Stay on the current entry until it fails. The original behavior. |
| `"round-robin"` | Advance to the next entry at every turn boundary. Spreads load across the pool, and keeps every OAuth account exercised — and therefore refreshed through the normal capture machinery. |
| `"stalest-first"` | Serve the turn with the available account whose token expires soonest: the account most in need of a refresh gets picked first. Under steady traffic it degenerates to round-robin. `accounts` pools only — on a `keys` pool it warns and behaves as `"round-robin"`. |
| `"random"` | A uniformly random available entry other than the current one, for when a fixed rotation pattern is unwanted. |

Two rules that hold for every strategy:

- **Advancement happens only at turn boundaries, never mid-turn.** A turn is one logical unit of
  work, so every request in it goes out on the entry that was installed when the turn started.
- **Cooldowns still bind.** A strategy spreads load; it never selects an entry that is known to be
  bad. And failure rotation wins: while a rotated-in replacement is still waiting for its retry
  turn, the strategy does not move away from it.

Strategy advancement is silent by design — the pool is doing what you asked, not reporting an
event. It is visible in the trace (`PI_KEYROUTER_TRACE`), e.g.
`advance cline home -> work (round-robin)`.

### Resuming across sessions

A rotation that lands on key #2 used to be forgotten when the session ended: the next one started
back on key #1 and had to rediscover the 429. Each pool now records which entry was active in an
`active` field, so the next session resumes there — falling forward to the next available entry if
that one is currently on cooldown.

```jsonc
{
  "providers": [{
    "name": "tokenharbor",
    "active": "jsjery123",              // ← keyrouter writes this; you don't
    "keys": [
      { "name": "jery99961",  "value": "$TOKENHARBOR_API_KEY" },
      { "name": "jsjery123",  "value": "$TOKENHARBOR_API_KEY2" }
    ]
  }]
}
```

It stores the entry **name**, not an index, because this file moves under you: reordering or
inserting entries shifts every index after it, while a name still identifies the credential you
meant. An entry that has since been renamed or deleted is simply unknown, and the pool starts at its
first entry.

Only the name is written — never a key value or a token. The write is atomic, is skipped when the
position is unchanged, and `/keyrouter reset` deletes the field so the next session genuinely starts
fresh.

### Leases — one credential per concurrent worker

A pool is shared by every pi process on the machine: a subagent, a second window, a `pi` running in
another directory. Left alone they all install the same first entry and then hit the same 429 at
the same time. A **lease** is the coordination: an exclusive claim on one entry of a pool.

The claim is a file under `~/.pi/keyrouter-leases/`, created with an exclusive create, so the
filesystem — not a lock protocol — decides the winner. The first process to install an entry holds
the claim; another process sees it and picks a different entry. The claim is released when the
entry is replaced, when the pools are handed back (`reset`, `reload`), and at shutdown. A claim
whose owner process is gone is stale and is taken over.

Within one process, a request holds its entry for the duration of that request, so a rotation never
walks onto a credential that is already serving one. A lease is a **preference, never a lock**: when
every entry is leased, the busy one is reused rather than leaving the request with no credential at
all.

`/keyrouter status` shows who holds each entry:

```
tokenharbor (keys, active: primary, installed: yes, source: runtime)
  → primary  uses=4 fails=0 status=ok lease=this-session
    backup   uses=2 fails=0 status=ok lease=pid 48213
    spare    uses=0 fails=0 status=ok
```

A manual `/keyrouter account` pin overrides the lease: you asked for that credential explicitly,
so the pool installs it even when another process holds the claim.

**OAuth pools do not use leases.** pi's credential store holds exactly one credential per provider
id — `~/.pi/agent/auth.json` is `{ [providerId]: credential }` — and every process reads the same
file, so two processes cannot hold two different accounts for one provider: there is no slot to
lease. Spreading OAuth accounts across concurrent processes needs a distinct provider id per
account, which is the architecture keyrouter deliberately does not use (it never registers
providers). Run those processes against different provider ids, or give them separate agent homes,
when they need different accounts.

---

## OAuth

Handled entirely by pi — keyrouter implements no auth flows, calls no refresh endpoint, and
never writes `auth.json` itself.

There are two distinct OAuth features, and they are independent:

### 1. Leaving your existing login alone (API-key pools)

- **Providers you signed into** (`/login anthropic`, subscription logins): keyrouter detects the
  stored OAuth credential via pi's exported `readStoredCredential()` and **leaves the provider
  alone**. Injecting an api-key would shadow your login, so the pool is skipped with a notice.
  Opt in per pool with `"takeoverOAuth": true`.
- **OAuth-only providers** (no api-key auth method at all): skipped permanently — an injected key
  would make requests fail.
- **When the pool is exhausted or the session ends**, the overlay is removed and pi falls back to
  exactly what you had before: auth.json, env, or OAuth.

pi's own `pi auth check <provider>` / `pi auth print-bearer-token` keep working on those providers.

> **Caveat.** The guard reads the stored credential under the **pool's provider id**. If a provider
> borrows auth from somewhere else — for example a `cx-providers` entry whose credential actually
> lives under a built-in id — the login is invisible to this check and a pool for that id will take
> over. Only pool provider ids whose own credential is what you want rotated.

### 2. Rotating between several OAuth logins (`accounts` pools)

If you have **several logins for the same provider** — two subscription accounts, a work and a
personal one — an `accounts` pool rotates between them on the same signals that rotate API keys.
This is the case pi itself cannot express: `auth.json` is a `Record<providerId, Credential>`
with exactly one credential per provider id, so accounts 2..N have nowhere to live. keyrouter
holds them and swaps them in.

```jsonc
{
  "providers": [
    {
      "name": "cline",
      "accounts": [
        { "name": "work", "credential": "$CLINE_WORK" },
        { "name": "home", "credential": "@~/.pi/accounts/cline-home.json" },
        {
          "name": "inline",
          "credential": {
            "type": "oauth",
            "access": "...",
            "refresh": "...",
            "expires": 1791056623000
          }
        }
      ],
      "rotateOnQuota": true
    }
  ]
}
```

- `credential` accepts an inline object, `$ENV` holding a **JSON string**, or `@file` (a JSON
  file with one object; `~` is expanded). Use `$ENV` or `@file` with mode `0600` so tokens stay
  out of the config file.
- A credential is used only if it has `type: "oauth"`, a non-empty `access`, a `refresh`, and a
  numeric `expires`. Anything else is dropped with a warning **naming the account only**, never the
  value.
- `keys` and `accounts` are mutually exclusive for one provider.
- `rotateOnQuota` (default `true`) decides whether an account-level limit rotates the pool. Each
  account is a separate subscription, so this defaults the opposite way from `keys` pools — see
  [Rotation rules](#rotation-rules).
- `identityPath` (optional) says where this provider's account identity lives inside a credential.
  See [Attributing a refreshed credential](#attributing-a-refreshed-credential).

**How it works.** keyrouter installs an account with pi's own credential store
(`runtime.credentials.modify`), so pi's file lock, cache and revision counter all stay coherent.
pi then owns auth resolution, headers and refresh exactly as it does for a single login. It never
uses the api-key overlay for an `accounts` pool: `setRuntimeApiKey` stores only a string, and pi's
resolver returns early on any override — on an OAuth-only provider that yields **no auth at all**,
and on a dual-auth provider it **freezes the token** so pi stops refreshing it.

**Refresh stays pi's job, always.** keyrouter never refreshes a token. pi refreshes lazily and
persists the result to `auth.json` — so keyrouter reads the live credential back into the pool both
when it leaves an account and after installing one, and **writes the refreshed values back to
`keyrouter.json`**. That last part is essential rather than tidy: pi holds one credential per
provider, so installing account #2 overwrites whatever pi refreshed, and keyrouter's own copy would
otherwise still carry the access token from an account's **last login**. Since access tokens are
short-lived (60 minutes for Cline), a stale copy means every account in the pool presents an
expired token and the whole pool reads as dead. A dead refresh token is treated as a dead account,
and the pool rotates away from it.

**Idle accounts are refreshed at session start.** An account that sits in the pool unused goes
through none of that — pi never sees it, so its stored copy keeps an expired access token and an
unexercised refresh token, and whether that token still redeems weeks later is up to the provider.
At `session_start`, keyrouter therefore asks **pi's own refresh implementation** — the provider's
`oauth.refresh`, the same function pi's request path calls — to renew every *idle* account whose
token has less than ~5 minutes of validity left, with pi's own 15-second exchange timeout, and
writes the result back through the usual write-back rules. keyrouter still implements no part of
OAuth. The *active* account is skipped: pi refreshes it at request time and the capture machinery
syncs that; sweeping its pool copy as well would race pi's refresh of the same token — and for
providers that rotate the refresh token on every exchange, each side would consume the other's
token. The sweep is non-blocking and never touches `auth.json`, only the pool and
`keyrouter.json`. An account whose refresh fails is marked like a request-time refresh failure and
named in one notice: reviving a dead login still needs a `/login` only you can perform.

The write-back is scoped and conservative: only accounts written as an **inline object** are
updated (`$ENV` and `@file` references are left alone), only the credential fields change, and the
write is skipped entirely when nothing moved, so a normal run never rewrites your config. It is
atomic (temp file + rename), so an interrupted write cannot truncate a file holding live
credentials. If the write fails you get one warning and the session continues — persistence is an
optimization, not a requirement.
### Attributing a refreshed credential

When pi hands back a refreshed credential, keyrouter must decide **which pool account it belongs
to** before writing it. It cannot simply use the `active` field: pi holds exactly one credential per
provider, so if you `/login` as account A while the saved `active` still names slot B, `auth.json`
holds A's token while the file says B. Writing it to the slot the pointer names would alias B onto
A, orphan B's own refresh token, and make B fail with `invalid_grant` on its next use even though
nothing had been wrong with it.

So the credential is matched, strongest signal first:

| # | Signal | Notes |
|---|---|---|
| 1 | your `identityPath` | authoritative; beats every guess below |
| 2 | an identity claim decoded from a token field | `email`, `preferred_username`, `sub`, ... |
| 3 | a known credential field | `accountId`, `projectId`, `userID`, `machineID`, `clientId` |
| 4 | exact `refresh`-token equality | works on opaque credentials; tried late because it rotates |
| 5 | the `active` pointer | only when keyrouter itself installed the credential |

Levels 2 and 3 are best-effort by nature — providers do not agree on where an identity lives, and
some credentials carry none at all. That is what `identityPath` is for.

```json
{
  "name": "cline",
  "identityPath": "access:email",
  "accounts": [ /* ... */ ]
}
```

The format is **`level1:level2`**:

- **`level1`** — a key of the credential object: `access`, `refresh`, `accountId`, or a dotted path
  for a nested field.
- **`level2`** — a path into that value **after decoding it**. Optional: with no colon, `level1`'s own
  value is compared as-is.

Decoding is automatic and best-effort, because a credential may hold JSON, a JWT, a base64-wrapped
blob, or nothing encoded at all:

| `identityPath` | Meaning |
|---|---|
| `"refresh"` | compare the refresh token and nothing else |
| `"access:email"` | decode `access`, read its `email` |
| `"access:user.email"` | the same, for a nested claim |
| `"accountId"` | compare the credential's own `accountId` |
| `"accountId:sub"` | decode `accountId`, read its `sub` |

The decode order is JWT → JSON → base64-wrapped-JSON, stopping at the first form that yields
structure. A plain string that merely happens to be base64-decodable is **not** decoded: most opaque
tokens are base64-ish, and decoding one would produce mojibake that would then be reported as an
identity. Only a decode that produces real JSON is accepted.

A path that resolves nowhere is almost always a typo. It is reported once, and detection falls back
to the automatic levels — a typo must never stop refreshes from being persisted.

Two safeguards apply when the signals are insufficient:

- **Ambiguity is refused.** If two slots share the identity you named (two logins to one address, or a
  coarse field like a shared `projectId`) and nothing sharper separates them, nothing is written.
- **A mismatched slot is refused.** Before writing, the identity already stored in the target slot is
  compared with the incoming one. If they name different accounts the write is skipped with a warning,
  because the stored credential holds a refresh token that cannot be recovered. Only stable
  identifiers are compared — the refresh token rotates, so including it would flag every legitimate
  write as a conflict.

Both refusals are logged to the trace sink and surfaced as a warning naming the provider, so a
credential that stopped persisting is visible rather than silent.

**Persistence.** The pool owns the provider credential while the extension is loaded. On a clean
shutdown (or `/keyrouter reset`) the credential that was stored when the session started is put
back; if there was none, the active account is left installed, because that is still a valid login
and logging you out would be worse. If pi is killed mid-session, `auth.json` simply holds a pool
account — still a valid login, and the next session resumes the account the last one ended on (see
[Resuming across sessions](#resuming-across-sessions)). keyrouter keeps no side copy of your
credentials anywhere: the `active` field holds an account **name** only.

**When a pool is exhausted**, the active account is left in place and pi surfaces the original
error, rather than leaving you logged out.

> **Security.** `accounts` pools need real credentials somewhere. Prefer `$ENV` / `@file` over
> inlining them, and keep the file mode at `0600`. keyrouter logs account **names** only and
> redacts every token.

---

## Commands

```
/keyrouter status    live pool state per provider (kind, active entry, install state, expiry)
/keyrouter reload     re-read ~/.pi/keyrouter.json
/keyrouter reset      hand providers back to pi's own credentials immediately
/keyrouter account <provider> [name|index]    pin a specific key or account
/keyrouter strategy <provider> [strategy]    show or set a pool's rotation strategy
/keyrouter add <provider> [name]    add a key or an account to a pool
/keyrouter remove <provider> <name|index>    remove a key or an account from a pool
```

`reset` also clears each pool's saved `active` position, so the next session starts at the first
entry rather than resuming onto the credential you just handed back.

The completion menu fills the rest in: the subcommands first, then the configured pools after
`account`, `strategy`, `add` or `remove`, then that pool's entries for `account` and `remove`, or
the strategy values valid for that pool's kind for `strategy`. Entry names are matched case-insensitively, and the pool's
current `active` entry is labelled as such. Suggestions stop as soon as the command is complete, so
`status` and `reload` never offer operands.

`account` switches a pool to a specific credential, and works for either pool kind. It accepts an
exact name, a case-insensitive name, or a 1-based index. With no name it reports the pool and the
available choices:

```
/keyrouter account cline         → cline (oauth) — active: work
                                   Choose one: /keyrouter account cline <work|home>
/keyrouter account cline home    → cline now using account home. Rotation continues from here.
/keyrouter account cline 1       → cline now using account work (pool default).
```

A pinned credential has its **cooldown cleared** — a manual pick is deliberate, so it must not be
one the automatic picker would immediately skip — and any pending retry is dropped. Rotation then
continues from the pinned position on the next failure, so this is a nudge rather than a lock.
Installs go through exactly the same path as automatic rotation, including capturing pi's rotated
blob before leaving the previous credential. The pin is also saved as the pool's `active`, so it
survives a restart.

`strategy` shows or changes how a pool picks its next entry at a turn boundary. With no arguments
it lists every pool; naming only the pool reports it; naming a pool and a value sets it:

```
/keyrouter strategy                  → strategies
                                         cline (oauth): stalest-first
                                         tokenharbor (keys): round-robin
                                       Set one: /keyrouter strategy <provider> <failover|round-robin|stalest-first|random>
/keyrouter strategy cline             → cline (oauth) — strategy: stalest-first
                                       Choose one: /keyrouter strategy cline <failover|round-robin|stalest-first|random>
/keyrouter strategy cline random     → cline strategy: stalest-first -> random (applies from the next turn boundary).
```

The change never rotates immediately — strategies act only at turn boundaries — and it is saved to
`~/.pi/keyrouter.json`, so it survives a reload and a restart. Setting `failover` removes the field
from the file (absent already means failover). On a `keys` pool, `stalest-first` is not even
offered: it orders by token expiry, which keys do not have, so it degrades to `round-robin` with a
warning — the command stores the effective value so a later reload does not warn again. A strategy
other than `failover` also shows up in `/keyrouter status` next to the pool's `source`.

`add` and `remove` manage a pool's entries without hand-editing the file:

```
/keyrouter add tokenharbor backup      → prompts for the key, then:
                                         added backup to tokenharbor. It joins the pool on the next turn.
/keyrouter add tokenharbor              → the name defaults to key-3
/keyrouter add cline                   → captures the account pi is holding (run /login first)
/keyrouter remove tokenharbor backup    → confirms, then:
                                         removed backup from tokenharbor.
```

`add` asks for an API key in a prompt and writes it to `~/.pi/keyrouter.json` — keyrouter never
runs a login of its own. (pi's prompt is a plain text field, not a masked one, so the key is
visible while you type it.) For an `accounts` pool it captures the credential **pi** is holding right
now, so the flow stays pi's own: `/login` first, then `/keyrouter add <provider>`. If pi is already
holding one of the pool's accounts, the command says so rather than adding the same credential
twice.

`remove` deletes the entry from the file after a confirmation, and forgets the pool's `active`
position when that was the entry removed. pi's own login is never touched.

`status` prints, per provider: the pool kind, the active entry, whether keyrouter has installed
anything, pi's own `source` for the provider, and each entry's `uses`, `fails`, last status and
cooldown. Counters and cooldowns are per-session; only the active position carries over, via the
`active` field. For `accounts` pools it also shows how long the credential has left — never the
token:

```
cline (oauth, active: home, installed: yes, source: stored)
  → work  uses=4 fails=1 status=rate-limited (cooldown) expires=in 47m
    home  uses=2 fails=0 status=ok expires=in 12m
```

Rotations, overloads and exhaustion each notify one themeable line. **`notifications`** sets how much of
that reaches you — `"all"` (default), `"quiet"`, or `"silent"`:

| Event | `all` | `quiet` | `silent` |
|---|---|---|---|
| rotation for `rate-limited` — the entry cools down and rejoins on its own | shown | silent | silent |
| provider `overloaded` — no key change, pi retries on its own | shown | silent | silent |
| rotation for `unauthorized` / `quota` / `refresh-failed` — the credential needs you (replace the key, top up the account, re-login) | shown | shown | silent |
| pool exhausted — the request you are waiting on actually fails | shown | shown | shown |

Pool exhaustion is never silenced: hiding the one event where the request dies would only make the
provider's own error look unexplained. `/keyrouter status` names the active level whenever it is not
the default. In headless/print mode there is
no UI, so set `PI_KEYROUTER_TRACE=<file>` to log decisions (credential **names** only, never values) —
the trace records every decision regardless of the level:

```
2026-... bootstrap tokenharbor -> primary
2026-... rotate tokenharbor primary -> backup (429 rate-limited)
2026-... continue tokenharbor (retry with the rotated key, 1/3)
2026-... success tokenharbor key=backup (cooldown cleared)
2026-... clear tokenharbor (override removed)

2026-... oauth install cline -> work (2 account(s))
2026-... rotate cline work -> home (401 unauthorized)
2026-... continue cline (retry with the rotated key, 1/2)
2026-... oauth restore cline -> session-start credential
```

---

## Compatibility note

Versions before 0.80.8 of pi exposed `ModelRegistry.authStorage`. pi 1.0.0 removed it: the
`ModelRegistry` given to extensions is a read-oriented facade over the internal `ModelRuntime`, and
its credential writers (`setRuntimeApiKey`, `login`, …) are not part of that facade.

Two internals are reached through that facade, each behind its own capability check and each
verified against pi 1.0.0's shipped bundle:

1. **The runtime overlay** (`runtime`, for `keys` pools), once the facade's `runtime` field — a
   plain property that survives bundling. It also awaits the now-async setters, where 0.78.x was
   synchronous.
2. **The credential store** (`runtime.credentials`, for `accounts` pools), whose `modify()` writes
   through pi's own `AuthStorage` so the file lock, the shared `readState` cache and the revision
   counter all stay coherent. Writing `auth.json` directly would risk clobbering a concurrent
   `/login`.

If a future pi hides either one, that pool kind reports once and stays inert — **`keys` pools and
`accounts` pools degrade independently**, so neither can take the other down. `test/verify-runtime-credentials.mjs`
is the executable record of the behaviour both depend on; run it first when bumping pi.

---

## Development

```bash
bun install
bun x tsc --noEmit -p tsconfig.json          # strict + noUncheckedIndexedAccess
node test/fake-openai-server.mjs --selftest  # the fake server's own plan engine
node test/unit-oauth.mjs                     # config parsing, store guards, /keyrouter args (no pi needed)
node test/verify-runtime-credentials.mjs     # probes pi's credential-store behaviour
node test/oauth-fixture-smoke.mjs            # proves the OAuth fixture works WITHOUT keyrouter
node test/unit-identity.mjs                  # credential->account attribution, incl. the incident replay
node test/run.mjs                            # end-to-end, 37 cases
```

Slash commands only exist in the interactive TUI, so `/keyrouter account` cannot be reached from a
`--print` run. Its argument handling is therefore a pure exported function (`parseCommandArgs`)
covered by `unit-oauth.mjs`, and the effect of a switch — including pi's refreshed-blob capture and
the shutdown restore — is exercised live in the TUI and by the automatic-rotation cases.

`test/run.mjs` starts `test/fake-openai-server.mjs` on an OS-assigned free port, spawns real
`pi --print` runs against an **isolated** agent dir and keyrouter config, and asserts on
independent signals: which `Authorization` header each request carried (the proof of rotation),
keyrouter's trace log, pi's final output, and — for OAuth cases — a log written by the fixture
provider's own refresh hook.

> Nothing touches `~/.pi`. The suite sha256s your real `~/.pi/agent/auth.json` before and after
> and **fails the run** if it changed. That check is a release blocker, because the OAuth tests
> write credentials.

The API-key cases use the `krtest` provider (api-key auth). The OAuth cases additionally load
`test/fixture/oauth-provider.ts`, which registers `kroauth` — an **OAuth-only** provider with no
`apiKey` auth method, mirroring `openai-codex`. That is what makes the tests meaningful: an
api-key overlay on such a provider resolves to nothing, so every request proves keyrouter used the
credential store rather than the overlay. The fixture also models **refresh-token rotation**, so a
credential that keyrouter failed to sync back is rejected as already-used instead of silently
working.

The fake server is scriptable — `sequence` for per-request steps, `byKey` to pin a key's fate,
plus presets for `hang`, `drop` and `badJson`:

```bash
node test/fake-openai-server.mjs --port 8791
curl -X POST 127.0.0.1:8791/__admin/plan -d '{"byKey":{"sk-a":429},"default":"ok"}'
curl 127.0.0.1:8791/__admin/log          # shows the key per request
```

Useful runner flags: `node test/run.mjs rotate` (filter), `oauth-` (just the OAuth cases),
`--verbose`, `--keep-open`.

> The `verify-runtime-credentials.mjs` probe documents the pi 1.0.0 behaviour this design rests
> on; keep it green when bumping pi. It also prints which built-in providers are OAuth-only vs
> dual-auth, which is the data behind the skip rules.

```
index.ts          entry point: events, rotation, continuation
rotation.ts       pure key-pick / cooldown logic
config.ts         config load, $ENV expansion, path override
types.ts          shared types
notification.ts   ui.notify lines
test/
  fake-openai-server.mjs  scriptable OpenAI-compatible endpoint
  run.mjs                 e2e suite
  fixture/                isolated agent dir + configs
```

---

### Publishing

Releases go out from `.github/workflows/publish.yml`, triggered by pushing a `v*` tag. The workflow
typechecks first, fails if the tag does not match `package.json`, then publishes with
`--provenance`.

There is **no npm token in this repo**. npm no longer accepts TOTP 2FA, and is retiring
bypass-2FA tokens for direct publishing, so publishing authenticates through **Trusted Publishing**:
the job's OIDC identity (`permissions: id-token: write`) is exchanged by npm for publish rights. To
set it up, add a trusted publisher on npm for the `@jeryjs` scope pointing at this repo and the
`publish.yml` workflow.

## License

MIT
