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
pi install git:github.com/jeryjs/pi-keyrouter   # or npm:jeryjs/pi-keyrouter once published
# create ~/.pi/keyrouter.json with your keys or accounts
/reload
```

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
      "takeoverOAuth": false
    }
  ],
  "maxRetries": 3,            // rotations per provider before giving up
  "cooldownMs": 60000,        // how long a failed key stays bad
  "overloadedCooldownMs": 30000 // provider-wide pause on "overloaded"/529
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

The write-back is scoped and conservative: only accounts written as an **inline object** are
updated (`$ENV` and `@file` references are left alone), only the credential fields change, and the
write is skipped entirely when nothing moved, so a normal run never rewrites your config. It is
atomic (temp file + rename), so an interrupted write cannot truncate a file holding live
credentials. If the write fails you get one warning and the session continues — persistence is an
optimization, not a requirement.

**Persistence.** The pool owns the provider credential while the extension is loaded. On a clean
shutdown (or `/keyrouter reset`) the credential that was stored when the session started is put
back; if there was none, the active account is left installed, because that is still a valid login
and logging you out would be worse. If pi is killed mid-session, `auth.json` simply holds a pool
account — still a valid login, and the next session installs account #1 again. keyrouter keeps no
side copy of your credentials anywhere.

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
```

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
blob before leaving the previous credential.

`status` prints, per provider: the pool kind, the active entry, whether keyrouter has installed
anything, pi's own `source` for the provider, and each entry's `uses`, `fails`, last status and
cooldown. For `accounts` pools it also shows how long the credential has left — never the token:

```
cline (oauth, active: home, installed: yes, source: stored)
  → work  uses=4 fails=1 status=rate-limited (cooldown) expires=in 47m
    home  uses=2 fails=0 status=ok expires=in 12m
```

Rotations, overloads and exhaustion each notify one themeable line. In headless/print mode there is
no UI, so set `PI_KEYROUTER_TRACE=<file>` to log decisions (credential **names** only, never values):

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
node test/run.mjs                            # end-to-end, 27 cases
```

Slash commands only exist in the interactive TUI, so `/keyrouter account` cannot be reached from a
`--print` run. Its argument handling is therefore a pure exported function (`parseCommandArgs`)
covered by `unit-oauth.mjs`, and the effect of a switch — including pi's refreshed-blob capture and
the shutdown restore — is exercised live in the TUI and by the automatic-rotation cases.
```

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

## License

MIT
