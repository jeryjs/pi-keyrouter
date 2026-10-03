# 🔑 pi-keyrouter

**API key pools for [pi](https://pi.dev) — injected into providers you already have.**

Multiple keys per provider · automatic 429/401/403 failover · no custom providers, no fetch hacks.

Migrated for **pi 1.0.0**. Auth, retries, OAuth, storage and headers stay entirely inside pi; this
extension only swaps which API key pi resolves.

```bash
pi install Y:/All-Projects/pi/pi-keyrouter   # or npm:pi-keyrouter once published
# create ~/.pi/keyrouter.json with your keys
/reload
```

---

## What it does

`~/.pi/keyrouter.json` declares a **pool** per provider id. At session start keyrouter puts the
first healthy key of each pool into pi's *runtime credential overlay* — the same mechanism
`pi --api-key` uses. That overlay wins over `auth.json` and environment variables, so every request
for that provider carries your pooled key.

When a request fails, keyrouter reads the error off the assistant message (`message_end`), marks the
key bad, and writes the next key into the overlay. pi's own retry then uses it.

**It never registers a provider.** Pools point at provider ids that already exist — built-ins like
`google` or `anthropic`, ids from `models.json`, and ids owned by **other extensions** such as
`cx-providers`. Nothing is shadowed, merged, or unregistered, so it cannot stomp on another
extension's provider config.

```
user prompt
   → pi resolves auth for provider "tokenharbor"   → overlay key (pool A)
   → provider answers 429
   → message_end: mark A bad, write pool key B     → overlay updated
   → pi's built-in retry                            → request uses B
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

Set `PI_KEYROUTER_CONFIG=/path/to/file` to use a different config path (the test suite relies on it).

---

## Rotation rules

The classification is deliberate, because pi only *retries* some failures.

| Signal | Detected from | Action |
|---|---|---|
| `429` / "rate limit" / "too many requests" | assistant error message | key → cooldown, **rotate** |
| `401` / `403` / "unauthorized" / "forbidden" | assistant error message | key → cooldown, **rotate** |
| `529` / "overloaded" | assistant error message | every key cools, **no rotation** (provider is busy, keys are fine) |
| `500` / `502` / `503` | assistant error message | **ignored** — pi already retries these on the same key |
| "quota exceeded" / "insufficient_quota" / billing | assistant error message | **ignored** — an account limit that rotating keys cannot fix |
| any 2xx | `after_provider_response` | key marked ok, its cooldown cleared |

Two consequences of pi's retry policy worth knowing:

- **401/403 are not in pi's retryable set.** pi stops immediately. To keep key rotation useful,
  keyrouter uses `agent_before_settle` — pi's actionable boundary that may add exactly one more
  request — and appends a hidden message so the continuation is valid. The extra request now runs
  with the rotated key. Capped at `maxRetries` per provider until that provider succeeds again, so
  an all-bad pool cannot loop.
- **Failed requests are not visible to `after_provider_response`.** The OpenAI SDK throws on non-2xx,
  so pi's response hook never fires. That is why errors are read from `message_end`.

---

## OAuth

Handled entirely by pi — keyrouter implements no auth flows.

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

---

## Commands

```
/keyrouter status    live pool state per provider
/keyrouter reload     re-read ~/.pi/keyrouter.json
/keyrouter reset      drop all overrides immediately, hand providers back to pi
```

`status` prints, per provider: the current key, whether an override is active, and each key's
`uses`, `fails`, last status and cooldown state.

Rotations, overloads and exhaustion each notify one themeable line. In headless/print mode there is
no UI, so set `PI_KEYROUTER_TRACE=<file>` to log decisions (key **names** only, never values).

```
2026-... bootstrap tokenharbor -> primary
2026-... rotate tokenharbor primary -> backup (429 rate-limited)
2026-... continue tokenharbor (retry with the rotated key, 1/3)
2026-... success tokenharbor key=backup (cooldown cleared)
2026-... clear tokenharbor (override removed)
```

---

## Compatibility note

Versions before 0.80.8 of pi exposed `ModelRegistry.authStorage`. pi 1.0.0 removed it: the
`ModelRegistry` given to extensions is a read-oriented facade over the internal `ModelRuntime`, and
its credential writers (`setRuntimeApiKey`, `login`, …) are not part of that facade.

This build reaches the runtime overlay through the facade's `runtime` field, which is a plain
property that survives pi's bundling — verified against pi 1.0.0's shipped bundle. It is guarded by
a capability check: if a future pi hides it, keyrouter reports *"runtime credential overrides
unavailable"* once and stays inert instead of crashing pi at startup. It also awaits the now-async
setter, where 0.78.x was synchronous.

---

## Development

```bash
bun install
bun x tsc --noEmit -p tsconfig.json   # strict + noUncheckedIndexedAccess
node test/fake-openai-server.mjs --selftest
node test/run.mjs                     # end-to-end, 16 cases
```

`test/run.mjs` starts `test/fake-openai-server.mjs` on a random port, spawns real `pi --print` runs
against an **isolated** agent dir and keyrouter config, and asserts on three independent signals:
which `Authorization` header each request carried (the proof of rotation), keyrouter's trace log,
and pi's final output. Nothing touches `~/.pi`.

The fake server is scriptable — `sequence` for per-request steps, `byKey` to pin a key's fate,
plus presets for `hang`, `drop` and `badJson`:

```bash
node test/fake-openai-server.mjs --port 8791
curl -X POST 127.0.0.1:8791/__admin/plan -d '{"byKey":{"sk-a":429},"default":"ok"}'
curl 127.0.0.1:8791/__admin/log          # shows the key per request
```

Useful runner flags: `node test/run.mjs rotate` (filter), `--verbose`, `--keep-open`.

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
