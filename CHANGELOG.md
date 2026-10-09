# Changelog

Notable changes to **pi-keyrouter**.

Versions `0.1.0` – `0.4.0` were published by the original author
([lowern1ght](https://github.com/lowern1ght)) as part of the
[pi-soly](https://github.com/lowern1ght/pi-soly) monorepo under
`packages/pi-keyrouter`. `1.0.0` onward is the fork maintained at
[jeryjs/pi-keyrouter](https://github.com/jeryjs/pi-keyrouter).

Entries for `0.1.0` – `0.4.0` are reconstructed from the published npm
artifacts: the `pi-keyrouter` registry metadata (versions, publish dates,
`gitHead`) and the `0.4.0` package contents. Version-level attribution is
therefore firm; which change landed in which exact minor version is inferred
from those artifacts and marked as such. Entries from `1.0.0` on are written
from the repository history directly.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [1.3.2] — 2026-10-09

### Changed

- **The publish workflow targets current runner and toolchain versions.**
  `actions/checkout` and `actions/setup-node` move to `v6` and Node to `24`.
  Trusted publishing requires npm >= 11.5.1 and Node >= 22.14.0, so pinning `24`
  clears both floors deliberately rather than relying on whatever an unpinned
  `22` happens to resolve to. `package-manager-cache: false` drops a cache that
  is keyed off the lockfile and buys nothing in a job whose only real step is
  `npm publish`.

  This release exists to validate the trusted publisher configured for this
  package, which only binds to the repository on a successful OIDC publish —
  and to carry provenance, which trusted publishing generates automatically but
  which was absent from `1.3.1` because that version did not go through the
  workflow.

## [1.3.1] — 2026-10-09

### Changed

- **The npm package is now `@jeryjs/pi-keyrouter`.** The unscoped `pi-keyrouter`
  name on npm belongs to the original author (`lowern1ght`, from the pi-soly
  monorepo) and has been frozen at `0.4.0`, so the `1.x` line could never be
  published under it. Install with `pi install npm:@jeryjs/pi-keyrouter`.

- **Description and keywords now match the GitHub repository**, so the two do not
  drift: the same one-line summary, and the repo's topics as package keywords.

- **The test suite is no longer published.** It stays in git but is out of the npm
  tarball. That halves the package (273 KB → 132 KB) and keeps files like
  `test/fixture/agent/auth.json` out of a credential tool's published artifact —
  they only ever held fixtures, but the name is not worth shipping.

- **`repository.directory` dropped.** The repo root *is* the package; the
  `packages/pi-keyrouter` path was inherited from the old monorepo and rendered
  a broken link on the package page.

- **`@earendil-works/pi-coding-agent` peer range is now `*`**, matching the other
  host-provided packages. pi suppresses automatic peer installation, so a
  `>=1.0.0` constraint bought nothing and could emit a peer warning.

### Added

- **`LICENSE.md`.** The package declared MIT in `package.json` but shipped no
  license file, so npm's page and any tarball consumer had no terms. The original
  project's notice — `Copyright (c) 2026 pi-extensions contributors` — is
  retained, since MIT requires the notice to travel with the code, with the
  fork's copyright added beneath it.

## [1.3.0] — 2026-10-09

### Added

- **Tab-completion for `/keyrouter`.** The command now offers its four
  subcommands, then the configured pool names after `account`, then that pool's
  entries — so `/keyrouter account <TAB> <TAB>` reaches a credential without
  typing or remembering its name. Entry matching is case-insensitive, pools are
  labelled by kind (`key pool` / `oauth pool`), and the pool's current `active`
  entry is marked. Completion stops once the command is complete, so `status`,
  `reload` and `reset` never offer operands they do not take.

  Pools come from the already-loaded config when there is one, and are read from
  disk otherwise, so the menu works before the first turn of a session.

## [1.2.0] — 2026-10-09

### Fixed

- **Rotation now survives a session, so a rotated pool no longer restarts on its
  first key.** `activate()` bootstrapped from a hardcoded preferred index of `0`
  and nothing was written to disk, so every new session began on entry #1 and had
  to rediscover the failures that had moved the pool off it. Each pool now
  records the entry it ended on in an `active` field, and the next session
  resumes there — falling forward to the next available entry when that one is on
  cooldown.

  A **name** rather than an index, because the config moves under you: reordering
  or inserting entries shifts every index after it, while a name still identifies
  the intended credential. An entry that has since been renamed or deleted is
  unknown, and the pool starts at its first entry — the previous behaviour.

  keyrouter writes only the name, never a key value or token. The write is atomic
  (temp file + rename), is skipped when the position is unchanged so a session
  that never rotates never touches the file, and leaves the rest of the config —
  including key order and formatting — exactly as it found it. A failure warns
  once and rotation continues, as with the credential write-back.

  Cooldowns are deliberately *not* carried over: they are per-session facts, and
  honouring a 60-second cooldown from a session hours ago would only keep a
  healthy key out of the pool.

- **`/keyrouter reset` now clears the saved position.** Without this it was a
  no-op for the next session, which resumed straight back onto the credential the
  command had just handed back to pi.

- **`/keyrouter account <provider> <name>` now survives a restart**, since a
  manual pin is saved as the pool's `active` like any other rotation.

## [1.1.1] — 2026-10-06

### Fixed

- **Refreshed credentials are now persisted, so pooled accounts stop going
  stale.** pi refreshes lazily and writes the rotated access/refresh pair to
  `auth.json`; keyrouter keeps its own copy of each account, and installing the
  next account overwrote what pi had refreshed. The pool therefore kept the
  access token from an account's *last login* — and because access tokens are
  short-lived (60 minutes for WorkOS/Cline), any real use left the pool
  installing an expired token. Every account then failed with an OAuth refresh
  error and looked dead. Fixes
  `OAUTH refresh failed for <provider>` repeating across all accounts in a pool.
- `UNAUTHORIZED_RE` matched `401` inside pi's `OAuth refresh failed for …`
  wrapper, mislabelling a dead credential as a plain unauthorized error. The
  refresh-failure classification now runs first, since it is strictly more
  specific.

### Added

- `writeBackCredentials()` in `config.ts`: merges a refreshed credential back
  into `keyrouter.json` in place. Only accounts written as an **inline object**
  are eligible (`$ENV` / `@file` references are the user's own indirection and
  are left alone), only the credential fields change, the write is atomic
  (temp file + rename) so an interrupted write cannot truncate a file holding
  live credentials, it is skipped entirely when nothing changed, and a failure
  warns once instead of throwing.
- `test/cline-refresh-probe.mjs`: probes a provider's token-refresh endpoint per
  stored account and reports which tokens are genuinely dead versus merely
  stale, without persisting anything. This is the tool that distinguishes
  "the credential is dead" from "we sent a stale one" from "the request was
  malformed" — distinctions pi's single-sentence error collapses.

### Changed

- `ProviderRuntime` gained `configName`. Persisting has to match the config
  entry by the name the user wrote, because `resolveProviderId` may have
  canonicalized it (`z-ai` → `zai`) and the config is never rewritten to the
  canonical form.
- `captureAccount()` now takes the runtime and writes through to disk;
  `sameCredential()` decides whether a write is needed by comparing **both**
  secrets and the expiry, since providers differ in which part of the pair
  rotates.

### Tests

- `oauth-persists-refreshed-credential-to-config` asserts the refreshed value
  reaches the config **file**, not just memory. Verified to be a real test:
  temporarily disabling the write makes it fail on exactly the write-back
  assertions and nothing else.
- `oauth-does-not-churn-config-when-nothing-changed` guards the no-op path.
- 20 new unit checks covering `writeBackCredentials` (provider-specific extras,
  sibling accounts, unknown top-level fields, no-op behaviour, unknown pool) and
  `sameCredential` (both secrets, moved expiry, null safety).
- Suite: 29/29 e2e, 100/100 unit, `tsc` clean. The real `~/.pi/agent/auth.json`
  is unchanged and the real `keyrouter.json` is byte-identical after a run
  (correctly a no-op).

## [1.1.0] — 2026-10-03

### Added

- **`/keyrouter account <provider> [name|index]`** — pin a pool to a specific
  API key or OAuth account. Works for either pool kind. Accepts an exact name, a
  case-insensitive name, or a 1-based ordinal; with no name it reports the pool
  and the available choices.
- A pinned credential has its cooldown cleared and any pending retry dropped — a
  manual pick is deliberate, so it must not be one the automatic picker would
  immediately skip. Rotation continues from the pinned position on the next
  failure, making this a nudge rather than a lock.

### Changed

- The install path is **shared with automatic rotation**
  (`applyAccount` / `applyKey`, with the capture step before leaving the
  previous credential). A second install path would have been the easiest way to
  lose pi's rotated refresh token.
- The `/keyrouter` command description and usage line list the new subcommand.

### Tests

- `parseCommandArgs()` extracted as a pure exported function with 16 unit checks
  (bare invocation, unknown subcommand, case-insensitivity, ordinals, operand
  case preservation) — slash commands only exist in the interactive TUI, so
  print-mode tests cannot reach the handler.
- The handler was verified **live in the TUI**: status rendering, the no-arg
  listing, switch by name, switch by ordinal, unknown provider, unknown name,
  and a real `auth.json` showing the newly installed credential with the
  unrelated provider entry intact, followed by
  `oauth restore … -> session-start credential` on exit.

## [1.0.0] — 2026-10-03

### Added

- **OAuth account pools (`accounts`).** A provider can declare several stored
  OAuth logins and keyrouter rotates between them on the same signals that
  rotate API keys. This is the case pi itself cannot express: `auth.json` is a
  `Record<providerId, Credential>` holding exactly one credential per provider
  id, so accounts 2..N have nowhere to live.
  - Installs go through pi's own credential store
    (`runtime.credentials.modify`), so pi's file lock, shared `readState` cache
    and revision counter stay coherent. Writing `auth.json` directly would risk
    clobbering a concurrent `/login`.
  - pi keeps owning OAuth entirely: the flow, `/login`, refresh, and headers.
    keyrouter never refreshes a token and never writes `auth.json` itself.
  - Because pi rotates refresh tokens in place, the pool reads the live
    credential back both when it leaves an account and after installing one.
  - `credential` accepts an inline object, `$ENV` holding a JSON string, or
    `@file`. A credential is used only if it has `type: "oauth"`, a non-empty
    `access`, a `refresh`, and a numeric `expires`; anything else is dropped with
    a warning naming the account only.
  - `rotateOnQuota` (default `true`) decides whether an account-level limit
    rotates the pool. Deliberately the opposite default from API-key pools:
    each OAuth account is a separate subscription, so a limit is exactly when
    the next account is wanted, whereas a different API key on the same account
    cannot lift an account-wide limit.
  - On clean shutdown the credential that was stored at session start is put
    back. If there was none, the active account is left installed, because that
    is still a valid login and logging the user out would be worse.
- Dead-refresh-token errors (`OAuth refresh failed`, `invalid_grant`) are
  classified as a dead account and rotated away from.
- `/keyrouter status` shows the pool kind, active entry, install state, pi's own
  `source` for the provider, and each entry's expiry — never a token.
- Status output shows credential expiry as a relative time, and free of the
  credential value.
- `test/verify-runtime-credentials.mjs`, `test/oauth-fixture-smoke.mjs`,
  `test/oauth-cases.mjs`, `test/fixture/oauth-provider.ts` and
  `test/unit-oauth.mjs`.
- The test runner picks an OS-assigned free port instead of guessing in a fixed
  range, which intermittently landed on a Windows reserved port and failed as
  `EACCES`.

### Changed

- **Migrated to pi 1.0.0.** `ModelRegistry.authStorage` was removed upstream: the
  `ModelRegistry` given to extensions is now a read-oriented facade over the
  internal `ModelRuntime`, and its credential writers are not part of that
  facade. keyrouter reaches the runtime overlay through the facade's `runtime`
  field, behind a capability check, and awaits the now-async setters.
- **Never registers its own provider.** Pools point at provider ids that already
  exist — built-ins, `models.json` ids, and ids owned by other extensions such
  as `cx-providers`. Nothing is shadowed, merged or unregistered.
- Provider ids are resolved case-insensitively against the ids pi actually knows
  and stored in canonical form, so `z-ai` / `Z.AI` map to the real id.
- `keys` and `accounts` are mutually exclusive for one provider; specifying both
  is reported and `keys` wins.
- API-key pools now bootstrap their first key at session start. Previously the
  index was tracked but the key was never actually installed.
- A pool with no usable keys after `$ENV` expansion is dropped with a warning
  instead of silently doing nothing.

### Fixed

- The runtime api_key overlay is never used for an `accounts` pool.
  `setRuntimeApiKey` stores only a string and pi's resolver returns early on any
  override: on an OAuth-only provider (e.g. `openai-codex`) that yields **no auth
  at all**, and on a dual-auth provider it **freezes the token** so pi stops
  refreshing it. Verified against pi 1.0.0 — with an overlay installed on
  `openai-codex`, `getProviderAuthStatus()` still reports `source=runtime` while
  `getAuth()` resolves to `undefined`.
- Activation clears any leftover api_key overlay before installing an account,
  so an earlier API-key configuration cannot shadow the OAuth credential.
- `401` / `403` and quota errors are not in pi's retryable set, so a rotation
  triggered by one of them was never used. Such swaps now request exactly one
  more request at pi's `agent_before_settle` boundary, appending a hidden
  message to make the continuation valid, and are bounded by `maxRetries` per
  provider so an all-bad pool cannot loop.
- The per-provider continuation budget is respected when the picked entry is
  still cooling, rather than spending a request on another cooldown.

### Tests

- Full e2e suite against a scriptable fake OpenAI-compatible server, asserting on
  three independent signals: which `Authorization` header each request carried
  (the proof rotation happened), keyrouter's trace log, and pi's final output.
- The suite sha256s the real `~/.pi/agent/auth.json` before and after the run and
  **fails if it changed**, because the OAuth cases write credentials.
- The OAuth cases load `test/fixture/oauth-provider.ts`, which registers
  `kroauth` — an OAuth-only provider mirroring `openai-codex`. An api-key
  overlay on such a provider resolves to nothing, so every request proves
  keyrouter used the credential store rather than the overlay. The fixture also
  models refresh-token rotation, so a credential that is not synced back is
  rejected as already-used instead of silently working.

## [0.4.0] — 2026-06-24

The last release of the original line, and the version this fork started from.

- Switched from wrapping `globalThis.fetch` to pi's native
  `authStorage.setRuntimeApiKey()`. The fetch wrapper did not work: pi-ai's
  OpenAI SDK captures the `fetch` reference when the client is created, before
  extensions load, so the SDK kept calling the original function.
- `/keyrouter enable` / `disable` subcommands, and a Box widget notification on
  every key switch.
- 33 tests.
- *Inferred version attribution:* the `0.4.0` package contents are as listed
  here; the `enable`/`disable` split and the widget are attributed to this
  release from those contents.

## [0.3.1] — 2026-06-17

- Packaging fix: file count went from 6 to 7 and unpacked size grew to 28.9 kB.
  *Inferred from the published artifact metadata; the exact content of the
  added file is not recorded here.*

## [0.3.0] — 2026-06-17

- Reported as a feature release by its version bump. *Details not recoverable
  from the published artifacts.*

## [0.2.3] — 2026-06-17

- Patch release. *Details not recoverable from the published artifacts.*

## [0.2.2] — 2026-06-17

- Patch release. *Details not recoverable from the published artifacts.*

## [0.2.1] — 2026-06-17

- Patch release. *Details not recoverable from the published artifacts.*

## [0.2.0] — 2026-06-17

- Reported as a feature release by its version bump. *Details not recoverable
  from the published artifacts.*

## [0.1.0] — 2026-06-17

- Initial published release: API key rotation for pi-coding-agent. Multiple keys
  per provider, automatic 429/401 fallback, and a max-retries guard.
- Config at `~/.pi/keyrouter.json`, deliberately user-level only — project-local
  config files are ignored so a cloned repository cannot override real keys.
- `match` URL substrings per provider, `maxRetries`, and `cooldownMs`.
- Docs at this release describe rotating the current key on 429 and marking keys
  `rate-limited` or `unauthorized` with a cooldown, plus clearing the override
  and surfacing the real error once all keys are exhausted.

[Unreleased]: https://github.com/jeryjs/pi-keyrouter/compare/v1.3.2...HEAD
[1.3.2]: https://github.com/jeryjs/pi-keyrouter/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/jeryjs/pi-keyrouter/compare/v1.3.0...v1.3.1
[1.2.0]: https://github.com/jeryjs/pi-keyrouter/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/jeryjs/pi-keyrouter/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/jeryjs/pi-keyrouter/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/jeryjs/pi-keyrouter/compare/v0.4.0...v1.0.0
[0.4.0]: https://www.npmjs.com/package/pi-keyrouter/v/0.4.0
[0.3.1]: https://www.npmjs.com/package/pi-keyrouter/v/0.3.1
[0.3.0]: https://www.npmjs.com/package/pi-keyrouter/v/0.3.0
[0.2.3]: https://www.npmjs.com/package/pi-keyrouter/v/0.2.3
[0.2.2]: https://www.npmjs.com/package/pi-keyrouter/v/0.2.2
[0.2.1]: https://www.npmjs.com/package/pi-keyrouter/v/0.2.1
[0.2.0]: https://www.npmjs.com/package/pi-keyrouter/v/0.2.0
[0.1.0]: https://www.npmjs.com/package/pi-keyrouter/v/0.1.0