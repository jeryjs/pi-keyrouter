# Handoff: OAuth account pools for pi-keyrouter

> **STATUS: IMPLEMENTED.** This document is now the design record rather than a to-do list.
> All 8 steps in §6 are complete: `accounts` pools rotate between stored OAuth logins, all 12 OAuth
> cases and the 16 original API-key cases pass (**27/27**), `tsc` is clean, and the suite proves the
> real `~/.pi/agent/auth.json` is byte-identical before and after. See §11 for what implementation
> changed relative to this plan — three things in §3 turned out to be wrong, and one design detail
> (§4.6 restore semantics) needed adjusting.

**Deliverable:** pi-keyrouter rotates between multiple stored OAuth accounts for a provider, on the
same signals that already rotate API keys, while leaving token refresh 100% owned by pi.

**Repo:** `Y:\All-Projects\pi\pi-keyrouter` (branch `main`)

**Read this whole document before changing the OAuth path.** Everything under "Verified reference"
was read from the installed pi 1.0.0 during design and later re-confirmed by
`test/verify-runtime-credentials.mjs`.

---

## 1. Mission and success criteria

---

## 1. Mission and success criteria

Add a second pool type to keyrouter:

| | API-key pool (exists, 16/16 tests) | OAuth pool (this task) |
|---|---|---|
| Config | `"keys": [{name, value}]` | `"accounts": [{name, credential}]` |
| Install | `runtime.setRuntimeApiKey(id, "sk-...")` | `runtime.credentials.modify(id, () => blob)` |
| Persisted | no (in-memory overlay) | **yes** (`auth.json`) |
| Refresh owner | n/a | **pi** (`resolveStoredOAuth`) |
| Code per provider | none | none |

Success criteria:

1. A provider configured with `accounts` installs account #1 into pi's credential store at session
   start, and requests carry that account's auth.
2. A 429, 401, 403, or an account-level limit/`quota exceeded` error rotates to the next account and
   the next request carries it. For the non-retryable classes this requires the existing
   `agent_before_settle` continuation (pi does not retry those).
3. **keyrouter never refreshes a token.** pi refreshes lazily; keyrouter only copies blobs.
4. Refreshed tokens are not lost: before leaving an account, keyrouter reads the store back into that
   account's pool entry, so a later re-install uses pi's rotated tokens, not stale ones.
5. On clean shutdown the credential that was installed at session start is reinstalled.
6. If `runtime.credentials` is missing or not writable, keyrouter reports once and stays inert for
   OAuth pools only. API-key pools must keep working.
7. Everything is generic: one code path for every provider. No provider-specific branching anywhere.
8. Full suite green: existing 16 API-key cases + the new OAuth cases. `bun x tsc --noEmit` clean.

Non-goals: implementing any OAuth flow; calling any refresh endpoint; registering providers;
inventing a multi-account slot in pi; touching the user's real `~/.pi` in tests or during
development.

---

## 2. Verified reference (pi 1.0.0)

Install root: `Y:\Dev\NodeJS\node_modules\@earendil-works\pi-coding-agent\`
Bundled CLI actually run by `pi.cmd`: `dist\bundle\cli.js`

### 2.1 Why the API-key overlay cannot carry OAuth

`dist/core/runtime-credentials.js` — `overrides` is `Map<providerId, string>`:

```js
export class RuntimeCredentials {
    store;
    overrides = new Map();
    constructor(store) { this.store = store; }
    setRuntimeApiKey(providerId, apiKey) { this.overrides.set(providerId, apiKey); }
    removeRuntimeApiKey(providerId) { this.overrides.delete(providerId); }
    hasRuntimeApiKey(providerId) { return this.overrides.has(providerId); }
    async read(providerId, options) {
        options?.signal?.throwIfAborted();
        const override = this.overrides.get(providerId);
        return override ? { type: "api_key", key: override } : this.store.read(providerId, options);
    }
    async list(options) { /* store entries + overrides as {providerId, type:"api_key"} */ }
    modify(providerId, fn, options) { return this.store.modify(providerId, fn, options); } // ← delegates
    async delete(providerId, options) { await this.store.delete(providerId, options); this.overrides.delete(providerId); }
}
```

`pi-ai/dist/auth/resolve.js` returns early for any override:

```js
const stored = await readCredential(credentials, provider.id, signal);
if (stored) {
    if (stored.type === "oauth"   && provider.auth.oauth)  return resolveStoredOAuth(credentials, provider.id, provider.auth.oauth, stored, signal, overrides?.minOAuthValidityMs);
    if (stored.type === "api_key" && provider.auth.apiKey) return resolveApiKey(requestAuthContext, provider.auth.apiKey, provider.id, credential, signal);
    return undefined;   // ← api_key credential on an OAuth-only provider = no auth at all
}
```

Consequences the agent must respect:

- Injecting an api_key for an **OAuth-only** provider (no `auth.apiKey`) breaks auth outright.
- Injecting an api_key for a provider that has **both** (e.g. `cline`) works but **freezes** the token:
  the api_key branch never refreshes.
- Therefore OAuth pools must never set a runtime override, and must remove any override left from an
  earlier API-key config for that id.

### 2.2 The store pi actually uses

`dist/core/model-runtime.js:79`

```js
const credentials = new RuntimeCredentials(options.credentials ?? DefaultAuthStorage.create(options.authPath));
```

So reachable as `ctx.modelRegistry.runtime.credentials` (a `RuntimeCredentials`), whose `.store` is the
value class. Call `modify` on the `RuntimeCredentials` itself — it forwards to the store and it is one
hop shallower than reaching `.store` directly.

`dist/core/auth-storage.js` (class `AuthStorage implements CredentialStore`):

```js
async modify(provider, fn, options) {
    let latestData = this.readState.data;
    let revision;
    const result = await this.storage.withLockAsync(async (content) => {
        const currentData = this.parseStorageData(content);
        const next = await fn(currentData[provider]);
        if (next === undefined) {                       // undefined = "no change"
            latestData = currentData;
            revision = this.authPath ? getFileRevision(this.authPath) : undefined;
            return { result: currentData[provider] };
        }
        const merged = { ...currentData, [provider]: next };
        latestData = merged;
        return { result: next, next: JSON.stringify(merged, null, 2) };
    }, options);
    this.updateReadState(latestData, revision);
    return result;
}
```

Key properties:

- Writes are serialized by `withLockAsync` (async chain) + `proper-lockfile` on the file.
- The write is whole-file, `JSON.stringify(merged, null, 2)`, mode `0o600`.
- `updateReadState(latestData, revision)` keeps the in-process cache coherent.
- **`readLatestData()`** (used by `read()`) compares `getFileRevision(authPath)` against
  `readState.revision` and reloads when the file changed:

```js
async readLatestData(options) {
    if (!this.authPath) { /* non-file backend */ }
    const revision = getFileRevision(this.authPath);
    if (revision !== undefined && revision === this.readState.revision) return this.readState.data;
    /* else reload from storage, coalesced with an AbortController + reader refcount */
}
```

- `sharedAuthFileReadState` is a **module-level singleton** keyed by `authPath`, so every
  `AuthStorage` for the same file shares one `readState`.
- `ReadOnlyAuthStorage.modify/delete` throw `"Read-only credential storage cannot modify auth.json"`.
  Catch this and degrade (it is what a read-only mode uses).
- `read()` resolves `!command` / `$ENV` only for `type: "api_key"` credentials; OAuth blobs pass
  through untouched.

Also exported from the package root (`dist/index.js:6`): `readStoredCredential(providerId, authPath?)`,
a plain sync file read returning `data[providerId]` or `undefined`. Use for **reads only**.

`AuthStorage` itself is **not** exported from the package root (removed in 0.80.8). Do not try to
import it; use pi's live instance.

### 2.3 Credential shape

`pi-ai/dist/auth/types.d.ts`

```ts
export interface ApiKeyCredential { type: "api_key"; key?: string; env?: ProviderEnv }
export interface OAuthCredentials { refresh: string; access: string; expires: number; [key: string]: unknown }
export interface OAuthCredential extends OAuthCredentials { type: "oauth" }
export type Credential = ApiKeyCredential | OAuthCredential;
```

`auth.json` is `Record<providerId, Credential>` — **exactly one credential per provider id**. There is
no multi-account slot anywhere in pi; that is why pools must hold accounts 2..N.

Field variance across the 8 OAuth providers on this machine (all handled opaquely):

| provider | extra fields |
|---|---|
| github-copilot | `availableModelIds` |
| openai-codex | `accountId` |
| google-antigravity, google-gemini-cli | `projectId` |
| kiro | `authMethod`, `clientId`, `clientSecret`, `region` |
| qoder | `email`, `machineID`, `name`, `userID` |
| cline, kilo | (common fields only) |

### 2.4 Refresh is lazy and pi-owned

`resolveStoredOAuth` (in `pi-ai/dist/auth/resolve.js`):

- Minimum remaining validity `Math.max(5min, minOAuthValidityMs ?? 0)`.
- If expiring: `credentials.modify(providerId, async (current) => { ... oauth.refresh(current, refreshSignal) ... }, { signal })`
  with a 15 s refresh timeout, then `return { auth: await oauth.toAuth(credential), source: "OAuth" }`.
- The rotated credential is persisted **by pi**, under the same provider id, before release.

So: install blobs, never refresh, and read back to keep pool copies fresh.

### 2.5 Retry semantics (drives the classification table)

`pi-ai/dist/utils/retry.js`

- `NON_RETRYABLE_PROVIDER_LIMIT_ERROR_PATTERN`: `GoUsageLimitError`, `FreeUsageLimitError`,
  `Monthly usage limit reached`, `available balance`, `insufficient_quota`, `out of budget`,
  `quota exceeded`, `billing`, `subscription_sharing_usage_limit_exceeded`.
- `RETRYABLE_PROVIDER_ERROR_PATTERN` includes `overloaded`, `currently experiencing high demand`,
  `rate.?limit`, `too many requests`, `429`, `500`, `502`, `503`, `504`, `520`, `524`,
  `service.?unavailable`, `server.?error`, `internal.?error`, `provider.?returned.?error`,
  `ended without`, `stream ended before message_stop`, transport/network phrases,
  `retry delay`, `you can retry your request`, `ResourceExhausted`, and the two
  `subscription_sharing_*_unavailable` strings.
- **`401`, `403`, `unauthorized`, `forbidden` appear in neither list** → `isRetryableAssistantError()`
  is false → pi stops on the first failure. This is why the settle-time continuation exists.
- `retryDelayMs(policy, attempt) = min(baseDelayMs * 2**(attempt-1), maxAgentDelayMs ?? 60_000)`.

### 2.6 Continuation mechanics

`dist/core/agent-session.js`:

```js
async _runAgentPrompt(messages) {
    await this.agent.prompt(messages);
    while (!this._agentRunAbortRequested) {
        if (await this._handlePostAgentRun()) {          // pi's own retry/compaction/queue
            if (this._agentRunAbortRequested) break;
            await this.agent.continue(); continue;
        }
        if (this._agentRunAbortRequested || !(await this._runBeforeSettleBoundary())) break;
        await this.agent.continue();
    }
}

async _runBeforeSettleBoundary() {
    if (!this._extensionRunner.hasHandlers("agent_before_settle")) return this.agent.hasQueuedMessages();
    const result = await this._extensionRunner.emitBoundary({ type: "agent_before_settle", outcome: this._lastActivityOutcome }, ...);
    this._commitBoundaryDrafts(result.entries);
    this._flushPendingCustomMessages();
    const finalContext = this._buildBoundaryContext([], "agent_before_settle");
    const shouldContinue = result.continue || this.agent.hasQueuedMessages();
    if (shouldContinue && !finalContext.canContinue) {      // ← continue is validated AFTER entries commit
        if (result.continue) this._reportInvalidBoundaryContinuation("agent_before_settle");
        return false;
    }
    return shouldContinue;
}
```

`_buildBoundaryContext` computes:

```js
const llmMessages = convertToLlm(projection.messages);
const finalRole = llmMessages[llmMessages.length - 1]?.role;
const contextCanContinue = hasNonSystemContext && finalRole !== "assistant";
const pendingCustomContext = this._pendingCustomMessages.length > 0;
canContinue: contextCanContinue || pendingCustomContext ||
    (boundary === "turn_end" ? this.agent.hasQueuedMessages()
                             : finalRole === "assistant" && this.agent.hasQueuedMessages())
```

`dist/core/messages.js` `convertToLlm()` maps a `role: "custom"` message to `role: "user"`, which is
exactly why keyrouter's hidden `custom_message` draft makes `continue: true` valid after a failed
assistant turn. This is already implemented and tested; reuse it.

### 2.7 Boundary handler contract

`dist/core/extensions/runner.js` `emitBoundary()`:

```js
let entries = [], shouldContinue = false, context = await buildContext(entries);
for (const { ext, handlers } of snapshotEventHandlers(this.extensions, baseEvent.type)) {
    for (const handler of handlers) {
        const event = { ...baseEvent, entries, continue: shouldContinue, context };
        try {
            const handlerResult = await handler(event, ctx);
            if (handlerResult?.entries !== undefined) entries = handlerResult.entries;
            if (handlerResult?.continue !== undefined) shouldContinue = handlerResult.continue;
        } catch (err) { this.emitError({ /* extension path, event, message, stack */ }); }
    }
}
```

So a handler receives the accumulated `entries` and must return `[...event.entries, myDraft]`.

### 2.8 Misc facts that matter

- `ModelRegistry` (what `ctx.modelRegistry` is) is a facade; the runtime overlay is at
  `ctx.modelRegistry.runtime`. The `runtime` field name survives bundling — verified in
  `dist/bundle/chunks/chunk-33XOIQ5N.js` (`var ModelRegistry=class{runtime;constructor(runtime){this.runtime=runtime}...}`).
- jiti aliases `@earendil-works/pi-coding-agent` to `dist/index.js` (the module pi itself loaded), so
  a value import of `readStoredCredential` is a single shared instance, not a duplicate copy
  (`dist/core/extensions/loader.js:41,63`).
- `ModelRuntime.getProviderAuthStatus(providerId)` returns
  `{configured, source: "runtime" | "stored" | "environment" | ..., label?}`. It reports `"runtime"`
  when an overlay key exists, `"stored"` when the credential store has the id.
- `ModelRuntime.setRuntimeApiKey` / `removeRuntimeApiKey` are async and call
  `synchronizeCredentialState()` → `recomposeProvider` + `models.refresh({allowNetwork:false, providers:[id]})`
  + `updateModelSnapshot`, serialized per provider by `enqueueCredentialOperation`. They can throw
  `CredentialSynchronizationError`.
- `AgentMessage` is a union (`Message | CustomAgentMessages[...]`); `AssistantMessage` carries
  `provider`, `model`, `stopReason`, `errorMessage`. Read failures from there, not from
  `after_provider_response` (the OpenAI SDK throws on non-2xx, so pi's response hook never fires).
- `agent_before_settle` is the final actionable boundary; `agent_settled` is notification-only.

### 2.9 Reference provider: pi-free's cline

`C:\Users\Jery\.pi\agent\npm\node_modules\pi-free\dist\providers\cline\cline-auth.js`

```js
export function toApiKey(credentials) {
    const token = credentials.access;
    return token.startsWith("workos:") ? token : `workos:${token}`;
}
export const clineOAuthAuth = {
    name: "Cline", loginLabel: "Sign in with Cline",
    login: loginClineNative,
    refresh: refreshClineCredential,                       // wraps refreshClineToken
    async toAuth(credential) { return { apiKey: toApiKey(credential) }; },
};
export const clineAuth = { apiKey: clineApiKeyAuth, oauth: clineOAuthAuth };
```

`parseExpiresAt(expiresAt) = Math.max(Date.now() + 30_000, Date.parse(expiresAt) - 5 * 60_000)`.
`refreshClineToken` retries once after 1 s, then throws
`"Cline token refresh failed. Run /login cline to re-authenticate."`. `PROVIDER_CLINE = "cline"`.

This is a good example of why opaque blobs matter: cline turns its OAuth credential into an apiKey
string, copilot carries `availableModelIds`, kiro carries client credentials. keyrouter must never
look inside.

---

## 3. Answers (probed at implementation time)

All five questions were answered by `test/verify-runtime-credentials.mjs`, which is kept in the repo
as the executable record. Run it with `PI_PKG_ROOT` set to the pi package root for the
`ReadOnlyAuthStorage` case.

| # | Question | Answer |
|---|---|---|
| 1 | `AuthStorage.create()` signature | `static create(authPath = join(getAgentDir(), "auth.json"))` — confirmed at `auth-storage.js:282`. No behaviour depended on it. |
| 2 | Does `refresh()` update `authStatus.source`? | **Not needed.** Reading `getAuth()` after `modify()` reflects the write immediately. `getProviderAuthStatus()` is used for display only. |
| 3 | What wraps `_isRetryableError`? | Confirmed: `agent-session.js:2944` → `isRetryableAssistantError(message)`. The retry table in §2.5 holds as written. |
| 4 | End of `emitBoundary()` | Confirmed (`runner.js:797`): returns `{entries, continue, context, valid}`; **`valid: false` discards all entries** (`entries: []`, `continue: false`). Handlers returning invalid drafts therefore cannot corrupt the transcript, but a handler that returns a bad draft also silently loses its continuation. |
| 5 | Does a `custom_message` draft still buy one extra request for an OAuth pool? | Yes — proven by `oauth-rotate-on-401` and `oauth-rotate-on-account-quota`, which each assert exactly one continuation and a second request carrying the next account. |

### Three corrections to §2

1. **`getAuth().source` and `getProviderAuthStatus().source` use different vocabularies.** `getAuth()`
   says `"OAuth"`; `getProviderAuthStatus()` says `"stored"`. Both say `"runtime"` for an overlay.
   Comparing one enum against the other is a silent bug — the probe asserts both spellings.
2. **A resolved OAuth credential can legitimately carry `auth.apiKey`.** pi calls the provider's
   `oauth.toAuth(credential)`, and e.g. `openai-codex` turns its blob into a bearer string. So
   "does `auth.apiKey` exist?" proves nothing about whether an overlay is installed; `source` is the
   only trustworthy discriminator. (An earlier draft of this document got this wrong.)
3. **§2.1's claim is stronger than stated.** The probe confirms it directly against pi 1.0.0: with
   an api_key overlay installed on the OAuth-only provider `openai-codex`, `getProviderAuthStatus()`
   reports `source=runtime` (looks configured) while `getAuth()` resolves to **`undefined`** — no auth
   at all. That asymmetry is the entire reason OAuth pools must not use the overlay.

Built-in auth shapes for reference (from `@earendil-works/pi-ai/providers/all`): **42** providers, of
which `openai-codex` is the only OAuth-only one; the dual-auth set is `anthropic`, `github-copilot`,
`kimi-coding`, `meta`, `openai`, `openrouter`, `radius`, `xai`.

---

## 4. Design

### 4.1 Terminology

- **pool kind** — `"keys"` (api keys) or `"oauth"` (account blobs).
- **install** — write a pool entry into pi's credential store via `credentials.modify`.
- **capture** — read the store back and update the pool entry, preserving pi's refreshed tokens.
- **active account** — the pool index currently installed.

### 4.2 Config schema

```jsonc
{
  "providers": [
    {
      "name": "cline",
      "accounts": [
        { "name": "jery99961",  "credential": { "type": "oauth", "access": "…", "refresh": "…", "expires": 1791056623000 } },
        { "name": "jsjery123",  "credential": "$CLINE_ACCOUNT_2" },   // env holds a JSON string
        { "name": "third",      "credential": "@~/.pi/accounts/cline3.json" }
      ],
      "rotateOnQuota": true
    },
    { "name": "tokenharbor", "keys": [ { "name": "a", "value": "$TOKENHARBOR_API_KEY" } ] }
  ],
  "maxRetries": 3,
  "cooldownMs": 60000,
  "overloadedCooldownMs": 30000
}
```

Rules:

- `keys` and `accounts` are mutually exclusive; a provider with both is rejected with a warning.
- `credential` accepts: an inline object; `$NAME` / `${NAME}` where the env value is a JSON string;
  or `@path` (leading `@`, `~` expanded) pointing at a JSON file containing one credential object.
- After resolution the result must be an object with `type === "oauth"`, a non-empty string `access`,
  a string `refresh`, and a numeric `expires`. Anything else is dropped from the pool with one warning.
- Dropping all accounts drops the provider from config (existing behaviour for empty `keys`).
- `rotateOnQuota` defaults to `true` for `accounts` pools and is ignored for `keys` pools.
- Secrets: document that the config may hold live credentials; recommend `$ENV` / `@file` with mode
  `0600`. Never log a credential value; log only account names.

### 4.3 Data model

Reuse `KeyState` from `rotation.ts` so the existing picker/cooldown logic is shared unchanged. Extend
it with one opaque field:

```ts
export interface KeyState {
  name: string;
  value: string;              // keys pool: the key. oauth pool: "" (never read)
  credential?: OAuthCredential; // oauth pool only — opaque blob
  lastStatus: "ok" | "rate-limited" | "unauthorized" | "untried";
  cooldownUntil: number;
  overloadedUntil: number;
  uses: number;
  failures: number;
}
```

`ProviderRuntime` gains a kind and OAuth bookkeeping; keep the existing fields so the API-key path is
untouched:

```ts
type PoolKind = "keys" | "oauth";

interface ProviderRuntime {
  providerId: string;
  kind: PoolKind;
  keys: KeyState[];            // entries for both kinds (rotation.ts stays generic)
  currentIndex: number;        // active pool index for both kinds
  injecting: boolean;          // keys pool: overlay written, needs clearing
  sessionStartIndex: number;   // oauth pool: index installed at activate(), for restore
  pendingContinue: boolean;
  continuations: number;
}
```

### 4.4 New module: `oauth.ts`

Keep `index.ts` from growing. Export small, dependency-injected functions so they can be unit tested
without pi:

```ts
// oauth.ts
export interface CredentialStoreApi {
  read(providerId: string, options?: { signal?: AbortSignal }): Promise<unknown>;
  modify(
    providerId: string,
    fn: (current: unknown) => Promise<unknown>,
    options?: { signal?: AbortSignal },
  ): Promise<unknown>;
  hasRuntimeApiKey?(providerId: string): boolean;
}

/** Reach pi's live credential store through the ModelRegistry facade. Capability-checked. */
export function credentialStore(registry: unknown): CredentialStoreApi | undefined {
  const runtime = (registry as { runtime?: { credentials?: Partial<CredentialStoreApi> } })?.runtime;
  const store = runtime?.credentials;
  if (!store || typeof store.modify !== "function" || typeof store.read !== "function") return undefined;
  return store as CredentialStoreApi;
}

export function isOAuthCredential(value: unknown): value is OAuthCredential;

/** Install a blob. Returns false (never throws) so callers can degrade. */
export async function installCredential(
  store: CredentialStoreApi,
  providerId: string,
  credential: OAuthCredential,
): Promise<boolean>;

/** Read the live credential so pi's refresh rotation is not lost. */
export async function captureCredential(
  store: CredentialStoreApi,
  providerId: string,
): Promise<OAuthCredential | undefined>;

/** Ensure no api-key overlay shadows the OAuth credential. */
export async function clearOverlay(registry: unknown, providerId: string): Promise<void>;

/** Parse config forms: inline object | $ENV JSON string | @file. */
export function parseAccountCredential(raw: unknown): OAuthCredential | undefined;
```

Implementation notes:

- `installCredential`: `await store.modify(providerId, async () => credential)` — returning the object
  is what writes it. Catch and return `false`, reporting the message once (mirror the existing
  `lastErrorNotified` pattern). A `ReadOnlyAuthStorage` throw lands here and must produce the same
  single, actionable warning.
- `captureCredential`: `const current = await store.read(providerId); return isOAuthCredential(current) ? current : undefined;`
- After a successful install of the **first** account in a session, consider
  `ctx.modelRegistry.refresh({ providers: [providerId], allowNetwork: false })` and swallow errors;
  treat as cosmetic.
- Never write `auth.json` with `fs`. Going through `modify` is what keeps the lock, the revision
  counter, and pi's `readState` coherent.

### 4.5 Rotation flow (OAuth)

In the existing `message_end` rotation branch, branch on `rt.kind`:

```ts
if (rt.kind === "oauth") {
  // 1. preserve whatever pi refreshed for the account we are leaving
  const leaving = await captureCredential(store, providerId);
  if (leaving && rt.currentIndex >= 0) rt.keys[rt.currentIndex].credential = leaving;

  // 2. pick the next available account (existing rotation.ts logic, unchanged)
  const nextIdx = pickNextKey(rt.keys, rt.currentIndex + 1, Date.now());
  if (nextIdx < 0 || nextIdx === rt.currentIndex) { /* exhausted: stop, no restore needed */ }
  const next = rt.keys[nextIdx];
  if (!next?.credential) return;

  // 3. install it
  if (!(await installCredential(store, providerId, next.credential))) return;
  rt.currentIndex = nextIdx;
  recordUse(next);

  // 4. capture again: pi may normalise or the write may have merged
  const installed = await captureCredential(store, providerId);
  if (installed) next.credential = installed;

  // 5. ask for the extra request when pi will not retry this class
  rt.pendingContinue = nextClassNeedsContinuation && isAvailable(next, Date.now());
  trace(`oauth rotate ${providerId} ${previousName} -> ${next.name} (${status} ${reason})`);
  return;
}
```

The API-key path stays exactly as it is today (overlay + `pendingContinue`), so the 16 existing tests
must keep passing with no edits.

### 4.6 Activation and shutdown (OAuth)

`activate()`:

- Resolve the provider id as today.
- Skip reasons for an `accounts` pool: `missing` (provider not registered) or `oauth-unsupported`
  (provider has no `auth.oauth`). **Do not** apply the API-key pool's "provider has no `auth.apiKey`"
  rejection.
- If `credentialStore(registry)` is undefined → report once, mark the pool permanently skipped.
- If the pool is bootstrapping: capture the current stored credential first and keep it as
  `sessionStartIndex`'s counterpart (session-start copy, in memory only), then install account #1.
  Record `rt.sessionStartIndex = 0`.
- Also `await clearOverlay(registry, providerId)` once, so a leftover api_key override from an earlier
  API-key configuration cannot shadow the OAuth credential.

`session_shutdown` and `/keyrouter reset`:

- OAuth pools: capture the active account, then reinstall the credential recorded at session start
  (or, if it was absent, leave the active account installed and say so). Clear `injected` tracking.
- API-key pools: unchanged (`removeRuntimeApiKey` for every id in `injected`).

**Persistence semantics (state this in the README).** keyrouter does not restore accounts 2..N out of
`auth.json`; the pool owns the provider credential while the extension is loaded. If pi is killed
mid-session, `auth.json` is left holding a pool account — still a valid login, so there is no broken
state, and the next session installs account #1 again. Do **not** add a side file containing original
credentials; duplicating secrets outside `auth.json` is the thing this design deliberately avoids. If
the user disables keyrouter entirely, they `/login <provider>` once to choose a different account.

### 4.7 Classification table for OAuth pools

Reuse the existing regexes in `index.ts` and add the OAuth-only rows.

| Signal in `errorMessage` | OAuth action | Needs continuation? |
|---|---|---|
| `429`, `rate.?limit`, `too many requests` | rotate | no (pi retries) |
| `401`, `403`, `unauthorized`, `forbidden`, `invalid_api_key` | rotate | **yes** (pi never retries) |
| `quota exceeded`, `insufficient_quota`, `billing`, `usage limit`, `available balance`, `out of budget` | rotate when `rotateOnQuota` (default true) | **yes** (pi marks non-retryable) |
| `OAuth refresh failed`, `re-authenticate`, `invalid_grant`, `token has been revoked` | rotate (dead refresh token) | **yes** |
| `529`, `overloaded` | provider-wide cooldown, no rotation | no |
| `500`/`502`/`503`/`504`, `internal.?error`, `server.?error` | ignore; pi retries the same account | no |
| anything else | ignore | no |

Contrast worth keeping in tests: an API-key pool must **not** rotate on `quota exceeded`, because
rotating a key within one account cannot lift an account limit. An OAuth pool **must**, because each
account is a separate subscription.

### 4.8 Status output

Extend `/keyrouter status` per pool kind:

```
cline (oauth, active: jsjery123, installed: yes, source: stored)
  → jery99961   uses=4 fails=1 status=rate-limited (cooldown)
    jsjery123   uses=2 fails=0 status=ok
```

Show `credential.expires` as a relative time (`in 12m`, `expired`) but never the token.

### 4.9 Guard rails

- Never log or trace `access` / `refresh` values. Trace account **names** only.
- Never call any HTTP endpoint for OAuth. If the agent finds itself writing a refresh request, the
  design has been violated.
- One warning per provider per failure class (reuse the `skipReported` / `lastErrorNotified` pattern).
- The continuation budget (`config.maxRetries`, per provider until success) applies to OAuth pools too.
  Do not add a second counter.

---

## 5. Test plan

Harness already exists and is the model to follow: `test/fake-openai-server.mjs` (scriptable
OpenAI-compatible server, logs the `Authorization` header per request) and `test/run.mjs` (16 cases,
isolated `PI_CODING_AGENT_DIR` + `PI_KEYROUTER_CONFIG`, asserts on server log + trace + pi output).

### 5.1 New fixture extension

OAuth cannot be tested through the existing `krtest` provider (it has `auth.apiKey`, no `auth.oauth`).
Add `test/fixture/oauth-provider.ts`, loaded with an extra `-e` for OAuth cases:

```ts
// test/fixture/oauth-provider.ts — registers an OAuth-only provider for tests.
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { appendFileSync } from "node:fs";

const log = (message: string) => {
  const path = process.env.KR_OAUTH_LOG;
  if (!path) return;
  try { appendFileSync(path, `${new Date().toISOString()} ${message}\n`); } catch {}
};

export default function (pi: ExtensionAPI): void {
  pi.registerProvider("kroauth", {
    name: "KR OAuth Test",
    baseUrl: `${process.env.KR_FAKE_BASE}/v1`,
    api: "openai-completions",
    models: [{
      id: "fake-gpt", name: "Fake GPT", reasoning: false, input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128000, maxTokens: 1024,
    }],
    oauth: {
      name: "KR OAuth",
      async login() { throw new Error("login is not exercised by tests"); },
      async refreshToken(credential) {
        log(`refresh access=${credential.access}`);
        if (credential.access === "access-dead") throw new Error("OAuth refresh failed: invalid_grant");
        const stamp = Date.now();
        return { ...credential, type: "oauth", access: `refreshed-${stamp}`, refresh: `refresh-${stamp}`, expires: stamp + 3_600_000 };
      },
      getApiKey(credential) { return `oauth:${credential.access}`; },
    },
  });
}
```

This deliberately has **no** `apiKey` auth method, so it reproduces the real OAuth-only constraint:
an api_key override would resolve to `undefined` and fail.

The fake server then observes `Authorization: Bearer oauth:<access>` per request, which is the proof
of which account is installed.

### 5.2 Cases to add

Runner changes needed first: allow a case to specify extra extensions, an extra env map, and an
arbitrary seeded `auth.json` (the existing `auth` field only handles `krtest`), plus a per-case
oauth log file.

| # | case | seed | plan | asserts |
|---|---|---|---|---|
| 1 | `oauth-installs-first-account` | accounts a1,a2 (`access-1`,`access-2`), both `expires` in the future | `{default:"ok"}` | server saw `oauth:access-1`; trace `oauth install kroauth -> a1`; no refresh logged |
| 2 | `oauth-rotate-on-429` | a1 `expires` future | `{byKey:{"oauth:access-1":429}, default:"ok"}` | server saw `access-1` then `access-2`; pi printed PONG; trace rotate; exactly 0 continuations (pi retried) |
| 3 | `oauth-rotate-on-401` | as above | `{byKey:{"oauth:access-1":401}, default:"ok"}` | `access-2` served the continuation; exactly 1 continuation |
| 4 | `oauth-rotate-on-quota` | as above | plan returns HTTP 402 with `{"error":{"message":"Monthly usage limit reached","code":"subscription_sharing_usage_limit_exceeded"}}` for `access-1` | rotated to `access-2`, PONG, exactly 1 continuation |
| 5 | `oauth-pi-refreshes-and-keyrouter-syncs-back` | a1 with `expires: Date.now() - 1000` (expired), a2 valid | `{byKey:{"oauth:refreshed-*":429}, default:"ok"}` style: 429 on a1 forces rotation, then 429 on a2 forces rotation back | oauth log shows exactly 1 `refresh access=access-1`; **no** "keyrouter refresh" wording anywhere; second visit to a1 sends `oauth:refreshed-…`, never `oauth:access-1` |
| 6 | `oauth-dead-refresh-token-rotates` | a1 `access-dead`, a2 valid | `{default:"ok"}` | oauth log shows the refresh attempt; pi's error mentions refresh failure; keyrouter rotated to a2; PONG; exactly 1 continuation |
| 7 | `oauth-restores-session-start-account` | accounts a1,a2 | 429 on a1 then ok on a2 | after the run, `auth.json["kroauth"].access === "access-1"` (or its refreshed form) — i.e. the session-start account is back |
| 8 | `oauth-overlay-is-cleared` | accounts only, plus `PI_KEYROUTER_CONFIG` variant that previously had `keys` for `kroauth` | `{default:"ok"}` | the request is `oauth:access-1`, never a bare api key; trace shows the overlay clear |
| 9 | `oauth-capability-guard` | unit level, `test/unit-oauth.mjs` via `node --experimental-strip-types` | n/a | `credentialStore({})` → `undefined`; `installCredential` on a throwing store → `false`, no throw; `parseAccountCredential` handles object / `$ENV` JSON / `@file` / rejects `{type:"api_key"}` |
| 10 | regression | all 16 existing cases | unchanged | still green, no edits to their expectations |

`byKey` matching uses exact bearer strings, so case 5 needs either a server-side predicate extension
(add `byKeyPrefix` to the plan, a small, justified addition) or a `sequence` plan that yields the
needed order regardless of key. Prefer the latter to avoid changing the server: `sequence` steps are
consumed per request, so `["429","429","ok"]` gives exactly the two rotations plus success.

### 5.3 Isolation and safety requirements

- `run.mjs` must keep every invocation inside the fixture agent dir; assert at the end of the suite
  that the **real** `~/.pi/agent/auth.json` is byte-identical (record a sha256 before and after the
  suite and print it). Failing this assertion is a release blocker.
- OAuth cases must never resolve to a real provider id (`kroauth` only).
- No network: `PI_OFFLINE=1`, and the fixture oauth provider points at the fake server.
- Keep the fake server's `build` marker check and the random-port default; a stale server produces
  impossible failures.

### 5.4 Commands

```bash
cd /y/All-Projects/pi/pi-keyrouter
bun x tsc --noEmit -p tsconfig.json                     # must be clean
node test/fake-openai-server.mjs --selftest             # must pass
node test/run.mjs oauth-                                # only the new cases while iterating
node test/run.mjs                                       # full suite
node test/verify-runtime-keys.mjs kroauth               # overlay probe (extend for credentials.modify)
```

Notes for the shell in this environment: `interactive_shell` dispatch runs under Git bash
(`Y:/Dev/Git/usr/bin/bash.exe`), so use bash syntax there, or call
`powershell.exe -NoProfile -Command "..."` when PowerShell is needed. In Git bash use forward slashes.

---

## 6. Implementation order with gates

Work in this order. Do not start a step before the previous gate passes.

**Step 0 — reconfirm.** Read the files in section 7. Run the existing suite once to see 16/16. Write
`test/verify-runtime-credentials.mjs` and answer every item in section 3.
*Gate:* probes run, answers recorded, suite green.

**Step 1 — types and config.** `types.ts` (extend `KeyState` with `credential?`; add
`accounts`, `rotateOnQuota`), `config.ts` (`parseAccountCredential`, mutual exclusion, drop-with-warning).
*Gate:* `tsc` clean; `node test/run.mjs` still 16/16 (OAuth config is inert so far).

**Step 2 — `oauth.ts`.** The store adapter, installer, capture, overlay clear, credential parser.
No wiring into `index.ts` yet.
*Gate:* `test/unit-oauth.mjs` passes for the guard and parser cases.

**Step 3 — fixture oauth provider.** `test/fixture/oauth-provider.ts` plus runner support for extra
extensions, env, seeded `auth.json`, and the oauth log.
*Gate:* a hand-run `pi -e` invocation with a hand-written config installs account #1 and the server
logs `oauth:access-1`. This is the single most valuable early check; do not proceed until it works.

**Step 4 — activation and shutdown.** Install account #1, clear stale overlays, capture/restore,
skip reasons, capability guard.
*Gate:* cases 1, 7, 8 pass.

**Step 5 — rotation.** The OAuth branch in `message_end`, capture-on-leave, install, capture-after,
continuation decisions from the table in 4.7.
*Gate:* cases 2, 3, 4, 6 pass.

**Step 6 — refresh sync-back.** Verify case 5 end to end. If pi's rotated token is not observed,
re-read the `modify` and `readLatestData` paths in 2.2 before changing anything; the bug is almost
certainly ordering (capture must happen after the request, before the swap).
*Gate:* case 5 green, and a manual inspection of a fixture `auth.json` shows `refreshed-*`.

**Step 7 — status, docs, tidy.** `/keyrouter status` for OAuth pools, README section (schema,
classification table, persistence/restore semantics, security, limits), workspace check.
*Gate:* `tsc` clean, `node test/run.mjs` fully green, `git status` clean of stray files, real
`auth.json` checksum unchanged.

**Step 8 — commit.** One commit, conventional message, listing the OAuth pool feature and the test
additions. Do not commit generated fixture files (`.gitignore` already ignores them).

---

## 7. Files to read first

Project (all verified this session):

- `index.ts` — events, rotation, continuation, `/keyrouter` command. Note `skipReason`, `applyKey`,
  `clearKey`, `activate`, the `message_end` branch, `agent_before_settle`, `session_shutdown`.
- `rotation.ts` — `initKeyStates`, `isAvailable`, `markBad`, `markOk`, `markOverloaded`, `pickNextKey`,
  `recordUse`. Pure; reuse unchanged for both pool kinds.
- `config.ts` — `configPath` (honours `PI_KEYROUTER_CONFIG`), `expandEnv`, `hasUnresolvedRef`,
  `normalize`.
- `types.ts` — `ApiKey`, `ProviderConfig`, `KeyRouterConfig`, `KeyState`, `RotationEvent`.
- `notification.ts` — `notifyRotation` / `notifyOverloaded` / `notifyExhausted` (reuse; add an OAuth
  account variant or generalise the label).
- `test/run.mjs`, `test/fake-openai-server.mjs`, `test/verify-runtime-keys.mjs` — harness to extend.
- `README.md` — update, especially the OAuth caveat paragraph.

pi internals (read-only reference; exact paths in section 2):

- `dist/core/runtime-credentials.js`, `dist/core/auth-storage.js`, `dist/core/model-runtime.js`,
  `dist/core/model-registry.js`, `dist/core/agent-session.js`, `dist/core/extensions/runner.js`,
  `dist/core/extensions/loader.js`, `dist/core/extensions/types.d.ts`.
- `node_modules/@earendil-works/pi-ai/dist/auth/resolve.js`, `.../auth/types.d.ts`,
  `.../utils/retry.js`, `.../utils/error-body.js`.
- `pi-free/dist/providers/cline/cline-auth.js` (worked example of an OAuth provider).

---

## 8. Pitfalls (learned the hard way)

1. **Never use `setRuntimeApiKey` for an OAuth pool.** On an OAuth-only provider it yields no auth at
   all; on a dual-auth provider it freezes the token so pi never refreshes. Explicitly clear any
   existing overlay for the id.
2. **`modify` returning `undefined` means "no change".** Return the credential object to write it.
3. **Never write `auth.json` with `fs`.** Use the store so the lockfile and `readState` revision stay
   coherent; an out-of-band write can be clobbered by pi or missed by its cache.
4. **Capture before swapping away, and again after installing.** Refresh rotates refresh tokens; a
   stale pool copy can burn an account.
5. **401/403 and quota-class errors are not retried by pi.** Without the `agent_before_settle`
   continuation the rotation happens and is never used. This is already implemented — call it, do not
   reinvent it.
6. **`continue: true` is validated after the drafts commit.** The hidden `custom_message` draft is what
   makes it legal; keep passing `[...event.entries, draft]`.
7. **Spawning pi from Node requires `stdio: ["ignore", "pipe", "pipe"]`.** pi merges stdin content into
   the prompt, so an open pipe hangs it until timeout.
8. **`pi` on Windows is a shim.** Spawn `process.execPath` with `dist/bundle/cli.js`.
9. **`AuthStorage` is not exported from the package root.** Do not import it; use the live instance.
   `readStoredCredential` is the only public credential read.
10. **Do not read inside the blob.** Copilot, Kiro, Qoder, Antigravity and Gemini-CLI each carry
    provider-specific fields. keyrouter must stay opaque or it will break one of them.
11. **Do not test against real accounts.** All OAuth test work uses `kroauth` and the fake server, in
    the fixture agent dir.
12. **A leftover fake server on the test port produces impossible failures.** Keep the random port and
    the `build` marker check; kill stray listeners before a full run.

---

## 9. Starter prompt for the handoff agent

> Read `docs/HANDOFF-oauth-rotation.md` in full, then follow section 6 in order, stopping at each
> gate. Section 2 is verified reference; section 3 lists what you must confirm with your own probes
> before relying on it. Reuse the existing rotation, continuation and test harness machinery instead of
> writing new mechanisms. Do not implement any OAuth flow, do not call any refresh endpoint, and do not
> write `auth.json` outside pi's credential store. Report at the end with: probe answers, files
> changed, test results, the real `auth.json` checksum before/after, and anything in this document that
> turned out to be wrong.

---

## 10. Open questions for the owner

1. `rotateOnQuota` default `true` for OAuth pools — confirm. (Rationale: each account is a separate
   subscription, so an account limit is exactly when you want the next account.)
2. Should `/keyrouter` gain a manual selector (`/keyrouter account <provider> <name>`) in addition to
   automatic rotation? Cheap to add; not required by the success criteria.
3. Should `keys` and `accounts` be combinable for one provider (single pool mixing api keys and OAuth
   accounts)? The current design rejects it; mixing is easy later if wanted.

---

## 11. Implementation report

### Files

| File | Change |
|---|---|
| `types.ts` | Added `OAuthCredential` (opaque, index-signature), `AccountEntry`, `PoolKind`, `KeyStatus`; `ProviderConfig` gained `accounts`/`kind`/`rotateOnQuota` and made `keys` optional; `KeyState` gained `credential?`; `RotationReason` gained `quota`/`refresh-failed`. |
| `config.ts` | Added `parseAccountCredential` (`@file` / `$ENV` JSON / inline), `validateCredential`, account normalization, `keys`+`accounts` mutual exclusion, and `warnings` (which never contain a credential value). |
| `oauth.ts` | **New.** `credentialStore` (capability-guarded facade access), `isOAuthCredential`, `installCredential`, `captureCredential`, `hasStoredOAuthLogin`, `clearOverlay`. |
| `rotation.ts` | Added `initAccountStates`; `markBad` now records the reason verbatim. Everything else shared unchanged. |
| `notification.ts` | `notifyExhausted` takes a pool kind for wording; added `notifyOAuthUnsupported`. |
| `index.ts` | Kind-aware `ProviderRuntime`, `skipReason`, activation/install/capture/restore, the OAuth rotation branch, kind-aware classification, status output. The `keys` path is behaviourally unchanged. |
| `test/oauth-cases.mjs` | **New.** 12 cases. |
| `test/fixture/oauth-provider.ts` | **New.** OAuth-only `kroauth` provider; models refresh-token rotation. |
| `test/unit-oauth.mjs` | **New.** 46 unit checks, no pi/server needed. |
| `test/verify-runtime-credentials.mjs` | **New.** Probes pi's credential store; answer record for §3. |
| `test/oauth-fixture-smoke.mjs` | **New.** Proves the fixture works *without* keyrouter. |
| `test/run.mjs` | OAuth plumbing, `byKey`/`sequence` reuse, OS-assigned free port, real-auth.json checksum guard. |

### Results

```
bun x tsc --noEmit -p tsconfig.json      clean
node test/fake-openai-server.mjs --selftest   all plan cases pass
node test/unit-oauth.mjs                 46/46
node test/verify-runtime-credentials.mjs all credential-store probes pass
node test/oauth-fixture-smoke.mjs        all checks pass
node test/run.mjs                        27/27   (16 API-key + 1 existing OAuth + 10 new OAuth)
real auth.json                           unchanged (sha256 8f73695a…)
```

Also verified against the real user config: all three pools bootstrapped (`tokenharbor`,
`google`, `openrouter`), the request authenticated with the pooled key, a 404 model error was
correctly **not** rotated, and every override was cleared on shutdown.

### Deviations from this plan

1. **The OAuth path went into `index.ts` rather than a new rotation module.** §4.4 proposed keeping
   `oauth.ts` for store access only, which is what happened — the helpers (`applyAccount`,
   `captureAccount`, `restoreSessionStartAccount`) live beside `applyKey`/`clearKey` in `index.ts`
   so the two pool kinds sit side by side and the `keys` path stays readable.
2. **Credential types are structurally typed, not imported from pi-ai.** `@earendil-works/pi-ai`
   is a peer dependency that does not resolve from the extension's own node_modules
   (`ERR_PACKAGE_PATH_NOT_EXPORTED`). Reaching into it would also break under pi's bundler, so
   `OAuthCredential` is a local structural type with an index signature and every store call is
   capability-checked. The blob stays opaque, which is what the eight differently-shaped built-in
   providers need.
3. **§4.6's restore semantics needed one adjustment.** "Restore the session-start credential" is only
   correct when there *was* one. If the provider had no stored credential, keyrouter leaves the
   active pool account installed rather than logging the user out — it is still a valid login, and
   the next session installs account #1 again. Traces say which branch was taken.
4. **`rotateOnQuota` is per-pool, not global**, and is forced `false` for `keys` pools by
   construction (the field is only set for `accounts` pools), so the two kinds cannot drift.

### Two testing traps worth remembering

1. **A credential seeded into `auth.json` never runs.** keyrouter installs account #1 at session
   start, replacing it before the first request. Two cases failed on this before the special
   credentials (near-expiry, dead refresh token) were moved into the pool *config*, where keyrouter
   installs from. If a future test needs a specific stored credential, it must be a pool entry.
2. **A fixture that accepts a reused refresh token cannot detect a lost rotation.** The fixture now
   consumes refresh tokens like a real provider, so a pool that failed to sync pi's rotated blob
   back fails with `invalid_grant` instead of silently succeeding. That turned
   `oauth-pi-refreshes-and-keyrouter-syncs-back` into a real assertion: the pool returns to account
   #1 and re-installs pi's **rotated** credential, with pi refreshing exactly once.

### Still open

§10 stands: `rotateOnQuota` defaults to `true` for `accounts` pools (confirm), and a manual
`/keyrouter account <provider> <name>` selector plus mixed `keys`+`accounts` pools remain
unimplemented because nothing in the success criteria needs them.