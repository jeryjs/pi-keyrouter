# pi internals

Two areas of pi's behaviour are load-bearing for this extension and are not
obvious from reading the extension source. Both were established by reading
pi's compiled output under `node_modules/@earendil-works/pi-coding-agent/dist/`.

## 1. The continuation path (`agent_before_settle`)

### Why a hidden message exists

pi does **not** retry 401, 403, quota errors, or refresh failures. 429 is in its
retryable set; those four are not. Without intervention, keyrouter rotates onto a
healthy credential and that credential goes unused until the following turn.

The rotation alone is not enough, because of `canContinue`. In
`core/agent-session.js`, `_buildBoundaryContext` computes:

```js
contextCanContinue = llmMessages.some(m => m.role !== "system") && finalRole !== "assistant"
```

After a failed request the last message **is** the failed assistant turn, so
`finalRole === "assistant"` and `canContinue` is false. A continuation is then
rejected outright with `_reportInvalidBoundaryContinuation`.

The fix is to append a custom message, which converts to a non-assistant role and
makes the continuation legal. The `continue: true` return value alone is not
enough — returning empty entries fails the same guard.

`pi.sendMessage({ triggerTurn: true })` queues a custom message and takes the
identical path, so it is not an alternative.

### The text is never inspected

The guard checks the **role**, never the content. Any body works. Changing the
text cannot break the mechanism, which is why the `rotate-on-401`,
`rotate-on-403`, `two-failures-walk-A-B-C` and `all-keys-401-budget-stops-loop`
e2e cases pass regardless of wording.

### But the model does read it

`convertToLlm` in `core/messages.js` maps `role: "custom"` → `role: "user"`
**unconditionally**, ignoring `display`. Two consequences that are easy to
conflate:

| Channel | Controlled by | Result |
|---|---|---|
| TUI chat | `display: false` | Hidden — `addMessageToChat` gates on it |
| Model context | not gated by `display` | Visible as a user turn |

So `display: false` hides a custom message from the user while the model still
receives it. Anything sent this way is model-visible input, and a recent user turn
carries real weight in the model's output.

A bare `.` would also satisfy the guard but changes model behaviour — the model
receives an uninformative user turn and may respond to the 401 by apologising
rather than resuming.

### Current wording and why

```ts
content: "Retrying."
```

The previous wording was `"pi-keyrouter: the API key was rotated after the last
failed request. Retry the previous turn using the new credentials."`

Pi maps the message to a user turn, so the model read it. It therefore asserted an
external credential change that the model cannot observe or verify, and invited
narration of that change back to the user. The maintainer chose `"Retrying."`:
still enough signal for the model to resume the task rather than apologise for the
401, without claiming anything untrue.

Do not expand this back into an instruction without asking. The trade-off is
deliberate and was discussed explicitly.

### `customType` is a debugging affordance

The type is `"pi-keyrouter.retry"`. It appears in session transcripts and is what
makes these entries identifiable when reading a `.jsonl` by hand, even though the
message is never rendered in the TUI.

## 2. Extension packaging requirements

From `https://pi.dev/docs/latest/packages`.

| Requirement | Rationale |
|---|---|
| `pi-package` in `keywords` | Eligibility for the pi.dev gallery. Without it: published but invisible. |
| Explicit `pi` manifest | Declares entry points when resources are not in conventional directories |
| Paths relative to package root | Glob resolution base |
| Host packages in `peerDependencies` at `"*"` | Pi supplies them; a version constraint can emit spurious peer warnings |
| Host packages **not** in `dependencies` | A physical copy bypasses pi's module mapping and duplicates classes/registries. pi warns when it detects this. |
| No bundling of host packages | Same reason |

Host-provided packages: `@earendil-works/pi-ai`, `@earendil-works/pi-agent-core`,
`@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui`, and `typebox`
(published as `@sinclair/typebox`). Pi suppresses automatic peer installation for
npm and git packages, so declaring a range buys nothing.

### Entry point semantics

The manifest declares **extension entry points**, not files. Only `index.ts` is
listed. `config.ts`, `oauth.ts`, `rotation.ts`, `notification.ts` and `types.ts`
are imported modules that Node resolves relative to the entry file; they belong in
`files` so they ship, but they are not extensions.

The explicit manifest is not cosmetic here: pi's default discovery scans
conventional directories (`extensions/`, `skills/`, `prompts/`, `themes/`), and
these modules sit at the package root. Without the `pi` block, `index.ts` would
likely not be discovered at all.

### The gallery indexes npmjs only

`pi.dev/packages` is not fed by GitHub Packages, git remotes, or any other
registry, and `pi install npm:…` does not reach them without per-user `.npmrc`
configuration. A GitHub Packages mirror was evaluated and declined — it solves an
authentication problem, not a discoverability one.

Optional `pi.image` / `pi.video` fields add gallery previews; this package does
not set them. Indexing is asynchronous after publish.

### Verifying the published package

Isolate it from any real agent directory:

```powershell
$t = "$env:TEMP\kr-verify"
New-Item -ItemType Directory -Force -Path "$t\agent" | Out-Null
$env:PI_CODING_AGENT_DIR = "$t\agent"
pi install npm:@jeryjs/pi-keyrouter
pi list
Get-ChildItem "$t\agent\npm\node_modules\@jeryjs\pi-keyrouter" -File | Select-Object Name
Remove-Item -Recurse -Force $t
```

Expected: `added 1 package`, the source listed by `pi list`, and the six `.ts`
modules plus README/CHANGELOG/LICENSE present. Host packages should **not** be
installed — peer suppression is correct behaviour, not a failure.

To prove the extension loads and its imports resolve (file presence alone does
not), point `PI_KEYROUTER_CONFIG` at a pool for a provider that exists, set
`PI_KEYROUTER_TRACE`, and run a print-mode request. A `bootstrap <provider> ->
<key>` trace line proves `index.ts`, `config.ts` and `rotation.ts` all resolved
from the tarball.

Note that a *missing* activation notice is ambiguous — it looks identical to a
silent load failure. Confirm with the trace file or a real slash command rather
than inferring success from silence.
