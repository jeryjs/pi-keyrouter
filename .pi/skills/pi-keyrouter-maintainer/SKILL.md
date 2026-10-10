---
name: pi-keyrouter-maintainer
description: Conventions, release procedure, and hard-won failure modes for maintaining pi-keyrouter. Use this whenever the work touches releasing or versioning this package, publishing @jeryjs/pi-keyrouter to npm, the GitHub Actions publish workflow, pushing tags, or making any commit in this repository. Also consult it for any ambiguous request in this repo — the maintainer requires explicit confirmation before commits, tags, and publishes, and guessing wrong has caused undoable churn. Covers the Windows toolchain quirks this repo is developed on and the pi extension packaging rules the package must satisfy.
compatibility: Windows with PowerShell 5.1, git, gh CLI, npm CLI, Node 22+. Bash heredocs and `Set-Content -Encoding UTF8` both corrupt work here — see references/windows-environment.md.
---

# pi-keyrouter maintainer guide

Operating knowledge for this repository that is not derivable from its code or
git history: the maintainer's collaboration rules, the release procedure, the
publishing failure modes already paid for, and the pi internals that shaped a
past design decision.

## Contents

| Reference | Read it when |
|---|---|
| `references/npm-publishing.md` | Publishing, versioning, tags, or a publish failure |
| `references/windows-environment.md` | Anything involving shell, encoding, or waiting |
| `references/pi-internals.md` | Changing the retry/continuation path or packaging |

## Collaboration rules

These are not stylistic preferences; each has a correction behind it.

### Confirm before every irreversible action

Approval is scoped to what was proposed. "Proceed" authorizes that edit — not the
commit that follows, not the tag after that, not the publish after that. Ask
separately for each step, showing the exact command.

Unprompted commits and unprompted edits to files outside the stated scope have
both had to be reverted in this repo. One round-trip of confirmation is cheaper
than an undo, and the maintainer reads the diff either way.

Never force-push `main` without explicit permission for that specific push. The
maintainer does it themselves when needed; it is their call to make.

### Answer questions, don't execute them

`"Is X better than what we had?"` asks for a judgement. Editing files in
response is a mistake even when the answer is yes. Signals: a question mark, or
a request to compare / explain / evaluate.

The reliable pattern when intent is unclear — make the edit, then stop and show
the diff — is to answer first and offer the change separately.

### Minimal changes are a requirement

A fix here was rejected for creating a new module, a new file on disk, and 122
lines of tests, when the whole problem was one field in an existing config
file.

Before introducing a new file, module, or on-disk artifact, check whether the
existing structure already has a home for it. Extending an adjacent writer beats
writing a new one; adding a field beats adding a file.

A new on-disk artifact needs one of three specific justifications: isolation from
a file holding credentials, isolation from a file the maintainer hand-edits, or
a compatibility guarantee for existing installs. "Cleaner" does not qualify.

### Separate what was verified from what was reasoned

The maintainer checks claims and will say so. A previous agent asserted that a
retry "re-runs the same turn" — phrased as if replay were involved, and as if
model behaviour had been observed. Neither was true.

State the evidence: what the code shows, what the test suite proves, and what
was inferred but not measured. Unmeasured inference is fine when labelled.
Overclaiming is what destroys the value of an agent's report.

## Release procedure

```
1. Bump package.json version; add a CHANGELOG entry under that version
2. Update the CHANGELOG compare links at the bottom of the file
3. npm run typecheck && npm test
4. Commit  (confirm first)
5. git push origin main
6. git tag -a vX.Y.Z -m "vX.Y.Z - <short reason>"
7. git push origin vX.Y.Z   (confirm first — this publishes)
```

Step 7 triggers `.github/workflows/publish.yml`: a `verify` job (`npm ci` →
`npx tsc --noEmit` → tag-matches-version guard), then `publish` (OIDC trusted
publishing with `--provenance --access public`). No npm token lives in the repo.

Two failure modes dominate this procedure; both are covered in detail in
`references/npm-publishing.md`:

- **Configuring the trusted publisher after pushing the tag.** npm binds a
  trusted publisher only on a successful OIDC publish, so a tag pushed first
  burns the attempt. Configure first, then push the tag.
- **Concluding a publish failed too early.** npm takes one to three minutes to
  serve a version it has accepted. Re-query before reacting; re-running the
  publish yields a version-already-exists error and no new information.

## Repository facts that are easy to get wrong

- **The package is `@jeryjs/pi-keyrouter`.** The unscoped `pi-keyrouter` on npm
  belongs to the original author (lowern1ght, from the pi-soly monorepo), frozen
  at `0.4.0`. It is not available.
- **`LICENSE` carries two copyright lines on purpose.** `pi-extensions
  contributors` is upstream's repo-wide monorepo notice, retained because MIT
  requires the notice to travel with the code; `Jery Js` is the fork's. Do not
  "correct" the upstream line to a person's name — that edits the notice rather
  than retaining it. A NOTICE file was considered and declined.
- **`repository.directory` was removed deliberately.** The repository root *is*
  the package; the inherited `packages/pi-keyrouter` path rendered a broken link
  on the npm page.
- **The test suite is excluded from `files` on purpose.** It stays in git and is
  not published, which keeps `test/fixture/agent/auth.json` out of a credential
  tool's artifact and halves the tarball.
- **The `publish` job is gated on `startsWith(github.ref, 'refs/tags/')`.** A
  `workflow_dispatch` runs from a branch where `ref_name` is `main` and no
  version exists. Without the gate a manual dispatch could publish from main with
  no tag, burning an immutable version number.
- **Runner targets are Node 24 with `checkout@v6` and `setup-node@v6`.** Trusted
  publishing requires npm ≥ 11.5.1 and Node ≥ 22.14.0; Node 20 on runners is
  deprecated.
- **Published history is partly frozen.** `1.3.1` exists without provenance
  because it shipped outside the workflow. npm versions are immutable, so
  `1.3.2` and `1.3.3` exist partly to carry provenance properly.

## Verification commands

```powershell
npm run typecheck          # bun x tsc --noEmit -p tsconfig.json
npm test                   # selftest + unit + 32 e2e cases
npm run test:unit          # fast; no pi, no network, no credentials
```

The e2e suite hashes the real `~/.pi/agent/auth.json` before and after and fails
the run if it changed. That check is a release blocker, not a formality — the
OAuth cases write credentials.

Before publishing a change to the extension's runtime behaviour, confirm the
rotation cases still pass: `rotate-on-401`, `rotate-on-403`,
`two-failures-walk-A-B-C`, and `all-keys-401-budget-stops-loop`. They depend on
the continuation path described in `references/pi-internals.md`.
