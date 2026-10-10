# npm publishing and versioning

Publishing goes through GitHub Actions only. A local `npm publish` cannot work
on this account and is not a fallback — see *TOTP 2FA is retired* below.

## How publishing works

`.github/workflows/publish.yml` triggers on `push: tags: ["v*"]`:

| Job | Does |
|---|---|
| `verify` | `npm ci`, then `npx tsc --noEmit -p tsconfig.json`, then fails if the tag does not match `package.json` |
| `publish` | OIDC trusted publishing, `npm publish --provenance --access public` |

The version guard exists because npm versions are immutable. A mismatched tag
would otherwise burn a version number silently.

The `publish` job is gated on `startsWith(github.ref, 'refs/tags/')` so a manual
`workflow_dispatch` — which runs from a branch — can exercise `verify` without
being able to publish.

### Configuring the trusted publisher

Add it **before** pushing a release tag. npm binds a trusted publisher only on a
successful OIDC publish, so a tag pushed first burns the attempt.

Location: `npmjs.com/package/@jeryjs/pi-keyrouter/access`.
(`/settings/<user>/publishing` returns 404.)

| Field | Value |
|---|---|
| Package or scope | `@jeryjs` |
| Repository owner | `jeryjs` |
| Repository name | `pi-keyrouter` |
| Workflow filename | `publish.yml` |

The filename is `publish.yml`, not `.github/workflows/publish.yml`. npm validates
that the workflow exists on the default branch at that path.

After configuring, re-trigger with:

```powershell
git push origin vX.Y.Z --force
```

## Failure modes

### TOTP 2FA is retired

```
npm profile enable-2fa auth-and-writes
npm error code E404
npm error 404 Not Found - Adding a new TOTP 2FA is no longer supported.
```

npm removed TOTP entirely. Every publish attempt also emits:

> npm tokens that bypass 2FA are being restricted for account changes and direct
> publishing. Learn how to prepare: https://gh.io/npm-gat-bypass2fa-deprecation

There is no local workaround, and `npm publish --otp=…` can never work on this
account. Trusted Publishing is the only path.

### E403 — 2FA required

```
npm error code E403
npm error 403 Forbidden - Two-factor authentication or granular access token
        with bypass 2fa enabled is required to publish packages.
```

A local publish that never had 2FA. Expected — it is why releases go through the
workflow instead.

### E404 on PUT — trusted publisher not configured

```
npm error code E404
npm error 404 Not Found - PUT https://registry.npmjs.org/@jeryjs%2fpi-keyrouter
        - Not found
```

This is the OIDC failure mode and is **not** a missing package. npm could not
match the workflow's OIDC identity against any configured trusted publisher, so
the package reads as nonexistent. The 404-instead-of-403 is the tell.

Fix: configure the trusted publisher (above), then re-push the tag.

### Publish succeeded but `npm view` 404s

npm prints:

```
npm notice publish Signed provenance statement with source and build information from GitHub Actions
npm notice Your package is being processed and may take a few minutes to become available.
npm notice + @jeryjs/pi-keyrouter@1.3.3
```

That `+` line is success. The registry then takes **one to three minutes** to
serve it. This project hit exactly this: `1.3.3` published successfully with
signed provenance, and `npm view` reported nothing while `latest` still pointed
at `1.3.2`.

Re-query rather than re-publishing:

```powershell
npm view @jeryjs/pi-keyrouter dist-tags versions --json
npm view @jeryjs/pi-keyrouter time --json
```

`time.modified` moving is the reliable signal. Re-running the publish instead
produces a version-already-exists error and no new information.

### Version already exists

npm versions cannot be replaced. Ship a new one instead.

### The tag push did nothing

The workflow triggers on tag pushes only. A tag pushed *before* the workflow
existed produces no run at all — force-push it to retrigger.

### Tag does not match version

```
X tag main is vmain but package.json is 1.3.1
```

The guard firing on a `workflow_dispatch`, which is correct behaviour. Push a tag
rather than dispatching manually.

## Immutability and cleanup

- **Published versions are permanent.** `1.3.1` cannot be retrofitted with
  provenance; that is why later versions exist.
- **Unpublishing works only within 72 hours** of publish. Outside that window it
  is impossible. `npm view @jeryjs/pi-keyrouter time --json` gives the timestamp.
- **`npm unpublish` requires browser auth that an agent cannot complete.** The
  auth URL is redacted in both captured console output and the npm debug log:

  ```
  npm error ... https://www.npmjs.com/auth/cli/***
  ```

  The maintainer must run the command in their own terminal, open the URL it
  prints, and paste back the token it returns.
- **Never let a placeholder reach `latest`.** A `npm stage publish` left a
  `0.0.0-stage` version behind once; it was removable only because it was still
  inside the 72-hour window.

## Verifying a release

```powershell
npm view @jeryjs/pi-keyrouter dist-tags --json                   # latest flipped?
npm view @jeryjs/pi-keyrouter@X.Y.Z dist.attestations --json    # provenance present?
npm view @jeryjs/pi-keyrouter versions --json                    # list sane?
```

Provenance appears as:

```json
{ "dist.attestations": { "provenance": { "predicateType": "https://slsa.dev/provenance/v1" } } }
```

Missing attestations mean that version bypassed the workflow.

## Version numbering

The maintainer prefers patch bumps over minor ones — `1.3.1` and `1.3.2` and
`1.3.3` rather than `1.4.0` — and does not want released version numbers
rewritten. A change is patch-worthy if it fixes behaviour, tightens tooling, or
documents; reserve minor for a new user-facing capability.
