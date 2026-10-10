# Windows environment

This repository is developed on Windows with PowerShell 5.1. Several conventions
that work elsewhere fail here, and the failures are silent or misleading.

## Shell

### No heredocs

`git commit -F - <<'EOF'` is a PowerShell parse error. Write the message to a
temp file and reference it:

```powershell
git commit -F "C:\Users\...\kr-commit-msg.txt"
```

### Do not pipe code through `-e`

PowerShell mangles inline `node -e` scripts containing regexes or escapes,
silently corrupting the logic. Write a temp `.mjs` and run it.

### Success messages look like errors

`git push` writes its normal progress to stderr. In PowerShell this surfaces as
`NativeCommandError` with red text wrapping a correct message:

```
git : To https://github.com/jeryjs/pi-keyrouter.git
At line:1 char:1
+ git push origin main
```

Trust `$LASTEXITCODE` over the stderr shape.

### Multi-line output arrives with escape codes inline

Some commands return `[31m`-prefixed content even when the text is correct. Do
not treat colour codes as data corruption.

## File editing

### Never `Set-Content -Encoding UTF8`

Windows PowerShell 5.1 adds a BOM and double-encodes non-ASCII. A single edit
through it turned `🔑` into `ðŸ”‘` and `—` into `â€"`, corrupting a source file
that then displayed as mojibake everywhere.

Use the edit tool for all edits.

If a file is already damaged, repair by re-encoding through the CP1252 table
(mapping each character back to its byte, then decoding as UTF-8) and stripping
the leading BOM. Byte-level repair cannot be expressed with the edit tool's
string-replacement API.

### Do not hand-build multi-line edit payloads

A malformed JSON escape in a hand-built payload produced literal `", ` tails on
four lines, clobbering a block of code. The failure surfaced later as
`Unterminated string literal`. Prefer writing a fresh file with the write tool
for large restructures, and typecheck immediately after any multi-line edit so a
mangled line is attributable.

## Tooling

- Content search: the grep tool (`rg`), not `Select-String`.
- File search: the glob tool, not `Get-ChildItem -Recurse`.
- Those constraints apply to the agent's own tools. Within PowerShell for ad-hoc
  inspection, `rg` and `Select-String` both work.

## Waiting

The maintainer does not want long sleeps in automation. Batch independent
operations into one command instead of polling serially, and use the shortest
defensible interval when a poll is genuinely required.

One case genuinely requires waiting: **npm registry propagation** after a
successful publish, which is a real network delay of one to three minutes, not a
retry loop. See `npm-publishing.md`.

Avoid `gh run watch` when a `gh run view` a few seconds later would answer the
question; the watch blocks for the full run including post-job cleanup.

## TypeScript

`bun x tsc --noEmit -p tsconfig.json` is the project's typecheck, running with
`strict` and `noUncheckedIndexedAccess`.

CI runs `npx tsc` instead, because the package script shells out to `bun`, which
is not installed on the GitHub runner.
