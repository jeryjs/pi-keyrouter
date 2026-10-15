@echo off
REM ============================================================================
REM  run-watcher.cmd - launches the credential-sync watcher, hidden.
REM
REM  Started by the "pi-keyrouter-sync-watch" scheduled task at logon. Kept as a
REM  .cmd rather than inlining the command so the exact working directory and
REM  node path can be pinned in one readable place.
REM
REM  The node path is absolute on purpose. A scheduled task gets no PATH from the
REM  interactive shell, and this repo lives on Y: with a portable Node install, so
REM  "node" is not reliably resolvable from the task environment.
REM ============================================================================

setlocal

set "NODE_EXE=Y:\Dev\NodeJS\node.exe"
set "SCRIPT=Y:\All-Projects\pi\pi-keyrouter\tools\sync-watch\watch-sync.mjs"

if not exist "%NODE_EXE%" exit /b 1
if not exist "%SCRIPT%" exit /b 1

cd /d "Y:\All-Projects\pi\pi-keyrouter\tools\sync-watch"
"%NODE_EXE%" "%SCRIPT%"
exit /b %ERRORLEVEL%