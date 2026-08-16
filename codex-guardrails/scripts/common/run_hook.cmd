@echo off
setlocal
rem Shared runner for agent hooks that invoke a bundled Python script directly
rem (no uv). Resolves a Python (the Noma-managed installs first, then PATH) and
rem runs scripts\<script> [event] fail-open - a missing or unusable interpreter
rem must never break the agent session, so every bail-out exits 0.
rem
rem Usage: run_hook.cmd <script-name> [event]  (script resolved next to scripts\)
set "NOMA_HOOK_SCRIPT=%~dp0..\%~1"
set "NOMA_PYTHON=%ProgramW6432%\Noma\python\python.exe"
if not exist "%NOMA_PYTHON%" set "NOMA_PYTHON=%ProgramFiles%\Noma\python\python.exe"
if not exist "%NOMA_PYTHON%" set "NOMA_PYTHON=%ProgramData%\Noma\python\python.exe"
if exist "%NOMA_PYTHON%" ("%NOMA_PYTHON%" "%NOMA_HOOK_SCRIPT%" %~2 & exit /B 0)
where python >nul 2>&1 || exit /B 0
python "%NOMA_HOOK_SCRIPT%" %~2
exit /B 0
