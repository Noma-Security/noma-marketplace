@echo off
rem Shared runner for every Codex hook event: resolve a Python (the Noma-managed
rem installs first, then PATH) and run codex_hook.py fail-open - a missing or
rem unusable interpreter must never break the Codex session, so every bail-out
rem exits 0.
set "NOMA_PYTHON=%ProgramW6432%\Noma\python\python.exe"
if not exist "%NOMA_PYTHON%" set "NOMA_PYTHON=%ProgramFiles%\Noma\python\python.exe"
if not exist "%NOMA_PYTHON%" set "NOMA_PYTHON=%ProgramData%\Noma\python\python.exe"
if exist "%NOMA_PYTHON%" ("%NOMA_PYTHON%" "%~dp0codex_hook.py" & exit /B 0)
where python >nul 2>&1 || exit /B 0
python "%~dp0codex_hook.py"
exit /B 0
