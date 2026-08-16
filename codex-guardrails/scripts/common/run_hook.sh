#!/bin/sh
# Shared runner for agent hooks that invoke a bundled Python script directly (no
# uv). Resolves a Python — the Noma-managed installs first, then PATH — and runs
# scripts/<script> [args...] fail-open: a missing or unusable interpreter must
# never break the agent session, so every bail-out exits 0. On macOS the bare
# /usr/bin/python3 without the Xcode CLI tools pops the interactive installer
# dialog — skip it instead.
#
# Usage: run_hook.sh <script-name> [args...]  ($script resolved next to scripts/)
NOMA_PYTHON=/usr/local/noma/python/bin/python3
[ -x "$NOMA_PYTHON" ] || NOMA_PYTHON="$HOME/.noma/python/bin/python3"
[ -x "$NOMA_PYTHON" ] || NOMA_PYTHON="$(command -v python3 || command -v python)" || exit 0
case "$(uname):$NOMA_PYTHON" in
  Darwin:/usr/bin/python*) xcode-select -p >/dev/null 2>&1 || exit 0 ;;
esac
script="$1"
shift
"$NOMA_PYTHON" "$(dirname "$0")/../$script" "$@" || true
