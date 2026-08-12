#!/bin/sh
# Shared runner for every Codex hook event: resolve a Python (the Noma-managed
# installs first, then PATH) and run codex_hook.py fail-open — a missing or
# unusable interpreter must never break the Codex session, so every bail-out
# exits 0. On macOS the bare /usr/bin/python3 without the Xcode CLI tools would
# pop the interactive installer dialog — skip it instead.
NOMA_PYTHON=/usr/local/noma/python/bin/python3
[ -x "$NOMA_PYTHON" ] || NOMA_PYTHON="$HOME/.noma/python/bin/python3"
[ -x "$NOMA_PYTHON" ] || NOMA_PYTHON="$(command -v python3 || command -v python)" || exit 0
case "$(uname):$NOMA_PYTHON" in
  Darwin:/usr/bin/python*) xcode-select -p >/dev/null 2>&1 || exit 0 ;;
esac
"$NOMA_PYTHON" "$(dirname "$0")/codex_hook.py" || true
