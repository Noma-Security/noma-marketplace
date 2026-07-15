#!/usr/bin/env python3
"""Noma guardrails - unified cross-OS Cursor hook.

One entry point for every Cursor hook event, invoked via uv so a single Python
implementation replaces the old per-OS sh and PowerShell hooks:

    uv run --no-project hook.py        # reads the hook event JSON on stdin

Cursor hooks gate synchronously: Cursor holds the pending action until the hook
exits, and a JSON decision on stdout controls it. The Noma server's response
body IS that decision, so it is forwarded verbatim. On any failure (no key,
empty stdin, network down) the hook prints nothing and exits 0 - emitting no
decision leaves Cursor's own default behavior in place, whereas emitting
"allow" would widen consent (e.g. skip approvals Cursor itself would ask for).

Stdlib only, no f-strings/annotations - runs on any python3 (the vendored
common package carries the same constraint; see common/).
"""

import json
import os
import socket
import sys

try:
    from common import engine, credentials, transport, debug
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import engine, credentials, transport, debug

# Noma-specific config, passed into the generic common/ package so it stays
# agent-agnostic. Same credential-store service as the Claude Code plugin, so
# one stored key serves both.
KEYCHAIN_SERVICE = "noma-guardrails"
HOOKS_PATH = "/cursor/v1/hooks"
NOMA_API_URL = os.environ.get("NOMA_API_URL") or "https://api.noma.security"
DEBUG_LOG_FILENAME = "cursor-guardrails-debug.log"


def enrich(payload):
    """Add the hostname to the payload dict (best-effort, never raises)."""
    try:
        host = socket.gethostname()
    except Exception as e:
        debug.exc("gethostname", e)
        host = ""
    if host:
        payload["hostname"] = host
    debug.log("enriched host=" + (host or "?"))
    return payload


def main():
    # Brand the shared debug module's log file for this plugin (in main, not at
    # import, so importing this module has no side effects).
    debug.set_log_filename(DEBUG_LOG_FILENAME)
    api_key = credentials.resolve_api_key(KEYCHAIN_SERVICE)
    if not api_key:
        # Degrade quietly: with no key there's nothing to send, and a hook must
        # never surface an error in the user's session. Do nothing, exit clean.
        debug.log("no API key resolved (env/credential store); nothing to send")
        return 0

    raw = engine.read_stdin()
    if not raw:
        debug.log("empty hook input payload from stdin; nothing to send")
        return 0

    event = None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            event = parsed
    except Exception as e:
        debug.exc("stdin JSON parse", e)
        event = None

    if event is not None:
        debug.log("event " + str(event.get("hook_event_name")))
        payload_str = json.dumps(enrich(event), ensure_ascii=False, separators=(",", ":"))
    else:
        # stdin was not valid JSON - forward it verbatim, unenriched.
        debug.log("stdin not valid JSON; forwarding verbatim (" + str(len(raw)) + " bytes)")
        payload_str = raw

    # The response body is Cursor's decision for this event; transport prints
    # it verbatim, or nothing when the POST fails (Cursor's defaults apply).
    return transport.post(payload_str, api_key, NOMA_API_URL, HOOKS_PATH)


if __name__ == "__main__":
    sys.exit(main())
