#!/usr/bin/env python3
"""Noma guardrails - unified cross-OS Claude Code hook.

One entry point for every hook event, invoked via uv so a single Python
implementation replaces the old per-OS bash and PowerShell hooks:

    uv run --no-project hook.py        # reads the hook event JSON on stdin

It resolves the API key from the environment or the OS credential store,
enriches the event with host/user, builds the MCP-server inventory on
UserPromptSubmit, and POSTs the result to the Noma hooks endpoint. The
credential-store reads and the POST live in the vendored common package
(credentials/transport); this file is just the per-event orchestration.

Stdlib only, no f-strings/annotations - runs on any python3 (the vendored
common package carries the same constraint; see common/).
"""

import json
import os
import sys

try:
    from common import engine, credentials, transport, debug
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import engine, credentials, transport, debug

from mcp_discovery import discover_claude_code

# Noma-specific config, passed into the generic common/ package so it stays
# agent-agnostic.
KEYCHAIN_SERVICE = "noma-guardrails"
HOOKS_PATH = "/claude/v1/hooks"
NOMA_API_URL = os.environ.get("NOMA_API_URL") or "https://api.noma.security"
DEBUG_LOG_FILENAME = "claude-code-guardrails-debug.log"


def account_email():
    """The logged-in Claude account's email from ~/.claude.json, or "".

    Claude Code hook events carry no user identity, so the account email
    (oauthAccount.emailAddress) is the closest stable one. Only that single
    field is read - the file's top level holds unrelated, sensitive state.
    """
    home = os.environ.get("HOME") or os.path.expanduser("~")
    doc = engine.read_json(os.path.join(home, ".claude.json"))
    account = doc.get("oauthAccount") if isinstance(doc, dict) else None
    email = account.get("emailAddress") if isinstance(account, dict) else None
    return email if isinstance(email, str) else ""


def enrich(payload):
    """Add hostname/username to the payload dict (best-effort, never raises).

    username is the Claude account email when the user is logged in, else the
    OS username."""
    return engine.enrich_identity(payload, account_email() or credentials.current_user())


def main():
    # Brand the shared debug module's log file for this plugin (in main, not at
    # import, so importing this module has no side effects).
    debug.set_log_filename(DEBUG_LOG_FILENAME)
    api_key = credentials.resolve_api_key(KEYCHAIN_SERVICE)
    if not api_key:
        # Degrade quietly: with no key there's nothing to send, and a hook must
        # never surface an error in the user's session. Do nothing, exit clean.
        debug.log("no API key resolved (env/settings/credential store); nothing to send")
        return 0

    raw = engine.read_stdin()
    debug.log("read " + str(len(raw)) + " bytes from stdin")

    event = None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            event = parsed
    except Exception as e:
        debug.exc("stdin JSON parse", e)
        event = None

    if event is not None and event.get("hook_event_name") == "UserPromptSubmit":
        # Augment the prompt event with the per-scope MCP inventory. The engine
        # degrades to the event alone if discovery turns up nothing.
        debug.log("event UserPromptSubmit; building MCP inventory")
        home = os.environ.get("HOME") or os.path.expanduser("~")
        payload = enrich(engine.build_payload(event, discover_claude_code, home, os.getcwd()))
        debug.log("MCP inventory: " + str(len(payload.get("mcp_artifacts") or [])) + " artifact(s)")
        payload_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    elif event is not None:
        debug.log("event " + str(event.get("hook_event_name")) + "; no inventory")
        payload_str = json.dumps(enrich(event), ensure_ascii=False, separators=(",", ":"))
    else:
        # stdin was not valid JSON - forward it verbatim, unenriched.
        debug.log("stdin not valid JSON; forwarding verbatim (" + str(len(raw)) + " bytes)")
        payload_str = raw

    return transport.post(payload_str, api_key, NOMA_API_URL, HOOKS_PATH)


if __name__ == "__main__":
    sys.exit(main())
