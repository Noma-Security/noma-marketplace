#!/usr/bin/env python3
"""Noma guardrails hook adapter for Codex.

Reads a Codex hook event from stdin, enriches it with endpoint identity, builds
the MCP-server inventory on UserPromptSubmit, and forwards it to Noma. The
backend returns the Codex-native hook response, which is written unchanged by
the shared transport. Stdlib only; Python 3.6+.
"""

import json
import os
import sys

try:
    from common import credentials, debug, engine, transport
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import credentials, debug, engine, transport

from codex_mcp_discovery import collect_codex_artifacts

KEYCHAIN_SERVICE = "noma-guardrails"
HOOKS_PATH = "/codex/v1/hooks"
NOMA_API_URL = os.environ.get("NOMA_API_URL") or "https://api.noma.security"
DEBUG_LOG_FILENAME = "codex-guardrails-debug.log"


def enrich(payload):
    return engine.enrich_identity(payload, credentials.current_user())


def add_mcp_artifacts(event):
    """Attach a complete MCP inventory; omission preserves the cached inventory."""
    cwd = event.get("cwd")
    if not isinstance(cwd, str) or cwd == "":
        cwd = os.getcwd()
    home = os.environ.get("HOME") or os.path.expanduser("~")
    artifacts, complete = collect_codex_artifacts(home, cwd)
    if complete:
        event["mcp_artifacts"] = artifacts
    else:
        event.pop("mcp_artifacts", None)
    return event


def main():
    debug.set_log_filename(DEBUG_LOG_FILENAME)
    api_key = credentials.resolve_api_key(KEYCHAIN_SERVICE)
    if not api_key:
        debug.log("no API key resolved; nothing to send")
        return 0

    raw = engine.read_stdin()
    try:
        event = json.loads(raw)
    except Exception as e:
        debug.exc("stdin JSON parse", e)
        return 0
    if not isinstance(event, dict):
        debug.log("stdin JSON is not an object; nothing to send")
        return 0

    if event.get("hook_event_name") == "UserPromptSubmit":
        debug.log("event UserPromptSubmit; building MCP inventory")
        event = add_mcp_artifacts(event)

    payload = json.dumps(enrich(event), ensure_ascii=False, separators=(",", ":"))
    return transport.post(payload, api_key, NOMA_API_URL, HOOKS_PATH)


if __name__ == "__main__":
    sys.exit(main())
