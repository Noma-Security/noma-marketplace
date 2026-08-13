#!/usr/bin/env python3
"""Noma guardrails hook adapter for GitHub Copilot CLI.

Reads a Copilot hook event from stdin, enriches it with endpoint identity,
attaches the MCP inventory on userPromptSubmitted, and forwards it to Noma.
The backend's Copilot-native response is written unchanged by the shared
transport. Stdlib only; Python 3.6+.
"""

import json
import os
import sys

try:
    from common import credentials, debug, engine, transport
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import credentials, debug, engine, transport

from copilot_mcp_discovery import copilot_home, discover_copilot


KEYCHAIN_SERVICE = "noma-guardrails"
HOOKS_PATH = "/github-copilot/v1/hooks"
NOMA_API_URL = os.environ.get("NOMA_API_URL") or "https://api.noma.security"
DEBUG_LOG_FILENAME = "copilot-guardrails-debug.log"

_PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_jsonc(path):
    """Parse a JSONC file (JSON with full-line `//` comments), or None. Only
    lines whose first non-whitespace is `//` are dropped, so `//` inside string
    values (e.g. URLs) is untouched. Never raises."""
    try:
        with open(path) as f:
            raw = f.read()
    except Exception as e:
        debug.exc("copilot config read " + str(path), e)
        return None
    kept = [line for line in raw.splitlines() if not line.lstrip().startswith("//")]
    try:
        return json.loads("\n".join(kept))
    except Exception as e:
        debug.exc("copilot config parse " + str(path), e)
        return None


def account_login():
    """The logged-in GitHub account from <copilot home>/config.json, or "".

    Copilot hook events carry no user identity. The loggedInUsers shape is
    undocumented, so it is parsed defensively (strings, {login/user/email}
    objects, or a map keyed by login) and used only when it names exactly one
    account. Only that field is read - config.json may hold auth state.

    Copilot writes config.json as JSONC (leading `//` comment lines), which
    stdlib json cannot parse, so full-line comments are stripped first. Even
    when present the identity is a GitHub login, not an email - Copilot never
    hands the hook an email.
    """
    home = os.environ.get("HOME") or os.path.expanduser("~")
    doc = _read_jsonc(os.path.join(copilot_home(home), "config.json"))
    users = doc.get("loggedInUsers") if engine.is_object(doc) else None
    if engine.is_object(users):
        entries = list(users.keys())
    elif isinstance(users, list):
        entries = users
    else:
        entries = []
    logins = []
    for entry in entries:
        login = entry
        if engine.is_object(entry):
            login = entry.get("login") or entry.get("user") or entry.get("email")
        if isinstance(login, str) and login != "" and login not in logins:
            logins.append(login)
    return logins[0] if len(logins) == 1 else ""


def plugin_version():
    """The installed plugin's manifest version, or "" (never raises)."""
    manifest = engine.read_json(os.path.join(_PLUGIN_ROOT, ".plugin", "plugin.json"))
    version = manifest.get("version") if engine.is_object(manifest) else None
    return version if isinstance(version, str) else ""

def normalize(event, argv_event):
    """Fill in hookEventName from the hooks.json argv hint when the payload
    lacks it."""
    if "hookEventName" not in event and argv_event:
        event["hookEventName"] = argv_event
    return event


def enrich(payload):
    """username is the logged-in GitHub account when resolvable, else the OS user."""
    return engine.enrich_identity(payload, account_login() or credentials.current_user())


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

    event = normalize(event, sys.argv[1] if len(sys.argv) > 1 else None)

    if event.get("hookEventName") == "userPromptSubmitted":
        debug.log("event userPromptSubmitted; building MCP inventory")
        home = os.environ.get("HOME") or os.path.expanduser("~")
        payload = enrich(engine.build_payload(event, discover_copilot, home, event.get("cwd", "")))
        debug.log("MCP inventory: " + str(len(payload.get("mcp_artifacts") or [])) + " artifact(s)")
    else:
        debug.log("event " + str(event.get("hookEventName")) + "; no inventory")
        payload = enrich(event)

    version = plugin_version()
    if version:
        payload["pluginVersion"] = version

    payload_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return transport.post(payload_str, api_key, NOMA_API_URL, HOOKS_PATH)


if __name__ == "__main__":
    sys.exit(main())
