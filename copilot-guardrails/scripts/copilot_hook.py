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
# equals .version in .plugin/plugin.json; CI enforces it
HOOK_VERSION = "1.1.3"
HOOKS_PATH = "/github-copilot/v1/hooks"
HOOKS_PATH_V2 = "/github-copilot/v2/hooks"
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

TRANSCRIPT_TAIL_BYTES = 1024 * 1024


def _transcript_tail(transcript_path):
    """Whole JSONL records from the end of the file, at most TRANSCRIPT_TAIL_BYTES.
    One byte before the window is read to tell a record boundary from a cut record."""
    size = os.path.getsize(transcript_path)
    start = max(size - TRANSCRIPT_TAIL_BYTES - 1, 0)
    with open(transcript_path, "rb") as f:
        f.seek(start)
        raw = f.read()
    if start > 0:
        raw = raw[1:] if raw[:1] == b"\n" else raw.split(b"\n", 1)[-1]
    return raw


def last_assistant_message(transcript_path):
    """Final response text from Copilot's session events.jsonl: agentStop hands the
    hook only its path. Tool-call-only turns carry content "" and are skipped."""
    try:
        raw = _transcript_tail(transcript_path)
    except Exception as e:
        debug.exc("transcript read " + str(transcript_path), e)
        return ""
    # JSONL delimits on LF only; str.splitlines() would also break on U+2028/U+2029
    # inside a message.
    lines = raw.decode("utf-8", "replace").split("\n")
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except Exception:
            continue
        if not engine.is_object(entry) or entry.get("type") != "assistant.message":
            continue
        data = entry.get("data")
        content = data.get("content") if engine.is_object(data) else None
        if isinstance(content, str) and content != "":
            return content
    debug.log("transcript has no assistant text " + str(transcript_path))
    return ""


def add_last_assistant_message(event):
    if event.get("stop_hook_active") is True:
        return event
    existing = event.get("lastAssistantMessage")
    if isinstance(existing, str) and existing != "":
        return event
    path = event.get("transcriptPath")
    if not isinstance(path, str) or path == "":
        return event
    message = last_assistant_message(path)
    if message:
        event["lastAssistantMessage"] = message
    return event


def normalize(event, argv_event):
    """Fill in hookEventName from the hooks.json argv hint when the payload
    lacks it."""
    if "hookEventName" not in event and argv_event:
        event["hookEventName"] = argv_event
    return event


def enrich(event):
    """username is the global git user.email when set (Copilot never exposes an
    account email), else the logged-in GitHub login, else the OS user."""
    username = engine.resolve_username((("git", credentials.git_email),
                                        ("github", account_login),
                                        ("os", credentials.current_user)))
    return engine.enrich_identity(event, username)


def main():
    debug.set_log_filename(DEBUG_LOG_FILENAME)
    api_key, key_scope = credentials.resolve_api_key(KEYCHAIN_SERVICE)
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
        if event.get("hookEventName") == "agentStop":
            event = add_last_assistant_message(event)
        payload = enrich(event)

    payload["hookVersion"] = HOOK_VERSION
    version = plugin_version()
    if version:
        payload["pluginVersion"] = version

    payload_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if key_scope == credentials.KeyScope.DATA_COLLECTOR_KEY:
        return transport.post(payload_str, api_key, NOMA_API_URL, HOOKS_PATH_V2, scheme="")
    return transport.post(payload_str, api_key, NOMA_API_URL, HOOKS_PATH)


if __name__ == "__main__":
    sys.exit(main())
