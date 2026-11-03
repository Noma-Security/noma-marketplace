#!/usr/bin/env python3
"""Noma guardrails hook adapter for Kiro (CLI V3 and IDE 1.x).

Reads a Kiro hook event from stdin, enriches it with endpoint identity,
attaches the MCP inventory and the account email on UserPromptSubmit and the
final response on Stop, forwards it to Noma, and maps the backend verdict onto
Kiro's hook protocol: PreToolUse block -> reason on stderr + EXIT_BLOCK (which
the hooks.json command turns into Kiro's exit 2), PreToolUse ask -> the
hookSpecificOutput JSON Kiro turns into its native Allow/Deny prompt, Stop
block -> a continue decision, UserPromptSubmit block -> the reason as context
(Kiro cannot block a prompt before it reaches the model). Anything else exits 0
with no stdout, so a clean scan never changes Kiro's behaviour. Stdlib only;
Python 3.6+.
"""

import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

try:
    from common import installed_config, credentials, debug, engine, http_senders, transport
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import installed_config, credentials, debug, engine, http_senders, transport

from kiro_mcp_discovery import discover_kiro, kiro_home


# equals .version in .plugin/plugin.json; CI enforces it
HOOK_VERSION = "1.1.0"
# Kiro has one route: the gateway takes the ingestion key (bare) or the per-endpoint JWT (Bearer) on it.
HOOKS_PATH = "/kiro/v1/hooks"
DEBUG_LOG_FILENAME = "kiro-guardrails-debug.log"
# Branded before the import-time config load so its debug lines land in this hook's log.
debug.set_log_filename(DEBUG_LOG_FILENAME)
installed_config.apply_installed_env()
NOMA_API_URL = transport.api_url()

EVENT_PROMPT = "UserPromptSubmit"
EVENT_PRE_TOOL = "PreToolUse"
EVENT_POST_TOOL = "PostToolUse"
EVENT_STOP = "Stop"

DECISION_BLOCK = "block"
DECISION_ASK = "ask"
# Kiro blocks on ANY exit 2, python's own "can't open file" included, so a block leaves the hook as this
# private code and the hooks.json command maps it to 2 and every other exit to 0 (fail open).
EXIT_BLOCK = 42
DEFAULT_BLOCK_REASON = "Blocked by Noma policy."
DEFAULT_ASK_REASON = "Noma policy requires confirmation."

WHOAMI_TIMEOUT_SECONDS = 3
# Kiro kills a hook at the 25 s timeout hooks.json sets; the rest covers interpreter startup and the verdict.
HOOK_BUDGET_SECONDS = 22
# One deadline for the whole identity chain; the POST gets what is left of HOOK_BUDGET_SECONDS.
IDENTITY_BUDGET_SECONDS = 5
MIN_LOOKUP_SECONDS = 0.5
KIRO_CLI_NAMES = ("kiro-cli", "kiro-cli.exe")
KIRO_CLI_PATHS = ("/Applications/Kiro CLI.app/Contents/MacOS/kiro-cli",)
KIRO_TOKEN_PATH = (".aws", "sso", "cache", "kiro-auth-token.json")
KIRO_PROFILE_PATH = ("Kiro", "User", "globalStorage", "kiro.kiroagent", "profile.json")
KIRO_MANAGEMENT_URL = "https://management.%s.kiro.dev/?profileArn=%s&isEmailRequired=true"
KIRO_REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
KIRO_PROFILE_ARN = re.compile(r"^arn:aws[a-z-]*:codewhisperer:[a-z0-9-]+:[0-9]{12}:profile/[A-Za-z0-9]+$")
MAX_IDE_FILE_BYTES = 64 * 1024
TRANSCRIPT_TAIL_BYTES = 1024 * 1024
SESSION_BUCKET_HEX = 16
SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

_PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def plugin_version():
    """The installed plugin's manifest version, or "" (never raises)."""
    manifest = engine.read_json(os.path.join(_PLUGIN_ROOT, ".plugin", "plugin.json"))
    version = manifest.get("version") if engine.is_object(manifest) else None
    return version if isinstance(version, str) else ""


def normalize(event, argv_event):
    """Fill in hook_event_name from the hooks.json argv hint when the payload
    lacks it."""
    if "hook_event_name" not in event and argv_event:
        event["hook_event_name"] = argv_event
    return event


# --- Stop: the response is not in the event, only in Kiro's session store -----


def session_messages_path(home, cwd, session_id):
    """Kiro keeps `<KIRO_HOME>/sessions/<sha256(cwd)[:16]>/<session_id>/messages.jsonl`,
    cwd exactly as the hook payload carries it (verified on CLI V3 and IDE 1.x)."""
    if not isinstance(cwd, str) or cwd == "" or not isinstance(session_id, str) or session_id == "":
        return ""
    bucket = hashlib.sha256(cwd.encode("utf-8")).hexdigest()[:SESSION_BUCKET_HEX]
    return os.path.join(kiro_home(home), "sessions", bucket, session_id, "messages.jsonl")


def find_session_messages(home, cwd, session_id):
    """The session's messages.jsonl, or "". The bucket hashes Kiro's own spelling of the workspace
    path, which on Windows is not the hook's cwd, so a miss falls back to finding the session by id."""
    if not isinstance(session_id, str) or not SESSION_ID.match(session_id):
        return ""
    path = session_messages_path(home, cwd, session_id)
    if path and os.path.isfile(path):
        return path
    root = os.path.join(kiro_home(home), "sessions")
    try:
        buckets = sorted(os.listdir(root))
    except OSError:
        return ""
    for bucket in buckets:
        path = os.path.join(root, bucket, session_id, "messages.jsonl")
        if os.path.isfile(path):
            return path
    debug.log("no session store for " + session_id)
    return ""


def _transcript_tail(path):
    """Whole JSONL records from the end of the file, at most TRANSCRIPT_TAIL_BYTES.
    One byte before the window is read to tell a record boundary from a cut record."""
    size = os.path.getsize(path)
    start = max(size - TRANSCRIPT_TAIL_BYTES - 1, 0)
    with open(path, "rb") as f:
        f.seek(start)
        raw = f.read()
    if start > 0:
        raw = raw[1:] if raw[:1] == b"\n" else raw.split(b"\n", 1)[-1]
    return raw


def assistant_response(path):
    """Text of the assistant records after the last user record, joined with
    blank lines; "" when there is none. Kiro writes "..." placeholder records
    while streaming, which carry no text."""
    try:
        raw = _transcript_tail(path)
    except Exception as e:
        debug.exc("session store read " + str(path), e)
        return ""
    parts = []
    for line in raw.decode("utf-8", "replace").split("\n"):
        try:
            record = json.loads(line)
        except Exception:
            continue
        payload = record.get("payload") if engine.is_object(record) else None
        if not engine.is_object(payload):
            continue
        if payload.get("type") == "user":
            parts = []
        elif payload.get("type") == "assistant":
            content = payload.get("content")
            if isinstance(content, str) and content.strip() not in ("", "..."):
                parts.append(content)
    if not parts:
        debug.log("session store has no assistant text " + str(path))
    return "\n\n".join(parts)


def add_assistant_response(event, home):
    existing = event.get("assistant_response")
    if isinstance(existing, str) and existing != "":
        return event
    path = find_session_messages(home, event.get("cwd"), event.get("session_id"))
    if path:
        text = assistant_response(path)
        if text:
            event["assistant_response"] = text
    return event


# --- UserPromptSubmit: identity, resolved on every prompt -----------------------


def _executable(names):
    """The first of names under an absolute PATH entry, else "". A relative entry ("", ".")
    resolves against the agent's workspace, where a planted binary would run as the user."""
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        directory = directory.strip().strip('"')
        if not directory or not os.path.isabs(directory):
            continue
        for name in names:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return ""


def _run(cmd, timeout):
    """stdout of a command, or "" on any failure (never raises). A bare command name resolves
    on absolute PATH entries only, and the child never inherits NOMA_API_KEY."""
    binary = cmd[0] if os.path.isabs(cmd[0]) else _executable((cmd[0], cmd[0] + ".exe"))
    if not binary:
        debug.log("command " + cmd[0] + " not found on an absolute PATH entry")
        return ""
    env = dict(os.environ)
    env.pop("NOMA_API_KEY", None)
    try:
        completed = subprocess.run([binary] + list(cmd[1:]), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout, env=env)
    except Exception as e:
        debug.exc("run " + cmd[0], e)
        return ""
    if completed.returncode != 0:
        debug.log("command " + cmd[0] + " exited " + str(completed.returncode))
        return ""
    return completed.stdout.decode("utf-8", "replace")


def kiro_cli_path():
    """`kiro-cli` from PATH, else the macOS app bundle (the IDE launches hooks with
    a minimal PATH), else ""."""
    on_path = _executable(KIRO_CLI_NAMES)
    if on_path:
        return on_path
    for path in KIRO_CLI_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return ""


def whoami_email(timeout=WHOAMI_TIMEOUT_SECONDS):
    """The signed-in Kiro account's email from `kiro-cli whoami --format json`
    (a network call, ~1.6 s), or "". Only the first stdout line is JSON; Kiro
    appends profile lines after it."""
    cli = kiro_cli_path()
    if not cli:
        return ""
    out = _run([cli, "whoami", "--format", "json"], min(timeout, WHOAMI_TIMEOUT_SECONDS))
    first = out.strip().split("\n", 1)[0] if out.strip() else ""
    try:
        doc = json.loads(first)
    except Exception:
        return ""
    email = doc.get("email") if engine.is_object(doc) else None
    return email if isinstance(email, str) else ""


def kiro_ide_profile_path(home):
    """Kiro IDE's sign-in profile (it holds the profile ARN) under the OS's app-data root."""
    if sys.platform == "darwin":
        base = os.path.join(home, "Library", "Application Support")
    elif sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return os.path.join(base, *KIRO_PROFILE_PATH)


def _token_expired(expires_at):
    if not isinstance(expires_at, str):
        return False
    try:
        stamp = datetime.datetime.strptime(expires_at[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return False
    return stamp <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _post_kiro_management(url, headers, body, timeout):
    """The 2xx body through curl, else urllib when curl never sent; raises on any failure."""
    sender = http_senders.native_sender()
    if sender is not None:
        try:
            return sender.send(url, headers, body, timeout)[1]
        except http_senders.NotSent as e:
            debug.exc("Kiro management call via " + sender.name + " never sent", e)
    return http_senders.UrllibSender().send(url, headers, body, timeout)[1]


def ide_token_email(timeout=WHOAMI_TIMEOUT_SECONDS):
    """The Kiro IDE sign-in's email from the GetUsageLimits call `kiro-cli whoami` makes,
    authenticated with the IDE's own token, or "". The token only goes to Kiro's management
    endpoint, in a header, never in argv or the payload."""
    home = os.environ.get("HOME") or os.path.expanduser("~")
    token = engine.read_json(os.path.join(home, *KIRO_TOKEN_PATH), MAX_IDE_FILE_BYTES)
    profile = engine.read_json(kiro_ide_profile_path(home), MAX_IDE_FILE_BYTES)
    if not engine.is_object(token) or not engine.is_object(profile):
        return ""
    access, region, arn = token.get("accessToken"), token.get("region") or "us-east-1", profile.get("arn")
    if not (isinstance(access, str) and access and isinstance(region, str) and KIRO_REGION.match(region)
            and isinstance(arn, str) and KIRO_PROFILE_ARN.match(arn)):
        debug.log("Kiro IDE sign-in incomplete; no IDE email lookup")
        return ""
    if _token_expired(token.get("expiresAt")):
        debug.log("Kiro IDE token expired; no IDE email lookup")
        return ""
    headers = {"Content-Type": "application/x-amz-json-1.0",
               "X-Amz-Target": "AmazonCodeWhispererService.GetUsageLimits",
               "x-amzn-codewhisperer-optout": "false",
               "Authorization": "Bearer " + access,
               "User-Agent": "noma-kiro-guardrails/" + HOOK_VERSION}
    body = json.dumps({"profileArn": arn, "isEmailRequired": True}, separators=(",", ":"))
    try:
        doc = json.loads(_post_kiro_management(KIRO_MANAGEMENT_URL % (region, urllib.parse.quote(arn, safe="")),
                                               headers, body, min(timeout, WHOAMI_TIMEOUT_SECONDS)))
    except Exception as e:
        debug.exc("Kiro IDE email lookup", e)
        return ""
    info = doc.get("userInfo") if engine.is_object(doc) else None
    email = info.get("email") if engine.is_object(info) else None
    return email if isinstance(email, str) else ""


def directory_email(timeout=WHOAMI_TIMEOUT_SECONDS):
    """The OS directory's email for the current user: macOS `dscl` (populated
    by MDM / Platform SSO enrolment), Windows `whoami /upn`. "" elsewhere or
    when unset."""
    user = credentials.current_user()
    if sys.platform == "darwin" and user:
        out = _run(["dscl", ".", "-read", "/Users/" + user, "EMailAddress"], timeout)
        for line in out.splitlines():
            if line.startswith("EMailAddress:"):
                return line.split(":", 1)[1].strip()
        return ""
    if sys.platform.startswith("win"):
        out = _run(["whoami", "/upn"], timeout).strip()
        return out if "@" in out else ""
    return ""


def git_email(timeout=WHOAMI_TIMEOUT_SECONDS):
    """credentials.git_email under the identity deadline instead of its own 5 s."""
    return _run(["git", "config", "--global", "--default", "", "--get", "user.email"], timeout).strip()


def account_email():
    """Email for every UserPromptSubmit: the Kiro sign-in (kiro-cli, else the
    IDE's own token), else the OS directory, else the global git identity,
    else "" (the backend then falls
    back to the OS username every event carries). The lookups share one
    IDENTITY_BUDGET_SECONDS deadline; one that would start with less than
    MIN_LOOKUP_SECONDS left is skipped."""
    deadline = time.monotonic() + IDENTITY_BUDGET_SECONDS

    def bounded(name, lookup):
        def resolve():
            remaining = deadline - time.monotonic()
            if remaining < MIN_LOOKUP_SECONDS:
                debug.log("identity budget spent; skipping " + name)
                return ""
            return lookup(remaining)
        return name, resolve

    return engine.resolve_username((bounded("kiro", whoami_email),
                                    bounded("ide", ide_token_email),
                                    bounded("directory", directory_email),
                                    bounded("git", git_email)))


def enrich(event):
    """Every event carries the OS user; the email travels on UserPromptSubmit
    only, and the backend caches it per session, sliding its TTL on each event."""
    return engine.enrich_identity(event, credentials.current_user())


# --- the backend verdict, mapped onto Kiro's protocol ----------------------------


def apply_decision(event_name, reply):
    """Exit code for a backend reply ({decision?, reason?}); the only output
    channels Kiro honours are PreToolUse exit 2 (block), PreToolUse stdout ask
    JSON, and the Stop continue decision. UserPromptSubmit exit 2 is advisory:
    Kiro appends the reason to the prompt instead of blocking it."""
    if not engine.is_object(reply):
        return 0
    if reply.get("ok") is True and "decision" not in reply:
        # Only the MDM install probe route answers {"ok": true}; the installer reads it on stdout.
        sys.stdout.write(json.dumps(reply) + "\n")
        return 0
    decision = reply.get("decision")
    reason = reply.get("reason") if isinstance(reply.get("reason"), str) else ""
    if event_name == EVENT_PRE_TOOL:
        if decision == DECISION_BLOCK:
            sys.stderr.write((reason or DEFAULT_BLOCK_REASON) + "\n")
            return EXIT_BLOCK
        if decision == DECISION_ASK:
            sys.stdout.write(json.dumps({"hookSpecificOutput": {
                "permissionDecision": "ask",
                "permissionDecisionReason": reason or DEFAULT_ASK_REASON}}) + "\n")
            return 0
    elif event_name == EVENT_PROMPT and decision == DECISION_BLOCK:
        sys.stderr.write((reason or DEFAULT_BLOCK_REASON) + "\n")
        return EXIT_BLOCK
    elif event_name == EVENT_STOP and decision == DECISION_BLOCK:
        sys.stdout.write(json.dumps({"decision": "block", "reason": reason or DEFAULT_BLOCK_REASON}) + "\n")
        return 0
    return 0


def resolve_credential():
    """(key, scheme) for HOOKS_PATH: the per-endpoint token as Bearer, NOMA_API_KEY and the MDM ingestion
    certificate bare. No credential-store service: its API key needs an access-token route Kiro lacks."""
    key, key_scope = credentials.resolve_api_key()
    if key_scope == credentials.KeyScope.ENDPOINT_TOKEN:
        return key, "Bearer"
    return key, ""


def main():
    deadline = time.monotonic() + HOOK_BUDGET_SECONDS
    api_key, scheme = resolve_credential()
    if not api_key:
        debug.log("no ingestion key or endpoint token resolved; nothing to send")
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
    event_name = event.get("hook_event_name")
    home = os.environ.get("HOME") or os.path.expanduser("~")

    if event_name == EVENT_PROMPT:
        debug.log("event UserPromptSubmit; building MCP inventory")
        payload = engine.build_payload(event, discover_kiro, home, event.get("cwd", ""))
        debug.log("MCP inventory: " + str(len(payload.get("mcp_artifacts") or [])) + " artifact(s)")
        email = account_email()
        if email:
            payload["email"] = email
    else:
        debug.log("event " + str(event_name) + "; no inventory")
        payload = event
        if event_name == EVENT_STOP:
            payload = add_assistant_response(payload, home)
    payload = enrich(payload)

    payload["hook_version"] = HOOK_VERSION
    version = plugin_version()
    if version:
        payload["plugin_version"] = version

    replies = []
    payload_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    transport.post(payload_str, api_key, NOMA_API_URL, HOOKS_PATH, scheme=scheme, on_response=replies.append,
                   budget_seconds=deadline - time.monotonic())
    return apply_decision(event_name, replies[0] if replies else None)


def run():
    """EXIT_BLOCK for a block verdict, 0 for every other outcome (a crash included)."""
    try:
        return EXIT_BLOCK if main() == EXIT_BLOCK else 0
    except Exception as e:
        debug.exc("kiro hook", e)
        return 0


if __name__ == "__main__":
    sys.exit(run())
