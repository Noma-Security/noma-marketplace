#!/usr/bin/env python3
"""Noma guardrails hook adapter for Codex.

Reads a Codex hook event from stdin, enriches it with endpoint identity, builds
the MCP-server inventory on UserPromptSubmit, and forwards it to Noma. The
backend returns the Codex-native hook response, which is written unchanged by
the shared transport. Stdlib only; Python 3.6+.
"""

import base64
import hashlib
import json
import os
import re
import sys

try:
    import tomllib
except ImportError:  # Python < 3.11: the top-level line scan below is the fallback
    tomllib = None

try:
    from common import credentials, debug, engine, transport
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import credentials, debug, engine, transport

from codex_mcp_discovery import CODEX_CONFIG_FILENAME, _codex_home, _system_config_path, collect_codex_artifacts

KEYCHAIN_SERVICE = "noma-guardrails"
# equals .version in .codex-plugin/plugin.json; CI enforces it
HOOK_VERSION = "2.2.1"
HOOKS_PATH = "/codex/v1/hooks"
HOOKS_PATH_V2 = "/codex/v2/hooks"
NOMA_API_URL = os.environ.get("NOMA_API_URL") or "https://api.noma.security"
DEBUG_LOG_FILENAME = "codex-guardrails-debug.log"
AUTH_FILENAME = "auth.json"
AUTH_MAX_BYTES = 64 * 1024
CONFIG_MAX_BYTES = 256 * 1024
# cli_auth_credentials_store is a top-level key; a line scan avoids needing tomllib (3.11+).
CREDENTIALS_STORE_RE = re.compile(r'^\s*cli_auth_credentials_store\s*=\s*["\']([^"\']*)["\']')
TOML_TABLE_HEADER_RE = re.compile(r'^\s*\[')
KEYRING_STORES = ("keyring", "auto")
# macOS is excluded: Codex's keychain item is ACL-bound to the codex binary, so a
# `security -w` read from the hook can raise an authorization dialog on every event.
# Windows is excluded: the keyring crate refuses blobs over 2560 bytes and Codex adds
# no chunking, so a ChatGPT token document never lands in the Credential Manager.
KEYRING_PLATFORMS = ("linux",)
# How Codex (codex-rs/login/src/auth/storage.rs) keys its keyring entry: service
# KEYRING_SERVICE, account "cli|" + sha256(canonical CODEX_HOME)[:16].
KEYRING_SERVICE = "Codex Auth"
CODEX_KEYRING_ACCOUNT_PREFIX = "cli|"


def _jwt_claims(token):
    """Unverified payload of a JWT, or None. Verification is not needed: the
    token was issued to this user and is read for the email claim only."""
    try:
        segment = token.split(".")[1]
        padded = segment + "=" * (-len(segment) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception as e:
        debug.exc("id_token decode", e)
        return None
    return claims if isinstance(claims, dict) else None


def _keyring_account(codex_home):
    digest = hashlib.sha256(os.path.realpath(codex_home).encode("utf-8")).hexdigest()
    return CODEX_KEYRING_ACCOUNT_PREFIX + digest[:16]


def _keyring_auth(codex_home):
    """auth.json content from the OS credential store, or None."""
    raw = credentials.read_store_entry(KEYRING_SERVICE, _keyring_account(codex_home))
    if not raw:
        return None
    try:
        doc = json.loads(raw)
    except Exception as e:
        debug.exc("keyring auth parse", e)
        return None
    if not isinstance(doc, dict):
        return None
    debug.log("codex auth read from OS credential store")
    return doc


def _email_from_auth(doc):
    tokens = doc.get("tokens") if isinstance(doc, dict) else None
    id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
    claims = _jwt_claims(id_token) if isinstance(id_token, str) else None
    email = claims.get("email") if claims else None
    return email if isinstance(email, str) else ""


def _scan_credentials_store(text):
    """Top-level cli_auth_credentials_store from TOML text without a parser, or
    None. Strings (basic with backslash escapes, literal, and both multiline
    forms), comments and array nesting are tracked so their contents are never
    read as a table header or as the key."""
    quote = None
    depth = 0
    for line in text.splitlines():
        if quote is None and depth == 0:
            if TOML_TABLE_HEADER_RE.match(line):
                return None  # top-level keys end at the first [table]
            match = CREDENTIALS_STORE_RE.match(line)
            if match:
                return match.group(1)
        i = 0
        while i < len(line):
            char = line[i]
            if quote:
                if char == "\\" and quote[0] == '"':
                    i += 1  # escaped character never closes the string
                elif line.startswith(quote, i):
                    i += len(quote) - 1
                    quote = None
            elif line.startswith('"""', i) or line.startswith("'''", i):
                quote = line[i:i + 3]
                i += 2
            elif char in ("'", '"'):
                quote = char
            elif char == "#":
                break
            elif char == "[":
                depth += 1
            elif char == "]":
                depth = max(depth - 1, 0)
            i += 1
        if quote in ("'", '"'):
            quote = None  # single-line strings cannot continue past the line
    return None


def _read_credentials_store(path):
    """cli_auth_credentials_store from one config.toml, or None when the file is
    missing, unreadable or does not set it. tomllib when available, else a scan."""
    try:
        with open(path, "rb") as f:
            raw = f.read(CONFIG_MAX_BYTES)
    except Exception as e:
        debug.exc("config.toml read " + str(path), e)
        return None
    text = raw.decode("utf-8", "replace")
    if tomllib is not None:
        try:
            value = tomllib.loads(text).get("cli_auth_credentials_store")
            return value if isinstance(value, str) and value != "" else None
        except Exception as e:
            debug.exc("config.toml parse " + str(path), e)
    return _scan_credentials_store(text)


def _credentials_store(codex_home):
    """Effective cli_auth_credentials_store: the user config wins over the system
    layer (/etc/codex/config.toml); "file" is Codex's default when neither sets it.
    Project configs cannot set credential settings, so they are not read."""
    paths = [os.path.join(codex_home, CODEX_CONFIG_FILENAME), _system_config_path()]
    for path in paths:
        if path and os.path.exists(path):
            value = _read_credentials_store(path)
            if value is not None:
                return value
    return "file"


def account_email():
    """The logged-in ChatGPT account's email, or "".

    Codex hook events carry no user identity, so the id_token email claim is
    the closest stable one. Read from $CODEX_HOME/auth.json; the OS credential
    store is consulted only on KEYRING_PLATFORMS and only when Codex is
    configured to use it, so file-mode machines never touch the keychain. Only
    the email claim is used - the document holds live tokens.
    """
    home = os.environ.get("HOME") or os.path.expanduser("~")
    codex_home = _codex_home(home)
    email = _email_from_auth(engine.read_json(os.path.join(codex_home, AUTH_FILENAME), AUTH_MAX_BYTES))
    if not email and sys.platform in KEYRING_PLATFORMS and _credentials_store(codex_home) in KEYRING_STORES:
        email = _email_from_auth(_keyring_auth(codex_home))
    return email


def _event_cwd(event):
    cwd = event.get("cwd")
    if not isinstance(cwd, str) or cwd == "":
        cwd = os.getcwd()
    return cwd


def enrich(event):
    """username is the ChatGPT account email when logged in, else the global git
    user.email, else the OS username."""
    username = engine.resolve_username((("account", account_email),
                                        ("git", credentials.git_email),
                                        ("os", credentials.current_user)))
    return engine.enrich_identity(event, username)


def add_mcp_artifacts(event):
    """Attach a complete MCP inventory; omission preserves the cached inventory."""
    cwd = _event_cwd(event)
    home = os.environ.get("HOME") or os.path.expanduser("~")
    artifacts, complete = collect_codex_artifacts(home, cwd)
    if complete:
        event["mcp_artifacts"] = artifacts
    else:
        event.pop("mcp_artifacts", None)
    return event


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

    event["hook_version"] = HOOK_VERSION

    if event.get("hook_event_name") == "UserPromptSubmit":
        debug.log("event UserPromptSubmit; building MCP inventory")
        event = add_mcp_artifacts(event)

    payload = json.dumps(enrich(event), ensure_ascii=False, separators=(",", ":"))
    if key_scope == credentials.KeyScope.DATA_COLLECTOR_KEY:
        return transport.post(payload, api_key, NOMA_API_URL, HOOKS_PATH_V2, scheme="")
    return transport.post(payload, api_key, NOMA_API_URL, HOOKS_PATH)


if __name__ == "__main__":
    sys.exit(main())
