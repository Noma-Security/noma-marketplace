"""Generic inventory core: filesystem/stdio helpers, the (scope, kind, path,
content) artifact schema, and the discoverer harness.

Agent-agnostic and OS-agnostic. A *discoverer* is any callable ``(home, cwd)``
returning a list of ``(scope, kind, path, content)`` candidates; the core drops
empty content and emits the rest. Stdlib only.
"""

import json
import os
import socket
import sys

from . import debug


def is_object(v):
    """True for a JSON object (dict); JSON arrays are list, null is None."""
    return isinstance(v, dict)


# --- filesystem / stdio (every failure degrades to None/"") ------------------


def read_json(path):
    """Parse a JSON file, or None on any read/decode/parse failure."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception as e:
        debug.exc("read_json open/read " + str(path), e)
        return None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        debug.exc("read_json parse " + str(path), e)
        return None
    debug.log("read_json ok " + str(path))
    return obj


def file_exists(path):
    return os.path.exists(path)


def read_stdin():
    try:
        return sys.stdin.buffer.read().decode("utf-8")
    except Exception as e:
        debug.exc("read_stdin", e)
        return ""


def enrich_identity(payload, username):
    """Add endpoint identity to a payload, best-effort."""
    try:
        hostname = socket.gethostname()
    except Exception as e:
        debug.exc("gethostname", e)
        hostname = ""
    if hostname:
        payload["hostname"] = hostname
    if username:
        payload["username"] = username
    debug.log("enriched hostname=" + ("yes" if hostname else "no") +
              " username=" + ("yes" if username else "no"))
    return payload


# --- artifact / payload assembly ---------------------------------------------


def make_artifact(scope, kind, path, content):
    return {"scope": scope, "kind": kind, "path": path, "content": content}


def build_inventory(discoverer, home, cwd):
    """Run a discoverer and keep only non-empty artifacts. Best-effort: a
    discoverer error yields whatever was collected so far (never raises), so a
    discovery failure can't break the hook."""
    artifacts = []
    try:
        for scope, kind, path, content in discoverer(home, cwd):
            if is_object(content) and len(content) > 0:
                artifacts.append(make_artifact(scope, kind, path, content))
    except Exception as e:
        debug.exc("build_inventory discoverer", e)
    debug.log("build_inventory: " + str(len(artifacts)) + " artifact(s) kept")
    return artifacts


def build_payload(event, discoverer, home, cwd_fallback):
    """Add the per-scope MCP inventory to a parsed hook event and return it.

    Pure (no stdin/stdout/env) so it is directly unit-testable. ``event`` is the
    already-parsed event dict; its own cwd wins, and cwd_fallback is used only
    when the event omits it.
    """
    if isinstance(event.get("cwd"), str) and event["cwd"] != "":
        cwd = event["cwd"]
    else:
        cwd = cwd_fallback
    event["mcp_artifacts"] = build_inventory(discoverer, home, cwd) if discoverer else []
    return event
