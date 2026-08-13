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


def read_json(path, max_bytes=None):
    """Parse bounded JSON, or None on any size/read/decode/parse failure."""
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes + 1) if max_bytes is not None else f.read()
    except Exception as e:
        debug.exc("read_json open/read " + str(path), e)
        return None
    if max_bytes is not None and len(raw) > max_bytes:
        debug.log("read_json too large " + str(path))
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


def canonical_path(path, path_mod=os.path):
    """A path folded to one canonical spelling: separators/`.`/`..` collapsed
    (normpath) and case normalized (normcase). Both are no-ops on POSIX.

    For comparing two spellings of the same path ONLY. normcase lowercases on
    Windows: opening the result usually still works (NTFS is case-insensitive
    by default) but breaks on case-sensitive NTFS dirs (WSL trees) and SMB
    shares, and a reported/shown path must keep its on-disk spelling — so use
    real paths for I/O and artifacts, canonical ones for comparison keys.
    path_mod defaults to os.path; pass ntpath to force Windows semantics (tests).
    """
    return path_mod.normcase(path_mod.normpath(path))


def git_repository_root(cwd):
    """Nearest Git root, resolving valid linked worktrees to the main checkout."""
    current = cwd
    while isinstance(current, str) and current != "":
        git_entry = os.path.join(current, ".git")
        if file_exists(git_entry):
            if os.path.isdir(git_entry) or not os.path.isfile(git_entry):
                return current
            try:
                with open(git_entry, "r") as handle:
                    value = handle.read(4097)
            except Exception as e:
                debug.exc("gitdir read " + str(git_entry), e)
                return current
            if len(value) > 4096:
                return current
            redirect = value.strip()
            if not redirect.startswith("gitdir:"):
                return current
            git_dir = redirect[len("gitdir:"):].strip()
            if git_dir == "":
                return current
            if not os.path.isabs(git_dir):
                git_dir = os.path.normpath(os.path.join(current, git_dir))
            worktrees_dir = os.path.dirname(git_dir)
            main_git_dir = os.path.dirname(worktrees_dir)
            if os.path.basename(worktrees_dir) != "worktrees" \
                    or os.path.basename(main_git_dir) != ".git" \
                    or not os.path.isdir(git_dir):
                return current
            return os.path.dirname(main_git_dir)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


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
