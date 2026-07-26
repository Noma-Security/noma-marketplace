"""Cursor MCP discovery for the guardrails plugin.

The Cursor specifics (which files at which scopes) live here; the generic
allowlist pipeline lives in the vendored common package (mcp_utils).
Imported by hook.py on beforeSubmitPrompt.

Sources (empirical research 2026-07-22 — Cursor documents no resolution order;
the backend enforces precedence by artifact rank, this module only collects):
  user        : ~/.cursor/{mcp,.mcp}.json
  workspace   : <workspace root>/.cursor/{mcp,.mcp}.json for every workspace root
  plugin      : per installed plugin (~/.cursor/plugins/<source>/<plugin>/):
                  .cursor-plugin/plugin.json `mcpServers` field (inline map,
                  path, or an array of either)  -> kind cursor_plugin_json
                  folder-discovered {mcp,.mcp}.json -> kind cursor_mcp_json
                  .cursor-plugin/marketplace.json in the plugins tree; each
                  plugins[] entry's `mcpServers` (path or inline) -> kind
                  cursor_marketplace_json. Path values resolve against the
                  marketplace root — the base `source` paths are written from
                  (empirically unverified; revisit with a real marketplace
                  install).

Stdlib only, no f-strings/annotations — runs on any python3.
"""

import os
import sys

try:
    from common import engine, debug, mcp_utils
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import engine, debug, mcp_utils

# Cursor holds both a plugin's plugin.json and a marketplace's marketplace.json
# under a .cursor-plugin subdirectory.
_CURSOR_PLUGIN_DIR = ".cursor-plugin"


def _discover_plugins(home):
    """Plugin and marketplace candidates from the ~/.cursor/plugins tree.

    Cursor nests installed plugins at variable depth (e.g.
    plugins/cache/<marketplace>/<plugin>/<commit>/.cursor-plugin), so the tree
    is walked for every directory holding a .cursor-plugin manifest folder;
    plugin.json yields plugin candidates and marketplace.json yields
    marketplace candidates, both keyed off the directory that holds it."""
    out = []
    plugins_root = os.path.join(home, ".cursor", "plugins")
    # Guarded to return partial results: discover_cursor builds one list per
    # event, so a raise here would discard the other scopes' candidates too,
    # and the resulting empty mcp_artifacts would clear the backend's cached
    # inventory (empty-on-prompt means "no servers configured").
    try:
        for current, dirs, _files in os.walk(plugins_root):
            dirs.sort()
            if os.path.basename(current) != _CURSOR_PLUGIN_DIR:
                continue
            holder = os.path.dirname(current)
            if engine.file_exists(os.path.join(current, "plugin.json")):
                out.extend(mcp_utils.plugin_candidates(
                    "plugin", "cursor_plugin_json", "cursor_mcp_json", holder, _CURSOR_PLUGIN_DIR))
            if engine.file_exists(os.path.join(current, "marketplace.json")):
                out.extend(mcp_utils.marketplace_candidates(
                    "plugin", "cursor_marketplace_json", holder, _CURSOR_PLUGIN_DIR))
    except Exception as e:
        debug.exc("cursor plugin walk " + plugins_root, e)
    return out


def discover_cursor(home, workspace_roots):
    """Return (scope, kind, path, content) MCP candidates for Cursor.

    One candidate per config source; the engine later drops any whose server
    map is empty. workspace_roots comes from the hook event (Cursor is
    multi-root); duplicates and non-string entries are skipped.
    """
    candidates = []
    candidates.extend(mcp_utils.mcp_file_candidates("user", "cursor_mcp_json", os.path.join(home, ".cursor")))

    seen = set()
    for root in workspace_roots or []:
        if not isinstance(root, str) or root == "" or root in seen:
            continue
        seen.add(root)
        candidates.extend(mcp_utils.mcp_file_candidates("workspace", "cursor_mcp_json", os.path.join(root, ".cursor")))

    candidates.extend(_discover_plugins(home))

    if debug.enabled():
        for scope, kind, path, content in candidates:
            has = engine.is_object(content) and len(content) > 0
            debug.log("cursor discovery: " + scope + "/" + kind + " " + str(path) +
                      (" -> has servers" if has else " -> empty"))
    return candidates
