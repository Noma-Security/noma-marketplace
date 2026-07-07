"""Claude Code MCP server-config allowlisting.

Claude Code stores MCP servers under an `mcpServers` (or `servers`) wrapper key.
This module pulls out that map and reduces each server to a type/url/command/args
allowlist with secret-looking values masked, so any identifier a backend derives
from the output is clean by construction; env, headers and everything else never
leave the machine. Claude-Code-specific (it encodes Claude Code's config
conventions), so it lives with the plugin rather than in the shared common/
library; a different agent (e.g. Cursor) would need its own version.

`server_content(doc)` runs the full pipeline: extract -> clean -> wrap.
"""

import json
import os
import sys

try:
    from common import is_object, sanitize_args, sanitize_str
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import is_object, sanitize_args, sanitize_str


def extract_servers(doc):
    """The {name: config} server map from a config doc: the `mcpServers` key,
    else `servers`, else {}.

    Claude Code wraps servers under one of these keys in every config file
    except a plugin's .mcp.json (see extract_plugin_servers), so a wrapper-less
    "bare map" of servers is intentionally ignored here. This matters most for
    files whose top level also holds unrelated, sensitive state (settings.json's
    env/tokens, ~/.claude.json): keying off the explicit wrapper means a secret
    there can never be mistaken for a server config.
    """
    if not is_object(doc):
        return {}
    m = doc.get("mcpServers")
    if not is_object(m):
        m = doc.get("servers")
    return m if is_object(m) else {}


def extract_plugin_servers(doc):
    """The {name: config} server map from a plugin's .mcp.json.

    Plugin .mcp.json files come in two shapes, and Claude Code loads both: the
    wrapped {"mcpServers": {...}} form, and a bare {name: config} map (what the
    official marketplace plugins ship, e.g. context7). The wrapper wins when
    present; otherwise every object-valued top-level entry is taken as a server.
    Reading the bare shape is safe only for this file: unlike settings.json or
    ~/.claude.json, a plugin .mcp.json holds nothing but server configs.
    """
    if not is_object(doc):
        return {}
    if is_object(doc.get("mcpServers")) or is_object(doc.get("servers")):
        return extract_servers(doc)
    out = {}
    for name in doc:
        if is_object(doc[name]):
            out[name] = doc[name]
    return out


def _as_arg_string(value):
    """A command-line arg as a string, matching jq / JSON.stringify `tostring`:
    strings pass through; 8080 -> "8080", true -> "true"."""
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"))


def clean_server(cfg):
    """Reduce one server config to the allowlisted identity fields.

    Keeps only type/url/command/args; url and command are secret-sanitized, args
    are sanitized then stringified. Everything else (env, headers, ...) is dropped.
    """
    if not is_object(cfg):
        return {}
    out = {}
    if isinstance(cfg.get("type"), str):
        out["type"] = sanitize_str(cfg["type"])
    if isinstance(cfg.get("url"), str):
        out["url"] = sanitize_str(cfg["url"])
    if isinstance(cfg.get("command"), str):
        out["command"] = sanitize_str(cfg["command"])
    if isinstance(cfg.get("args"), list):
        out["args"] = [_as_arg_string(v) for v in sanitize_args(cfg["args"])]
    return out


def clean_servers(server_map):
    """Apply clean_server to every entry in a {name: config} map."""
    if not is_object(server_map):
        return {}
    out = {}
    for name in server_map:
        out[name] = clean_server(server_map[name])
    return out


def wrap_servers(server_map):
    """Wrap a cleaned server map back under {mcpServers: ...}; {} when empty."""
    return {"mcpServers": server_map} if len(server_map) > 0 else {}


def server_content(doc):
    """A config file's MCP servers, allowlisted and wrapped: {mcpServers: {...}},
    or {} when there are none. The full extract -> clean -> wrap pipeline."""
    return wrap_servers(clean_servers(extract_servers(doc)))


def plugin_server_content(doc):
    """server_content for a plugin's .mcp.json: same clean -> wrap pipeline, but
    extraction also accepts the bare {name: config} shape (extract_plugin_servers)."""
    return wrap_servers(clean_servers(extract_plugin_servers(doc)))


def manifest_content(doc):
    """A plugin manifest verbatim, with its inline mcpServers/servers cleaned.

    Metadata (name/version/author/...) is benign and sent as-is.
    """
    if not is_object(doc):
        return {}
    out = {}
    for key in doc:
        if key in ("mcpServers", "servers"):
            continue
        out[key] = doc[key]
    for wrapper in ("mcpServers", "servers"):
        if is_object(doc.get(wrapper)):
            cleaned = clean_servers(doc[wrapper])
            if len(cleaned) > 0:
                out[wrapper] = cleaned
    return out


def with_plugin_meta(content, name, version):
    """Tag non-empty content with the plugin's manifest name and version.

    Both come from the plugin manifest (.claude-plugin/plugin.json); the backend
    needs the name to parse mcp__plugin_<name>_* tool calls and reports the
    version alongside it. Empty content is untouched, and each field is tagged
    only when present.
    """
    if is_object(content) and len(content) > 0:
        if name:
            content["pluginName"] = name
        if version:
            content["pluginVersion"] = version
    return content
