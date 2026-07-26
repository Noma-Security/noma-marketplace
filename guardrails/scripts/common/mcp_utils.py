"""Generic MCP server-config allowlisting shared by the agent plugins.

Every agent this marketplace supports stores MCP servers as a {name: config}
map under an `mcpServers` (or `servers`) wrapper key. This module pulls out
that map and reduces each server to a type/url/command/args allowlist with
secret-looking values masked, so any identifier a backend derives from the
output is clean by construction; env, headers and everything else never leave
the machine. Agent-specific config shapes (e.g. Claude Code's plugin manifest
and bare-map plugin .mcp.json) stay with their plugin.

`build_server_content(doc)` runs the full pipeline: extract -> clean -> wrap.
"""

import json
import os

from . import debug
from .engine import file_exists, is_object, read_json
from .redaction import sanitize_args, sanitize_str

MCP_FILENAMES = ("mcp.json", ".mcp.json")

# Wrapper keys a server map lives under, in precedence order (mcpServers wins).
MCP_WRAPPER_KEYS = ("mcpServers", "servers")


def _extract_servers(doc, allow_bare=False):
    """The {name: config} server map from a config doc: the `mcpServers` key,
    else `servers`, else {}.

    Keying off an explicit wrapper matters most for files whose top level also
    holds unrelated, sensitive state: a secret there can never be mistaken for a
    server config. So the wrapper is required by default; an explicitly empty
    wrapper still reads as "no servers", never as a bare entry named "mcpServers".

    allow_bare=True additionally accepts a wrapper-less {name: config} map (every
    object-valued top-level entry is a server). Pass it ONLY for a doc a caller
    has *declared* to be MCP config -- a plugin manifest's inline mcpServers, a
    file it names, or a plugin's bare .mcp.json (e.g. context7). Never enable it
    for a file merely discovered by name.
    """
    if not is_object(doc):
        return {}
    for wrapper in MCP_WRAPPER_KEYS:
        if is_object(doc.get(wrapper)):
            return doc[wrapper]
    if not allow_bare:
        return {}
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


def _clean_server(cfg):
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


def _clean_servers(server_map):
    """Apply _clean_server to every entry in a {name: config} map."""
    if not is_object(server_map):
        return {}
    out = {}
    for name in server_map:
        out[name] = _clean_server(server_map[name])
    return out


def _wrap_servers(server_map):
    """Wrap a cleaned server map back under {mcpServers: ...}; {} when empty."""
    return {"mcpServers": server_map} if len(server_map) > 0 else {}


def build_server_content(doc, allow_bare=False):
    """A config doc's MCP servers, allowlisted and wrapped: {mcpServers: {...}},
    or {} when there are none. The full extract -> clean -> wrap pipeline.

    allow_bare accepts a wrapper-less {name: config} map; pass it only for a doc
    explicitly declared to be MCP config (see _extract_servers)."""
    return _wrap_servers(_clean_servers(_extract_servers(doc, allow_bare)))


def mcp_file_candidates(scope, kind, directory, allow_bare=False):
    """One candidate (scope, kind, path, content) per existing dedicated MCP file
    (mcp.json / .mcp.json) in directory -- each file's server map allowlisted and
    wrapped, no manifest metadata. allow_bare accepts a wrapper-less
    {name: config} map (see build_server_content)."""
    out = []
    for filename in MCP_FILENAMES:
        path = os.path.join(directory, filename)
        if file_exists(path):
            out.append((scope, kind, path, build_server_content(read_json(path), allow_bare)))
    return out


def with_plugin_meta(content, name, version):
    """Tag non-empty content with the providing plugin's manifest name and version.

    The backend needs the name to attribute plugin-provided servers and reports
    the version alongside it. Empty content is untouched, and each field is
    tagged only when present.
    """
    if is_object(content) and len(content) > 0:
        if name:
            content["pluginName"] = name
        if version:
            content["pluginVersion"] = version
    return content


def _manifest_str(manifest, field):
    """A string field from a parsed manifest, or ""."""
    if is_object(manifest) and isinstance(manifest.get(field), str):
        return manifest[field]
    return ""


def _declared_field(manifest):
    """The manifest's declared MCP config field: the first non-None wrapper key
    (MCP_WRAPPER_KEYS order, so mcpServers wins), else None. Unlike
    _extract_servers the value need not be a map -- it may also be a path string
    or an array of either."""
    for key in MCP_WRAPPER_KEYS:
        if manifest.get(key) is not None:
            return manifest[key]
    return None


def _declared_mcp_candidates(scope, kind, base_dir, manifest_path, manifest):
    """Candidates from a manifest's mcpServers/servers field (mcpServers wins):
    an inline map, a path (resolved against base_dir), or an array of either.

    An inline map is emitted merged with the manifest's other fields, so the
    plugin's metadata (name/version/...) travels with its servers; a path/file
    config carries only the plugin name+version.
    """
    field_value = _declared_field(manifest)
    name = _manifest_str(manifest, "name")
    version = _manifest_str(manifest, "version")
    # Both wrapper keys stay out of the metadata: the losing key's raw config
    # must never reach the merged artifact unsanitized.
    metadata = dict((key, manifest[key]) for key in manifest if key not in MCP_WRAPPER_KEYS)
    values = field_value if isinstance(field_value, list) else [field_value]
    out = []
    for value in values:
        if isinstance(value, str) and value != "":
            # normpath only (no normcase): the path is opened and reported in the
            # artifact, so its on-disk spelling must survive; case-folding is for
            # comparisons (engine.canonical_path), not for emitted paths.
            path = os.path.normpath(value if os.path.isabs(value) else os.path.join(base_dir, value))
            if not file_exists(path):
                debug.log("declared mcp config missing: " + path)
                continue
            content = build_server_content(read_json(path), allow_bare=True)
            out.append((scope, kind, path, with_plugin_meta(content, name, version)))
        elif is_object(value):
            content = build_server_content(value, allow_bare=True)
            if len(content) == 0:
                continue
            merged = dict(metadata)
            merged.update(content)
            out.append((scope, kind, manifest_path, with_plugin_meta(merged, name, version)))
    return out


def marketplace_candidates(scope, kind, marketplace_root, manifest_dir):
    """Candidates from a marketplace manifest's plugins[] mcpServers/servers
    entries, emitted under (scope, kind). manifest_dir is the subdirectory holding
    marketplace.json under marketplace_root (e.g. ".cursor-plugin"). The tree
    walk that finds marketplace_root is the caller's (agent-specific) concern.
    """
    manifest_path = os.path.join(marketplace_root, manifest_dir, "marketplace.json")
    doc = read_json(manifest_path)
    if not is_object(doc) or not isinstance(doc.get("plugins"), list):
        return []
    out = []
    for entry in doc["plugins"]:
        if not is_object(entry) or _declared_field(entry) is None:
            continue
        out.extend(_declared_mcp_candidates(scope, kind, marketplace_root, manifest_path, entry))
    return out


def plugin_candidates(scope, plugin_kind, mcp_kind, plugin_dir, manifest_dir):
    """Candidates from one installed plugin directory: the manifest's
    mcpServers/servers field (emitted as plugin_kind), then folder-discovered mcp
    files (emitted as mcp_kind), all under scope. manifest_dir is the subdirectory holding
    plugin.json under plugin_dir (e.g. ".cursor-plugin").
    """
    manifest_path = os.path.join(plugin_dir, manifest_dir, "plugin.json")
    manifest = read_json(manifest_path) if file_exists(manifest_path) else None
    name = _manifest_str(manifest, "name")
    version = _manifest_str(manifest, "version")
    out = []
    if is_object(manifest) and _declared_field(manifest) is not None:
        out.extend(_declared_mcp_candidates(scope, plugin_kind, plugin_dir, manifest_path, manifest))
    for _scope, kind, path, content in mcp_file_candidates(scope, mcp_kind, plugin_dir, allow_bare=True):
        out.append((_scope, kind, path, with_plugin_meta(content, name, version)))
    return out
