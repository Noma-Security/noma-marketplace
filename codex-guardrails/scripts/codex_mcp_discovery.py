#!/usr/bin/env python3
"""Codex MCP discovery for the guardrails plugin.

The Codex specifics (which files at which scopes, the TOML shape) live here; the
generic allowlist pipeline lives in the vendored common package (mcp_utils).
Imported by codex_hook.py on UserPromptSubmit.

Scope of collection (see design-log/ai_dr/NOM-9564): access control for
file-backed MCP servers. Sources, lowest precedence first:

  plugin  : manifest-declared/default MCP and app files from Codex's known
            installed, bundled, and primary-runtime plugin roots

  system  : /etc/codex/config.toml (Unix/macOS only)
  user    : $CODEX_HOME/config.toml (CODEX_HOME defaults to ~/.codex)
  project : <dir>/.codex/config.toml for every directory from the project root
            (nearest ancestor holding a project_root_marker, default .git) down
            to cwd, emitted root-first so the closest file wins the backend's
            same-rank merge. A project layer is included only when the trust map
            in the merged system/user config marks the layer directory, detected
            project root, or Git repository root trusted; unknown is skipped.

Not collected (documented fail-open classes): CLI --profile/--config and
cloud-managed fragments. codex_apps connector IDs are collected for session
inventory but calls remain unresolved by the backend.

Completeness: collect returns (artifacts, complete). complete is False when any
present TOML config failed to read/parse, was too large, or Python lacks tomllib
(< 3.11). The hook omits incomplete inventories so the backend never treats a
partial snapshot as authoritative. Plugin failures omit only the affected plugin
or, for a global limit, the plugin tier. Only type/url/command/args plus the
enabled control and app connector IDs are extracted, with secrets masked;
env/header/auth tables never leave the machine.

Stdlib only, no f-strings/annotations — runs on any python3 (P0 hooks work on
3.6+; MCP discovery requires 3.11+ for tomllib, guaranteed by the managed MDM
runtime).
"""

import glob
import os
import sys

try:
    from common import engine, debug, mcp_utils, redaction
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import engine, debug, mcp_utils, redaction

try:
    import tomllib
except ImportError:  # Python < 3.11: discovery degrades to complete=False.
    tomllib = None

CODEX_CONFIG_FILENAME = "config.toml"
_MCP_SERVERS_TABLE = "mcp_servers"
_DEFAULT_PROJECT_ROOT_MARKERS = (".git",)
_MAX_CONFIG_BYTES = 1 << 20
_MAX_PLUGIN_MANIFESTS = 4096
_MAX_PLUGIN_FILE_BYTES = 1 << 20
_MAX_PLUGIN_TOTAL_BYTES = 8 << 20
_PLUGIN_MANIFEST = os.path.join(".codex-plugin", "plugin.json")


class _PluginTierLimit(Exception):
    pass


def _codex_home(home):
    return os.environ.get("CODEX_HOME") or os.path.join(home, ".codex")


def _system_config_path():
    if os.name == "nt":
        return None
    return os.path.join("/etc", "codex", CODEX_CONFIG_FILENAME)


def _read_doc(path):
    """(doc, ok) — the parsed config.toml at path.

    A missing file is a clean (None, True); a present file that cannot be read or
    parsed is (None, False), which marks the whole collection incomplete so the
    backend keeps its cached inventory rather than trusting a partial snapshot.
    """
    if not engine.file_exists(path):
        return None, True
    try:
        with open(path, "rb") as handle:
            data = handle.read(_MAX_CONFIG_BYTES + 1)
    except Exception as e:
        debug.exc("codex config read " + str(path), e)
        return None, False
    if len(data) > _MAX_CONFIG_BYTES:
        debug.log("codex config too large " + str(path))
        return None, False
    try:
        return tomllib.loads(data.decode("utf-8")), True
    except Exception as e:
        debug.exc("codex config parse " + str(path), e)
        return None, False


def _append_servers(artifacts, scope, path, doc):
    """Append a (scope, codex_config_toml, path, content) artifact when the doc's
    mcp_servers table yields any allowlisted server; empty content is dropped."""
    servers = doc.get(_MCP_SERVERS_TABLE) if engine.is_object(doc) else None
    if not engine.is_object(servers):
        servers = {}
    content = mcp_utils.build_server_content({"mcpServers": servers})
    if engine.is_object(content) and len(content) > 0:
        artifacts.append(engine.make_artifact(scope, "codex_config_toml", path, content))


def _trust_lookup_keys(path):
    logical = os.path.abspath(path)
    canonical = os.path.realpath(logical)
    keys = [engine.canonical_path(canonical)]
    logical_key = engine.canonical_path(logical)
    if logical_key != keys[0]:
        keys.append(logical_key)
    return keys


def _trust_map(doc):
    projects = doc.get("projects") if engine.is_object(doc) else None
    if not engine.is_object(projects):
        return {}
    out = {}
    for path, entry in projects.items():
        if engine.is_object(entry) and isinstance(entry.get("trust_level"), str):
            out[engine.canonical_path(path)] = entry["trust_level"]
    return out


def _project_root_markers(doc):
    if not engine.is_object(doc) or "project_root_markers" not in doc:
        return None, True
    markers = doc["project_root_markers"]
    if not isinstance(markers, list) or any(not isinstance(marker, str) for marker in markers):
        return None, False
    return tuple(markers), True


def _trust_level(path, trust_map):
    for key in _trust_lookup_keys(path):
        if key in trust_map:
            return trust_map[key]
    return None


def _is_trusted(directory, project_root, repo_root, trust_map):
    for candidate in (directory, project_root, repo_root):
        if not candidate:
            continue
        level = _trust_level(candidate, trust_map)
        if level is not None:
            return level == "trusted"
    return False


def _project_config_dirs(cwd, markers):
    """Directories from the enclosing project root (nearest ancestor holding a
    marker) down to cwd, root first; cwd alone when no marker is found."""
    if not markers:
        return [cwd]
    chain = []
    current = cwd
    while isinstance(current, str) and current != "":
        chain.append(current)
        if any(engine.file_exists(os.path.join(current, marker)) for marker in markers):
            chain.reverse()
            return chain
        parent = os.path.dirname(current)
        if parent == current:
            return [cwd]
        current = parent
    return [cwd]


def _runtime_plugin_roots(home):
    cache_home = os.environ.get("XDG_CACHE_HOME") or os.path.join(home, ".cache")
    roots = [
        os.path.join(home, ".codex-runtimes", "codex-primary-runtime"),
        os.path.join(cache_home, "codex-runtimes", "codex-primary-runtime"),
        os.path.join(home, "Library", "Caches", "codex-runtimes", "codex-primary-runtime"),
    ]
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        roots.append(os.path.join(local_app_data, "codex-runtimes", "codex-primary-runtime"))
    return roots


def _plugin_searches(home):
    codex_home = _codex_home(home)
    cache_root = os.path.join(codex_home, "plugins", "cache")
    bundled_root = os.path.join(codex_home, ".tmp", "bundled-marketplaces", "openai-bundled")
    searches = [
        (cache_root, os.path.join(cache_root, "*", "*", "*", _PLUGIN_MANIFEST)),
        (bundled_root, os.path.join(bundled_root, "plugins*", "*", _PLUGIN_MANIFEST)),
    ]
    for runtime_root in _runtime_plugin_roots(home):
        plugins_root = os.path.join(runtime_root, "plugins")
        searches.append((plugins_root, os.path.join(plugins_root, "*", _PLUGIN_MANIFEST)))
        searches.append((plugins_root,
                         os.path.join(plugins_root, "*", "plugins", "*", _PLUGIN_MANIFEST)))
    return searches


def _real_key(path):
    return os.path.normcase(os.path.realpath(path))


def _contained(path, root):
    candidate = _real_key(path)
    boundary = _real_key(root)
    try:
        return os.path.commonpath([candidate, boundary]) == boundary
    except (OSError, ValueError):
        return False


def _plugin_manifest_paths(home):
    candidates = []
    raw_count = 0
    for rank, search in enumerate(_plugin_searches(home)):
        root, pattern = search
        for path in glob.iglob(pattern):
            raw_count += 1
            if raw_count > _MAX_PLUGIN_MANIFESTS:
                raise _PluginTierLimit()
            candidates.append((rank, path, root))

    seen = set()
    out = []
    for _rank, path, root in sorted(candidates, key=lambda item: (item[0], os.path.normcase(item[1]))):
        if not _contained(path, root) or not os.path.isfile(path):
            debug.log("codex plugin manifest invalid " + str(path))
            continue
        key = _real_key(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _read_plugin_doc(path, state):
    key = _real_key(path)
    if key in state["docs"]:
        return state["docs"][key]
    if not os.path.isfile(path):
        debug.log("codex plugin JSON is not a regular file " + str(path))
        result = (None, False)
        state["docs"][key] = result
        return result
    try:
        size = os.path.getsize(path)
    except Exception as e:
        debug.exc("codex plugin JSON size " + str(path), e)
        result = (None, False)
        state["docs"][key] = result
        return result
    if size > _MAX_PLUGIN_FILE_BYTES:
        debug.log("codex plugin JSON too large " + str(path))
        result = (None, False)
        state["docs"][key] = result
        return result
    if state["bytes"] + size > _MAX_PLUGIN_TOTAL_BYTES:
        raise _PluginTierLimit()
    state["bytes"] += size
    doc = engine.read_json(path, _MAX_PLUGIN_FILE_BYTES)
    result = (doc, engine.is_object(doc))
    state["docs"][key] = result
    return result


def _component_doc(plugin_dir, manifest, field, default_filename, state, allow_inline=False):
    if field in manifest:
        value = manifest[field]
        if allow_inline and engine.is_object(value):
            return value, True
        if not (isinstance(value, str) and value.startswith("./") and value != "./"):
            return None, False
        path = os.path.normpath(os.path.join(plugin_dir, value))
        if not _contained(path, plugin_dir) or not os.path.isfile(path):
            return None, False
        return _read_plugin_doc(path, state)

    path = os.path.join(plugin_dir, default_filename)
    if not os.path.lexists(path):
        return None, True
    if not _contained(path, plugin_dir) or not os.path.isfile(path):
        return None, False
    return _read_plugin_doc(path, state)


def _plugin_apps(doc):
    if not engine.is_object(doc):
        return {}
    apps = doc.get("apps")
    if not engine.is_object(apps):
        return {}
    out = {}
    for alias, config in apps.items():
        if not (isinstance(alias, str) and alias != "" and engine.is_object(config)):
            continue
        app_id = config.get("id")
        if isinstance(app_id, str) and app_id != "":
            out[alias] = redaction.sanitize_str(app_id)
    return out


def _plugin_artifact(manifest_path, state):
    manifest, ok = _read_plugin_doc(manifest_path, state)
    if not ok:
        return None
    name = manifest.get("name")
    version = manifest.get("version")
    if not (isinstance(name, str) and name != ""):
        debug.log("codex plugin manifest missing name " + str(manifest_path))
        return None
    if version is None:
        version = ""
    elif not isinstance(version, str):
        debug.log("codex plugin manifest invalid version " + str(manifest_path))
        return None

    plugin_dir = os.path.dirname(os.path.dirname(manifest_path))
    mcp_doc, mcp_ok = _component_doc(
        plugin_dir, manifest, "mcpServers", ".mcp.json", state, allow_inline=True)
    apps_doc, apps_ok = _component_doc(plugin_dir, manifest, "apps", ".app.json", state)
    if not mcp_ok or not apps_ok:
        debug.log("codex plugin declaration invalid " + str(manifest_path))
        return None

    content = mcp_utils.build_server_content(mcp_doc, allow_bare=True) \
        if mcp_doc is not None else {}
    apps = _plugin_apps(apps_doc)
    if apps:
        content["apps"] = apps
    if not content:
        return None
    mcp_utils.with_plugin_meta(content, name, version)
    return engine.make_artifact("plugin", "codex_plugin_json", manifest_path, content)


def _collect_plugin_artifacts(home):
    try:
        state = {"bytes": 0, "docs": {}}
        artifacts = []
        for manifest_path in _plugin_manifest_paths(home):
            try:
                artifact = _plugin_artifact(manifest_path, state)
            except _PluginTierLimit:
                raise
            except Exception as e:
                debug.exc("codex plugin " + str(manifest_path), e)
                continue
            if artifact is not None:
                artifacts.append(artifact)
        return artifacts
    except _PluginTierLimit:
        debug.log("codex plugin discovery limit exceeded; plugin tier omitted")
        return []
    except Exception as e:
        debug.exc("codex plugin discovery", e)
        return []


def collect_codex_artifacts(home, cwd):
    """(artifacts, complete) — the non-empty Codex MCP artifacts for this event
    and whether the snapshot is complete (see module docstring)."""
    if tomllib is None:
        debug.log("codex discovery: tomllib unavailable (Python < 3.11); reporting incomplete")
        return [], False

    artifacts = []
    try:
        system_path = _system_config_path()
        system_doc = None
        if system_path:
            system_doc, ok = _read_doc(system_path)
            if not ok:
                return [], False
            _append_servers(artifacts, "system", system_path, system_doc)

        user_path = os.path.join(_codex_home(home), CODEX_CONFIG_FILENAME)
        user_doc, ok = _read_doc(user_path)
        if not ok:
            return [], False
        _append_servers(artifacts, "user", user_path, user_doc)

        trust_map = _trust_map(system_doc)
        trust_map.update(_trust_map(user_doc))

        markers, ok = _project_root_markers(user_doc)
        if not ok:
            return [], False
        if markers is None:
            markers, ok = _project_root_markers(system_doc)
            if not ok:
                return [], False
        if markers is None:
            markers = _DEFAULT_PROJECT_ROOT_MARKERS

        if isinstance(cwd, str) and cwd != "":
            absolute_cwd = os.path.abspath(cwd)
            directories = _project_config_dirs(absolute_cwd, markers)
            project_root = directories[0]
            repo_root = engine.git_repository_root(absolute_cwd)
            for directory in directories:
                project_path = os.path.join(directory, ".codex", CODEX_CONFIG_FILENAME)
                if not engine.file_exists(project_path):
                    continue
                if not _is_trusted(directory, project_root, repo_root, trust_map):
                    debug.log("codex discovery: project " + str(directory) + " not trusted; skipped")
                    continue
                project_doc, ok = _read_doc(project_path)
                if not ok:
                    return [], False
                _append_servers(artifacts, "project", project_path, project_doc)
        artifacts.extend(_collect_plugin_artifacts(home))
    except Exception as e:
        debug.exc("codex discovery", e)
        return [], False

    debug.log("codex discovery: " + str(len(artifacts)) + " artifact(s), complete=True")
    return artifacts, True
