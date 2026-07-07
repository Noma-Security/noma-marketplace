#!/usr/bin/env python3
"""Claude Code MCP discovery for the guardrails plugin.

The Claude Code specifics (which files at which scopes) live here; the generic
engine (redaction, allowlist, artifact schema, I/O) lives in the vendored
common package. The discoverer is imported by hook.py on UserPromptSubmit.

Stdlib only, no f-strings/annotations — runs on any python3.
"""

import os
import sys

try:
    from common import engine, debug
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import engine, debug

# Claude-Code-specific config logic; a sibling script in this plugin (not part of
# the generic vendored package). The bootstrap above put scripts/ on the path,
# making both `common` and this module's siblings importable.
import mcp_servers as servers


# Enterprise-deployed config by OS (macOS, Linux, Windows) — the first path that
# exists wins. Windows uses %PROGRAMDATA% (system-wide, drive-independent) under
# ClaudeCode/. Module-level so tests can repoint them.
_PROGRAMDATA = os.environ.get("PROGRAMDATA") or "C:\\ProgramData"

MANAGED_MCP_PATHS = [
    "/Library/Application Support/ClaudeCode/managed-mcp.json",     # macOS
    "/etc/claude-code/managed-mcp.json",                           # Linux
    os.path.join(_PROGRAMDATA, "ClaudeCode", "managed-mcp.json"),  # Windows
]
MANAGED_SETTINGS_PATHS = [
    "/Library/Application Support/ClaudeCode/managed-settings.json",     # macOS
    "/etc/claude-code/managed-settings.json",                          # Linux
    os.path.join(_PROGRAMDATA, "ClaudeCode", "managed-settings.json"),  # Windows
]


# --- plugin manifests --------------------------------------------------------
# Claude Code resolves a plugin's manifest at .claude-plugin/plugin.json (the
# only supported location). These helpers keep that path in one place.

def _plugin_manifest_path(install_path):
    """Path to the plugin manifest, or None if it does not exist."""
    path = os.path.join(install_path, ".claude-plugin", "plugin.json")
    return path if engine.file_exists(path) else None


def _manifest_field(install_path, field):
    """A string field from the plugin manifest, or "" when absent."""
    manifest = engine.read_json(os.path.join(install_path, ".claude-plugin", "plugin.json"))
    if servers.is_object(manifest) and isinstance(manifest.get(field), str):
        return manifest[field]
    return ""


# --- discovery helpers -------------------------------------------------------

def _first_existing(paths):
    """The first path in the list that exists on disk, or None."""
    for path in paths:
        if engine.file_exists(path):
            return path
    return None


# Path module for comparisons only (filesystem access stays on os.path).
# Module-level so tests can repoint it to ntpath and exercise the Windows
# comparison semantics on any host.
_PATH_CMP = os.path


def _project_root(cwd):
    r"""The directory Claude Code treats as the project root for this cwd.

    Claude Code keys project config by the enclosing git repository root, not
    the launch directory: a session started in <repo>\plugins still loads the
    .claude.json projects entry and .mcp.json of <repo>, and never creates a
    projects entry for the subdirectory. Looking these up under the raw cwd
    therefore silently drops every project-scoped server when the session
    starts below the root. Walk up from cwd to the first directory holding a
    .git entry (a directory normally, a file for worktrees/submodules); for a
    linked worktree the main checkout is the root Claude Code keys by, so its
    resolution wins (see _worktree_main_root). When no repository encloses
    cwd, Claude Code uses cwd itself, so it is returned unchanged.
    """
    current = cwd
    while isinstance(current, str) and current != "":
        if engine.file_exists(os.path.join(current, ".git")):
            main_root = _worktree_main_root(current)
            return main_root if main_root else current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return cwd


def _worktree_main_root(root):
    """The main checkout enclosing a linked-worktree root, or None.

    A linked worktree's .git is a file redirecting to the repository's common
    git dir: "gitdir: <main>/.git/worktrees/<name>". Claude Code follows that
    redirect and keys the worktree's project config by <main>, so <main> IS
    the project root whenever it resolves. Only the worktree layout is
    followed — a submodule's redirect points at .git/modules/<name> and stays
    its own project — and a dangling redirect (main checkout gone) returns
    None so the caller degrades to the worktree root itself.
    """
    git_entry = os.path.join(root, ".git")
    if os.path.isdir(git_entry) or not engine.file_exists(git_entry):
        return None
    try:
        with open(git_entry, "r") as f:
            redirect = f.readline().strip()
    except Exception as e:
        debug.exc("worktree gitdir read " + str(git_entry), e)
        return None
    if not redirect.startswith("gitdir:"):
        return None
    git_dir = redirect[len("gitdir:"):].strip()
    if git_dir == "":
        return None
    if not os.path.isabs(git_dir):
        git_dir = os.path.normpath(os.path.join(root, git_dir))
    worktrees_dir = os.path.dirname(git_dir)
    if os.path.basename(worktrees_dir) != "worktrees":
        return None
    if not engine.file_exists(git_dir):
        return None
    return os.path.dirname(os.path.dirname(worktrees_dir))


def _same_path(left, right):
    r"""True when two spellings name the same directory.

    On Windows one directory has many valid spellings, and the two sides of
    our lookups really do spell it differently: Claude Code keys .claude.json
    projects (and plugin projectPath) with forward slashes
    (C:/Users/x/proj) while the hook's cwd arrives from the OS with
    backslashes (C:\Users\x\proj); case may differ too. Comparing them as raw
    strings therefore reports "project not in config" and silently drops its
    servers from the inventory. normpath folds the separators, normcase the
    casing; both are no-ops on POSIX.
    """
    return (_PATH_CMP.normcase(_PATH_CMP.normpath(left)) ==
            _PATH_CMP.normcase(_PATH_CMP.normpath(right)))


def _mcp_file_candidate(scope, path):
    """A candidate for a dedicated MCP file (mcp.json / .mcp.json)."""
    return (scope, "claude_mcp_json", path,
            servers.server_content(engine.read_json(path)))


def _project_entry(projects, project_root):
    """The projects[...] entry for one candidate root, or {} when absent."""
    entry = projects.get(project_root)
    if not servers.is_object(entry):
        # An exact-key miss does not mean the project is absent: on Windows
        # the key and the root spell the same directory differently (see _same_path).
        for project_key in projects:
            if isinstance(project_key, str) and _same_path(project_key, project_root):
                entry = projects[project_key]
                break
    return entry if servers.is_object(entry) else {}


def _claude_json_candidates(home, project_root):
    """User- and local-scope servers from ~/.claude.json.

    The file's top level holds unrelated, sensitive state (prompts, tokens,
    metrics), so only the server maps are taken, never the whole file:
      - user  scope: the top-level mcpServers/servers block only
      - local scope: projects[project_root].mcpServers/servers only
    """
    path = os.path.join(home, ".claude.json")
    doc = engine.read_json(path)
    if not servers.is_object(doc):
        return []

    candidates = [("user", "claude_json", path, servers.server_content(doc))]

    projects = doc.get("projects")
    if not servers.is_object(projects):
        projects = {}
    entry = _project_entry(projects, project_root)
    candidates.append(("local", "claude_json", path, servers.server_content(entry)))
    return candidates


def _discover_plugins(home, project_root):
    """One set of artifacts per installed plugin active for this project."""
    out = []
    registry = engine.read_json(os.path.join(home, ".claude", "plugins", "installed_plugins.json"))
    if not (servers.is_object(registry) and servers.is_object(registry.get("plugins"))):
        return out
    plugins = registry["plugins"]
    for plugin_key in plugins:
        installs = plugins[plugin_key]
        if not isinstance(installs, list):
            continue
        for install in installs:
            if not servers.is_object(install):
                continue
            # A "local"-scoped install applies only to its own project.
            if install.get("scope") == "local":
                project_path = install.get("projectPath")
                if not (isinstance(project_path, str) and _same_path(project_path, project_root)):
                    continue
            install_path = install.get("installPath")
            if not isinstance(install_path, str) or install_path == "":
                continue

            # Full manifest: metadata + inline mcpServers (cleaned). Manifest
            # mcpServers are additive to .mcp.json, so both are emitted.
            manifest_path = _plugin_manifest_path(install_path)
            if manifest_path:
                out.append((
                    "plugin", "claude_plugin_json", manifest_path,
                    servers.manifest_content(engine.read_json(manifest_path)),
                ))

            # Dedicated server file, tagged with the plugin's manifest name +
            # version (the backend needs the name to parse mcp__plugin_<name>_*
            # tool calls; the version is reported alongside it). Parsed with the
            # plugin-shape extractor: marketplace plugins ship this file as a
            # bare {name: config} map, without the mcpServers wrapper.
            mcp_file = os.path.join(install_path, ".mcp.json")
            if engine.file_exists(mcp_file):
                out.append((
                    "plugin", "claude_mcp_json", mcp_file,
                    servers.with_plugin_meta(
                        servers.plugin_server_content(engine.read_json(mcp_file)),
                        _manifest_field(install_path, "name"),
                        _manifest_field(install_path, "version")),
                ))
    return out


def discover_claude_code(home, cwd):
    """Return (scope, kind, path, content) MCP candidates for Claude Code.

    One candidate per known config location; the engine later drops any whose
    server map is empty. Project-scoped lookups use the enclosing git root,
    not the raw cwd — for a linked worktree, the main checkout's root
    (see _project_root). Sources by scope:
      user / local : ~/.claude.json          (servers only; also holds secrets)
      user         : ~/.claude/mcp.json
      project      : <project root>/.mcp.json
      plugin       : each installed plugin's manifest + .mcp.json
      managed      : enterprise managed-mcp.json / managed-settings.json
      remote       : server-pushed ~/.claude/remote-settings.json
    """
    root = _project_root(cwd)
    if root != cwd:
        debug.log("discovery: project root " + str(root) + " (cwd " + str(cwd) + ")")

    candidates = []
    candidates.extend(_claude_json_candidates(home, root))
    candidates.append(_mcp_file_candidate("user", os.path.join(home, ".claude", "mcp.json")))
    candidates.append(_mcp_file_candidate("project", os.path.join(root, ".mcp.json")))
    candidates.extend(_discover_plugins(home, root))

    # Managed MCP config (enterprise-deployed); first existing path wins.
    managed_mcp = _first_existing(MANAGED_MCP_PATHS)
    if managed_mcp:
        candidates.append(("managed", "claude_managed_mcp_json", managed_mcp,
                           servers.server_content(engine.read_json(managed_mcp))))

    # Settings files hold unrelated/secret state, so only their mcpServers/servers
    # block is taken, never the whole file. Server-pushed "remote" settings
    # outrank enterprise "managed" settings.
    remote_settings = os.path.join(home, ".claude", "remote-settings.json")
    candidates.append(("remote", "claude_settings_json", remote_settings,
                       servers.server_content(engine.read_json(remote_settings))))

    managed_settings = _first_existing(MANAGED_SETTINGS_PATHS)
    if managed_settings:
        candidates.append(("managed", "claude_settings_json", managed_settings,
                           servers.server_content(engine.read_json(managed_settings))))

    if debug.enabled():
        for scope, kind, path, content in candidates:
            has = engine.is_object(content) and len(content) > 0
            debug.log("discovery: " + scope + "/" + kind + " " + str(path) +
                      (" -> has servers" if has else " -> empty"))
        debug.log("discovery: " + str(len(candidates)) + " candidate(s) before empty-drop")

    return candidates
