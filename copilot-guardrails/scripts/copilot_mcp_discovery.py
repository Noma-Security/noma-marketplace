"""GitHub Copilot MCP discovery (user, project, plugin scopes) for the
guardrails plugin; the generic allowlist pipeline lives in common.mcp_utils.

Copilot has no managed/remote scope to collect: the enterprise MCP
registry/allowlist is GitHub-side policy the CLI enforces after a network
fetch, and local policy.d carries hooks only. --additional-mcp-config and the
built-in github-mcp-server are likewise not file-discoverable.

Project emit order is load-bearing: repo-root first, cwd last — the backend
merges same-rank artifacts last-wins, so closer-to-cwd wins.

Stdlib only, no f-strings/annotations — runs on any python3.
"""

import os
import sys

try:
    from common import engine, debug, mcp_utils
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import engine, debug, mcp_utils


# Copilot's documented manifest search order; "" is the plugin root itself.
_PLUGIN_MANIFEST_DIRS = (".plugin", "", os.path.join(".github", "plugin"), ".claude-plugin")

# The local marketplace cache location is undocumented; only these bounded
# trees are walked, never the whole home.
_MARKETPLACE_TREES = ("installed-plugins", "marketplaces")


def copilot_home(home):
    # $COPILOT_HOME replaces the entire ~/.copilot path; the dot prefix
    # survives under XDG (Copilot's documented quirk).
    override = os.environ.get("COPILOT_HOME")
    if override:
        return override
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return os.path.join(xdg_config_home, ".copilot")
    return os.path.join(home, ".copilot")


def _file_candidate(scope, kind, path, allow_bare):
    if not engine.file_exists(path):
        return []
    return [(scope, kind, path, mcp_utils.build_server_content(engine.read_json(path), allow_bare))]


def _project_dirs(cwd):
    if not isinstance(cwd, str) or cwd == "":
        return []
    try:
        chain = []
        current = os.path.abspath(cwd)
        while True:
            chain.append(current)
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        repo_root_index = 0
        for i in range(len(chain)):
            if engine.file_exists(os.path.join(chain[i], ".git")):
                repo_root_index = i
        dirs = chain[:repo_root_index + 1]
        dirs.reverse()
        return dirs
    except Exception as e:
        debug.exc("copilot project walk " + str(cwd), e)
        return []


def _plugin_manifest_dir(plugin_dir):
    # No manifest anywhere -> first candidate: plugin_candidates then reads no
    # manifest and still emits the folder-discovered mcp files, untagged.
    for manifest_dir in _PLUGIN_MANIFEST_DIRS:
        if engine.file_exists(os.path.join(plugin_dir, manifest_dir, "plugin.json")):
            return manifest_dir
    return _PLUGIN_MANIFEST_DIRS[0]


def _plugin_meta(plugin_dir, manifest_dir):
    manifest_path = os.path.join(plugin_dir, manifest_dir, "plugin.json")
    manifest = engine.read_json(manifest_path) if engine.file_exists(manifest_path) else None
    name = ""
    version = ""
    if engine.is_object(manifest):
        if isinstance(manifest.get("name"), str):
            name = manifest["name"]
        if isinstance(manifest.get("version"), str):
            version = manifest["version"]
    return name, version


def _plugin_dirs(installed_root):
    out = []
    if not os.path.isdir(installed_root):
        return out
    for marketplace in sorted(os.listdir(installed_root)):
        marketplace_dir = os.path.join(installed_root, marketplace)
        if not os.path.isdir(marketplace_dir):
            continue
        for plugin in sorted(os.listdir(marketplace_dir)):
            plugin_dir = os.path.join(marketplace_dir, plugin)
            if os.path.isdir(plugin_dir):
                out.append(plugin_dir)
    return out


def _plugin_dir_candidates(plugin_dir):
    manifest_dir = _plugin_manifest_dir(plugin_dir)
    out = mcp_utils.plugin_candidates(
        "plugin", "copilot_plugin_json", "copilot_mcp_json", plugin_dir, manifest_dir)
    # Copilot also documents .github/mcp.json inside a plugin, which
    # plugin_candidates does not scan on its own.
    name, version = _plugin_meta(plugin_dir, manifest_dir)
    for scope, kind, path, content in mcp_utils.mcp_file_candidates(
            "plugin", "copilot_mcp_json", os.path.join(plugin_dir, ".github"), allow_bare=True):
        out.append((scope, kind, path, mcp_utils.with_plugin_meta(content, name, version)))
    return out


def _discover_plugins(copilot_root):
    # Guarded for partial results: a raise would discard the other scopes'
    # candidates, and empty mcp_artifacts clears the backend's cached inventory.
    out = []
    installed_root = os.path.join(copilot_root, "installed-plugins")
    try:
        for plugin_dir in _plugin_dirs(installed_root):
            out.extend(_plugin_dir_candidates(plugin_dir))
    except Exception as e:
        debug.exc("copilot plugin walk " + installed_root, e)
    return out + _discover_marketplaces(copilot_root)


def _discover_marketplaces(copilot_root):
    out = []
    for tree in _MARKETPLACE_TREES:
        tree_root = os.path.join(copilot_root, tree)
        try:
            for current, dirs, files in os.walk(tree_root):
                dirs.sort()
                if "marketplace.json" in files:
                    out.extend(mcp_utils.marketplace_candidates(
                        "plugin", "copilot_marketplace_json", current, ""))
        except Exception as e:
            debug.exc("copilot marketplace walk " + tree_root, e)
    return out


def discover_copilot(home, cwd):
    """Return (scope, kind, path, content) MCP candidates for GitHub Copilot;
    the engine later drops any whose server map is empty."""
    copilot_root = copilot_home(home)
    candidates = []
    candidates.extend(_file_candidate(
        "user", "copilot_mcp_json", os.path.join(copilot_root, "mcp-config.json"), False))
    for directory in _project_dirs(cwd):
        candidates.extend(_file_candidate(
            "project", "copilot_github_mcp_json", os.path.join(directory, ".github", "mcp.json"), True))
        candidates.extend(_file_candidate(
            "project", "copilot_project_mcp_json", os.path.join(directory, ".mcp.json"), True))
    candidates.extend(_discover_plugins(copilot_root))

    if debug.enabled():
        for scope, kind, path, content in candidates:
            has = engine.is_object(content) and len(content) > 0
            debug.log("copilot discovery: " + scope + "/" + kind + " " + str(path) +
                      (" -> has servers" if has else " -> empty"))
    return candidates
