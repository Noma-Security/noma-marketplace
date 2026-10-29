"""Kiro MCP discovery (user, project, agent-profile and legacy scopes) for the
guardrails plugin; the generic allowlist pipeline lives in common.mcp_utils.

Kiro resolves MCP servers agent profile > workspace mcp.json > global mcp.json,
same server name = full override, and a workspace entry holding only
`"disabled": true` removes the global server (verified on CLI 2.32.0 V3). The
backend applies those rules; the hook only ships every file it can find, each
reduced to the allowlisted identity fields. Kiro spells the off switch
`disabled`, the shared allowlist keeps `enabled`, so it is translated before
cleaning (an entry with only `disabled: true` must survive as `enabled: false`).

Markdown agent profiles (`.kiro/agents/*.md`, YAML front matter) are not parsed:
stdlib has no YAML and the JSON form carries the same `mcpServers` field.

Kiro's enterprise MCP registry is server-side (the Kiro Profile), nothing to
collect. `KIRO_HOME` relocates the whole `~/.kiro` tree and is honoured.

Stdlib only, no f-strings/annotations - runs on any python3.
"""

import os
import sys

try:
    from common import engine, debug, mcp_utils
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import engine, debug, mcp_utils


KIND_MCP_JSON = "kiro_mcp_json"
KIND_AGENT_JSON = "kiro_agent_json"
KIND_LEGACY_MCP_JSON = "kiro_amazonq_mcp_json"
MCP_SETTINGS_RELPATH = os.path.join(".kiro", "settings", "mcp.json")


def kiro_home(home):
    override = os.environ.get("KIRO_HOME")
    if override:
        return override
    return os.path.join(home, ".kiro")


def _with_enabled(doc):
    """Translate Kiro's `disabled` flag to the allowlist's `enabled` on every
    server entry; the rest of the doc is left untouched."""
    if not engine.is_object(doc):
        return doc
    out = dict(doc)
    for wrapper in mcp_utils.MCP_WRAPPER_KEYS:
        servers = doc.get(wrapper)
        if not engine.is_object(servers):
            continue
        fixed = {}
        for name in servers:
            cfg = servers[name]
            if engine.is_object(cfg) and isinstance(cfg.get("disabled"), bool):
                cfg = dict(cfg)
                cfg["enabled"] = not cfg["disabled"]
            fixed[name] = cfg
        out[wrapper] = fixed
    return out


def _file_candidate(scope, kind, path):
    if not engine.file_exists(path):
        return []
    content = mcp_utils.build_server_content(_with_enabled(engine.read_json(path)))
    return [(scope, kind, path, content)]


def _agent_candidates(scope, agents_dir):
    # One artifact per JSON profile; the backend reads the agent name from the
    # path. Guarded for partial results so one unreadable profile cannot drop
    # the other scopes' candidates.
    out = []
    try:
        if not os.path.isdir(agents_dir):
            return out
        for filename in sorted(os.listdir(agents_dir)):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(agents_dir, filename)
            if not os.path.isfile(path):
                continue
            content = mcp_utils.build_server_content(_with_enabled(engine.read_json(path)))
            out.append((scope, KIND_AGENT_JSON, path, content))
    except Exception as e:
        debug.exc("kiro agents walk " + str(agents_dir), e)
    return out


def discover_kiro(home, cwd):
    """Return (scope, kind, path, content) MCP candidates for Kiro; the engine
    later drops any whose server map is empty."""
    root = kiro_home(home)
    candidates = []
    candidates.extend(_file_candidate("user", KIND_MCP_JSON, os.path.join(root, "settings", "mcp.json")))
    candidates.extend(_agent_candidates("user", os.path.join(root, "agents")))
    if isinstance(cwd, str) and cwd != "":
        candidates.extend(_file_candidate("project", KIND_MCP_JSON, os.path.join(cwd, MCP_SETTINGS_RELPATH)))
        candidates.extend(_agent_candidates("project", os.path.join(cwd, ".kiro", "agents")))
    candidates.extend(_file_candidate(
        "user", KIND_LEGACY_MCP_JSON, os.path.join(home, ".aws", "amazonq", "mcp.json")))

    if debug.enabled():
        for scope, kind, path, content in candidates:
            has = engine.is_object(content) and len(content) > 0
            debug.log("kiro discovery: " + scope + "/" + kind + " " + str(path) +
                      (" -> has servers" if has else " -> empty"))
    return candidates
