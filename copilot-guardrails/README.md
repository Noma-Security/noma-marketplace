# Noma Guardrails for GitHub Copilot

Runtime protection for GitHub Copilot agents: supported hook events are sent to the Noma AIDR backend for policy evaluation, and enforcement decisions are returned in Copilot's native hook response format.

The plugin uses a thin, standard-library-only Python adapter (`scripts/copilot_hook.py`) backed by the shared Noma guardrails runtime in `scripts/common/`. It runs via [`uv`](https://docs.astral.sh/uv/) on macOS, Linux, and Windows.

For more details, visit [noma.security](https://noma.security).

## Hook coverage

| Event | Data collected | Enforcement |
| --- | --- | --- |
| `userPromptSubmitted` | User prompt | Allow or block |
| `preToolUse` | Tool name and arguments | Allow, block, or apply a validated mask |
| `postToolUse` | Tool name, arguments, and result | Allow or block |
| `agentStop` | Final assistant response | Allow or flag the detection reason |

- **MCP server inventory**: on every prompt, sends the machine's Copilot MCP configuration:
  - **User scope**: `<copilot home>/mcp-config.json`, where the Copilot home is `$COPILOT_HOME` when set, else `$XDG_CONFIG_HOME/.copilot`, else `~/.copilot`.
  - **Project scope**: `.github/mcp.json` and `.mcp.json` per directory from the repository root down to the working directory.
  - **Plugin scope**: every plugin installed under `<copilot home>/installed-plugins/` (marketplace and `_direct` installs) — its `plugin.json` `mcpServers` declaration (inline map or config-file path), its `mcp.json`/`.mcp.json`/`.github/mcp.json`, and per-plugin `mcpServers` entries in cached `marketplace.json` manifests.
  - **Managed scope**: nothing is collected, by design — GitHub Copilot has no local managed MCP config file. Enterprise MCP governance (the internal registry URL and the "Registry only" allowlist) is configured in GitHub org/enterprise Copilot policy and enforced server-side by the CLI itself, so every server the CLI can actually run is already covered by the scopes above.

  Only server identity fields (`type`, `url`, `command`, `args`) are sent per server, with secret-looking values masked — `env`, `headers`, and all other fields never leave your machine.

## Prerequisites

- GitHub Copilot CLI with plugin hooks (prompt block/mask outputs require CLI ≥ 1.0.78)
- A Noma API key from your Noma Technical Account Manager
- macOS, Linux, or Windows
- [`uv`](https://docs.astral.sh/uv/) on the `PATH` of the environment that launches Copilot

## Installation

Add the Noma marketplace and install the plugin:

```bash
copilot plugin marketplace add Noma-Security/noma-marketplace
copilot plugin install guardrails@noma
```

Restart Copilot after installing.

Supported surface: the GitHub Copilot CLI. VS Code Copilot is not supported by this release.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `NOMA_API_KEY` | — | API key; falls back to the OS credential store under `noma-guardrails` |
| `NOMA_API_URL` | `https://api.noma.security` | Noma endpoint; events are posted to `<url>/github-copilot/v1/hooks` |
| `NOMA_DRYRUN` | — | Print the payload instead of sending it |
| `NOMA_DEBUG` | — | Write diagnostics to `~/.noma/copilot-guardrails-debug.log` |

### Operating system credential store

If `NOMA_API_KEY` is not in Copilot's process environment, the hook looks it up in the current user's credential store.

#### macOS

```bash
security add-generic-password -s "noma-guardrails" -a "$USER" -w
```

#### Linux

Requires `secret-tool` from libsecret:

```bash
secret-tool store --label="Noma guardrails" service noma-guardrails username "$USER"
```

#### Windows

```powershell
$key = Read-Host "Noma API key"
cmdkey /generic:noma-guardrails /user:$env:USERNAME /pass:$key
```

## Enforcement behavior

- `preToolUse` can deny a tool call or replace its arguments with backend-provided masked JSON after validating that the object shape and required command fields are preserved.
- `userPromptSubmitted` and `postToolUse` cannot replace content, so mask verdicts are returned as blocks.
- An `agentStop` block flags the detection reason. It cannot retract a response that Copilot has already produced.
- Missing credentials, unavailable dependencies, malformed input, and transport failures degrade quietly without interrupting Copilot.

## GitHub Copilot coding agent (cloud)

The Copilot coding agent (the cloud agent that works on assigned issues and pull requests) runs in GitHub's infrastructure, where this plugin's local install path does not apply. As a best-effort, repo-level option you can commit a `.github/hooks/noma.json` that points `type: "http"` hooks at the Noma endpoint directly:

```json
{
  "version": 1,
  "hooks": {
    "userPromptSubmitted": [
      {
        "type": "http",
        "url": "https://api.noma.security/github-copilot/v1/hooks",
        "headers": { "x-noma-key": "Bearer ${NOMA_API_KEY}" },
        "allowedEnvVars": ["NOMA_API_KEY"],
        "timeoutSec": 25
      }
    ]
  }
}
```

Repeat the entry for `preToolUse`, `postToolUse`, and `agentStop`, and provide `NOMA_API_KEY` as an actions secret exposed to the agent's environment. Note that the coding agent's firewall must allow-list the endpoint, and this path is unverified/best-effort — validate it in your environment before relying on it.

## Verification

1. Ask Copilot to perform a sensitive action, such as reading `~/.ssh/config`.
2. Open the Noma Console → Runtime Protection → Inferences.
3. Filter by `Application ID -> GitHub Copilot`.

## Troubleshooting

### Hooks are not firing

- Confirm the plugin is installed and enabled.
- Restart Copilot after installing the plugin or changing its environment.
- Confirm the Copilot CLI release supports plugin hooks (block/mask on prompts requires CLI ≥ 1.0.78).

### `uv` is not found

Confirm `uv --version` works in the environment that launches Copilot. Install it with `brew install uv` on macOS, `winget install astral-sh.uv` on Windows, or the supported package/install method for your Linux distribution.

### No inferences appear in Noma

- Set `NOMA_DEBUG=1` and inspect `~/.noma/copilot-guardrails-debug.log`.
- Check for `401 Unauthorized` or `403 Forbidden`, which normally indicates an invalid or expired key.
- Verify `NOMA_API_URL` if you override the default endpoint.

## Beta status

> **Note**: Noma Guardrails for GitHub Copilot is currently in **Beta**. Beta status means Noma is actively researching, iterating, and developing this feature. Based on feedback, market innovation, and technical and commercial viability, Noma may decide to suspend further work on this feature. To gain early access to a beta feature initiative, contact your Noma Technical Account Manager.

## Support

For support and access to beta features, contact your Noma Technical Account Manager.

## About Noma Security

Noma Security handles security for AI, providing comprehensive protection for AI-powered development tools and workflows.
