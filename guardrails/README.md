# Noma Security - Claude Code Hooks Plugin

**Runtime Protection for Claude Code Agents**

Noma Security provides active runtime protection for Claude Code by sitting between your AI agents and their intended actions. This plugin enables you to evaluate, allow, or block high-risk activities in real-time.

For more details, visit [noma.security](https://noma.security).

## What We Protect

With Claude Code Hooks enabled, Noma acts as a security gatekeeper for the following high-risk agent actions:

- **Shell execution**: Prevent unauthorized terminal commands or malicious script injections
- **MCP tool execution**: Governs Model Context Protocol interactions and unauthorized tool use
- **MCP server inventory** (all platforms): On every prompt, sends the MCP server configuration files. Only server identity fields (`type`, `url`, `command`, `args`) are sent per server, with secret-looking values masked — `env`, `headers`, and all other fields never leave your machine. Built in dependency-free Python (standard library only) and run via `uv`, so it behaves identically on macOS, Linux, and Windows
- **File reads**: Protects sensitive local data (e.g., `.env` files, SSH keys) from being indexed or sent to the LLM
- **User prompt submission**: Scans and filters sensitive data, PCI, PII, PHI before it leaves your local environment

## Prerequisites

- **Claude Code v2.0.12+**: Ensure you are running a supported version of the CLI
- **Noma API Key**: Request an API Key for this plugin from your Noma Technical Account manager (Note: This is not an API Key that you create within the Noma Console)
- **Supported OS**: macOS, Linux, or Windows — one plugin, identical behavior on all three
- **[`uv`](https://docs.astral.sh/uv/)**: the hooks run via `uv` (Astral's Python runner), which supplies the Python the hook needs — no system `python3` or `pip` packages required. `uv` must be on the `PATH` of the environment Claude Code launches hooks in

## Installation

### Step 1: Add the Noma Marketplace

Add the Noma marketplace to your Claude Code instance:

```bash
claude plugin marketplace add https://github.com/Noma-Security/noma-marketplace
```

### Step 2: Install the Guardrails Plugin

One cross-platform plugin covers macOS, Linux, and Windows:

```bash
claude plugin install guardrails@noma
```

The hooks run a single Python entry point (`scripts/hook.py`) via `uv`, so the runtime and credential handling are identical on every OS.

## Configuration

To connect Claude Code to your Noma instance, you need to configure the `NOMA_API_KEY`.

### Option A: Managed Settings (Recommended for Teams)

If your organization manages Claude Code usage via a centralized `settings.json`, your administrator can push these configurations directly:

1. Navigate to your organization's Claude management console
2. In the Managed settings section, update the `settings.json` to include the Noma environment variables **and the settings required for the plugin installation** — the Noma marketplace and the enabled plugin — so the plugin is installed and enabled for every user automatically:

```json
{
  "env": {
    "NOMA_API_KEY": "your-secret-api-key"
  },
  "extraKnownMarketplaces": {
    "noma": {
      "source": {
        "source": "github",
        "repo": "Noma-Security/noma-marketplace"
      }
    }
  },
  "enabledPlugins": {
    "guardrails@noma": true
  }
}
```

With these settings pushed, users skip the manual `claude plugin marketplace add` / `claude plugin install` steps above.

On macOS and Linux, the `env` block is optional: if the API key is provisioned in the OS credential store instead (see Option C — e.g. seeded by your MDM at deploy time), the managed settings only need `extraKnownMarketplaces` and `enabledPlugins`. On Windows the credential store is not supported at the moment, so the key must be delivered via the `env` block.

### Option B: Local Environment

For individual setups, instead of exporting variables in your shell profile, Claude Code reads configurations from a local JSON file. This mirrors the structure used in the Managed Settings method.

To configure your local environment, add your Noma credentials to the following path: ~/.claude/settings.json
Claude Code injects everything under the `env` key into the hook's environment. Example settings.json structure:

```json
{
  "env": {
    "NOMA_API_KEY": "your-secret-api-key"
  }
}
```

### Option C: Operating System Credential Store (macOS & Linux, Most Secure Local)

If `NOMA_API_KEY` is not set via env var or `settings.json`, the hook scripts will look it up from the OS credential store: the Keychain on macOS, or libsecret / GNOME Keyring (`secret-tool`) on Linux. The key is encrypted at rest by the OS and bound to your user account. This option is not supported on Windows — use Option A or B there.

Store the key once:

```bash
# macOS — -w with no value prompts for the key, so it never lands in your shell history
security add-generic-password -s "noma-guardrails" -a "$USER" -w

# Linux — secret-tool prompts for the key (requires libsecret / GNOME Keyring)
secret-tool store --label="Noma guardrails" service noma-guardrails username "$USER"
```

The `guardrails` plugin retrieves it via `security find-generic-password` (macOS) or `secret-tool lookup` (Linux) at hook fire time.

## Activation

### Initialize and Approve Hooks

Once the plugin and settings are in place, authorize the managed settings within Claude Code:

1. **Launch Claude Code**: Start a new session
2. **Approve Managed Settings**: You'll see a prompt regarding "Managed settings require approval." This is a security feature to ensure you trust the configured API endpoints
3. **Select 1.** Yes, I trust these settings to proceed

If you installed the plugin during an active session, refresh the state:

```bash
/reload-plugins
```

## Verification

To confirm that Noma is actively protecting your session:

1. **Test an action**: Ask Claude Code to perform a sensitive task, such as "Read the contents of my ~/.ssh/config file"
2. **Check Noma Console**: Navigate to Runtime Protection → Sessions in the Noma Console
3. Filter by `Application ID -> Claude-Code` to see real-time allow/block events

Look for Debug mode indicators and status bar labels to confirm protection is active.

## Troubleshooting

### Hooks are not firing

- **Check Plugin Status**: Run `claude plugin list` to ensure `guardrails@noma` is listed and active
- **Restart or Reload**: Always run `/reload-plugins` after making changes to your plugin configuration. Restart Claude after every environment variable change
- **Note**: Changes in the team panel may take a few minutes to be applied

### `uv` not found / hooks fail to launch

The hooks run via `uv run`. If hook events error with something like `uv: command not found`:

- Confirm `uv` is installed and on the `PATH` of the environment Claude Code launches hooks in (`uv --version`). Install it with `brew install uv` (macOS), `winget install astral-sh.uv` (Windows), `curl -LsSf https://astral.sh/uv/install.sh | sh` (Linux), or your MDM
- On a machine with no Python and no network, the first hook can be slow while `uv` provisions a Python — possibly exceeding the hook timeout. Pre-seed one with `uv python install` (your fleet's MDM can do this at deploy time)

### NOMA_API_KEY not found

The hook scripts look up the key in this order — first match wins:

1. Environment variable `NOMA_API_KEY`
2. `~/.claude/settings.json` (`env.NOMA_API_KEY`)
3. OS credential store (macOS Keychain / Linux libsecret): entry with service `noma-guardrails`

If none are configured, the hook silently sends nothing — by design it never interrupts your Claude Code session. Configure a key using one of the methods in the [Configuration](#configuration) section above. To confirm key resolution, set `NOMA_DEBUG=1` and check `~/.noma/claude-code-guardrails-debug.log`.

### Managed settings are not appearing

- **Verify JSON Schema**: Ensure your `settings.json` follows the correct Claude Code schema. Invalid syntax will cause the CLI to ignore managed settings
- **Auth Check**: Ensure you are logged into the correct Claude organization using `claude auth status`

### No inferences in Noma

- **API Key Validation**: Check the Claude Code debug logs (found at the path shown during startup) for any `401 Unauthorized` or `403 Forbidden` errors related to Noma

## Beta Status

> **Note**: Claude Code Hooks is currently in **Beta** status. Beta status means Noma is actively researching, iterating, and developing this feature. Based on feedback, market innovation, and technical and commercial viability, Noma may decide to suspend further work on this feature. To gain early access to a beta feature initiative, contact your Noma Technical Account Manager.

## Support

For support and access to beta features, contact your Noma Technical Account Manager.

## About Noma Security

Noma Security handles security for AI, providing comprehensive protection for AI-powered development tools and workflows.