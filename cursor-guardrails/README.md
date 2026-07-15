# Noma Guardrails for Cursor

Runtime protection for the Cursor IDE agent: every hook event (prompts, shell commands, MCP calls, file reads/edits) is sent to the Noma AIDR backend for policy evaluation, and the server's decision is returned to Cursor as the permission verdict.

One stdlib-only Python entry point (`scripts/hook.py`) run via [`uv`](https://docs.astral.sh/uv/), identical on macOS, Linux, and Windows.

For more details, visit [noma.security](https://noma.security).

## What we protect

- **Shell execution**: prevent unauthorized terminal commands or malicious script injections
- **MCP tool execution**: governs Model Context Protocol interactions and unauthorized tool use
- **File reads**: protects sensitive local data (e.g., `.env` files, SSH keys) from being indexed or sent to the LLM
- **User prompt submission**: scans and filters sensitive data, PCI, PII, PHI before it leaves your local environment
- **Everything else the agent does**: other tool calls are gated via Cursor's generic pre-tool-use hook, and post-action telemetry (tool outputs, file edits, assistant responses) streams to Noma for detection and visibility

## Prerequisites

- Cursor with plugin support
- **Noma API Key**: request one for this plugin from your Noma Technical Account Manager (this is not an API Key you create within the Noma Console)
- **Supported OS**: macOS, Linux, or Windows — one plugin, identical behavior on all three
- [`uv`](https://docs.astral.sh/uv/) on the `PATH` Cursor launches hooks with — `uv` supplies the Python the hook needs; no system `python3` or `pip` packages required

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NOMA_API_KEY` | — | API key; falls back to the OS credential store (service `noma-guardrails`: macOS Keychain, Linux libsecret, Windows Credential Manager) |
| `NOMA_API_URL` | `https://api.noma.security` | Noma endpoint; events POST to `<url>/cursor/v1/hooks` |
| `NOMA_DRYRUN` | — | print the payload instead of sending (testing) |
| `NOMA_DEBUG` | — | trace to `~/.noma/cursor-guardrails-debug.log` (diagnostics only, never secrets) |

### Storing the API key in the OS credential store

If `NOMA_API_KEY` is not set in the environment Cursor runs with, the hook looks it up in your operating system's built-in credential store. The key is encrypted at rest by the OS and bound to your user account.

#### macOS — Keychain

```bash
# -w with no value prompts for the key, so it never lands in your shell history
security add-generic-password -s "noma-guardrails" -a "$USER" -w
```

#### Linux — libsecret / GNOME Keyring

Requires `secret-tool` (package `libsecret-tools` on Debian/Ubuntu, `libsecret` on Fedora):

```bash
secret-tool store --label="Noma Guardrails" service noma-guardrails username "$USER"
# secret-tool will prompt for the API key
```

#### Windows — Credential Manager

```powershell
# Read-Host keeps the key out of your PowerShell history
$key = Read-Host "Noma API key"
cmdkey /generic:noma-guardrails /user:$env:USERNAME /pass:$key
```

The hook retrieves the key at fire time (`security find-generic-password`, `secret-tool lookup`, or the Windows `CredRead` API via Python's `ctypes`, respectively).

## Troubleshooting

### Hooks are not firing

- Verify the plugin is installed and enabled in Cursor's plugin settings
- Restart Cursor after installing the plugin or changing hook configuration — `hooks.json` is read at startup
- Remember the hook is **silent by design**: for clean events Cursor shows nothing; confirm activity in the Noma Console (see Verification below) or with `NOMA_DEBUG=1`

### `uv` not found / hooks fail to launch

The hooks run via `uv run`. If hook executions fail to start:

- Confirm `uv` is installed (`uv --version`) — `brew install uv`, `winget install astral-sh.uv`, or your fleet's MDM
- Make sure `uv` is on the `PATH` of the environment **Cursor launches hooks with**. Cursor is a GUI app: on macOS it may not inherit your shell profile's `PATH`, so a `uv` that works in your terminal can still be invisible to Cursor. Launching Cursor from the terminal (`cursor .`) picks up your shell environment
- On a machine with no Python and no network, the first hook can be slow while `uv` provisions an interpreter — possibly exceeding the 30s hook timeout. Pre-seed one with `uv python install`

### NOMA_API_KEY not found

The hook resolves the key in this order — first match wins:

1. Environment variable `NOMA_API_KEY` (in Cursor's process environment)
2. OS credential store entry `noma-guardrails` (see Configuration above)

With no key the hook sends nothing and stays silent (fail-open). Set `NOMA_DEBUG=1` and check `~/.noma/cursor-guardrails-debug.log` to see which lookup steps ran.

### Events fire but nothing is blocked

- Fail-open means any failure (backend unreachable, empty response) silently allows the action — check the debug log for `POST failed` entries
- Run the hook manually to inspect the payload without sending:

  ```bash
  echo '{"hook_event_name":"beforeShellExecution","command":"ls"}' | \
      NOMA_DRYRUN=1 uv run --no-project scripts/hook.py
  ```

### No inferences in Noma

- Check the debug log (`NOMA_DEBUG=1`) for `401 Unauthorized` / `403 Forbidden` errors — usually an invalid or expired API key
- Verify `NOMA_API_URL` points at your Noma instance if you override it

## Verification

1. Ask the Cursor agent to perform a sensitive action, such as "Read the contents of my ~/.ssh/config file"
2. Open the Noma Console → Runtime Protection → Inferences
3. Filter by `Application ID -> Cursor` to see real-time allow/block events

## Beta status

> **Note**: Noma Guardrails for Cursor is currently in **Beta**. Beta status means Noma is actively researching, iterating, and developing this feature. Based on feedback, market innovation, and technical and commercial viability, Noma may decide to suspend further work on this feature. To gain early access to a beta feature initiative, contact your Noma Technical Account Manager.

## Support

For support and access to beta features, contact your Noma Technical Account Manager.

## About Noma Security

Noma Security handles security for AI, providing comprehensive protection for AI-powered development tools and workflows.
