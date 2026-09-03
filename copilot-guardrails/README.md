# Noma Guardrails for GitHub Copilot

Runtime protection for GitHub Copilot agents: supported hook events are sent to the Noma AIDR backend for policy evaluation, and enforcement decisions are returned in Copilot's native hook response format.

The plugin uses a thin, standard-library-only Python adapter (`scripts/copilot_hook.py`) backed by the shared Noma guardrails runtime in `scripts/common/`. It runs via [`uv`](https://docs.astral.sh/uv/) on macOS, Linux, and Windows.

For more details, visit [noma.security](https://noma.security).

## Hook coverage

| Event | Data collected | Enforcement |
| --- | --- | --- |
| `userPromptSubmitted` | User prompt | Allow or block |
| `preToolUse` | Tool name and arguments | Allow, block, request interactive confirmation, or apply a validated mask |
| `postToolUse` | Tool name, arguments, and result | Allow or block |
| `agentStop` | Final assistant response | Allow or flag the detection reason |

## Prerequisites

- GitHub Copilot CLI ≥ 1.0.78 with plugin hooks
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

If `NOMA_API_KEY` is not in Copilot's process environment, on fleets provisioned for Noma MDM discovery the hook uses the ingestion key from the MDM-deployed certificate (macOS System keychain / Windows LocalMachine certificate store) and reports through `/github-copilot/v2/hooks` instead of `/github-copilot/v1/hooks`. With neither, it looks the key up in the current user's credential store.

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

- In interactive sessions, `preToolUse` ASK opens Copilot's native confirmation prompt with the Noma violation evidence. Copilot owns the available approval choices; Noma does not record the selected choice.
- `preToolUse` can deny a tool call or replace its arguments with backend-provided masked JSON after validating that the object shape and required command fields are preserved.
- `userPromptSubmitted` and `postToolUse` cannot replace content, so mask verdicts are returned as blocks.
- An `agentStop` block flags the detection reason. It cannot retract a response that Copilot has already produced.
- Missing credentials, unavailable dependencies, malformed input, and transport failures degrade quietly without interrupting Copilot.
- ASK is not supported in local headless sessions or Copilot cloud agent because no interactive user is available.

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

Do not use an ASK-enabled Noma profile with this cloud path. GitHub treats `preToolUse` ASK as deny when no user is available.

## Verification

1. Ask Copilot to perform a sensitive action, such as reading `~/.ssh/config`.
2. Open the Noma Console → Runtime Protection → Inferences.
3. Filter by `Application ID -> GitHub Copilot`.

## Troubleshooting

### Hooks are not firing

- Confirm the plugin is installed and enabled.
- Restart Copilot after installing the plugin or changing its environment.
- Confirm the Copilot CLI release is 1.0.78 or newer.

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
