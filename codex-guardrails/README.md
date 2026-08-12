# Noma Guardrails for Codex

Runtime protection for Codex agents: supported hook events are sent to the Noma AIDR backend for policy evaluation, and enforcement decisions are returned in Codex's native hook response format.

The plugin uses a thin, standard-library-only Python adapter (`scripts/codex_hook.py`) backed by the shared Noma guardrails runtime in `scripts/common/`. It runs on macOS, Linux, and Windows with the Noma-managed Python installation when present (deployed by the Noma fleet MDM script), falling back to the `python3`/`python` on the environment's `PATH`.

For more details, visit [noma.security](https://noma.security).

## Hook coverage

| Event | Data collected | Enforcement |
| --- | --- | --- |
| `UserPromptSubmit` | User prompt | Allow or block |
| `PreToolUse` | Tool name and input | Allow, block, or apply a validated mask |
| `PostToolUse` | Tool name, input, and response | Allow or block |
| `Stop` | Final assistant response | Allow or request that Codex continue with the detection reason |

Codex MCP access-control inventory is not part of this release.

## Prerequisites

- A current Codex CLI or ChatGPT desktop release with plugin hooks
- A Noma API key from your Noma Technical Account Manager
- macOS, Linux, or Windows
- Python 3.6+ — either the Noma-managed installation (`/usr/local/noma/python` or `~/.noma/python` on macOS/Linux, `C:\Program Files\Noma\python` or `C:\ProgramData\Noma\python` on Windows; deployed by the Noma fleet MDM script) or a `python3`/`python` on the `PATH` of the environment that launches Codex

## Installation

Add the Noma marketplace:

```bash
codex plugin marketplace add Noma-Security/noma-marketplace
```

Restart the ChatGPT desktop app, install `guardrails` from the Noma marketplace, then review and trust its hooks with `/hooks` in Codex.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `NOMA_API_KEY` | — | API key; falls back to the OS credential store under `noma-guardrails` |
| `NOMA_API_URL` | `https://api.noma.security` | Noma endpoint; events are posted to `<url>/codex/v1/hooks` |
| `NOMA_DRYRUN` | — | Print the payload instead of sending it |
| `NOMA_DEBUG` | — | Write diagnostics to `~/.noma/codex-guardrails-debug.log` |

### Operating system credential store

If `NOMA_API_KEY` is not in Codex's process environment, the hook looks it up in the current user's credential store.

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

- `PreToolUse` can deny a tool call or replace its input with backend-provided masked JSON after validating that the object shape and required command fields are preserved.
- `UserPromptSubmit` and `PostToolUse` cannot replace content, so mask verdicts are returned as blocks.
- A `Stop` block asks Codex to continue with the detection reason. It cannot retract a response that Codex has already produced.
- Missing credentials, unavailable dependencies, malformed input, and transport failures degrade quietly without interrupting Codex.

## Verification

1. Ask Codex to perform a sensitive action, such as reading `~/.ssh/config`.
2. Open the Noma Console → Runtime Protection → Inferences.
3. Filter by `Application ID -> Codex`.

## Troubleshooting

### Hooks are not firing

- Confirm the plugin is installed and enabled.
- Review and trust the current hook definition with `/hooks`.
- Restart Codex after installing the plugin or changing its environment.

### Python is not found

The hook silently does nothing when no usable Python exists. Confirm one of the Noma-managed installations listed under Prerequisites is present (ask your fleet admin to run the Noma MDM deploy script), or that `python3 --version` (or `python --version` on Windows) works in the environment that launches Codex.

### No inferences appear in Noma

- Set `NOMA_DEBUG=1` and inspect `~/.noma/codex-guardrails-debug.log`.
- Check for `401 Unauthorized` or `403 Forbidden`, which normally indicates an invalid or expired key.
- Verify `NOMA_API_URL` if you override the default endpoint.

## Beta status

> **Note**: Noma Guardrails for Codex is currently in **Beta**. Beta status means Noma is actively researching, iterating, and developing this feature. Based on feedback, market innovation, and technical and commercial viability, Noma may decide to suspend further work on this feature. To gain early access to a beta feature initiative, contact your Noma Technical Account Manager.

## Support

For support and access to beta features, contact your Noma Technical Account Manager.

## About Noma Security

Noma Security handles security for AI, providing comprehensive protection for AI-powered development tools and workflows.
