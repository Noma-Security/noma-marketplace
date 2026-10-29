# Noma Guardrails for Kiro

Runtime protection for Kiro agents: supported hook events are sent to the Noma AIDR backend for policy evaluation, and enforcement decisions are returned in Kiro's native hook protocol.

The plugin uses a thin, standard-library-only Python adapter (`scripts/kiro_hook.py`) backed by the shared Noma guardrails runtime in `scripts/common/`, run by the system Python, identical on macOS and Windows.

For more details, visit [noma.security](https://noma.security).

## Hook coverage

| Event | Data collected | Enforcement |
| --- | --- | --- |
| `UserPromptSubmit` | User prompt, the MCP server inventory, and the account email (see Identity) | Allow or flag: Kiro sends the prompt to the model regardless, and a block adds the detection reason to the model context |
| `PreToolUse` | Tool name and input, for built-in tools, MCP tools, and MCP tool loading | Allow, block, or request interactive confirmation |
| `PostToolUse` | Tool name, input, and result | Record only; Kiro does not act on this event |
| `Stop` | Final assistant response, read from Kiro's session store | Allow or request that Kiro continue with the detection reason |

## Prerequisites

- Kiro CLI (2.32 or newer) running the V3 agent engine — the default from Kiro CLI 3.0; on earlier releases run `kiro-cli settings chat.agentEngine v3` — or Kiro IDE 1.x
- A Noma ingestion credential: on fleets provisioned for Noma MDM discovery, the per-endpoint token or ingestion certificate the MDM deployed (no separate key needed), or an ingestion key from your Noma Technical Account Manager in `NOMA_API_KEY`. API keys are not accepted. See Credential
- macOS or Windows
- Python 3.6 or newer: `python3` on the `PATH` of the environment that launches Kiro (macOS), or an installed `python.exe` (Windows). Standard library only, no `pip` packages

## Installation

Kiro has no plugin marketplace: hooks are plain JSON files under `~/.kiro/hooks/`. Copy the plugin out of a checkout of this marketplace and install its hook file as `~/.kiro/hooks/noma.json`.

macOS:

```bash
git clone https://github.com/Noma-Security/noma-marketplace
sudo mkdir -p /usr/local/noma/guardrails
sudo cp -R noma-marketplace/kiro-guardrails /usr/local/noma/guardrails/kiro
mkdir -p ~/.kiro/hooks
cp /usr/local/noma/guardrails/kiro/hooks/hooks.json ~/.kiro/hooks/noma.json
```

To install under another directory, replace `/usr/local/noma/guardrails/kiro` in `~/.kiro/hooks/noma.json`.

Windows (PowerShell as administrator; the hook file is written without a byte-order mark). The hook command carries Python's absolute path: Kiro runs it through `cmd.exe` with the workspace as the current directory, and `cmd.exe` looks for a bare `python` there before `PATH`.

```powershell
git clone https://github.com/Noma-Security/noma-marketplace
$root = "$env:ProgramData\Noma\guardrails\kiro"
New-Item -ItemType Directory -Force (Split-Path $root) | Out-Null
Copy-Item -Recurse noma-marketplace\kiro-guardrails $root
$python = (Get-Command python.exe -CommandType Application -All -ErrorAction Stop | Where-Object Source -notlike '*\WindowsApps\*' | Select-Object -First 1).Source
if (-not $python) { throw 'install Python 3: only the Microsoft Store alias is on PATH' }
$hooks = Get-Content "$root\hooks\hooks.json" -Raw | ConvertFrom-Json
foreach ($hook in $hooks.hooks) { $hook.action.command = "`"$python`" `"$root\scripts\kiro_hook.py`" $($hook.trigger) & if errorlevel 43 (exit 0) else if errorlevel 42 (exit 2) else exit 0" }
New-Item -ItemType Directory -Force "$HOME\.kiro\hooks" | Out-Null
[System.IO.File]::WriteAllText("$HOME\.kiro\hooks\noma.json", ($hooks | ConvertTo-Json -Depth 5))
```

Every command ends in an exit-code mapping. Kiro blocks the action on any exit 2, so the hook reports a block as 42 and the command turns 42 into 2 and every other exit into 0: a hook that cannot start (Python missing, plugin moved) lets Kiro carry on instead of blocking it.

Kiro CLI reads the hook file when a session starts. Kiro IDE loads it on the next window restart and runs hooks only in a trusted workspace; it shows a "Noma Guardrails (<trigger>)" card in the chat for every hook run.

Supported surfaces: Kiro CLI with the V3 agent engine and Kiro IDE 1.x. The V2 CLI engine, Kiro Web, and cloud sessions are not supported.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `NOMA_API_KEY` | — | Ingestion key; see Credential for the fallbacks |
| `NOMA_API_URL` | `https://api.noma.security` | Noma endpoint; events are posted to `<url>/kiro/v1/hooks` |
| `NOMA_DRYRUN` | — | Print the payload instead of sending it |
| `NOMA_DEBUG` | — | Write diagnostics to `~/.noma/kiro-guardrails-debug.log` |

Kiro runs hooks with the environment of the Kiro process; set these variables where Kiro is launched.

### Identity

Every event carries the OS username and hostname. `UserPromptSubmit` also resolves the account email, and Noma attributes the session's later events to it: the signed-in Kiro account from `kiro-cli whoami` when the CLI is installed, else the same account lookup made with Kiro IDE's own sign-in (the hook reads the IDE's token from `~/.aws/sso/cache/kiro-auth-token.json` and sends it only to Kiro's management endpoint, never to Noma), else the OS directory record (`dscl` on macOS, `whoami /upn` on Windows), else the global `git config user.email`.

### Credential

The hook uses the first credential it finds:

1. An ingestion key in `NOMA_API_KEY` in Kiro's process environment, sent as is in the `x-noma-key` header
2. The per-endpoint token left by the Noma MDM discovery script (`/Library/Application Support/Noma/endpoint-token` on macOS, `%ProgramData%\Noma\endpoint-token` on Windows): a short-lived token bound to this device, sent as `x-noma-key: Bearer <token>`
3. The Noma MDM discovery ingestion certificate (macOS System keychain, then the login keychain; Windows LocalMachine, then CurrentUser certificate store), sent as is in the `x-noma-key` header

Every event goes to `/kiro/v1/hooks`. Without any of them, the hook sends nothing and Kiro runs unaffected.

## Enforcement behavior

- A `PreToolUse` block stops the tool call; Kiro shows the detection reason to the model and instructs it not to retry.
- `PreToolUse` ASK opens Kiro's native Allow/Deny prompt with the Noma violation evidence. In a non-interactive CLI session Kiro denies the call, unless the session runs with `--trust-all-tools`, which approves it.
- `UserPromptSubmit` cannot stop a prompt: Kiro sends it to the model and adds the hook's reason as context. Noma records the detection; the prompt itself still reaches the model.
- `PostToolUse` is observe-only: Kiro ignores hook output on this event.
- A `Stop` block asks Kiro to continue with the detection reason. It cannot retract a response that Kiro has already produced.
- Mask verdicts are recorded and allowed: Kiro has no channel to rewrite a prompt, a tool input, or a tool result.
- Missing credentials, unavailable dependencies, malformed input, and transport failures degrade quietly without interrupting Kiro.

## Verification

1. Ask Kiro to perform a sensitive action, such as reading `~/.ssh/config`.
2. Open the Noma Console → Runtime Protection → Inferences.
3. Filter by your Kiro application.

## Troubleshooting

### Hooks are not firing

- Kiro CLI: make the V3 engine the default (`kiro-cli settings chat.agentEngine v3`) and start a new session; the hook file is read at session start.
- Kiro IDE: trust the workspace, then restart the Kiro window.
- Confirm `~/.kiro/hooks/noma.json` is valid JSON and its `command` paths point at the installed plugin.

### Python not found / hooks never reach Noma

A hook that cannot start exits 0, so Kiro carries on and nothing reaches Noma. Run the command from `~/.kiro/hooks/noma.json` by hand to see the error:

- macOS: confirm `python3 --version` works in the environment that launches Kiro. Kiro IDE started from the Dock gets the system `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`), so `python3` there is `/usr/bin/python3`, which needs the Xcode Command Line Tools (`xcode-select --install`); to use another Python, put its absolute path in the hook commands
- Windows: confirm the `python.exe` path in each command exists. The install snippet takes the first `python.exe` on `PATH` and skips the Microsoft Store's alias under `WindowsApps`, which is not a Python; to use another Python, put its path in the commands

### No inferences appear in Noma

- Set `NOMA_DEBUG=1` and inspect `~/.noma/kiro-guardrails-debug.log`.
- Check for `401 Unauthorized` or `403 Forbidden`, which normally indicates an invalid or revoked ingestion key, or an API key used where an ingestion key is required.
- Verify `NOMA_API_URL` if you override the default endpoint.

## Beta status

> **Note**: Noma Guardrails for Kiro is currently in **Beta**. Beta status means Noma is actively researching, iterating, and developing this feature. Based on feedback, market innovation, and technical and commercial viability, Noma may decide to suspend further work on this feature. To gain early access to a beta feature initiative, contact your Noma Technical Account Manager.

## Support

For support and access to beta features, contact your Noma Technical Account Manager.

## About Noma Security

Noma Security handles security for AI, providing comprehensive protection for AI-powered development tools and workflows.
