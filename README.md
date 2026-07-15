# Noma Security Marketplace

> Runtime protection for AI coding agents: every prompt, shell command, MCP call, and file
> access your agent makes is evaluated by the [Noma](https://noma.security) AIDR platform
> in real time — allow, block, or flag, with full visibility in the Noma Console.

Noma Security sits between your AI agents and their intended actions. The plugins in this
marketplace hook into each agent framework's native extension points and stream hook
events to the Noma backend for policy evaluation, returning enforcement decisions to the
agent. One stdlib-only Python implementation, identical behavior on macOS, Linux, and
Windows.

## Available Plugins


| Plugin       | Agent                                         | Docs                                                       |
| ------------ | --------------------------------------------- | ---------------------------------------------------------- |
| `guardrails` | [Claude Code](https://claude.com/claude-code) | [guardrails/README.md](guardrails/README.md)               |
| `guardrails` | [Cursor](https://cursor.com)                  | [cursor-guardrails/README.md](cursor-guardrails/README.md) |



## What We Protect

- **User prompts** — scan for sensitive data (PCI, PII, PHI) before it leaves your machine
- **Shell execution** — evaluate terminal commands before they run
- **MCP tool execution** — govern Model Context Protocol interactions and unauthorized tool use
- **MCP server inventory** — report the agent's configured MCP servers per scope for organization-level access control (identity fields only, secrets masked)
- **File reads and edits** — protect sensitive local data (`.env` files, SSH keys) from being indexed or exfiltrated
- **Agent responses** — track what the agent returns

The exact hook coverage per agent is listed in each plugin's README.

## Quick Start


### Claude Code

```bash
claude plugin marketplace add https://github.com/Noma-Security/noma-marketplace
claude plugin install guardrails@noma
```

→ [Full Claude Code setup, configuration, and troubleshooting](guardrails/README.md)

### Cursor

The Cursor plugin follows [Cursor's plugin spec](https://cursor.com/docs/plugins)
(`.cursor-plugin/marketplace.json` at the repo root). Marketplace publication is in
progress; installation details live in the plugin README.

→ [Full Cursor setup and configuration](cursor-guardrails/README.md)

## Configuration

All plugins share the same configuration surface:


| Variable       | Default                     | Description                                                                                                                             |
| -------------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `NOMA_API_KEY` | —                           | API key; falls back to the OS credential store (service `noma-guardrails`: macOS Keychain, Linux libsecret, Windows Credential Manager) |
| `NOMA_API_URL` | `https://api.noma.security` | Noma endpoint                                                                                                                           |
| `NOMA_DRYRUN`  | —                           | print the payload instead of sending (testing)                                                                                          |
| `NOMA_DEBUG`   | —                           | diagnostic trace to a rotated per-user log file (never secrets)                                                                         |


## Design Principles

- **Fail open, degrade quietly** — a hook must never break or slow the user's session: any failure (no key, no network, bad input) exits clean without emitting a decision, leaving the agent's default behavior in place
- **No dependencies** — Python standard library only, run via `[uv](https://docs.astral.sh/uv/)`; no `pip`, works on any Python 3
- **Least data** — events are enriched with hostname/username only; MCP inventory ships server identity fields exclusively, with secret-looking values masked
- **Bounded execution** — every hook, HTTP call, and credential lookup carries a timeout


## Prerequisites

- A supported agent (see the plugin READMEs for minimum versions)
- `[uv](https://docs.astral.sh/uv/)` on the `PATH` the agent launches hooks with (`brew install uv`, `winget install astral-sh.uv`, or your fleet's MDM)
- A Noma API key


## Verification

1. Ask the agent to perform a sensitive action (e.g. "Read my ~/.ssh/config")
2. Open the Noma Console → Runtime Protection → Inferences
3. Filter by your application to see real-time allow/block events


## Support

For support and access to beta features, contact your Noma Technical Account Manager.

## About Noma Security

Noma Security handles security for AI, providing comprehensive protection for AI-powered
development tools and workflows. Learn more at [noma.security](https://noma.security).