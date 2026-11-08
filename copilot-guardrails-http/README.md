# Noma guardrails over HTTP hooks for GitHub Copilot

Copilot `type: "http"` hooks that POST every `userPromptSubmitted`, `preToolUse`, `postToolUse` and
`agentStop` event to `https://api.noma.security/github-copilot/v1/http-hooks`. Copilot makes the call
itself, so nothing runs on the endpoint: no Python, no scripts. Copilot's raw event has no event name, so
each hook names its event in `x-noma-hook-event-name` and sends this plugin's version, with `+http`, in
`x-noma-hook-version`.

## Setup

1. Create a Noma API key with the `github_copilot_hooks` scope and expose it to Copilot as `NOMA_API_KEY`.
   The hooks send it as `x-noma-key: Bearer ${NOMA_API_KEY}`, which TLS-inspecting proxies leave in place
   where they strip `Authorization`.
2. Install the plugin:

   ```bash
   copilot plugin marketplace add Noma-Security/noma-marketplace
   copilot plugin install guardrails-http@noma
   ```

   Or require it for the whole enterprise from `.github/copilot/managed-settings.json` in the enterprise's
   `.github-private` repo:

   ```json
   {
     "extraKnownMarketplaces": {
       "noma": { "source": { "source": "github", "repo": "Noma-Security/noma-marketplace" }, "autoUpdate": true }
     },
     "enabledPlugins": { "guardrails-http@noma": true }
   }
   ```

The same `hooks/hooks.json` also works unchanged as a repository's `.github/hooks/noma.json`.

## Behavior

- The user name and hostname come from the environment variables listed in `allowedEnvVars`; AI-DR uses
  the first non-empty value of each `|`-separated list.
- Set `NOMA_API_KEY` before enabling the plugin. With it unset or invalid the gateway answers `401`, and
  Copilot denies every tool call, because a `preToolUse` hook that gets a non-2xx or no answer fails closed.
  The same happens when the Noma endpoint is unreachable. Errors inside AI-DR are answered with allow.
- A repository's `"disableAllHooks": true` in `.github/copilot/settings.json` turns these hooks off; only
  hooks installed in `/etc/github-copilot/policy.d` by MDM are immune to it.
