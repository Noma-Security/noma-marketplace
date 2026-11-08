# Noma remote hooks for GitHub Copilot

Copilot `type: "http"` hooks that POST every `userPromptSubmitted`, `preToolUse`, `postToolUse` and
`agentStop` event to `https://api.noma.security/github-copilot/v1/hooks`. Copilot makes the call itself,
so nothing runs on the endpoint: no Python, no scripts.

## Setup

1. Create a Noma API key with the `github_copilot_hooks` scope and expose it to Copilot as `NOMA_API_KEY`.
   The hooks send it as `Authorization: Bearer ${NOMA_API_KEY}`.
2. Install the plugin:

   ```bash
   copilot plugin marketplace add Noma-Security/noma-marketplace
   copilot plugin install noma-remote-hooks@noma
   ```

   Or require it for the whole enterprise from `.github/copilot/managed-settings.json` in the enterprise's
   `.github-private` repo:

   ```json
   {
     "extraKnownMarketplaces": {
       "noma": { "source": { "source": "github", "repo": "Noma-Security/noma-marketplace" }, "autoUpdate": true }
     },
     "enabledPlugins": { "noma-remote-hooks@noma": true }
   }
   ```

The same `hooks/hooks.json` also works unchanged as a repository's `.github/hooks/noma.json`.

## Behavior

- The user name and hostname come from the environment variables listed in `allowedEnvVars`; AI-DR uses
  the first non-empty value of each `|`-separated list.
- With `NOMA_API_KEY` unset or invalid, or AI-DR unreachable, the gateway answers `{}` and Copilot carries
  on without inspection. Only an endpoint the machine cannot reach at all makes Copilot deny tool calls.
- A repository's `"disableAllHooks": true` in `.github/copilot/settings.json` turns these hooks off; only
  hooks installed in `/etc/github-copilot/policy.d` by MDM are immune to it.
