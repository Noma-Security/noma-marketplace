"""Shared, OS-portable plumbing for the Noma guardrails hook (stdlib only).

Agent-agnostic building blocks, vendored into the plugin via common/:
- ``engine`` — stdin/stdout + filesystem I/O, the ``(scope, kind, path, content)``
  artifact schema, the discoverer harness and payload assembly.
- ``redaction`` — best-effort secret masking for free-text fields.
- ``credentials`` — API-key resolution from env or the OS credential store
  (macOS Keychain / Linux libsecret / Windows Credential Manager).
- ``transport`` — POST a finished payload to the Noma hooks endpoint.

A plugin supplies a *discoverer* callable ``(home, cwd)`` returning
``(scope, kind, path, content)`` candidates and feeds it to
``engine.build_payload``. The Claude Code config conventions live with the
plugin (mcp_servers), not here, since they are agent-specific.
"""

from .redaction import sanitize_args, sanitize_str
from .engine import is_object

__all__ = [
    "sanitize_args",
    "sanitize_str",
    "is_object",
]
