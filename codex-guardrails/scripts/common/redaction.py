"""Best-effort masking of secret-looking substrings.

Vendor-agnostic. Direction of safety: over-redaction is acceptable, leaking is
not. Pattern order is intentional (substitutions run in sequence) and the tests
pin the exact output, so keep it stable. Stdlib only; no f-strings/walrus/
annotations so it runs on any python3.
"""

import re

REDACTED = "***REDACTED***"

# Ordered substring patterns applied to every free-text field (url/command/args),
# one per secret shape we recognize:
_KEY_VALUE_RE = re.compile(  # <name>=<value> where the name looks sensitive
    r"([A-Za-z0-9_-]*(?:token|secret|password|passwd|api[_-]?key|apikey"
    r"|access[_-]?key|credential|auth)[A-Za-z0-9_-]*)=([^ \t]+)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r'bearer[ \t]+[^ \t"]+', re.IGNORECASE)  # Bearer <token>
_VCS_TOKEN_RE = re.compile(  # GitHub / GitLab tokens
    r"\b(?:github_pat_|ghp_|gho_|ghu_|ghs_|ghr_|glpat-)[A-Za-z0-9_-]+"
)
_SK_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")  # OpenAI-style sk- keys
_SLACK_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]+")  # Slack tokens
_AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")  # AWS access key IDs
# JWTs (header.payload.signature):
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{14,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
# user:password@ embedded in a URL:
_URL_USERINFO_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@ \t]+:[^/@ \t]+@")


def sanitize_str(s):
    """Mask secret-looking substrings inside a single string."""
    s = _KEY_VALUE_RE.sub(lambda m: m.group(1) + "=" + REDACTED, s)
    s = _BEARER_RE.sub("Bearer " + REDACTED, s)
    s = _VCS_TOKEN_RE.sub(REDACTED, s)
    s = _SK_RE.sub(REDACTED, s)
    s = _SLACK_RE.sub(REDACTED, s)
    s = _AWS_RE.sub(REDACTED, s)
    s = _JWT_RE.sub(REDACTED, s)
    s = _URL_USERINFO_RE.sub(lambda m: m.group(1) + REDACTED + "@", s)
    return s


# A flag is "secret" when its name contains a sensitive keyword; the value that
# follows it is dropped wholesale (over-redaction by design).
_SECRET_FLAG_RE = re.compile(
    r"^--?[A-Za-z0-9_-]*(?:token|secret|password|passwd|api[-_]?key|apikey"
    r"|access[-_]?key|credential|auth|pat)[A-Za-z0-9_-]*$",
    re.IGNORECASE,
)


def sanitize_args(args):
    """Mask an argv list: drop values after secret flags, sanitize the rest."""
    out = []
    for i in range(len(args)):
        prev = args[i - 1] if i > 0 else None
        if isinstance(prev, str) and _SECRET_FLAG_RE.match(prev):
            out.append(REDACTED)
        elif isinstance(args[i], str):
            out.append(sanitize_str(args[i]))
        else:
            out.append(args[i])
    return out
