"""HTTP transport to the Noma guardrails hooks endpoint.

``post()`` ships a finished payload string to the backend, or prints it (and
sends nothing) when NOMA_DRYRUN is set. It sends through the OS-native client the
MDM scripts use, falling back to urllib (see http_senders). OS-portable, stdlib
only, no f-strings/annotations - runs on any python3.
"""

import json
import os
import re
import sys
import time
import urllib.parse

from . import debug, http_senders, installed_config

TIMEOUT_SECONDS = 10
# Both attempts share one budget so they fit the 25s hook timeout the manifests set.
BUDGET_SECONDS = 2 * TIMEOUT_SECONDS
MIN_ATTEMPT_SECONDS = 1
DEFAULT_API_URL = "https://api.noma.security"
NOMA_DOMAIN = "noma.security"
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
_HOST = re.compile(r"[a-z0-9.-]+")
_HOOKS_PATH = re.compile(r"(/[A-Za-z0-9._~-]*)+")


def _allowed_api_url(url):
    """https on a Noma host, or http(s) on loopback; no credentials, query or fragment."""
    if "\\" in url or any(c.isspace() or ord(c) < 32 for c in url):
        return False
    try:
        parts = urllib.parse.urlsplit(url)
        parts.port  # raises on a bad port
    except ValueError:
        return False
    host = parts.hostname or ""
    if parts.username is not None or parts.query or parts.fragment or (host != "::1" and not _HOST.fullmatch(host)):
        return False
    if host in LOOPBACK_HOSTS:
        return parts.scheme in ("http", "https")
    return parts.scheme == "https" and (host == NOMA_DOMAIN or host.endswith("." + NOMA_DOMAIN))


def api_url():
    """NOMA_API_URL when the installed config set it or it is allowed (_allowed_api_url), else
    the default: a repo's agent settings can inject env, and must not redirect the hooks' key and events."""
    url = os.environ.get("NOMA_API_URL") or DEFAULT_API_URL
    if url == installed_config.configured("NOMA_API_URL") or _allowed_api_url(url):
        return url
    debug.log("NOMA_API_URL ignored: not a Noma or loopback host; using " + DEFAULT_API_URL)
    return DEFAULT_API_URL


def _json_object_or_empty(body):
    try:
        if isinstance(json.loads(body), dict):
            return body
    except Exception as e:
        debug.exc("response JSON parse", e)
    return ""


def post(payload_str, api_key, api_url, hooks_path, scheme="Bearer", on_response=None,
         budget_seconds=BUDGET_SECONDS):
    """POST the payload to api_url + hooks_path; print the response if it is a
    JSON object (an error page or a truncated body prints nothing). With
    on_response set, the parsed JSON object is handed to it instead of printed,
    for agents whose hook protocol is not the backend's response verbatim.

    Two attempts, the second on any failure, through the same client. When the
    native client never got the request off the machine, urllib takes over without
    using up an attempt, so it gets the two tries it had before the native client
    existed. Every attempt gets an equal share of what is left of the shared budget
    (BUDGET_SECONDS, or less via budget_seconds for a caller that already spent part of
    its hook timeout) for the attempts left, and is skipped below MIN_ATTEMPT_SECONDS. With
    NOMA_DRYRUN set, print the payload instead of sending it (no network). Always returns 0: a failed send is
    swallowed so a backend outage never surfaces as a hook error (degrade quietly).
    scheme="" sends the credential bare in x-noma-key (v2 ingestion key)."""
    override = os.environ.get("NOMA_HOOKS_PATH")
    if override and _HOOKS_PATH.fullmatch(override):
        hooks_path = override
    elif override:
        debug.log("NOMA_HOOKS_PATH ignored: not a plain URL path")
    url = api_url.rstrip("/") + hooks_path
    if os.environ.get("NOMA_DRYRUN"):
        debug.log("DRY-RUN would POST to " + url + " (" + str(len(payload_str)) + " bytes)")
        sys.stdout.write(payload_str + "\n")
        return 0

    headers = {"Content-Type": "application/json",
               "x-noma-key": (scheme + " " + api_key) if scheme else api_key}
    fallback = http_senders.UrllibSender()
    first = http_senders.native_sender() or fallback
    debug.log("POST " + str(len(payload_str)) + " bytes to " + url + " via " + first.name)
    budget = min(budget_seconds, BUDGET_SECONDS)
    deadline = time.monotonic() + budget
    client = first
    attempts_left = 2
    # Every attempt gets at most TIMEOUT_SECONDS and an equal share of the budget left for the attempts left.
    timeout = min(TIMEOUT_SECONDS, budget / attempts_left)
    while True:
        if timeout < MIN_ATTEMPT_SECONDS:
            debug.log("POST to " + url + " stopped: no time left in the budget")
            return 0
        try:
            status, body = client.send(url, headers, payload_str, timeout)
            break
        except Exception as e:
            if isinstance(e, http_senders.NotSent) and client is not fallback:
                debug.exc("POST via " + client.name + " never sent (switching to " + fallback.name + ") " + url, e)
                client = fallback
            else:
                attempts_left -= 1
                if not attempts_left:  # both attempts failed: HTTP error, unreachable, timeout, ...
                    debug.exc("POST failed " + url, e)
                    return 0  # degrade quietly - a failed send must not error the user's session
                debug.exc("POST attempt via " + client.name + " failed (retrying) " + url, e)
        timeout = min(TIMEOUT_SECONDS, (deadline - time.monotonic()) / attempts_left)
    debug.log("POST ok " + url + " (HTTP " + str(status) + ")")
    decision = _json_object_or_empty(body) if body else ""
    if decision and on_response is not None:
        try:
            on_response(json.loads(decision))
        except Exception as e:
            debug.exc("response handler", e)
    elif decision:
        sys.stdout.write(decision if decision.endswith("\n") else decision + "\n")
    return 0
