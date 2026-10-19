"""HTTP transport to the Noma guardrails hooks endpoint.

``post()`` ships a finished payload string to the backend, or prints it (and
sends nothing) when NOMA_DRYRUN is set. It sends through the OS-native client the
MDM scripts use, falling back to urllib (see http_senders). OS-portable, stdlib
only, no f-strings/annotations - runs on any python3.
"""

import json
import os
import sys
import time

from . import debug, http_senders

TIMEOUT_SECONDS = 10
# Both attempts share one budget so they fit the 25s hook timeout the manifests set.
BUDGET_SECONDS = 2 * TIMEOUT_SECONDS
MIN_ATTEMPT_SECONDS = 1
DEFAULT_API_URL = "https://api.noma.security"


def _json_object_or_empty(body):
    try:
        if isinstance(json.loads(body), dict):
            return body
    except Exception as e:
        debug.exc("response JSON parse", e)
    return ""


def post(payload_str, api_key, api_url, hooks_path, scheme="Bearer"):
    """POST the payload to api_url + hooks_path; print the response if it is a
    JSON object (an error page or a truncated body prints nothing).

    Two attempts, the second on any failure, through the same client. When the
    native client never got the request off the machine, urllib takes over without
    using up an attempt, so it gets the two tries it had before the native client
    existed. Every attempt after the first gets only what is left of BUDGET_SECONDS,
    and is skipped below MIN_ATTEMPT_SECONDS. With
    NOMA_DRYRUN set, print the payload instead of sending it (no network). Always returns 0: a failed send is
    swallowed so a backend outage never surfaces as a hook error (degrade quietly).
    scheme="" sends the credential bare in x-noma-key (v2 ingestion key)."""
    hooks_path = os.environ.get("NOMA_HOOKS_PATH") or hooks_path
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
    deadline = time.monotonic() + BUDGET_SECONDS
    client = first
    attempts_left = 2
    timeout = TIMEOUT_SECONDS
    while True:
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
        timeout = min(TIMEOUT_SECONDS, deadline - time.monotonic())
        if timeout < MIN_ATTEMPT_SECONDS:
            debug.log("POST to " + url + " stopped: no time left in the budget")
            return 0
    debug.log("POST ok " + url + " (HTTP " + str(status) + ")")
    decision = _json_object_or_empty(body) if body else ""
    if decision:
        sys.stdout.write(decision if decision.endswith("\n") else decision + "\n")
    return 0
