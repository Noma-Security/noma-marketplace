"""HTTP transport to the Noma guardrails hooks endpoint.

``post()`` ships a finished payload string to the backend, or prints it (and
sends nothing) when NOMA_DRYRUN is set. OS-portable, stdlib only (urllib), no
f-strings/annotations - runs on any python3.
"""

import os
import sys
import urllib.request

from . import debug


def post(payload_str, api_key, api_url, hooks_path):
    """POST the payload to api_url + hooks_path; print the response.

    Retries once on a transient failure. With NOMA_DRYRUN set, print the payload
    instead of sending it (no network). Always returns 0: a failed send is
    swallowed so a backend outage never surfaces as a hook error (degrade quietly)."""
    url = api_url.rstrip("/") + hooks_path
    if os.environ.get("NOMA_DRYRUN"):
        debug.log("DRY-RUN would POST to " + url + " (" + str(len(payload_str)) + " bytes)")
        sys.stdout.write(payload_str + "\n")
        return 0

    req = urllib.request.Request(
        url,
        data=payload_str.encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "x-noma-key": "Bearer " + api_key},
        method="POST",
    )
    debug.log("POST " + str(len(payload_str)) + " bytes to " + url)
    try:
        try:
            resp = urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            debug.exc("POST attempt 1 failed (retrying) " + url, e)
            resp = urllib.request.urlopen(req, timeout=10)  # one retry on a transient failure
    except Exception as e:  # both attempts failed: HTTPError, URLError, timeout, ...
        debug.exc("POST failed " + url, e)
        return 0  # degrade quietly - a failed send must not error the user's session
    debug.log("POST ok " + url + " (HTTP " + str(resp.getcode()) + ")")
    try:
        body = resp.read().decode("utf-8", "replace")
    except Exception as e:
        debug.exc("response read " + url, e)
        body = ""
    finally:
        try:
            resp.close()
        except Exception as e:
            debug.exc("response close", e)
    if body:
        sys.stdout.write(body if body.endswith("\n") else body + "\n")
    return 0
