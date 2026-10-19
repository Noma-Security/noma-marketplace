"""Senders for the hooks POST: curl, the HTTP client the Noma MDM scripts use, and
urllib as the fallback.

curl trusts the OS certificate store (corporate TLS-inspection roots), which urllib's
bundled OpenSSL may not. A sender raises NotSent when the request never left the
machine - another client may then try it without sending the event twice - and
SendFailed when it may have reached the server. The payload never rides argv.
Stdlib only, no f-strings/annotations - runs on any python3.
"""

import os
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

from . import debug

SYSTEM_CURL = "/usr/bin/curl"
PROCESS_GRACE_SECONDS = 2
# Init failure (e.g. an option an old curl lacks), resolve proxy/host, connect, TLS
# handshake, certificate and CA-file errors, proxy handshake.
CURL_NOT_SENT_EXIT_CODES = frozenset([2, 5, 6, 7, 35, 58, 60, 77, 97])
CURL_TIMEOUT_EXIT_CODE = 28
# subprocess.CREATE_NO_WINDOW, which Python before 3.7 lacks.
CREATE_NO_WINDOW = 0x08000000


class SendFailed(Exception):
    """The request failed and may have reached the server."""


class NotSent(SendFailed):
    """The request never left the machine."""


def native_sender():
    """The curl sender for this platform, or None when curl is missing. curl always runs by
    absolute path: /usr/bin/curl else the first curl on an absolute PATH entry; on Windows the
    inbox curl.exe else the first curl.exe on an absolute PATH entry. A relative entry (".",
    empty) would resolve against the agent's workspace."""
    plat = sys.platform  # via a local so static analysis doesn't prune branches
    if plat == "win32":
        binary = _windows_curl()
        return CurlSender(binary, windows=True) if binary else None
    if os.access(SYSTEM_CURL, os.X_OK):
        return CurlSender(SYSTEM_CURL)
    path = os.pathsep.join(_absolute_path_entries())
    binary = shutil.which("curl", path=path) if path else None
    return CurlSender(binary) if binary else None


def _absolute_path_entries():
    """PATH without its relative entries ("", "."), which would resolve against the agent's
    workspace."""
    entries = (entry.strip().strip('"') for entry in os.environ.get("PATH", "").split(os.pathsep))
    return [entry for entry in entries if entry and os.path.isabs(entry)]


def _windows_curl():
    """Never the current directory - it is the agent's workspace, so a curl.exe planted there
    would receive the key - which CreateProcess and shutil.which search before PATH."""
    inbox = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "curl.exe")
    if os.path.isfile(inbox):
        return inbox
    for entry in _absolute_path_entries():
        if os.path.isfile(os.path.join(entry, "curl.exe")):
            return os.path.join(entry, "curl.exe")
    return None


class Sender(object):
    """A client for the hooks POST. send() returns (status, body) for a 2xx response and
    raises NotSent or SendFailed (urllib: any exception) otherwise."""

    name = ""

    def send(self, url, headers, body, timeout):
        raise NotImplementedError


class CurlSender(Sender):
    """POSTs through curl like the MDM discovery script: /usr/bin/curl first (the OS build and
    its default trust store), the payload on stdin, the headers from a pipe. curl.exe (Schannel +
    Windows store) has no /dev/fd, so there curl reads each header from its own environment
    (--variable/--expand-header, curl 8.3+): process-creation logging (EDR, Sysmon, event 4688)
    records argv, and the key must not land in it. An older curl.exe rejects the option with
    exit 2, a not-sent failure, so urllib takes over."""

    name = "curl"

    def __init__(self, binary, windows=False):
        self.binary = binary
        self.windows = windows

    def send(self, url, headers, body, timeout):
        cmd = [self.binary, "-sS", "-o", "-", "-w", "\\n%{http_code} %{time_connect}",
               "-X", "POST", url, "--max-time", "%g" % timeout] + _curl_proxy_args(url)
        if self.windows:
            # Schannel checks revocation by default and fails when the CA's revocation server is
            # unreachable (common behind TLS inspection); urllib and Invoke-WebRequest never check.
            env = dict(os.environ)
            header_args = []
            for index, (name, value) in enumerate(headers.items()):
                variable = "NOMA_CURL_HEADER_" + str(index)
                env[variable] = name + ": " + value
                header_args += ["--variable", "%" + variable, "--expand-header", "{{" + variable + "}}"]
            return self._run(cmd + header_args + ["--data-binary", "@-", "--ssl-no-revoke"],
                             body.encode("utf-8"), (), timeout, env)
        header_read, header_write = os.pipe()
        try:
            header_lines = "".join(name + ": " + value + "\n" for name, value in headers.items())
            os.write(header_write, header_lines.encode("utf-8"))
            os.close(header_write)
            header_write = None
            return self._run(cmd + ["-H", "@/dev/fd/" + str(header_read), "--data-binary", "@-"]
                             + _cacert_args(), body.encode("utf-8"), (header_read,), timeout)
        finally:
            os.close(header_read)
            if header_write is not None:
                os.close(header_write)

    def _run(self, cmd, stdin_bytes, pass_fds, timeout, env=None):
        extra = {"pass_fds": pass_fds} if pass_fds else {}
        if env is not None:
            extra["env"] = env
        if sys.platform == "win32":
            # A hook launched without a console (a GUI agent) would otherwise open one per event.
            extra["creationflags"] = CREATE_NO_WINDOW
        try:
            completed = subprocess.run(cmd, input=stdin_bytes, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, timeout=timeout + PROCESS_GRACE_SECONDS,
                                       **extra)
        except subprocess.TimeoutExpired:
            raise SendFailed("curl did not exit in time")
        except OSError as e:
            raise NotSent("curl could not start: " + str(e))
        errors = _curl_errors(completed.stderr)
        if errors:
            debug.log("curl stderr: " + errors)
        return _curl_result(completed)


def _curl_errors(stderr):
    """curl's own error lines, the only stderr -sS prints. A .curlrc with `verbose` or `trace`
    adds the request headers - the key included - which must never reach the debug log."""
    lines = (stderr or b"").decode("utf-8", "replace").splitlines()
    return "\n".join(line.strip() for line in lines if line.startswith("curl: "))


def _curl_proxy_args(url):
    """-x for the system proxy urllib would use (Windows registry / macOS settings), which
    curl ignores. curl reads the *_proxy env vars itself, credentials included; like
    urllib, any *_proxy setting means the system proxy is not consulted."""
    if urllib.request.getproxies_environment():
        return []
    parts = urllib.parse.urlsplit(url)
    proxy = urllib.request.getproxies().get(parts.scheme, "")
    if not proxy or urllib.request.proxy_bypass(parts.hostname or ""):
        return []
    # curl speaks plain HTTP to the proxy; Python reports a bare Windows "host:port" as
    # https:// for https, which curl would read as TLS to the proxy.
    proxy_parts = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
    return ["-x", "http://" + proxy_parts.netloc.rpartition("@")[2]]


def _cacert_args():
    """--cacert from CUSTOM_CA_CERT, else CURL_CA_BUNDLE (system curl ignores the latter),
    dropped when unreadable - the precedence of the MDM script's NOMA_CA_ARGS."""
    ca_file = os.environ.get("CUSTOM_CA_CERT") or os.environ.get("CURL_CA_BUNDLE") or ""
    if not ca_file:
        return []
    if not os.access(ca_file, os.R_OK):
        debug.log("CA bundle " + ca_file + " is not readable; using default TLS trust")
        return []
    return ["--cacert", ca_file]


def _curl_result(completed):
    response_body, _, trailer = completed.stdout.decode("utf-8", "replace").rpartition("\n")
    status_text, _, connect_text = trailer.partition(" ")
    code = completed.returncode
    if code == 0:
        status = int(status_text)
        if 200 <= status < 300:
            return status, response_body
        raise SendFailed("curl got HTTP " + str(status))
    if code in CURL_NOT_SENT_EXIT_CODES or (code == CURL_TIMEOUT_EXIT_CODE and _never_connected(connect_text)):
        raise NotSent("curl exit " + str(code))
    raise SendFailed("curl exit " + str(code))


def _never_connected(connect_text):
    try:
        return float(connect_text) == 0
    except ValueError:
        return False


class UrllibSender(Sender):
    """POSTs through Python's urllib - the hooks' original transport."""

    name = "urllib"

    def send(self, url, headers, body, timeout):
        req = urllib.request.Request(url, data=body.encode("utf-8"), headers=headers, method="POST")
        resp = urllib.request.urlopen(req, timeout=timeout)
        try:
            response_body = resp.read().decode("utf-8", "replace")
        except Exception as e:
            debug.exc("response read " + url, e)
            response_body = ""
        finally:
            try:
                resp.close()
            except Exception as e:
                debug.exc("response close", e)
        return resp.getcode(), response_body
