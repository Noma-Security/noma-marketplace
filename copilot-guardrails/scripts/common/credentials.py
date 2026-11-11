"""API-key resolution from the environment, the MDM certificate, or the OS
credential store.

``resolve_api_key(service, api_url)`` prefers the NOMA_API_KEY environment variable, then
the customer broker key from the MDM certificate (only when api_url, the URL the hook
sends to, is a non-Noma host), then the per-endpoint token the MDM discovery script left in
user scope, then the MDM discovery ingestion certificate, then the per-user credential store:
macOS Keychain (``security``), Linux libsecret / GNOME Keyring (``secret-tool``),
or Windows Credential Manager (``advapi32.CredReadW``). The store is keyed by the
caller-supplied ``service`` name (the guardrails hook passes "noma-guardrails").
It returns ``(key, KeyScope)`` so callers can tell which source won.

Also hosts the endpoint-identity fallbacks hooks share: ``current_user()`` (OS
login), ``git_email()`` (global git user.email) and ``read_store_entry()`` (a
credential another client stored).

OS-portable, stdlib only, no f-strings/annotations - runs on any python3.
"""

import enum
import getpass
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

from . import debug
from . import endpoint_token


class KeyScope(enum.Enum):
    """Which source resolved the transport credential."""
    NONE = "none"
    ENV = "env"
    BROKER_KEY = "broker_key"
    ENDPOINT_TOKEN = "endpoint_token"
    DATA_COLLECTOR_KEY = "data_collector_key"
    ACCESS_TOKEN = "access_token"


# MDM discovery ingestion key - base64(client_id:client_secret) in a SAN URI of
# an MDM-deployed inert certificate; see mdm_scripts/mobileconfig.go.
MDM_CERT_CN = "Noma MDM Ingestion Key"
MDM_KEY_SCHEME = "x-noma-key"
_MDM_KEY_RE_BODY = MDM_KEY_SCHEME + ":[A-Za-z0-9+/=]+"
_MDM_KEY_RE = MDM_KEY_SCHEME + ":([A-Za-z0-9+/=]+)"

# Second SAN entry; _MDM_KEY_RE cannot match it, so older readers still find only the ingestion key.
MDM_BROKER_KEY_SCHEME = "x-noma-broker-key"
_BROKER_KEY_CHARSET = "[A-Za-z0-9._~+/=-]"
_MDM_ENTRY_RE_BODY = ("(" + _MDM_KEY_RE_BODY + "|" + MDM_BROKER_KEY_SCHEME + ":" +
                      _BROKER_KEY_CHARSET + "+)([, ]|$)")
_MDM_ENTRY_RE = ("(" + MDM_KEY_SCHEME + "|" + MDM_BROKER_KEY_SCHEME + "):(" +
                 _BROKER_KEY_CHARSET + r"+)(?=[,\s]|$)")
_BROKER_KEY_VALID_RE = re.compile("^" + _BROKER_KEY_CHARSET + "{16,512}" + r"\Z")
_NOMA_HOST = "noma.security"


def current_user():
    """The current OS username, or "" if it cannot be determined."""
    try:
        return getpass.getuser()
    except Exception as e:
        debug.exc("current_user", e)
        return os.environ.get("USER") or os.environ.get("USERNAME") or ""


def git_email():
    """The user's global git user.email, or "". Global only: a repo-local override
    would make the same person report a different identity per checkout.
    --default keeps an unset key at exit 0, so only a missing git is an error."""
    return _run(["git", "config", "--global", "--default", "", "--get", "user.email"])


def _run(cmd, input_bytes=None, timeout=5):
    """Stripped stdout of cmd, or "" on any failure. stderr never reaches the
    agent UI: it is captured and forwarded to the debug trace so a helper's own
    diagnostics survive, and the timeout bounds a locked/slow credential store so
    the hook can't hang."""
    label = cmd[0] if cmd else "?"
    if input_bytes is None:
        stdin = {"stdin": subprocess.DEVNULL}
    else:
        stdin = {"input": input_bytes}
    try:
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=timeout, check=True, **stdin)
    except Exception as e:
        debug.exc("credential lookup (" + label + ")", e)
        _log_stderr(label, getattr(e, "stderr", None))
        return ""
    _log_stderr(label, completed.stderr)
    try:
        return completed.stdout.decode("utf-8").strip()
    except Exception as e:
        debug.exc("credential decode", e)
        return ""


def _log_stderr(label, raw):
    if raw:
        debug.log("credential lookup stderr (" + label + "): " + raw.decode("utf-8", "replace").strip())


# --- mac/Linux: subprocess against the platform secret helper ----------------

def _unix_key(service, user):
    """Read the API key from the macOS Keychain (``security``) or, on other
    POSIX systems, libsecret / GNOME Keyring (``secret-tool``); "" if absent."""
    plat = sys.platform  # via a local so static analysis doesn't prune branches
    if plat == "darwin":
        debug.log("querying macOS keychain (security) service=" + service + " account=" + user)
        return _run(["security", "find-generic-password",
                     "-s", service, "-a", user, "-w"])
    debug.log("querying libsecret (secret-tool) service=" + service + " account=" + user)
    return _run(["secret-tool", "lookup",
                 "service", service, "username", user])


# --- Windows: advapi32.CredReadW via ctypes ----------------------------------

def _windows_key(service):
    """Read the generic credential `service` from Windows Credential Manager via
    advapi32.CredReadW; "" on any failure. Mirrors the C# P/Invoke used by the
    retired PowerShell hook (blob stored as UTF-16LE)."""
    try:
        import ctypes
        from ctypes import wintypes

        cred_type_generic = 1

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        cred_read = advapi32.CredReadW
        cred_read.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                              ctypes.POINTER(ctypes.POINTER(CREDENTIAL))]
        cred_read.restype = wintypes.BOOL

        ptr = ctypes.POINTER(CREDENTIAL)()
        if not cred_read(service, cred_type_generic, 0, ctypes.byref(ptr)):
            return ""
        try:
            cred = ptr.contents
            size = int(cred.CredentialBlobSize)
            if size <= 0:
                return ""
            blob = ctypes.string_at(cred.CredentialBlob, size)
            return blob.decode("utf-16-le")
        finally:
            advapi32.CredFree(ptr)
    except Exception as e:
        debug.exc("windows credential read", e)
        return ""


def read_store_entry(service, account):
    """The secret another keyring-style client stored under service/account, or "".
    Windows generic credentials are keyed "<account>.<service>", the keyring crate's
    target name; macOS and Linux key by service plus account."""
    if sys.platform == "win32":
        return _windows_key(account + "." + service)
    return _unix_key(service, account)


def _from_store(service):
    """The API key from the OS credential store for the current user; "" if none."""
    plat = sys.platform  # via a local so static analysis doesn't prune branches
    debug.log("credential store lookup on platform=" + plat)
    if plat == "win32":
        return _windows_key(service)
    return _unix_key(service, current_user())


# --- MDM discovery ingestion certificate --------------------------------------

_MACOS_CERT_SH = """noma_cert_keys() {
  [ -f "$1" ] || return 0
  /usr/bin/security find-certificate -c '%s' -p "$1" 2>/dev/null \\
    | /usr/bin/openssl x509 -noout -text 2>/dev/null \\
    | grep -Eo 'URI:%s' | sed 's#^URI:##; s#[, ]$##; s#:#=#'
}
noma_keys=$(noma_cert_keys /Library/Keychains/System.keychain)
if [ -z "$noma_keys" ]; then
  noma_keys=$(noma_cert_keys "${HOME:-/var/root}/Library/Keychains/login.keychain-db")
fi
printf '%%s' "$noma_keys\"""" % (
    MDM_CERT_CN, _MDM_ENTRY_RE_BODY)


def _macos_cert_keys():
    """"scheme=value" lines for the entries on the deployed keychain cert (System, then login); "" if absent."""
    return _run(["/bin/sh", "-c", _MACOS_CERT_SH])


_WINDOWS_CERT_PS = """$NomaKeys = @()
foreach ($nomaLocation in @('LocalMachine', 'CurrentUser')) {
foreach ($nomaStoreName in @('Root', 'My')) {
    $nomaStore = [System.Security.Cryptography.X509Certificates.X509Store]::new($nomaStoreName, [System.Security.Cryptography.X509Certificates.StoreLocation]::$nomaLocation)
    try { $nomaStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly) }
    catch { [Console]::Error.WriteLine("cert store $nomaLocation\\$nomaStoreName not opened: $($_.Exception.Message)"); continue }
    try {
        foreach ($nomaCert in $nomaStore.Certificates) {
            if ($nomaCert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ne "%s") { continue }
            $nomaSan = $nomaCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
            if (-not $nomaSan) { continue }
            foreach ($nomaMatch in [regex]::Matches($nomaSan.Format($true), '%s')) {
                $NomaKeys += ($nomaMatch.Groups[1].Value + '=' + $nomaMatch.Groups[2].Value)
            }
            if ($NomaKeys.Count -gt 0) { break }
        }
    } finally {
        $nomaStore.Close()
    }
    if ($NomaKeys.Count -gt 0) { break }
}
if ($NomaKeys.Count -gt 0) { break }
}
if ($NomaKeys.Count -gt 0) { Write-Output $NomaKeys }""" % (MDM_CERT_CN, _MDM_ENTRY_RE)


def _windows_powershell():
    """Windows PowerShell by absolute path, or "": a bare name resolves in the current directory
    - the agent's workspace - before the system directories."""
    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    # Sysnative first: a 32-bit Python on 64-bit Windows sees System32 redirected to SysWOW64.
    for system_dir in ("Sysnative", "System32"):
        exe = os.path.join(system_root, system_dir, "WindowsPowerShell", "v1.0", "powershell.exe")
        if os.path.isfile(exe):
            return exe
    return ""


def _windows_cert_keys():
    """"scheme=value" lines for the entries on the deployed cert (LocalMachine, then CurrentUser); "" if absent."""
    powershell = _windows_powershell()
    if not powershell:
        debug.log("Windows PowerShell not found; no keys from the certificate store")
        return ""
    return _run([powershell, "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_CERT_PS])


def valid_broker_key(key):
    return bool(_BROKER_KEY_VALID_RE.match(key)) and not key.startswith("//")


def resolve_mdm_cert_keys():
    """(ingestion_key, broker_key) from one certificate read; "" when absent or malformed."""
    plat = sys.platform  # via a local so static analysis doesn't prune branches
    if plat == "win32":
        output = _windows_cert_keys()
    elif plat == "darwin":
        output = _macos_cert_keys()
    else:
        debug.log("no MDM ingestion certificate source on platform=" + plat)
        return "", ""
    entries = {}
    for line in output.splitlines():
        scheme, _, value = line.strip().partition("=")
        if scheme not in entries:
            entries[scheme] = value
    ingestion_key = entries.get(MDM_KEY_SCHEME, "")
    broker_key = entries.get(MDM_BROKER_KEY_SCHEME, "")
    if broker_key and not valid_broker_key(broker_key):
        debug.log("MDM certificate broker key rejected: not a valid key")
        broker_key = ""
    debug.log("MDM ingestion certificate " +
              ("returned an ingestion key" if ingestion_key else "returned no ingestion key") +
              (" and a broker key" if broker_key else " and no broker key"))
    return ingestion_key, broker_key


def resolve_ingestion_key():
    """The MDM discovery ingestion key from the OS certificate store; "" if unresolved."""
    return resolve_mdm_cert_keys()[0]


def _is_custom_broker_url(api_url):
    """True only for a non-Noma api_url host, so the broker key never reaches Noma; unparseable is False."""
    if not api_url:
        return False
    try:
        host = (urlparse(api_url).hostname or "").rstrip(".")
    except ValueError:
        return False
    return bool(host) and host != _NOMA_HOST and not host.endswith("." + _NOMA_HOST)


def resolve_api_key(service=None, api_url=None):
    """(key, key_scope): NOMA_API_KEY env wins, then the MDM broker key (only when
    api_url is a custom non-Noma host), then the per-endpoint token, then the MDM
    ingestion key, then the OS credential store; ("", KeyScope.NONE) when nothing
    resolves.

    `service` is the credential-store key, supplied by the caller so this module
    stays generic (the guardrails hook passes "noma-guardrails"); without one the
    store is skipped, for a hook whose route takes no API key.

    `api_url` must be the URL the hook posts to (transport.api_url()), not raw
    NOMA_API_URL: transport can ignore an env URL, and the key must follow the URL used."""
    key = os.environ.get("NOMA_API_KEY")
    if key:
        debug.log("API key resolved from NOMA_API_KEY env/settings")
        return key, KeyScope.ENV
    cert_ingestion_key = None
    if _is_custom_broker_url(api_url):
        cert_ingestion_key, broker_key = resolve_mdm_cert_keys()
        if broker_key:
            debug.log("credential: MDM certificate broker key (custom NOMA_API_URL host)")
            return broker_key, KeyScope.BROKER_KEY
    key = endpoint_token.read_token()
    if key:
        return key, KeyScope.ENDPOINT_TOKEN
    key = resolve_ingestion_key() if cert_ingestion_key is None else cert_ingestion_key
    if key:
        return key, KeyScope.DATA_COLLECTOR_KEY
    if not service:
        return "", KeyScope.NONE
    key = _from_store(service)
    debug.log("credential store " + ("returned a key" if key else "returned nothing"))
    if key:
        return key, KeyScope.ACCESS_TOKEN
    return "", KeyScope.NONE
