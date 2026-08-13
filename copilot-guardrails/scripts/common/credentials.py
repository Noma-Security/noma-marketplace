"""API-key resolution from the environment or the OS credential store.

``resolve_api_key(service)`` prefers the NOMA_API_KEY environment variable, then
falls back to the per-user credential store: macOS Keychain (``security``), Linux
libsecret / GNOME Keyring (``secret-tool``), or Windows Credential Manager
(``advapi32.CredReadW``). The store is keyed by the caller-supplied ``service``
name (the guardrails hook passes "noma-guardrails".

OS-portable, stdlib only, no f-strings/annotations - runs on any python3.
"""

import getpass
import os
import subprocess
import sys

from . import debug


def current_user():
    """The current OS username, or "" if it cannot be determined."""
    try:
        return getpass.getuser()
    except Exception as e:
        debug.exc("current_user", e)
        return os.environ.get("USER") or os.environ.get("USERNAME") or ""


def _run(cmd):
    """Stripped stdout of cmd, or "" on any failure. stderr is discarded so a
    missing helper never surfaces in the Claude Code UI, and a 5s timeout bounds
    a locked/slow credential store so the hook can't hang."""
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5)
    except Exception as e:
        debug.exc("credential lookup (" + (cmd[0] if cmd else "?") + ")", e)
        return ""
    try:
        return out.decode("utf-8").strip()
    except Exception as e:
        debug.exc("credential decode", e)
        return ""


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


def _from_store(service):
    """The API key from the OS credential store for the current user; "" if none."""
    plat = sys.platform  # via a local so static analysis doesn't prune branches
    debug.log("credential store lookup on platform=" + plat)
    if plat == "win32":
        return _windows_key(service)
    return _unix_key(service, current_user())


def resolve_api_key(service):
    """env NOMA_API_KEY first, then the OS credential store; "" if unresolved.

    `service` is the credential-store key, supplied by the caller so this module
    stays generic (the guardrails hook passes "noma-guardrails")."""
    key = os.environ.get("NOMA_API_KEY")
    if key:
        debug.log("API key resolved from NOMA_API_KEY env/settings")
        return key
    debug.log("NOMA_API_KEY not in env/settings; falling back to OS credential store")
    key = _from_store(service)
    debug.log("credential store " + ("returned a key" if key else "returned nothing"))
    return key
