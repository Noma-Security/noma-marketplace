r"""Env vars from the config file a managed (MDM) install writes for every agent's hooks.

The file lives at a fixed path per install scope, one for all agents::

    machine  /usr/local/noma/guardrails/config.json   (%ProgramData%\Noma\guardrails\config.json)
    user     ~/.noma/guardrails/config.json            (%LOCALAPPDATA%\Noma\guardrails\config.json)

    {"env": {"NAME": "value"}}

The first file that exists wins (machine before user; never merged), so a hook reads
the same file wherever its plugin is installed. The machine file counts only when an
administrator wrote it (owned by root, not group/world-writable; on Windows owned by
SYSTEM or Administrators): a standard user can create folders under %ProgramData%, and
that file would otherwise redirect every user's hooks. An untrusted one is skipped. An env var already set (non-blank) in
the process wins, so the file is a default; a blank one counts as unset, matching the
hooks' ``os.environ.get(...) or default`` fallbacks. CONFIG_WINS names in a trusted file
are the exception: it overrides the process for them, because an agent's project settings
(a repo's .claude/settings.json "env") reach the hook process and must not redirect hook
traffic. Trusted means the admin-owned machine file, or the file next to the running hook
(installed_path(): <guardrails>/<agent>/scripts/common/ -> <guardrails>/config.json, how the MDM
lays out both scopes) when the user or an admin owns it. The user path found through HOME /
LOCALAPPDATA is never trusted: the same project settings can point it at a file of their own.
Any problem (unreadable, malformed) leaves the environment untouched.

Stdlib only, no f-strings/annotations - runs on any python3.
"""

import json
import os
import sys

from . import debug, engine

CONFIG_FILENAME = "config.json"
MAX_CONFIG_BYTES = 64 * 1024
CONFIG_WINS = ("NOMA_API_URL",)
_WIN_LOCAL_SYSTEM_SID = 22  # WELL_KNOWN_SID_TYPE WinLocalSystemSid
_WIN_BUILTIN_ADMINISTRATORS_SID = 26  # WinBuiltinAdministratorsSid
_configured = {}


def configured(name):
    """The value a trusted config file (see the module doc) set for name in this process, or None."""
    return _configured.get(name)


def installed_path():
    """config.json of the guardrails dir this runtime runs from; found from __file__, never from env."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(here))), CONFIG_FILENAME)


def config_paths():
    """The machine and user config paths, in lookup order; must match the MDM installer's."""
    if sys.platform == "win32":
        machine_root = os.environ.get("ProgramData") or r"C:\ProgramData"
        user_root = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
        return [os.path.join(machine_root, "Noma", "guardrails", CONFIG_FILENAME),
                os.path.join(user_root, "Noma", "guardrails", CONFIG_FILENAME)]
    return [os.path.join("/usr/local/noma", "guardrails", CONFIG_FILENAME),
            os.path.join(os.path.expanduser("~"), ".noma", "guardrails", CONFIG_FILENAME)]


def _windows_owner_is_admin(path, or_current_user=False):
    """True when SYSTEM or Administrators (or_current_user: or this process's user) owns the file;
    False on any failure."""
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_info = advapi32.GetNamedSecurityInfoW
        get_info.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                             ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                             ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                             ctypes.POINTER(ctypes.c_void_p)]
        get_info.restype = wintypes.DWORD
        advapi32.IsWellKnownSid.argtypes = [ctypes.c_void_p, ctypes.c_int]
        advapi32.IsWellKnownSid.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        owner = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        # SE_FILE_OBJECT = 1, OWNER_SECURITY_INFORMATION = 1
        if get_info(path, 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor)) != 0:
            return False
        try:
            if advapi32.IsWellKnownSid(owner, _WIN_LOCAL_SYSTEM_SID) \
                    or advapi32.IsWellKnownSid(owner, _WIN_BUILTIN_ADMINISTRATORS_SID):
                return True
            return or_current_user and _windows_is_current_user(ctypes, wintypes, advapi32, kernel32, owner)
        finally:
            kernel32.LocalFree(descriptor)
    except Exception as e:
        debug.exc("installed config owner check " + path, e)
        return False


def _windows_is_current_user(ctypes, wintypes, advapi32, kernel32, sid):
    token = wintypes.HANDLE()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    # TOKEN_QUERY = 8, TokenUser = 1; TOKEN_USER starts with the user's SID pointer.
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 8, ctypes.byref(token)):
        return False
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
            return False
        return bool(advapi32.EqualSid(sid, ctypes.c_void_p.from_buffer(buf).value))
    finally:
        kernel32.CloseHandle(token)


def _file_trusted(path, or_current_user):
    """Owned by an administrator (or_current_user: or this process's user), and no one else can write it."""
    if os.path.islink(path):
        return False
    if sys.platform == "win32":
        return _windows_owner_is_admin(path, or_current_user)
    try:
        st = os.stat(path)
    except OSError:
        return False
    owners = (0, os.getuid()) if or_current_user else (0,)
    return st.st_uid in owners and not st.st_mode & 0o022


def _machine_file_trusted(path):
    """Only an administrator can have written the machine-scope file."""
    return _file_trusted(path, False)


def _installed_file_trusted(path):
    """The file next to the running hook: its user, or an admin, wrote it."""
    return _file_trusted(path, True)


def _load():
    """Returns (path, parsed document, trusted) for the first usable file, else (None, None, False).
    trusted is True only for a file that passed its ownership check, never inferred from its path."""
    machine, user = config_paths()
    installed = installed_path()
    candidates = [(machine, _machine_file_trusted, "not owned by an administrator")]
    if os.path.normcase(installed) != os.path.normcase(machine):
        candidates.append((installed, _installed_file_trusted, "not owned by this user or an administrator"))
    candidates.append((user, None, ""))
    for path, check, untrusted in candidates:
        if not os.path.isfile(path):
            continue
        if check is not None and not check(path):
            debug.log("installed config " + path + " ignored: " + untrusted)
            continue
        doc = engine.read_json(path, MAX_CONFIG_BYTES)
        if doc is None:
            debug.log("installed config " + path + " unreadable, ignored")
        return path, doc, check is not None
    debug.log("no installed config at " + ", ".join(path for path, _, _ in candidates))
    return None, None, False


def apply_installed_env():
    """Set every env var from the installed config file that the process lacks.

    Returns the names it set. Never raises. Logs names and reasons, never values."""
    applied = []
    path, doc, trusted = _load()
    if doc is None:
        return applied
    env = doc.get("env") if isinstance(doc, dict) else None
    if not isinstance(env, dict):
        debug.log("installed config " + path + " ignored: no \"env\" object")
        return applied
    for name, value in sorted(env.items()):
        if not isinstance(name, str) or not name or not isinstance(value, str) or not value:
            debug.log("installed config entry %r skipped: name and value must be non-empty strings" % name)
            continue
        if "=" in name or "\0" in name or "\0" in value:
            debug.log("installed config entry %r skipped: '=' in the name or a NUL character" % name)
            continue
        try:
            if not (trusted and name in CONFIG_WINS) and os.environ.get(name, "").strip():
                debug.log("installed config entry %r skipped: already set in the environment" % name)
                continue
            os.environ[name] = value
            if trusted:
                _configured[name] = value
        except (UnicodeError, ValueError) as e:
            debug.log("installed config entry %r skipped: the OS rejected it (%s)" % (name, type(e).__name__))
            continue
        applied.append(name)
    if applied:
        debug.log("installed config " + path + " applied " + ", ".join(applied))
    return applied
