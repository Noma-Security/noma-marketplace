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
the process always wins, so the file is a default, never an override; a blank one
counts as unset, matching the hooks' ``os.environ.get(...) or default`` fallbacks.
Any problem (unreadable, malformed) leaves the environment untouched.

Stdlib only, no f-strings/annotations - runs on any python3.
"""

import json
import os
import sys

from . import debug, engine

CONFIG_FILENAME = "config.json"
MAX_CONFIG_BYTES = 64 * 1024
_WIN_LOCAL_SYSTEM_SID = 22  # WELL_KNOWN_SID_TYPE WinLocalSystemSid
_WIN_BUILTIN_ADMINISTRATORS_SID = 26  # WinBuiltinAdministratorsSid


def config_paths():
    """The machine and user config paths, in lookup order; must match the MDM installer's."""
    if sys.platform == "win32":
        machine_root = os.environ.get("ProgramData") or r"C:\ProgramData"
        user_root = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
        return [os.path.join(machine_root, "Noma", "guardrails", CONFIG_FILENAME),
                os.path.join(user_root, "Noma", "guardrails", CONFIG_FILENAME)]
    return [os.path.join("/usr/local/noma", "guardrails", CONFIG_FILENAME),
            os.path.join(os.path.expanduser("~"), ".noma", "guardrails", CONFIG_FILENAME)]


def _windows_owner_is_admin(path):
    """True when SYSTEM or Administrators owns the file; False on any failure."""
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
            return bool(advapi32.IsWellKnownSid(owner, _WIN_LOCAL_SYSTEM_SID)
                        or advapi32.IsWellKnownSid(owner, _WIN_BUILTIN_ADMINISTRATORS_SID))
        finally:
            kernel32.LocalFree(descriptor)
    except Exception as e:
        debug.exc("installed config owner check " + path, e)
        return False


def _machine_file_trusted(path):
    """Only an administrator can have written the machine-scope file."""
    if os.path.islink(path):
        return False
    if sys.platform == "win32":
        return _windows_owner_is_admin(path)
    try:
        st = os.stat(path)
    except OSError:
        return False
    return st.st_uid == 0 and not st.st_mode & 0o022


def _load():
    """Returns (path, parsed document) for the first usable file, else (None, None)."""
    paths = config_paths()
    for index, path in enumerate(paths):
        if not os.path.isfile(path):
            continue
        if index == 0 and not _machine_file_trusted(path):
            debug.log("installed config " + path + " ignored: not owned by an administrator")
            continue
        doc = engine.read_json(path, MAX_CONFIG_BYTES)
        if doc is None:
            debug.log("installed config " + path + " unreadable, ignored")
        return path, doc
    debug.log("no installed config at " + ", ".join(paths))
    return None, None


def apply_installed_env():
    """Set every env var from the installed config file that the process lacks.

    Returns the names it set. Never raises. Logs names and reasons, never values."""
    applied = []
    path, doc = _load()
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
            if os.environ.get(name, "").strip():
                debug.log("installed config entry %r skipped: already set in the environment" % name)
                continue
            os.environ[name] = value
        except (UnicodeError, ValueError) as e:
            debug.log("installed config entry %r skipped: the OS rejected it (%s)" % (name, type(e).__name__))
            continue
        applied.append(name)
    if applied:
        debug.log("installed config " + path + " applied " + ", ".join(applied))
    return applied
