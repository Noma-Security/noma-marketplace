"""Per-endpoint hooks token left in user scope by the MDM discovery script.

The script runs as root/SYSTEM, exchanges the tenant ingestion key for a
short-lived gateway-signed JWT bound to this device, and writes it to a
world-readable file wrapped with the device id so a copy is useless off the
machine (it is obfuscation against off-device replay, not a secret from local
users). This module is the reader half; the writer lives in
mdm_scripts/discover.py and both must agree on every constant below.

The unwrapped token must look like a JWT - three base64url segments joined by
dots. Anything else, including an ``sk-`` access token written by an older
script, is rejected so the caller falls through to the next credential source.

File format (three lines)::

    noma-endpoint-token/v1
    expires_at=2026-09-16T10:00:00Z
    <base64 body>

macOS body: nonce[16] || ciphertext || tag[32] with k = HMAC-SHA256(key=FORMAT,
msg=host_id), keystream block i = HMAC(k, nonce || be32(i)), tag = HMAC(k, b"tag"
|| nonce || ciphertext). Windows body: DPAPI CryptProtectData(token,
entropy=host_id) in LocalMachine scope. host_id is the macOS IOPlatformUUID or
the Windows MachineGuid.

``read_token()`` returns "" on any failure, expiry or tamper so the
caller falls through to the next credential source. OS-portable, stdlib only,
no f-strings/annotations - runs on any python3.
"""

import base64
import datetime
import hashlib
import hmac
import os
import re
import struct
import sys

from . import debug

FORMAT = "noma-endpoint-token/v1"
EXPIRES_PREFIX = "expires_at="
EXPIRES_LAYOUT = "%Y-%m-%dT%H:%M:%SZ"
MACOS_TOKEN_PATH = "/Library/Application Support/Noma/endpoint-token"
WINDOWS_TOKEN_RELPATH = os.path.join("Noma", "endpoint-token")
MACHINE_GUID_KEY = "SOFTWARE\\Microsoft\\Cryptography"
MACHINE_GUID_VALUE = "MachineGuid"

_NONCE_LEN = 16
_TAG_LEN = 32
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_IOREG_UUID_RE = re.compile(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]+)"')
_MAX_FILE_BYTES = 4096


def token_path():
    """Where the discovery script writes the token for this platform."""
    if sys.platform == "win32":
        return os.path.join(os.environ.get("ProgramData") or "C:\\ProgramData", WINDOWS_TOKEN_RELPATH)
    return MACOS_TOKEN_PATH


def host_id():
    """The device id the token is wrapped with: IOPlatformUUID on macOS, MachineGuid
    on Windows; "" elsewhere or on failure."""
    plat = sys.platform  # via a local so static analysis doesn't prune branches
    if plat == "darwin":
        return _macos_platform_uuid()
    if plat == "win32":
        return _windows_machine_guid()
    return ""


def _macos_platform_uuid():
    from . import credentials  # lazy: credentials imports this module
    out = credentials._run(["/usr/sbin/ioreg", "-d2", "-c", "IOPlatformExpertDevice"])
    match = _IOREG_UUID_RE.search(out or "")
    return match.group(1) if match else ""


def _windows_machine_guid():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_GUID_KEY, 0,
                             winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        try:
            value, _ = winreg.QueryValueEx(key, MACHINE_GUID_VALUE)
        finally:
            winreg.CloseKey(key)
        return str(value)
    except Exception as e:
        debug.exc("machine guid read", e)
        return ""


def read_token():
    """The token from the endpoint token file, or "" when the file is absent,
    malformed, expired, tampered, or wrapped for another device."""
    path = token_path()
    try:
        with open(path, "rb") as handle:
            raw = handle.read(_MAX_FILE_BYTES + 1)
    except Exception as e:
        debug.exc("endpoint token read " + path, e)
        return ""
    if len(raw) > _MAX_FILE_BYTES:
        debug.log("endpoint token file too large; ignoring")
        return ""

    parsed = _parse(raw)
    if parsed is None:
        return ""
    expires_at, body = parsed
    if expires_at <= _utcnow():
        debug.log("endpoint token expired at " + expires_at.strftime(EXPIRES_LAYOUT))
        return ""

    device = host_id()
    if not device:
        debug.log("endpoint token present but no host id on platform=" + sys.platform)
        return ""

    token = _unwrap(body, device)
    if not token or not _TOKEN_RE.match(token):
        debug.log("endpoint token unwrap failed or malformed; ignoring")
        return ""
    debug.log("endpoint token resolved (expires " + expires_at.strftime(EXPIRES_LAYOUT) + ")")
    return token


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _parse(raw):
    try:
        lines = raw.decode("utf-8").strip().split("\n")
    except Exception as e:
        debug.exc("endpoint token decode", e)
        return None
    if len(lines) != 3 or lines[0].strip() != FORMAT or not lines[1].startswith(EXPIRES_PREFIX):
        debug.log("endpoint token file malformed")
        return None
    try:
        expires_at = datetime.datetime.strptime(lines[1][len(EXPIRES_PREFIX):].strip(), EXPIRES_LAYOUT)
        body = base64.b64decode(lines[2].strip(), validate=True)
    except Exception as e:
        debug.exc("endpoint token header parse", e)
        return None
    return expires_at, body


def _unwrap(body, device):
    plat = sys.platform  # via a local so static analysis doesn't prune branches
    if plat == "win32":
        plain = _dpapi_unprotect(body, device)
    else:
        plain = _hmac_unwrap(body, device)
    if not plain:
        return ""
    try:
        return plain.decode("utf-8")
    except Exception as e:
        debug.exc("endpoint token utf-8", e)
        return ""


# --- macOS: HMAC-SHA256 keystream + tag, keyed by the device id ---------------

def derive_key(device):
    return hmac.new(FORMAT.encode("utf-8"), device.encode("utf-8"), hashlib.sha256).digest()


def keystream(key, nonce, length):
    out = b""
    block = 0
    while len(out) < length:
        out += hmac.new(key, nonce + struct.pack(">I", block), hashlib.sha256).digest()
        block += 1
    return out[:length]


def tag(key, nonce, ciphertext):
    return hmac.new(key, b"tag" + nonce + ciphertext, hashlib.sha256).digest()


def _hmac_unwrap(body, device):
    if len(body) < _NONCE_LEN + _TAG_LEN + 1:
        return b""
    nonce = body[:_NONCE_LEN]
    ciphertext = body[_NONCE_LEN:-_TAG_LEN]
    key = derive_key(device)
    if not hmac.compare_digest(tag(key, nonce, ciphertext), body[-_TAG_LEN:]):
        debug.log("endpoint token tag mismatch")
        return b""
    stream = keystream(key, nonce, len(ciphertext))
    return bytes(bytearray(c ^ s for c, s in zip(bytearray(ciphertext), bytearray(stream))))


# --- Windows: DPAPI CryptUnprotectData via ctypes -----------------------------

def _dpapi_unprotect(body, device):
    try:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        def blob(data):
            buf = ctypes.create_string_buffer(data, len(data))
            return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(DATA_BLOB),
            ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL
        cryptprotect_ui_forbidden = 0x1

        entropy = blob(device.encode("utf-8"))
        cipher = blob(body)
        out = DATA_BLOB()
        if not crypt32.CryptUnprotectData(ctypes.byref(cipher), None, ctypes.byref(entropy),
                                          None, None, cryptprotect_ui_forbidden, ctypes.byref(out)):
            debug.log("CryptUnprotectData failed: " + str(ctypes.get_last_error()))
            return b""
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel32.LocalFree(out.pbData)
    except Exception as e:
        debug.exc("dpapi unprotect", e)
        return b""
