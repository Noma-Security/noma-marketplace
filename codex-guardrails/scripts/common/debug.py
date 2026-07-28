"""Opt-in debug logging for the otherwise-silent hook.

The hook degrades quietly by design: every failure is swallowed so a hook can
never surface an error in the user's Claude Code session. That makes a silent
no-op at a customer impossible to diagnose - and a hook's stderr isn't shown in
the session either, so diagnostics have to go somewhere durable.

When NOMA_DEBUG is set, this records a timestamped, leveled, source-located trace
to a LOG FILE via the stdlib ``logging`` module (cross-OS, no third-party deps).
Normal operation stays silent and exit codes never change.

Location: per-user and non-destructive by design - ``~/.noma/<filename>`` (its own
dir at mode 0700, size-capped by rotation, so it can't clobber the user's files or
fill the disk, and isn't a shared /tmp symlink target). The basename defaults to
``guardrails-debug.log``; the consuming plugin brands it via set_log_filename()
(the Claude Code hook sets ``claude-code-guardrails-debug.log``). Override the
full path with NOMA_DEBUG_FILE.

NEVER pass a secret here: log exception types/messages and safe context (command
name, file path, URL, byte counts) - never the API key, credential blob, MCP
env/headers, or the raw stdin/payload.

Stdlib only, no f-strings/annotations - runs on any python3.
"""

import logging
import logging.handlers
import os
import sys

_LOGGER = None
_LOGGER_PATH = None
_LOG_FILENAME = "guardrails-debug.log"  # generic default; plugins brand it via set_log_filename()

# Each line: "2026-06-29 14:23:01,123 ERROR pid=1234 [hook.py:60] message"
_FORMAT = "%(asctime)s %(levelname)s pid=%(process)d [%(noma_where)s] %(message)s"


def enabled():
    """True when debug diagnostics should be recorded (NOMA_DEBUG set)."""
    return bool(os.environ.get("NOMA_DEBUG"))


def set_log_filename(name):
    """Set the log file's basename - the consuming plugin supplies its branding
    (this module stays agent-agnostic; the Claude Code hook passes
    claude-code-guardrails-debug.log). Takes effect on the next log call (the
    logger rebinds when the path changes); NOMA_DEBUG_FILE still overrides the
    full path."""
    global _LOG_FILENAME
    if name:
        _LOG_FILENAME = name


def log_path():
    """The debug log file path (override via NOMA_DEBUG_FILE)."""
    custom = os.environ.get("NOMA_DEBUG_FILE")
    if custom:
        return custom
    home = os.environ.get("HOME") or os.path.expanduser("~")
    return os.path.join(home, ".noma", _LOG_FILENAME)


def _get_logger():
    """A rotating file logger bound to the current log_path(); rebuilt if the path
    changes (so NOMA_DEBUG_FILE is honored and tests stay isolated). None on
    failure - logging must never break the hook."""
    global _LOGGER, _LOGGER_PATH
    path = log_path()
    if _LOGGER is not None and _LOGGER_PATH == path:
        return _LOGGER

    logger = logging.getLogger("noma.guardrails")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # isolated: never reaches the root logger / app output
    for handler in list(logger.handlers):
        try:
            handler.close()
        except Exception:
            pass
        logger.removeHandler(handler)

    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, 0o700, exist_ok=True)
        # ~3 MB cap (1 MB x 3) so a forgotten NOMA_DEBUG can't fill the disk.
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=1048576, backupCount=2)
        handler.setFormatter(logging.Formatter(_FORMAT))
        logger.addHandler(handler)
    except Exception:
        logger = None

    _LOGGER = logger
    _LOGGER_PATH = path
    return logger


def _write(level, msg):
    """Record one line when enabled. Best-effort: a logging failure must never
    break the hook, so everything here is swallowed."""
    if not enabled():
        return
    try:
        frame = sys._getframe(2)  # the caller of log()/exc(), not this module
        where = os.path.basename(frame.f_code.co_filename) + ":" + str(frame.f_lineno)
    except Exception:
        where = "?"
    try:
        logger = _get_logger()
        if logger is not None:
            logger.log(level, msg, extra={"noma_where": where})
    except Exception:
        pass


def log(msg):
    """Record an INFO breadcrumb."""
    _write(logging.INFO, msg)


def exc(context, e):
    """Record an ERROR for a swallowed exception as 'context: ExcType: message'.

    Type + message + the caller-supplied context only - so a secret that
    triggered the failure is never written. Keep ``context`` free of secrets."""
    _write(logging.ERROR, context + ": " + type(e).__name__ + ": " + str(e))


def _reset():
    """Close handlers and drop the cached logger. Tests call this so the log file
    can be read/removed on every platform (Windows keeps the file open otherwise);
    the live hook never needs it (handlers close at process exit)."""
    global _LOGGER, _LOGGER_PATH
    logger = logging.getLogger("noma.guardrails")
    for handler in list(logger.handlers):
        try:
            handler.close()
        except Exception:
            pass
        logger.removeHandler(handler)
    _LOGGER = None
    _LOGGER_PATH = None
