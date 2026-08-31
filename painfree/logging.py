"""Structured JSON logging to stdout -- one event per line.

What this implements is not "we have logs". It is that an operator holding
nothing but ``docker logs`` can reconstruct an order end to end by grepping a
single id, and can diagnose a failure without attaching a debugger.

That comes apart into four rules, each of which has a mechanism here rather
than a convention:

* **One event per line, on stdout.** :func:`configure_logging` installs exactly
  one handler on the root logger, so records from uvicorn, SQLAlchemy and this
  service all leave through the same formatter. No files, no rotation, no
  severity split -- splitting streams reorders interleaved events, which is the
  one property a log of a distributed exchange cannot afford to lose.
* **Correlation on every line.** :func:`bind` puts ids in a
  :class:`~contextvars.ContextVar`, so a handler binds ``request_id`` once and
  every line emitted underneath it carries the id -- including lines from
  libraries that have never heard of painfree.
* **Exceptions carry a stack trace.** :meth:`Logger.exception` renders
  ``traceback`` into the line itself, so the trace is one JSON value rather
  than forty unparseable lines.
* **Identity added five names and one habit.** ``client_secret``,
  ``code_verifier``, ``session_id``, ``state`` and ``nonce`` are on the
  blocklist, and the values that a blocklist cannot help with -- an
  authorization code, a session cookie -- are never passed to a log call at
  all. Where one of them has to be traceable across two lines,
  :mod:`painfree.authn` logs the first twelve characters of its SHA-256
  instead, which joins two lines and reconstructs nothing.
* **Secrets never reach the stream.** :func:`redact` is the last thing that
  touches a value. It is defence in depth, not the control: the control is that
  callers log an ``order_id`` and a key fingerprint rather than a payload and a
  key. A blocklist that is the only defence eventually meets a field name it
  has not heard of.
"""

from __future__ import annotations

import contextlib
import contextvars
import datetime as _dt
import json
import logging
import re
import sys
import traceback
from typing import Any, Iterator

#: The ids that tie a line to the work it belongs to. Present when known; a line
#: never invents one. ``request_id`` is always set inside a request.
CORRELATION_FIELDS = (
    "request_id",
    "connection_id",
    "order_id",
    "job_id",
    "idempotency_key",
)

#: Field names whose value never appears in a log line, at any nesting depth.
SENSITIVE_FIELDS = frozenset({
    "authorization", "access_token", "api_key", "authorization_code", "bearer",
    "client_secret", "code_verifier", "cookie", "id_token", "key",
    "key_encryption_secret", "keycode", "nonce", "oidc_client_secret",
    "order_data", "passphrase", "password", "payload", "pem", "private_key",
    "private_pem", "refresh_token", "sealed_private", "sealed_secret",
    "secret", "session_id", "set-cookie", "signing_secret", "state", "token",
    "transaction_key", "webhook_secret",
})

REDACTED = "***"

#: Two shapes that are secret whatever field name they arrive under, and which
#: therefore also get scrubbed out of free text -- an exception message, or the
#: traceback that repeats it. A name-based blocklist cannot see either: it was
#: an interpolated exception message that leaked a bearer token the first time
#: this was tested. Two shapes is all that is claimed; see `SENSITIVE_FIELDS`
#: for the primary, name-based control.
PEM_BLOCK = re.compile(r"-----BEGIN[^-]{0,64}-----.*?-----END[^-]{0,64}-----", re.DOTALL)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?")

#: Longer strings are truncated before they are written. A payload that reached
#: a log line through a field name this module does not know is then a nuisance
#: rather than a disclosure.
MAX_STRING = 512

_context: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "painfree_log_context", default={}
)

_RESERVED = frozenset(vars(logging.makeLogRecord({})))
_IGNORED_ATTRIBUTES = frozenset({"painfree_fields", "painfree_context", "color_message"})


#: Exact strings this process knows are secret, whatever field name -- or none --
#: they arrive under. A shape-based rule cannot see a high-entropy passphrase:
#: it looks like any other string. Registering it is the only way free text that
#: interpolated it can be cleaned, and there is exactly one such value today.
_literal_secrets: set[str] = set()


def register_secret(value: str) -> None:
    """Never write this exact string to the log stream again, anywhere.

    Called by :func:`painfree.sealing.derive_custody_key`, so a process that can
    open the keyring has, by construction, already taught the log stream what
    not to print. Short values are ignored: redacting a common substring would
    make the stream unreadable, and a secret that short is refused elsewhere.
    """
    if value and len(value) >= 16:
        _literal_secrets.add(value)


def scrub(text: str) -> str:
    """Remove the known secrets from free text, leaving the rest readable.

    Used on exception messages and tracebacks, which have to stay diagnosable:
    replacing the whole trace would defeat the point of logging it.
    """
    for secret in _literal_secrets:
        if secret in text:
            text = text.replace(secret, "<redacted:secret>")
    text = PEM_BLOCK.sub("<redacted:pem>", text)
    return JWT.sub("<redacted:jwt>", text)


def context() -> dict[str, Any]:
    """The correlation ids currently bound, as a copy."""
    return dict(_context.get())


@contextlib.contextmanager
def bind(**fields: Any) -> Iterator[dict[str, Any]]:
    """Bind correlation ids for the duration of the block.

    Nested binds add to the enclosing ones; ``None`` values are dropped so a
    caller can pass an id it may not have without writing ``"job_id": null`` on
    every line.
    """
    merged = {**_context.get(), **{k: v for k, v in fields.items() if v is not None}}
    token = _context.set(merged)
    try:
        yield merged
    finally:
        _context.reset(token)


def redact(value: Any, *, key: str | None = None) -> Any:
    """Return ``value`` with anything that must not be logged removed.

    Applied to log fields and, by :mod:`painfree.audit`, to what is written to
    the audit log -- an audit trail is read by more people than a log stream is,
    so it gets the same treatment.
    """
    if key is not None and key.lower() in SENSITIVE_FIELDS:
        return REDACTED
    if isinstance(value, dict):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if isinstance(value, str):
        if "-----BEGIN" in value:
            return "<redacted:pem>"
        value = scrub(value)
        if len(value) > MAX_STRING:
            return value[:MAX_STRING] + f"…<truncated, {len(value)} chars>"
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))


class JsonFormatter(logging.Formatter):
    """Render one record as one line of JSON.

    Ordering is deliberate: timestamp, level, logger, event, then the
    correlation ids, then everything else. A human scanning the stream reads the
    same prefix on every line.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003 - stdlib name
        bound = getattr(record, "painfree_context", None)
        if bound is None:
            bound = context()
        fields = dict(getattr(record, "painfree_fields", {}) or {})

        # Records from libraries carry their extras as plain attributes.
        # `color_message` is uvicorn's ANSI-escaped copy of the message it just
        # logged; in a JSON stream it is the same sentence twice, once unreadable.
        for name, value in vars(record).items():
            if name in _RESERVED or name in _IGNORED_ATTRIBUTES:
                continue
            fields.setdefault(name, value)

        line: dict[str, Any] = {
            "timestamp": _dt.datetime.fromtimestamp(
                record.created, tz=_dt.timezone.utc
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        for name in CORRELATION_FIELDS:
            # An id that is not known is absent, never `null`. A line reading
            # `"order_id": null` invites a grep that silently matches nothing.
            if bound.get(name) is not None:
                line[name] = bound[name]
                fields.pop(name, None)
            elif fields.get(name) is not None:
                line[name] = redact(fields.pop(name), key=name)
            else:
                fields.pop(name, None)
        for name, value in fields.items():
            if name in line:
                continue
            line[name] = redact(value, key=name)

        if record.exc_info:
            exc_type, exc, tb = record.exc_info
            line["exception"] = getattr(exc_type, "__name__", str(exc_type))
            line["exception_message"] = redact(str(exc))
            # The trace is scrubbed rather than redacted: it has to stay
            # complete enough to debug from, and it repeats the exception
            # message, which is free text a call site may have interpolated
            # a credential into.
            line["traceback"] = scrub(
                "".join(traceback.format_exception(exc_type, exc, tb))
            )

        return json.dumps(line, ensure_ascii=False, default=str)


class _Stdout:
    """Whatever ``sys.stdout`` is *now*, not what it was at install time.

    ``logging.StreamHandler`` binds its stream once. That is wrong for a process
    whose stdout can be replaced -- a test harness capturing it, or a supervisor
    reopening it -- and it silently sends the lines somewhere no one is reading.
    """

    def write(self, text: str) -> int:
        return sys.stdout.write(text)

    def flush(self) -> None:
        sys.stdout.flush()


def configure_logging(level: str = "INFO", *, stream: Any = None) -> logging.Handler:
    """Install the one handler this process logs through.

    Idempotent: calling it again replaces the handler rather than adding a
    second one, which is what makes it safe from both lifespan startup and a
    test fixture.
    """
    handler = logging.StreamHandler(_Stdout() if stream is None else stream)
    handler.setFormatter(JsonFormatter())
    handler.set_name("painfree")

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    # uvicorn installs its own handlers on import; let its records reach ours
    # instead of being printed twice in two different formats.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True

    # uvicorn's access log is one line per request that carries no correlation
    # id -- it runs outside the middleware that binds one. `request.completed`
    # is the same fact with the id attached, so the uncorrelated twin is turned
    # off rather than left to double every request and drown the probe traffic
    # that `PROBE_PATHS` deliberately logs at debug.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    # `httpx` logs one line per request it makes, with the whole URL -- query
    # string included. Nothing in this service passes a credential in a query
    # string, but an HTTP client's own request log is not the place to find out:
    # it carries no correlation id and duplicates a call site that does.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Alembic narrates every migration context it opens at INFO. The fact worth
    # keeping -- what the schema went from and to -- is emitted structurally by
    # `painfree.db.migrate`, so the prose is turned down rather than left to
    # dilute a stream an operator is meant to grep.
    logging.getLogger("alembic").setLevel(logging.WARNING)
    return handler


class Logger:
    """A thin structured wrapper: an event name, then keyword fields.

    Deliberately not a ``LoggerAdapter``. The point is that ``log.info("x", a=1)``
    is the only shape available, so no call site can produce an interpolated
    sentence that the formatter would have to parse back apart.
    """

    __slots__ = ("_logger",)

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    def _emit(self, level: int, event: str, exc_info: Any = None, **fields: Any) -> None:
        if not self._logger.isEnabledFor(level):
            return
        self._logger.log(
            level,
            event,
            exc_info=exc_info,
            extra={"painfree_fields": fields, "painfree_context": context()},
            stacklevel=3,
        )

    def debug(self, event: str, **fields: Any) -> None:
        self._emit(logging.DEBUG, event, **fields)

    def info(self, event: str, **fields: Any) -> None:
        self._emit(logging.INFO, event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._emit(logging.WARNING, event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self._emit(logging.ERROR, event, **fields)

    def exception(self, event: str, exc_info: Any = True, **fields: Any) -> None:
        """Log where the exception was caught, with the trace.

        Every call site that uses this then decides, on the next line, whether
        to re-raise or convert. A bare ``except: pass`` fails review.
        """
        self._emit(logging.ERROR, event, exc_info=exc_info, **fields)


def get_logger(name: str) -> Logger:
    return Logger(name)
