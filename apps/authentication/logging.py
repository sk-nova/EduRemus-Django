"""Structured logging for the authentication path.

Two fields turn an authentication log line from an anecdote into evidence:

``schema``
    Which institution the line belongs to. Without it a log stream from a
    multi-tenant deployment cannot answer "what happened to *this* customer",
    which is the first question of both incident response and any per-tenant
    compliance review.
``request_id``
    Which request produced it. One authentication decision emits records from
    the middleware, the authenticator, a service and the exception handler;
    without a correlation id they are four unrelated lines.

Both are attached by filters rather than by the call sites, because a field
that every logger has to remember to pass is a field that is missing from
exactly the line you need.

**Never log a credential.** Not a token, not a fragment of one, not a
password, not an ``Authorization`` header. Logs are shipped to aggregators,
retained for months and read by people with no need for credential access, so
a token in a log line is a credential disclosed to all of them for the whole
retention period. Log the ``jti`` instead: it identifies a token without being
usable as one. :class:`SensitiveDataFilter` is the backstop for that rule, not
a licence to relax it -- it can only redact what it recognises.
"""

from __future__ import annotations

import json
import logging
import re
from contextvars import ContextVar
from typing import Any, Final

from apps.tenants.utils import current_schema_name

__all__ = [
    "JsonFormatter",
    "RequestIdFilter",
    "SensitiveDataFilter",
    "TenantContextFilter",
    "bind_request_id",
    "current_request_id",
    "request_id_var",
]

# A contextvar rather than thread-local storage: it is the one mechanism that
# survives both threads and async tasks, and the authentication path is
# reachable from both.
request_id_var: ContextVar[str] = ContextVar("eduremus_request_id", default="")

REDACTED: Final = "[redacted]"

# Any compact JWS: three base64url segments. Matched on shape rather than on
# where it appeared, because the whole point of a backstop is to catch the
# call site nobody reviewed.
_JWT_PATTERN: Final = re.compile(
    r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"
)

# Record attributes whose *value* is a credential, whatever the name suggests
# it holds. Compared case-insensitively against the extra fields a caller
# attached; the standard LogRecord attributes are never emitted anyway.
_SENSITIVE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "cookie",
        "credentials",
        "csrf_token",
        "http_authorization",
        "password",
        "private_key",
        "private_pem",
        "raw_token",
        "refresh_token",
        "secret",
        "session_key",
        "set_cookie",
        "token",
    }
)

# Everything the logging module puts on a record itself. Anything outside this
# set arrived through ``extra=`` and is what the JSON document is for.
_STANDARD_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


def current_request_id() -> str:
    """The correlation id bound to this request, or an empty string."""
    return request_id_var.get()


def bind_request_id(value: str) -> object:
    """Bind the correlation id, returning the token needed to unbind it."""
    return request_id_var.set(value)


# ---------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------


class TenantContextFilter(logging.Filter):
    """Attach the active schema to every record.

    Read from the live connection rather than passed in: the schema is
    connection state, and a value carried alongside the call could disagree
    with the one the query actually ran against.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.schema = current_schema_name()
        return True


class RequestIdFilter(logging.Filter):
    """Attach the correlation identifier bound by the middleware.

    Falls back to the request on the record when the contextvar is empty.
    That case is not hypothetical: Django logs ``Unauthorized: /path`` from
    ``BaseHandler.get_response``, which runs *after* the middleware chain has
    unwound and the contextvar has been reset -- so without the fallback the
    4xx and 5xx lines, the ones most worth correlating, would be the only ones
    with no id. ``request_meta.request_id`` caches its value on the request,
    so this returns what the middleware already decided rather than a new one.

    Records emitted outside a request -- management commands, migrations,
    startup -- carry an empty value rather than no field at all, so the log
    schema stays uniform for whatever parses it downstream.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get() or _from_record(record)
        return True


def _from_record(record: logging.LogRecord) -> str:
    request = getattr(record, "request", None)
    if request is None:
        return ""

    from apps.authentication.utils.request_meta import request_id

    try:
        return request_id(request)
    except AttributeError:
        # Django's own logging attaches whatever it was given; a record
        # carrying something that is not a request must not break the handler.
        return ""


class SensitiveDataFilter(logging.Filter):
    """Redact credentials that reached a log record despite the rule above.

    Mutating the record in place is deliberate: a filter that only *reported*
    a leak would still emit it. Two passes -- named fields whose value is a
    credential by definition, and anything JWT-shaped anywhere in the message.

    This is a backstop. It recognises the shapes it knows about, which is not
    the same as making it safe to log a credential.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in list(record.__dict__.items()):
            if key.lower() in _SENSITIVE_FIELDS:
                record.__dict__[key] = REDACTED
            elif isinstance(value, str):
                record.__dict__[key] = _scrub(value)

        if isinstance(record.msg, str):
            record.msg = _scrub(record.msg)

        if record.args:
            record.args = _scrub_args(record.args)

        return True


def _scrub(value: str) -> str:
    return _JWT_PATTERN.sub(REDACTED, value)


def _scrub_args(args: Any) -> Any:
    """Scrub ``%``-style arguments, whichever form they were passed in."""
    if isinstance(args, dict):
        return {
            key: (
                REDACTED
                if str(key).lower() in _SENSITIVE_FIELDS
                else (_scrub(value) if isinstance(value, str) else value)
            )
            for key, value in args.items()
        }
    if isinstance(args, tuple):
        return tuple(_scrub(item) if isinstance(item, str) else item for item in args)
    return args


# ---------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with every ``extra`` field promoted to a key.

    Hand-written rather than pulled from a library: the output is a dozen
    lines of ``json.dumps``, the alternative is a dependency on the
    authentication path's log handler, and the fallback for a value that
    cannot be serialised has to be "repr it and keep going" -- a log record is
    never worth raising over.
    """

    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRIBUTES or key in document:
                continue
            document[key] = value

        if record.exc_info:
            document["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            document["stack"] = self.formatStack(record.stack_info)

        return json.dumps(document, default=repr, ensure_ascii=False)
