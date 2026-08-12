"""Facts derived from the incoming request.

Everything here is client-supplied and therefore forgeable. The values are
used for audit records, session lists and anomaly scoring -- never as an
authorisation input. :func:`client_ip` is the one exception that needs care,
because lockout and throttling key on it: a spoofable address is a lockout
bypass in one direction and a denial-of-service lever in the other.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from typing import TYPE_CHECKING, Final

from django.conf import settings

if TYPE_CHECKING:
    from django.http import HttpRequest
    from rest_framework.request import Request

    # DRF's Request is not an HttpRequest subclass; it proxies to one. Both
    # are accepted because these helpers are called from views, authentication
    # classes and middleware alike.
    type AnyRequest = HttpRequest | Request

__all__ = [
    "client_ip",
    "device_identifier",
    "request_id",
    "user_agent",
]

# Echoed back to the client and written into logs, so it is bounded and
# restricted to characters that cannot break a header or a log line.
_REQUEST_ID_PATTERN: Final = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")

_USER_AGENT_MAX_LENGTH: Final = 512

# Not an HTTP_* key: nothing arriving from the client can collide with it.
_REQUEST_ID_META_KEY: Final = "eduremus.request_id"

_DEVICE_ID_LENGTH: Final = 16


def client_ip(request: AnyRequest) -> str | None:
    """The caller's address, honouring ``X-Forwarded-For`` only when trusted.

    ``X-Forwarded-For`` is a request header like any other: anyone can send
    one. It is read only when ``JWT_AUTH["TRUSTED_PROXY_HOPS"]`` says how many
    proxies actually sit in front of the application, and then only at the
    position those proxies control. With the default of 0 the header is
    ignored entirely, which is the correct behaviour for a deployment with no
    reverse proxy and the safe default for one that has not been characterised.

    Returns ``None`` rather than a placeholder when nothing parses: the audit
    and login-attempt columns are ``inet`` and reject a non-address, and a
    silent ``"0.0.0.0"`` would quietly merge unrelated clients into one
    lockout bucket.
    """
    hops = int(settings.JWT_AUTH.get("TRUSTED_PROXY_HOPS", 0))

    if hops > 0:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        chain = [part.strip() for part in forwarded.split(",") if part.strip()]
        # Each proxy appends the address it saw, so the entry written by the
        # outermost trusted hop is `hops` from the end. Anything to the left
        # of it was supplied by the client and is not evidence of anything.
        if len(chain) >= hops:
            candidate = _normalise_ip(chain[-hops])
            if candidate is not None:
                return candidate

    return _normalise_ip(request.META.get("REMOTE_ADDR", ""))


def device_identifier(request: AnyRequest) -> str:
    """A stable, non-identifying fingerprint for the calling device.

    Not a security control -- every input is client-supplied and forgeable. It
    exists so a user can recognise "Chrome on Windows" in their session list,
    and so an impossible-travel heuristic has something to key on. Never gate
    authorisation on it: browsers change their user agent on every update and
    corporate proxies rewrite these headers wholesale, so a hard check on this
    value rejects legitimate users constantly.
    """
    from apps.authentication.utils.hashing import sha256_hex

    material = "|".join(
        (
            request.META.get("HTTP_USER_AGENT", ""),
            request.META.get("HTTP_ACCEPT_LANGUAGE", ""),
            request.headers.get("X-Device-Id", ""),
        )
    )
    return sha256_hex(material)[:_DEVICE_ID_LENGTH]


def user_agent(request: AnyRequest) -> str:
    """The ``User-Agent`` header, truncated to what the column can hold."""
    return request.META.get("HTTP_USER_AGENT", "")[:_USER_AGENT_MAX_LENGTH]


def request_id(request: AnyRequest | None = None) -> str:
    """The correlation id for this request.

    A client-supplied ``X-Request-Id`` is honoured so a trace survives across
    service boundaries, but only when it is short and alphanumeric. The value
    is echoed in a response header and written to logs, where an unvalidated
    string is a header-injection and log-forging vector.
    """
    if request is not None:
        supplied = request.headers.get("X-Request-Id", "")
        if _REQUEST_ID_PATTERN.match(supplied):
            return supplied

        # Cached in META -- a plain dict on both request flavours -- so the
        # exception handler, the audit record and the response header all
        # report the same value for one request.
        cached = request.META.get(_REQUEST_ID_META_KEY)
        if isinstance(cached, str):
            return cached

    generated = str(uuid.uuid7())

    if request is not None:
        request.META[_REQUEST_ID_META_KEY] = generated

    return generated


def _normalise_ip(value: str) -> str | None:
    """Validate an address, tolerating the ``addr:port`` some proxies emit."""
    candidate = value.strip()
    if not candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    # "203.0.113.7:41234" -- an IPv4 address with a port. Bracketed IPv6
    # ("[2001:db8::1]:443") is handled by the same split on the closing
    # bracket. A bare IPv6 address has already parsed above.
    host = candidate.rsplit("]:", 1)[0].lstrip("[")
    if host == candidate:
        host = candidate.rsplit(":", 1)[0]

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None
