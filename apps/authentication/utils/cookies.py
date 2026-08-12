"""Refresh and CSRF cookie handling.

The access token never touches a cookie -- it lives in JavaScript memory and
travels in an ``Authorization`` header, which the browser never attaches
automatically and CSRF therefore cannot reach. The refresh token is the
opposite: it is a 30-day credential that must survive a page reload, so it goes
in an ``HttpOnly`` cookie where script cannot read it, and the CSRF exposure
that creates is closed by the three controls below.

``__Host-`` is the attribute that matters most here. On a shared parent domain
``acme.eduremus.com`` and ``beta.eduremus.com`` are *same-site* by the
browser's definition, so ``SameSite=Strict`` alone does not stop one
institution's cookie reaching another's host, and a sibling host could set a
``Domain=.eduremus.com`` cookie that shadows this one. The prefix forbids a
``Domain`` attribute outright, which pins the cookie to exactly the host that
set it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from django.conf import settings

from apps.authentication.exceptions import CSRFFailed
from apps.authentication.utils.hashing import constant_time_equal, random_token

if TYPE_CHECKING:
    from datetime import datetime

    from django.http import HttpRequest, HttpResponse
    from rest_framework.request import Request
    from rest_framework.response import Response

    type AnyRequest = HttpRequest | Request
    type AnyResponse = HttpResponse | Response

__all__ = [
    "assert_csrf",
    "clear_auth_cookies",
    "issue_csrf_token",
    "read_refresh_cookie",
    "set_auth_cookies",
]

_HOST_PREFIX: Final = "__Host-"


def set_auth_cookies(
    response: AnyResponse,
    *,
    refresh_token: str,
    csrf_token: str,
    expires_at: datetime,
) -> None:
    """Write both cookies. They are always set and cleared together."""
    _set_refresh_cookie(response, refresh_token, expires_at)
    _set_csrf_cookie(response, csrf_token, expires_at)


def clear_auth_cookies(response: AnyResponse) -> None:
    """Remove both cookies, on logout and on any refresh that fails.

    The delete must repeat the exact path the cookie was set with, or the
    browser keeps the original and the credential outlives the logout.
    """
    config = settings.JWT_AUTH

    for name in (config["REFRESH_COOKIE_NAME"], config["CSRF_COOKIE_NAME"]):
        response.delete_cookie(
            key=name,
            path=_cookie_path(name),
            samesite=config["REFRESH_COOKIE_SAMESITE"],
        )


def read_refresh_cookie(request: AnyRequest) -> str | None:
    """The raw refresh token, or ``None`` when the cookie is absent."""
    return request.COOKIES.get(settings.JWT_AUTH["REFRESH_COOKIE_NAME"]) or None


def issue_csrf_token() -> str:
    """A fresh double-submit value.

    Not a credential in itself: it proves only that the caller could read a
    cookie from this origin. An attacker who can read it already has script
    execution on the origin and does not need CSRF.
    """
    return random_token()


def assert_csrf(request: AnyRequest) -> None:
    """Double-submit verification for the cookie-authenticated endpoints.

    A cross-origin attacker can cause the cookie to be *sent* but cannot read
    it, and so cannot populate the header to match. Compared in constant time
    so the check does not itself leak the value one byte at a time.
    """
    config = settings.JWT_AUTH

    cookie_value = request.COOKIES.get(config["CSRF_COOKIE_NAME"], "")
    header_value = request.headers.get(config["CSRF_HEADER_NAME"], "")

    if not cookie_value or not constant_time_equal(cookie_value, header_value):
        raise CSRFFailed


def _set_refresh_cookie(
    response: AnyResponse, token: str, expires_at: datetime
) -> None:
    config = settings.JWT_AUTH
    name = config["REFRESH_COOKIE_NAME"]

    response.set_cookie(
        key=name,
        value=token,
        expires=expires_at,
        path=_cookie_path(name),
        # Mandatory for the __Host- prefix, and correct regardless: a
        # credential must never be sent in clear. http://localhost counts as a
        # secure context in every current browser, so development is unaffected.
        secure=True,
        # Unreachable from JavaScript, which is what contains the damage an
        # XSS can do to a 30-day credential.
        httponly=True,
        samesite=config["REFRESH_COOKIE_SAMESITE"],
        # Mandatory for the __Host- prefix. Host-only scoping is the point.
        domain=None,
    )


def _set_csrf_cookie(response: AnyResponse, token: str, expires_at: datetime) -> None:
    config = settings.JWT_AUTH
    name = config["CSRF_COOKIE_NAME"]

    response.set_cookie(
        key=name,
        value=token,
        expires=expires_at,
        path=_cookie_path(name),
        secure=True,
        # Deliberately readable by JavaScript: echoing it back in the
        # X-CSRF-Token header is the entire double-submit mechanism.
        httponly=False,
        samesite=config["REFRESH_COOKIE_SAMESITE"],
        domain=None,
    )


def _cookie_path(name: str) -> str:
    """The path a cookie may actually be set with.

    A ``__Host-`` cookie must use ``Path=/``: browsers reject the cookie
    outright otherwise, silently, and the endpoint then behaves as though the
    client never sent one. The configured path is honoured for any cookie not
    carrying the prefix.

    ``Path=/`` is also what makes the double-submit work at all -- JavaScript
    can only read a cookie whose path matches the *current* document, so a
    CSRF cookie scoped to ``/api/v1/auth`` is invisible to an application
    served from ``/``.
    """
    if name.startswith(_HOST_PREFIX):
        return "/"
    return settings.JWT_AUTH["REFRESH_COOKIE_PATH"]
