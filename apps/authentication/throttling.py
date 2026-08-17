"""Rate limiting, scoped per tenant.

An unscoped throttle key lets one institution's traffic exhaust another's
budget. It is easy to miss because nothing about a rate limiter looks like a
security control -- but a shared bucket is a cross-tenant availability lever,
and a shared *login* bucket is also a way to learn that another tenant is
being attacked.

Every key here is built by ``utils.cache_keys``. None is assembled inline,
which is the same rule the denylist and the user cache follow.

Throttles fail **open**: DRF swallows cache errors and allows the request, and
the ``default`` cache alias is configured with ``IGNORE_EXCEPTIONS``. That is
the intended policy -- a counter outage must not become an availability
outage, with the WAF as the outer backstop.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from rest_framework.throttling import (
    AnonRateThrottle,
    ScopedRateThrottle,
    SimpleRateThrottle,
    UserRateThrottle,
)

from apps.authentication.utils.cache_keys import throttle_key
from apps.authentication.utils.hashing import sha256_hex

if TYPE_CHECKING:
    from rest_framework.request import Request
    from rest_framework.views import APIView

__all__ = [
    "LoginRateThrottle",
    "PasswordChangeRateThrottle",
    "RefreshRateThrottle",
    "TenantScopedAnonThrottle",
    "TenantScopedEndpointThrottle",
    "TenantScopedUserThrottle",
]


def _principal(throttle: SimpleRateThrottle, request: Request) -> str:
    """The user's id when authenticated, otherwise the client address."""
    user = getattr(request, "user", None)
    if user is not None and user.is_authenticated:
        return str(user.pk)
    return str(throttle.get_ident(request))


class TenantScopedUserThrottle(UserRateThrottle):
    """The authenticated baseline, counted per user per schema."""

    def get_cache_key(self, request: Request, view: APIView) -> str | None:
        user = getattr(request, "user", None)
        if not (user and user.is_authenticated):
            return None
        return throttle_key(self.scope, str(user.pk))


class TenantScopedAnonThrottle(AnonRateThrottle):
    """The anonymous baseline, counted per address per schema."""

    def get_cache_key(self, request: Request, view: APIView) -> str | None:
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            return None
        return throttle_key(self.scope, str(self.get_ident(request)))


class TenantScopedEndpointThrottle(ScopedRateThrottle):
    """Per-endpoint limits, driven by ``view.throttle_scope``.

    Covers the endpoints whose rate differs from the baseline but whose key is
    the ordinary one -- verify, sessions, logout, logout-all, revoke.
    """

    def get_cache_key(self, request: Request, view: APIView) -> str | None:
        scope = getattr(view, self.scope_attr, None)
        if not scope:
            return None
        return throttle_key(str(scope), _principal(self, request))


class LoginRateThrottle(SimpleRateThrottle):
    """Login, keyed by schema + address + email.

    Both dimensions on purpose. Keying on the email as well as the address
    limits a distributed campaign against one account even when every request
    comes from a different network, while keying on the address as well as the
    email stops one office NAT from throttling everyone behind it.
    """

    scope = "login"

    def get_cache_key(self, request: Request, view: APIView) -> str | None:
        email = str(request.data.get("email", "") or "").lower()[:254]
        return throttle_key(self.scope, f"{self.get_ident(request)}:{email}")


class RefreshRateThrottle(SimpleRateThrottle):
    """Rotation, keyed per session, which catches a client refresh loop."""

    scope = "refresh"

    def get_cache_key(self, request: Request, view: APIView) -> str | None:
        cookie = request.COOKIES.get(settings.JWT_AUTH["REFRESH_COOKIE_NAME"], "")
        if not cookie:
            return None
        # Hashed, never stored raw: a refresh token must not become a Redis
        # key, where anything with cache access could read a live credential.
        return throttle_key(self.scope, sha256_hex(cookie)[:32])


class PasswordChangeRateThrottle(SimpleRateThrottle):
    """Password change, keyed per user. Limits history probing."""

    scope = "password_change"

    def get_cache_key(self, request: Request, view: APIView) -> str | None:
        user = getattr(request, "user", None)
        if not (user and user.is_authenticated):
            return None
        return throttle_key(self.scope, str(user.pk))
