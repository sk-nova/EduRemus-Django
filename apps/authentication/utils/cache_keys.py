"""The only place a Redis key is constructed.

PostgreSQL isolates tenants with ``search_path``. Redis has no equivalent: it
is one flat keyspace shared by every tenant in the deployment, so isolation
there is purely a naming discipline -- and a naming discipline applied by hand
is eventually forgotten. Every key in the authentication path is therefore
built by :func:`tenant_key` or one of the namespace helpers below, and a
hand-written ``cache.set()`` key anywhere in this app is a review failure.

The failure modes are not theoretical:

======================  ======================================================
Omitted prefix          Result
======================  ======================================================
``denylist``            A ``jti`` revoked in *acme* reads as revoked in *beta*
                        too -- or, when the values differ, a genuinely revoked
                        token in *beta* is not found and stays usable.
``user``                A cached ``User`` from *acme* is served to a request in
                        *beta*: a cross-tenant identity leak through the cache.
``throttle``            One institution's traffic throttles another's.
``lockout``             Tenants serialise against each other; latency scales
                        with tenant count.
======================  ======================================================

Note that ``CACHES["default"]`` deliberately sets no ``KEY_PREFIX``. A static
prefix separates this *application* from others sharing the Redis instance,
which is a different question from separating one tenant from another.
"""

from __future__ import annotations

from typing import Final

from apps.tenants.utils import current_schema_name

__all__ = [
    "denylist_key",
    "lockout_key",
    "session_key",
    "tenant_key",
    "throttle_key",
    "user_key",
]

# Distinguishes this application's keys from anything else in the same Redis
# database. Tenancy is handled separately, by the schema segment.
KEY_PREFIX: Final = "jwt"

# Namespaces, named once. A literal at the call site is how "denylist" becomes
# "denylsit" in one place and a revocation check silently stops matching.
NS_DENYLIST: Final = "denylist"
NS_USER: Final = "user"
NS_LOCKOUT: Final = "lockout"
NS_THROTTLE: Final = "throttle"
NS_SESSION: Final = "session"


def tenant_key(*parts: str) -> str:
    """Build a cache key namespaced to the active schema.

    Reads the schema from the live connection rather than taking it as an
    argument: the caller is always inside a request or an explicit
    ``schema_context``, and deriving it here means a caller cannot pass the
    wrong one.

    >>> tenant_key(NS_DENYLIST, "018f3c6a-8d90-7a11-b2c3-4d5e6f708192")
    'acme:jwt:denylist:018f3c6a-8d90-7a11-b2c3-4d5e6f708192'
    """
    return ":".join((current_schema_name(), KEY_PREFIX, *parts))


def denylist_key(jti: str) -> str:
    """Key for a revoked token id. Entries expire with the token itself."""
    return tenant_key(NS_DENYLIST, jti)


def user_key(user_id: str) -> str:
    """Key for a cached user on the authentication hot path."""
    return tenant_key(NS_USER, user_id)


def lockout_key(*parts: str) -> str:
    """Key for failure counters and lockout state.

    Takes the discriminators (email, IP) as parts rather than one composite
    string so a caller cannot accidentally build ``a:b`` and ``a`` + ``b`` as
    two different keys for the same subject.
    """
    return tenant_key(NS_LOCKOUT, *parts)


def throttle_key(scope: str, ident: str) -> str:
    """Key for a DRF throttle bucket."""
    return tenant_key(NS_THROTTLE, scope, ident)


def session_key(session_id: str) -> str:
    """Key for cached device-session state."""
    return tenant_key(NS_SESSION, session_id)
