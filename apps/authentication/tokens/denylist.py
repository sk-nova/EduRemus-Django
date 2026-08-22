"""Redis denylist for revoked tokens.

An access token is valid until it expires; that is what makes it cheap to
verify and what makes revoking one require somewhere to write "not this one".
Entries carry a TTL equal to the token's remaining lifetime, so they expire on
their own and no cleanup job exists to forget to run. Denylist size is bounded
by roughly *revocation rate x maximum token lifetime*.

This module is the one place in the codebase that fails **closed**. Everywhere
else a Redis outage degrades: a cache miss costs a query and nothing more. A
denylist miss is categorically different -- it answers "not revoked" for a
credential that was revoked, which is the wrong answer in the one direction
that matters. When revocation state cannot be read, the request is refused.

That is why the reads below go through their own cache alias. The default
alias sets ``IGNORE_EXCEPTIONS``, which converts a connection failure into a
``None`` return -- indistinguishable from "no entry found", and silently
fatal here. The denylist alias leaves it off so the failure surfaces as an
exception this module can turn into a 503.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.cache import caches
from django.utils import timezone

from apps.authentication import metrics
from apps.authentication.exceptions import ServiceUnavailable
from apps.authentication.utils.cache_keys import denylist_key

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

    from django.core.cache.backends.base import BaseCache

logger = logging.getLogger("eduremus.auth")

__all__ = ["denylist", "denylist_many", "is_denylisted"]


def _cache() -> BaseCache:
    return caches[settings.JWT_AUTH["DENYLIST_CACHE_ALIAS"]]


def denylist(jti: str, *, expires_at: datetime) -> None:
    """Mark a token as revoked until it would have expired anyway.

    A failure here is deliberately allowed to propagate. The caller is inside
    a transaction that also writes the durable revocation row, and a rollback
    that reports failure is better than a commit claiming a credential was
    revoked when the fast path never learned about it.
    """
    ttl = int((expires_at - timezone.now()).total_seconds())
    if ttl <= 0:
        # Already past its expiry; the signature check rejects it regardless,
        # and an entry with a non-positive TTL would be stored forever by some
        # backends.
        return

    _cache().set(denylist_key(jti), True, ttl)


def denylist_many(jtis: Iterable[str], *, expires_at: datetime) -> int:
    """Revoke a whole family at once. Returns the number of entries written."""
    ttl = int((expires_at - timezone.now()).total_seconds())
    if ttl <= 0:
        return 0

    entries = {denylist_key(jti): True for jti in jtis}
    if not entries:
        return 0

    _cache().set_many(entries, ttl)
    return len(entries)


def is_denylisted(jti: str) -> bool:
    """Whether this token has been explicitly revoked.

    Fails closed: an unreachable denylist raises rather than answering.
    """
    try:
        return bool(_cache().get(denylist_key(jti), False))
    except Exception:
        # Deliberately broad. Every failure mode of the cache backend -- a
        # refused connection, a timeout, a serialisation error -- has the same
        # consequence here, and none of them may be read as "not revoked".
        # Counted as well as logged: this is the metric the "API is failing
        # closed" alert reads, and it has to work when the database that would
        # hold an audit row is equally unreachable.
        metrics.record_denylist_error()
        logger.exception("denylist_unavailable", extra={"jti": jti})
        raise ServiceUnavailable from None
