"""Credential revocation at session, family, user and tenant granularity.

Two mechanisms, used together:

``token_version``
    One ``UPDATE`` on the user row invalidates every outstanding *access*
    token that account holds, because each carries the value it was minted
    with as ``jtv``. No enumeration, no per-token write, effective on the very
    next request.
``RefreshToken.status``
    The durable record of which refresh credentials may still be redeemed.

Plus the denylist for access tokens that must die before their short expiry.

The cache invalidation below is not an optimisation detail -- it is part of
the revocation. A cached ``User`` still carrying the old ``token_version``
makes every outstanding token valid for the remainder of the cache TTL, which
is the single most likely way to ship a "log out everywhere" that appears to
work and does not.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import UUID

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import transaction
from django.db.models import F
from django.utils import timezone

from apps.authentication.models import (
    AuthEventType,
    DeviceSession,
    RefreshToken,
    RevocationReason,
    TokenFamily,
    TokenStatus,
)
from apps.authentication.services import audit
from apps.authentication.tokens.denylist import denylist, denylist_many
from apps.authentication.utils.cache_keys import user_key

if TYPE_CHECKING:
    from datetime import datetime

    from django.http import HttpRequest
    from rest_framework.request import Request

    from apps.accounts.models import User

    type AnyRequest = HttpRequest | Request

logger = logging.getLogger("eduremus.auth")
UserModel = get_user_model()

__all__ = ["RevocationService"]


class RevocationService:
    """Revokes credentials in the active schema."""

    # -- one session ---------------------------------------------------

    def revoke_family(
        self,
        family_id: UUID | str,
        *,
        reason: RevocationReason,
        compromised: bool = False,
    ) -> int:
        """Revoke a whole refresh lineage and denylist what remains live.

        ``compromised`` records the stronger status used for reuse detection,
        which is what distinguishes an orderly logout from a lineage that was
        forcibly torn down in the forensic record.
        """
        status = TokenStatus.COMPROMISED if compromised else TokenStatus.REVOKED
        now = timezone.now()
        identifier = family_id if isinstance(family_id, UUID) else UUID(str(family_id))

        live = list(
            RefreshToken.objects.filter(family_id=identifier)
            .exclude(status__in=(TokenStatus.EXPIRED, TokenStatus.REVOKED))
            .values_list("jti", "expires_at")
        )

        revoked = (
            RefreshToken.objects.filter(family_id=identifier)
            .exclude(status=TokenStatus.EXPIRED)
            .update(status=status, revoked_at=now, revocation_reason=reason)
        )
        TokenFamily.objects.filter(pk=identifier, revoked_at__isnull=True).update(
            revoked_at=now, revocation_reason=reason
        )

        for jti, expires_at in live:
            denylist(str(jti), expires_at=expires_at)

        return revoked

    def revoke_access_token(self, jti: str, *, expires_at: datetime) -> None:
        """Deny one access token for the remainder of its short life."""
        denylist(jti, expires_at=expires_at)

    # -- one user ------------------------------------------------------

    def revoke_all_for_user(
        self,
        user: User,
        *,
        reason: RevocationReason,
        actor: User | None = None,
        request: AnyRequest | None = None,
        event: str = AuthEventType.FORCE_LOGOUT,
    ) -> int:
        """Invalidate every credential this account holds in this schema."""
        now = timezone.now()

        with transaction.atomic():
            # all_objects: a soft-deleted account still needs its outstanding
            # credentials killed, and `objects` would not find the row.
            UserModel.all_objects.filter(pk=user.pk).update(
                token_version=F("token_version") + 1,
                updated_at=now,
            )
            live = list(
                RefreshToken.objects.active()
                .filter(user=user)
                .values_list("jti", "expires_at")
            )
            revoked = (
                RefreshToken.objects.active()
                .filter(user=user)
                .update(
                    status=TokenStatus.REVOKED,
                    revoked_at=now,
                    revocation_reason=reason,
                )
            )
            TokenFamily.objects.filter(user=user, revoked_at__isnull=True).update(
                revoked_at=now, revocation_reason=reason
            )
            DeviceSession.objects.filter(user=user, ended_at__isnull=True).update(
                ended_at=now
            )

        # Outside the transaction on purpose: the cache is not transactional,
        # and a Redis round-trip inside an open transaction lengthens the lock
        # window on rows other requests are waiting for.
        self.invalidate_user_cache(user.pk)
        for jti, expires_at in live:
            denylist(str(jti), expires_at=expires_at)

        audit.record(
            event,
            user=user,
            actor=actor,
            request=request,
            detail={"reason": str(reason), "refresh_tokens_revoked": revoked},
        )
        return revoked

    # -- one tenant ----------------------------------------------------

    def revoke_all_in_schema(
        self,
        *,
        reason: RevocationReason = RevocationReason.TENANT_SUSPENDED,
        actor: User | None = None,
    ) -> int:
        """Invalidate every credential in the *currently active* schema.

        Used when a tenant is suspended. Flipping ``Tenant.is_active`` makes
        the middleware 404 subsequent requests, which covers traffic passing
        through it -- but not a gateway doing signature-only validation, nor a
        worker holding a token minted before the suspension. Those need the
        credentials themselves revoked, which is what this does.

        The caller is responsible for being inside the right schema; there is
        no tenant argument precisely because there is no tenant column.
        """
        now = timezone.now()

        with transaction.atomic():
            UserModel.all_objects.filter(deleted_at__isnull=True).update(
                token_version=F("token_version") + 1,
                updated_at=now,
            )
            live = list(
                RefreshToken.objects.active().values_list(
                    "user_id", "jti", "expires_at"
                )
            )
            revoked = RefreshToken.objects.active().update(
                status=TokenStatus.REVOKED,
                revoked_at=now,
                revocation_reason=reason,
            )
            TokenFamily.objects.filter(revoked_at__isnull=True).update(
                revoked_at=now, revocation_reason=reason
            )
            DeviceSession.objects.filter(ended_at__isnull=True).update(ended_at=now)

        for user_id in {row[0] for row in live}:
            self.invalidate_user_cache(user_id)
        for _, jti, expires_at in live:
            denylist(str(jti), expires_at=expires_at)

        audit.record(
            AuthEventType.TENANT_SUSPENDED,
            actor=actor,
            detail={"reason": str(reason), "refresh_tokens_revoked": revoked},
        )
        return revoked

    # -- helpers -------------------------------------------------------

    @staticmethod
    def invalidate_user_cache(user_id: object) -> None:
        """Drop the cached user so the next request re-reads ``token_version``."""
        cache.delete(user_key(str(user_id)))

    @staticmethod
    def denylist_jtis(jtis: list[str], *, expires_at: datetime) -> int:
        return denylist_many(jtis, expires_at=expires_at)
