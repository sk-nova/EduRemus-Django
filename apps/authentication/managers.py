"""Querysets for the token models.

Note what is absent: nothing here filters by tenant. There is no tenant column
to filter on, and adding one would be a second isolation mechanism capable of
disagreeing with the first. The ``search_path`` decides which schema's table a
query resolves against, so ``RefreshToken.objects.active()`` in a request for
*acme* can only ever see *acme* rows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.db import models
from django.utils import timezone

if TYPE_CHECKING:
    # Resolved by mypy for the QuerySet[...] parameters below. Those are
    # subscripts on a base class rather than annotations, so ruff cannot see
    # the names being used and reports them unused.
    from apps.authentication.models import (  # noqa: F401
        DeviceSession,
        RefreshToken,
    )

__all__ = [
    "DeviceSessionManager",
    "DeviceSessionQuerySet",
    "RefreshTokenManager",
    "RefreshTokenQuerySet",
]


class RefreshTokenQuerySet(models.QuerySet["RefreshToken"]):
    def active(self) -> RefreshTokenQuerySet:
        """Redeemable right now: ACTIVE and not yet past ``expires_at``.

        Both halves matter. A row keeps its ACTIVE status after its expiry
        passes -- nothing sweeps the table on a timer -- so status alone would
        return tokens that can no longer be redeemed.
        """
        return self.filter(status="active", expires_at__gt=timezone.now())

    def expired(self) -> RefreshTokenQuerySet:
        return self.filter(expires_at__lte=timezone.now())

    def for_family(self, family_id: object) -> RefreshTokenQuerySet:
        return self.filter(family_id=family_id)

    def for_user(self, user_id: object) -> RefreshTokenQuerySet:
        return self.filter(user_id=user_id)

    def compromised(self) -> RefreshTokenQuerySet:
        return self.filter(status="compromised")


class DeviceSessionQuerySet(models.QuerySet["DeviceSession"]):
    def live(self) -> DeviceSessionQuerySet:
        return self.filter(ended_at__isnull=True)

    def for_user(self, user_id: object) -> DeviceSessionQuerySet:
        return self.filter(user_id=user_id)


RefreshTokenManager = models.Manager.from_queryset(RefreshTokenQuerySet)
DeviceSessionManager = models.Manager.from_queryset(DeviceSessionQuerySet)
