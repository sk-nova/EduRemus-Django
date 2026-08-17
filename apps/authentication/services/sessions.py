"""Device sessions: creation, the per-user cap, listing and termination.

A session spans one login on one device and survives every refresh rotation
within it -- ``sid`` is stable while ``jti`` changes on each rotation. That is
what lets "sign out my other devices" mean something to a user, and what gives
the audit trail a stable handle to correlate on.

``device_id`` is advisory throughout. Every input to it is client-supplied and
forgeable, so it is used for recognition ("Chrome on Windows") and anomaly
scoring, never for an authorisation decision.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.authentication.models import (
    DeviceSession,
    RefreshToken,
    RevocationReason,
    TokenFamily,
    TokenStatus,
)

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from apps.accounts.models import User

# Session ids arrive both as UUIDs (from the ORM) and as strings (from the
# ``sid`` claim), so callers are spared the conversion.
type SessionId = UUID | str


def _as_uuid(value: SessionId) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))


__all__ = ["DeviceSessionService"]


class DeviceSessionService:
    """Session lifecycle within the active schema."""

    @property
    def _cap(self) -> int:
        return int(settings.JWT_AUTH["MAX_ACTIVE_SESSIONS_PER_USER"])

    def open(
        self,
        *,
        user: User,
        device_id: str,
        device_name: str = "",
        user_agent: str = "",
        ip_address: str | None = None,
    ) -> DeviceSession:
        """Start a session, retiring the oldest ones if the cap is reached."""
        self.enforce_cap(user)
        return DeviceSession.objects.create(
            user=user,
            device_id=device_id,
            device_name=device_name[:100],
            user_agent=user_agent[:512],
            ip_address=ip_address,
            last_seen_at=timezone.now(),
        )

    def live_for(self, user: User) -> QuerySet[DeviceSession]:
        """Sessions the user could still be using, newest first."""
        return DeviceSession.objects.live().for_user(user.pk)

    def touch(self, session_id: SessionId, *, ip_address: str | None = None) -> None:
        """Record activity on a session.

        A queryset update rather than a model save: this runs on request paths
        where the session object has not been loaded, and there is nothing to
        gain from fetching a row only to write one column back.
        """
        fields: dict[str, object] = {"last_seen_at": timezone.now()}
        if ip_address:
            fields["ip_address"] = ip_address
        DeviceSession.objects.filter(
            pk=_as_uuid(session_id), ended_at__isnull=True
        ).update(**fields)

    @transaction.atomic
    def end(
        self,
        session_id: SessionId,
        *,
        user: User,
        reason: RevocationReason = RevocationReason.LOGOUT,
    ) -> bool:
        """End one session and revoke the credentials scoped to it.

        Filtered by user as well as by id: a session identifier is not a
        capability, so terminating one must be authorised by ownership rather
        than by knowing the id.

        Returns whether a live session was actually ended, so callers can stay
        idempotent without treating "already ended" as an error.
        """
        identifier = _as_uuid(session_id)
        ended = DeviceSession.objects.filter(
            pk=identifier, user=user, ended_at__isnull=True
        ).update(ended_at=timezone.now())

        if not ended:
            return False

        now = timezone.now()
        RefreshToken.objects.active().filter(session_id=identifier).update(
            status=TokenStatus.REVOKED,
            revoked_at=now,
            revocation_reason=reason,
        )
        TokenFamily.objects.filter(
            session_id=identifier, revoked_at__isnull=True
        ).update(revoked_at=now, revocation_reason=reason)
        return True

    @transaction.atomic
    def enforce_cap(self, user: User) -> int:
        """Retire the oldest sessions so a new one stays within the cap.

        Runs *before* the new session is created, so it makes room for one:
        at the cap, the single oldest session is retired. Returns how many
        were retired.
        """
        live = DeviceSession.objects.live().for_user(user.pk)
        current = live.count()
        if current < self._cap:
            return 0

        surplus = list(
            live.order_by("created_at").values_list("pk", flat=True)[
                : current - self._cap + 1
            ]
        )
        if not surplus:
            return 0

        now = timezone.now()
        DeviceSession.objects.filter(pk__in=surplus).update(ended_at=now)
        RefreshToken.objects.active().filter(session_id__in=surplus).update(
            status=TokenStatus.REVOKED,
            revoked_at=now,
            revocation_reason=RevocationReason.SESSION_CAP,
        )
        TokenFamily.objects.filter(
            session_id__in=surplus, revoked_at__isnull=True
        ).update(revoked_at=now, revocation_reason=RevocationReason.SESSION_CAP)
        return len(surplus)
