"""Persistence for the authentication layer.

Six tables, all of them per-schema. Isolation is the schema, so **no model here
carries a tenant foreign key** and none may: a ``tenant_id`` column would be a
second, weaker mechanism capable of disagreeing with the first, and the class
of missing-``WHERE`` bug it reintroduces is exactly what schema isolation
eliminates.

These models inherit ``TimeStampedModel`` but deliberately **not**
``SoftDeleteModel``. Soft deletion provides ``restore()``, and a restorable
revoked credential is a privilege-escalation primitive. Revocation is terminal.
``DeviceSession.ended_at`` reads like a soft delete for the same shape of data
and has no restore path on purpose.
"""

from __future__ import annotations

import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.authentication.managers import DeviceSessionManager, RefreshTokenManager
from apps.core.models import TimeStampedModel

__all__ = [
    "AuthAuditEvent",
    "AuthEventType",
    "DeviceSession",
    "EventSeverity",
    "LoginAttempt",
    "PasswordHistory",
    "RefreshToken",
    "RevocationReason",
    "TokenFamily",
    "TokenStatus",
]


# =====================================================================
# ENUMERATIONS
# =====================================================================

# Kept as TextChoices rather than PostgreSQL enum types: adding a value is then
# an ordinary no-op migration rather than an ALTER TYPE replayed across every
# tenant schema.


class TokenStatus(models.TextChoices):
    ACTIVE = "active", _("Active")
    ROTATED = "rotated", _("Rotated")
    REVOKED = "revoked", _("Revoked")
    EXPIRED = "expired", _("Expired")
    COMPROMISED = "compromised", _("Compromised")


class RevocationReason(models.TextChoices):
    LOGOUT = "logout", _("User logged out")
    LOGOUT_ALL = "logout_all", _("User logged out of all devices")
    PASSWORD_CHANGED = "password_changed", _("Password changed")
    REUSE_DETECTED = "reuse_detected", _("Refresh token reuse detected")
    ADMIN_REVOKED = "admin_revoked", _("Revoked by an administrator")
    USER_DEACTIVATED = "user_deactivated", _("Account deactivated")
    TENANT_SUSPENDED = "tenant_suspended", _("Tenant suspended")
    SESSION_CAP = "session_cap", _("Session limit exceeded")
    KEY_ROTATED = "key_rotated", _("Signing key retired")


class AuthEventType(models.TextChoices):
    LOGIN_SUCCEEDED = "login_succeeded", _("Login succeeded")
    LOGIN_FAILED = "login_failed", _("Login failed")
    ACCOUNT_LOCKED = "account_locked", _("Account locked")
    TOKEN_REFRESHED = "token_refreshed", _("Token refreshed")
    REFRESH_UNKNOWN = "refresh_unknown", _("Unknown refresh token presented")
    REFRESH_REUSE_DETECTED = "refresh_reuse_detected", _("Refresh reuse detected")
    CROSS_TENANT_TOKEN_REJECTED = (
        "cross_tenant_token_rejected",
        _("Cross-tenant token rejected"),
    )
    LOGOUT = "logout", _("Logout")
    LOGOUT_ALL = "logout_all", _("Logout all devices")
    FORCE_LOGOUT = "force_logout", _("Forced logout")
    PASSWORD_CHANGED = "password_changed", _("Password changed")
    TENANT_SUSPENDED = "tenant_suspended", _("Tenant suspended")
    KEY_ROTATED = "key_rotated", _("Signing key rotated")


class EventSeverity(models.TextChoices):
    INFO = "info", _("Informational")
    NOTICE = "notice", _("Notice")
    WARNING = "warning", _("Warning")
    CRITICAL = "critical", _("Critical")


# =====================================================================
# MODELS
# =====================================================================


class DeviceSession(TimeStampedModel):
    """One login on one device. Survives refresh rotation; ends at logout."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid7, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="device_sessions",
        verbose_name=_("user"),
    )
    device_id = models.CharField(_("device ID"), max_length=64, db_index=True)
    device_name = models.CharField(_("device name"), max_length=100, blank=True)
    user_agent = models.CharField(_("user agent"), max_length=512, blank=True)
    ip_address = models.GenericIPAddressField(_("IP address"), null=True, blank=True)
    last_seen_at = models.DateTimeField(_("last seen at"), null=True, blank=True)
    ended_at = models.DateTimeField(_("ended at"), null=True, blank=True)

    objects: ClassVar[DeviceSessionManager] = DeviceSessionManager()

    class Meta:
        verbose_name = _("device session")
        verbose_name_plural = _("device sessions")
        ordering = ("-created_at",)
        indexes = (
            # Partial: the live-session lookup runs on every login (for the
            # session cap) and on every session list. Indexing only the open
            # sessions keeps it small regardless of historical volume.
            models.Index(
                fields=("user", "-created_at"),
                name="devsession_user_recent_idx",
                condition=models.Q(ended_at__isnull=True),
            ),
        )

    def __str__(self) -> str:
        return f"{self.user_id} @ {self.device_name or self.device_id}"

    @property
    def is_live(self) -> bool:
        return self.ended_at is None


class TokenFamily(TimeStampedModel):
    """A refresh-token lineage: one login, N rotations.

    Reuse detection operates at family granularity. A replayed token
    invalidates the whole lineage rather than only itself, because once a
    token has been redeemed twice there is no way to tell which of the two
    holders is the legitimate one.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid7, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="token_families",
        verbose_name=_("user"),
    )
    session = models.ForeignKey(
        DeviceSession,
        on_delete=models.CASCADE,
        related_name="token_families",
        verbose_name=_("device session"),
    )
    revoked_at = models.DateTimeField(_("revoked at"), null=True, blank=True)
    revocation_reason = models.CharField(
        _("revocation reason"),
        max_length=32,
        choices=RevocationReason.choices,
        blank=True,
    )

    class Meta:
        verbose_name = _("token family")
        verbose_name_plural = _("token families")
        ordering = ("-created_at",)
        indexes = (
            models.Index(
                fields=("user",),
                name="tokenfamily_user_live_idx",
                condition=models.Q(revoked_at__isnull=True),
            ),
        )

    def __str__(self) -> str:
        return f"family {self.pk} ({self.user_id})"

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class RefreshToken(TimeStampedModel):
    """A single generation within a family.

    The raw token is never stored -- only its SHA-256 digest -- so a database
    disclosure yields nothing redeemable.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid7, editable=False)
    token_hash = models.CharField(
        _("token hash"), max_length=64, unique=True, editable=False
    )
    jti = models.UUIDField(_("JWT ID"), unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="refresh_tokens",
        verbose_name=_("user"),
    )
    family = models.ForeignKey(
        TokenFamily,
        on_delete=models.CASCADE,
        related_name="tokens",
        verbose_name=_("family"),
    )
    session = models.ForeignKey(
        DeviceSession,
        on_delete=models.CASCADE,
        related_name="refresh_tokens",
        verbose_name=_("device session"),
    )
    generation = models.PositiveIntegerField(_("generation"), default=1)
    status = models.CharField(
        _("status"),
        max_length=16,
        choices=TokenStatus.choices,
        default=TokenStatus.ACTIVE,
        db_index=True,
    )
    replaced_by = models.OneToOneField(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="replaces",
        verbose_name=_("replaced by"),
    )
    revocation_reason = models.CharField(
        _("revocation reason"),
        max_length=32,
        choices=RevocationReason.choices,
        blank=True,
    )
    issued_at = models.DateTimeField(_("issued at"))
    rotated_at = models.DateTimeField(_("rotated at"), null=True, blank=True)
    revoked_at = models.DateTimeField(_("revoked at"), null=True, blank=True)
    expires_at = models.DateTimeField(_("expires at"), db_index=True)

    objects: ClassVar[RefreshTokenManager] = RefreshTokenManager()

    class Meta:
        verbose_name = _("refresh token")
        verbose_name_plural = _("refresh tokens")
        ordering = ("-issued_at",)
        indexes = (
            models.Index(fields=("family", "generation"), name="reftoken_lineage_idx"),
            # Partial: only ACTIVE rows are ever looked up by user, and they
            # are a small minority in a table that accumulates one ROTATED row
            # per refresh. The literal rather than TokenStatus.ACTIVE keeps the
            # generated migration independent of this module's enum members.
            models.Index(
                fields=("user", "status"),
                name="reftoken_user_active_idx",
                condition=models.Q(status="active"),
            ),
            models.Index(fields=("expires_at",), name="reftoken_expiry_idx"),
        )
        constraints = (
            models.CheckConstraint(
                condition=models.Q(generation__gte=1),
                name="reftoken_generation_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(expires_at__gt=models.F("issued_at")),
                name="reftoken_expiry_after_issue",
            ),
        )

    def __str__(self) -> str:
        return f"{self.family_id} gen {self.generation} ({self.status})"

    @property
    def is_usable(self) -> bool:
        return self.status == TokenStatus.ACTIVE and self.expires_at > timezone.now()


class LoginAttempt(TimeStampedModel):
    """Every authentication attempt, successful or not.

    ``email`` is a plain column rather than a foreign key because an attempt
    against an address that does not exist must still be recorded -- that is
    precisely the signal a credential-stuffing campaign produces.
    """

    email = models.EmailField(_("email address"), max_length=254, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="login_attempts",
        verbose_name=_("user"),
    )
    successful = models.BooleanField(_("successful"), default=False, db_index=True)
    ip_address = models.GenericIPAddressField(_("IP address"), null=True, blank=True)
    user_agent = models.CharField(_("user agent"), max_length=512, blank=True)
    failure_reason = models.CharField(_("failure reason"), max_length=64, blank=True)

    class Meta:
        verbose_name = _("login attempt")
        verbose_name_plural = _("login attempts")
        ordering = ("-created_at",)
        indexes = (
            # Serves the lockout window query, which is the hottest read on
            # this table and always filters to failures.
            models.Index(
                fields=("email", "-created_at"),
                name="loginattempt_email_recent_idx",
                condition=models.Q(successful=False),
            ),
            models.Index(
                fields=("ip_address", "-created_at"),
                name="loginattempt_ip_recent_idx",
            ),
        )

    def __str__(self) -> str:
        outcome = "ok" if self.successful else "failed"
        return f"{self.email} ({outcome})"


class AuthAuditEvent(TimeStampedModel):
    """Append-only security and audit trail.

    Never updated and never deleted by application code; retention is a
    scheduled operation. ``actor`` is set when an administrator acts on another
    principal, which is what distinguishes "user logged out" from "user *was*
    logged out".
    """

    event_type = models.CharField(
        _("event type"),
        max_length=48,
        choices=AuthEventType.choices,
        db_index=True,
    )
    severity = models.CharField(
        _("severity"),
        max_length=16,
        choices=EventSeverity.choices,
        default=EventSeverity.INFO,
        db_index=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="auth_events",
        verbose_name=_("user"),
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="auth_events_performed",
        verbose_name=_("actor"),
    )
    ip_address = models.GenericIPAddressField(_("IP address"), null=True, blank=True)
    user_agent = models.CharField(_("user agent"), max_length=512, blank=True)
    detail = models.JSONField(_("detail"), default=dict, blank=True)

    class Meta:
        verbose_name = _("authentication event")
        verbose_name_plural = _("authentication events")
        ordering = ("-created_at",)
        indexes = (
            models.Index(
                fields=("event_type", "-created_at"),
                name="authevent_type_recent_idx",
            ),
            models.Index(
                fields=("user", "-created_at"),
                name="authevent_user_recent_idx",
            ),
            # Partial: severity queries only ever ask for the serious ones.
            models.Index(
                fields=("-created_at",),
                name="authevent_critical_idx",
                condition=models.Q(severity__in=("warning", "critical")),
            ),
        )

    def __str__(self) -> str:
        return f"{self.event_type} ({self.severity})"


class PasswordHistory(TimeStampedModel):
    """Previous password hashes, to prevent immediate reuse.

    Hashes only. The comparison is an ordinary ``check_password`` against each
    retained hash; the plaintext is never known to the system.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="password_history",
        verbose_name=_("user"),
    )
    password_hash = models.CharField(_("password hash"), max_length=128)

    class Meta:
        verbose_name = _("password history entry")
        verbose_name_plural = _("password history")
        ordering = ("-created_at",)
        indexes = (
            models.Index(
                fields=("user", "-created_at"),
                name="pwdhistory_user_recent_idx",
            ),
        )

    def __str__(self) -> str:
        return f"password history for {self.user_id}"
