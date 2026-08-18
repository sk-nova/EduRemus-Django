"""Read-mostly admin for the authentication records.

Nothing here is editable. These tables are the evidence of what happened, and
an admin that can rewrite them is an admin that can rewrite the audit trail --
which is precisely what a compromised staff account would want to do. Sessions
are ended through the API or a management command, both of which revoke the
associated credentials; flipping ``ended_at`` by hand would leave the tokens
live and the record misleading.

Registered in every schema, so a tenant administrator sees their institution's
rows and only those. That falls out of the ``search_path`` rather than from
any filtering here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from django.contrib import admin

from apps.authentication.models import (
    AuthAuditEvent,
    DeviceSession,
    LoginAttempt,
    RefreshToken,
)

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest


# django-stubs types ModelAdmin as generic, but Django does not implement
# __class_getitem__ on it, so the parameter may only appear in annotations --
# never in a base-class list. Same reasoning as apps.tenants.admin.
class ReadOnlyAdmin(admin.ModelAdmin):  # type: ignore[type-arg]
    """Viewable, never writable."""

    def has_add_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(DeviceSession)
class DeviceSessionAdmin(ReadOnlyAdmin):
    list_display = ("id", "user", "device_name", "ip_address", "created_at", "ended_at")
    list_filter = ("ended_at", "created_at")
    search_fields = ("device_name", "device_id", "user__email")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)

    def get_queryset(self, request: HttpRequest) -> QuerySet[DeviceSession]:
        return super().get_queryset(request).select_related("user")


@admin.register(RefreshToken)
class RefreshTokenAdmin(ReadOnlyAdmin):
    """Token lineages.

    ``token_hash`` is deliberately absent from every display and search field.
    It is only a digest and not itself redeemable, but there is no operational
    question it answers that ``jti`` does not.
    """

    list_display = ("jti", "user", "family", "generation", "status", "expires_at")
    list_filter = ("status", "revocation_reason", "expires_at")
    search_fields = ("jti", "user__email")
    date_hierarchy = "issued_at"
    ordering = ("-issued_at",)
    exclude: ClassVar[tuple[str, ...]] = ("token_hash",)

    def get_queryset(self, request: HttpRequest) -> QuerySet[RefreshToken]:
        return super().get_queryset(request).select_related("user", "family")


@admin.register(LoginAttempt)
class LoginAttemptAdmin(ReadOnlyAdmin):
    list_display = ("email", "successful", "ip_address", "failure_reason", "created_at")
    list_filter = ("successful", "created_at")
    search_fields = ("email", "ip_address")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)


@admin.register(AuthAuditEvent)
class AuthAuditEventAdmin(ReadOnlyAdmin):
    list_display = (
        "event_type",
        "severity",
        "user",
        "actor",
        "ip_address",
        "created_at",
    )
    list_filter = ("event_type", "severity", "created_at")
    search_fields = ("user__email", "actor__email", "ip_address")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)

    def get_queryset(self, request: HttpRequest) -> QuerySet[AuthAuditEvent]:
        return super().get_queryset(request).select_related("user", "actor")
