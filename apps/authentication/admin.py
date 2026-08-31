"""Read-mostly admin for the authentication records.

Nothing here is editable. These tables are the evidence of what happened, and
an admin that can rewrite them is an admin that can rewrite the audit trail --
which is precisely what a compromised staff account would want to do. Sessions
are ended through the API or a management command, both of which revoke the
associated credentials; flipping ``ended_at`` by hand would leave the tokens
live and the record misleading.

Registered on both planes, so a tenant administrator sees their institution's
rows and platform staff see the public schema's. That falls out of the
``search_path`` rather than from any filtering here.

``auth.Group`` is registered here too. ``django.contrib.auth.admin`` registers
it on the default ``admin.site``, which is now mounted nowhere, and group
membership is what grants access to either plane -- so it has to be reachable
on both, and this app is its owner.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from django.contrib import admin
from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin
from django.contrib.auth.models import Group

from apps.authentication.models import (
    AuthAuditEvent,
    DeviceSession,
    LoginAttempt,
    RefreshToken,
)
from apps.core.admin import control_site, tenant_site

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


class DeviceSessionAdmin(ReadOnlyAdmin):
    list_display = ("id", "user", "device_name", "ip_address", "created_at", "ended_at")
    list_filter = ("ended_at", "created_at")
    search_fields = ("device_name", "device_id", "user__email")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)

    def get_queryset(self, request: HttpRequest) -> QuerySet[DeviceSession]:
        return super().get_queryset(request).select_related("user")


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


class LoginAttemptAdmin(ReadOnlyAdmin):
    list_display = ("email", "successful", "ip_address", "failure_reason", "created_at")
    list_filter = ("successful", "created_at")
    search_fields = ("email", "ip_address")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)


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


class RoleAdmin(BaseGroupAdmin):
    """The role groups, per schema.

    These are the rows seeded by ``0002_seed_default_roles`` in every schema,
    and ``utils.scopes.ROLE_SCOPES`` is what maps their names to the scopes a
    token carries. Since the admin plane split they are load-bearing in a
    second way: membership of ``platform_admin`` or ``tenant_admin`` is what
    admits someone to the control plane or the tenant plane. If nobody can edit
    groups, nobody can grant either.

    Accepted risk: a ``tenant_admin`` who can edit ``Group.permissions`` in
    their own schema can escalate their own Django model permissions within
    that schema. That is inherent to the role -- they already administer the
    institution. They cannot manufacture control-plane access: a
    ``platform_admin`` group they create in *acme* grants nothing, because
    ``control_site`` is not mounted on acme's hostname and additionally
    requires the public schema.
    """


# Ten explicit calls rather than a loop over the two sites: this block is the
# only record of which model reaches which plane, and it should read as a list,
# not as something to execute in your head.
#
# auth.Permission stays unregistered on both -- the rows are generated by
# migrations, the changelist is enormous, and hand-editing them is a footgun.
# Permissions are granted through groups. admin.LogEntry likewise stays
# unregistered, as it is by default.
control_site.register(Group, RoleAdmin)
control_site.register(DeviceSession, DeviceSessionAdmin)
control_site.register(RefreshToken, RefreshTokenAdmin)
control_site.register(LoginAttempt, LoginAttemptAdmin)
control_site.register(AuthAuditEvent, AuthAuditEventAdmin)

tenant_site.register(Group, RoleAdmin)
tenant_site.register(DeviceSession, DeviceSessionAdmin)
tenant_site.register(RefreshToken, RefreshTokenAdmin)
tenant_site.register(LoginAttempt, LoginAttemptAdmin)
tenant_site.register(AuthAuditEvent, AuthAuditEventAdmin)
