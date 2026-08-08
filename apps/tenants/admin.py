"""Admin for the tenant catalogue.

Both models are registered unconditionally, but they are only *reachable* from
the public schema: ``apps.tenants`` is in ``SHARED_APPS`` and not in
``TENANT_APPS``, so the router never creates its tables inside a tenant schema.
The permission hooks below make that explicit rather than letting a tenant-side
admin fail with a confusing exception -- and they are the reason a tenant
administrator can never enumerate other institutions.
"""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _
from django_tenants.admin import TenantAdminMixin
from django_tenants.utils import get_public_schema_name

from apps.tenants.models import Client, Domain
from apps.tenants.utils import current_schema_name


# django-stubs types ModelAdmin/InlineModelAdmin as generic, but Django itself
# does not implement __class_getitem__ on them, so the parameters may only
# appear in annotations (which `from __future__ import annotations` defers) --
# never in a base-class list.
class PublicSchemaOnlyAdmin(admin.ModelAdmin):  # type: ignore[type-arg]
    """Hides a model from the admin of every schema but the public one."""

    def _in_public_schema(self) -> bool:
        return current_schema_name() == get_public_schema_name()

    def has_module_permission(self, request: HttpRequest) -> bool:
        return self._in_public_schema() and super().has_module_permission(request)

    def has_view_permission(
        self,
        request: HttpRequest,
        obj: Any | None = None,
    ) -> bool:
        return self._in_public_schema() and super().has_view_permission(request, obj)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return self._in_public_schema() and super().has_add_permission(request)

    def has_change_permission(
        self,
        request: HttpRequest,
        obj: Any | None = None,
    ) -> bool:
        return self._in_public_schema() and super().has_change_permission(request, obj)

    def has_delete_permission(
        self,
        request: HttpRequest,
        obj: Any | None = None,
    ) -> bool:
        return self._in_public_schema() and super().has_delete_permission(request, obj)


class DomainInline(admin.TabularInline):  # type: ignore[type-arg]
    """Manage a tenant's hostnames from the tenant page."""

    model = Domain
    extra = 1
    fields = ("domain", "is_primary")


@admin.register(Client)
class ClientAdmin(TenantAdminMixin, PublicSchemaOnlyAdmin):
    """Create and suspend institutions.

    ``TenantAdminMixin`` swaps in a change form template that hides the save
    and delete buttons when the admin is not in the tenant's own schema or the
    public one, which is exactly when ``TenantMixin.save()`` would raise.
    """

    list_display = ("name", "slug", "schema_name", "is_active", "primary_domain")
    list_filter = ("is_active",)
    search_fields = ("name", "slug", "schema_name", "domains__domain")
    ordering = ("name",)
    prepopulated_fields = {"slug": ("name",)}  # noqa: RUF012
    inlines = (DomainInline,)

    fieldsets = (
        (None, {"fields": ("name", "slug", "is_active")}),
        (
            _("Schema"),
            {
                "fields": ("schema_name",),
                "description": _(
                    "Created on first save and never changed afterwards -- "
                    "renaming it here would not move the Postgres schema. "
                    "Leave blank to derive it from the slug."
                ),
            },
        ),
        (
            _("Important dates"),
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )
    readonly_fields = ("created_at", "updated_at")

    def get_readonly_fields(
        self,
        request: HttpRequest,
        obj: Client | None = None,
    ) -> tuple[str, ...]:
        # The schema is created from this value on the first save; afterwards
        # the row and the Postgres schema are welded together.
        if obj is not None:
            return (*self.readonly_fields, "schema_name")
        return self.readonly_fields

    def get_queryset(self, request: HttpRequest) -> QuerySet[Client]:
        return super().get_queryset(request).prefetch_related("domains")

    @admin.display(description=_("primary domain"))
    def primary_domain(self, obj: Client) -> str:
        return obj.primary_domain_name() or "—"

    def delete_model(self, request: HttpRequest, obj: Client) -> None:
        """Delete the catalogue row but keep the schema.

        Deliberately *not* a schema drop: losing a customer's entire dataset
        must not be one mis-click away. Use ``manage.py tenant_delete
        <schema> --drop-schema`` when the data really should go.
        """
        obj.delete(force_drop=False)

    def delete_queryset(self, request: HttpRequest, queryset: QuerySet[Client]) -> None:
        for obj in queryset:
            obj.delete(force_drop=False)


@admin.register(Domain)
class DomainAdmin(PublicSchemaOnlyAdmin):
    """Route hostnames to tenants."""

    list_display = ("domain", "tenant", "is_primary")
    list_filter = ("is_primary",)
    search_fields = ("domain", "tenant__name", "tenant__slug")
    ordering = ("domain",)
    autocomplete_fields = ("tenant",)

    def get_queryset(self, request: HttpRequest) -> QuerySet[Domain]:
        return super().get_queryset(request).select_related("tenant")
