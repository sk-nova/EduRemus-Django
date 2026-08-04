"""Admin integration for the custom user model."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from django.contrib import admin, messages
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from apps.accounts.forms import UserChangeForm, UserCreationForm

if TYPE_CHECKING:
    from apps.accounts.managers import UserQuerySet
    from apps.accounts.models import User

UserModel = get_user_model()


class DeletionStatusFilter(admin.SimpleListFilter):
    """Filter the changelist by soft-deletion state (defaults to active)."""

    title = _("deletion status")
    parameter_name = "deletion_status"

    def lookups(
        self,
        request: HttpRequest,
        model_admin: admin.ModelAdmin[Any],
    ) -> list[tuple[str, Any]]:
        return [("deleted", _("Deleted")), ("all", _("All"))]

    def choices(self, changelist: Any) -> Any:
        # SimpleListFilter labels its first (unselected) choice "All"; here
        # that state actually means "not deleted", so relabel it.
        for index, choice in enumerate(super().choices(changelist)):
            if index == 0:
                choice["display"] = _("Not deleted")
            yield choice

    def queryset(
        self,
        request: HttpRequest,
        queryset: QuerySet[Any],
    ) -> QuerySet[Any]:
        users = cast("UserQuerySet", queryset)
        value = self.value()
        if value == "all":
            return users
        if value == "deleted":
            return users.dead()
        return users.alive()


@admin.register(UserModel)
class UserAdmin(BaseUserAdmin):
    """Email-first admin with soft-delete aware actions.

    Subclasses ``auth.admin.UserAdmin`` purely to inherit its password-change
    view and permission plumbing; every field and form is replaced below.
    """

    add_form = UserCreationForm
    form = UserChangeForm
    model = UserModel

    list_display = (
        "email",
        "first_name",
        "last_name",
        "is_active",
        "is_staff",
        "is_deleted",
        "created_at",
    )
    list_filter = (DeletionStatusFilter, "is_active", "is_staff", "is_superuser")
    search_fields = ("email", "first_name", "last_name")
    ordering = ("-created_at",)
    list_per_page = 50

    readonly_fields = ("id", "last_login", "created_at", "updated_at", "deleted_at")
    filter_horizontal = ("groups", "user_permissions")

    fieldsets = (
        (None, {"fields": ("id", "email", "password")}),
        (_("Personal info"), {"fields": ("first_name", "last_name")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (
            _("Important dates"),
            {
                "fields": ("last_login", "created_at", "updated_at", "deleted_at"),
                "classes": ("collapse",),
            },
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "first_name",
                    "last_name",
                    "password1",
                    "password2",
                ),
            },
        ),
    )

    actions = ("soft_delete_selected", "restore_selected")

    @admin.display(boolean=True, description=_("deleted"), ordering="deleted_at")
    def is_deleted(self, obj: User) -> bool:
        return obj.is_deleted

    def get_queryset(self, request: HttpRequest) -> UserQuerySet:
        # Staff must be able to see and restore soft-deleted accounts, so the
        # changelist reads through the unfiltered manager. DeletionStatusFilter
        # narrows it back down to active users by default.
        queryset: UserQuerySet = self.model.all_objects.get_queryset()
        ordering = self.get_ordering(request)
        if ordering:
            queryset = queryset.order_by(*ordering)
        return queryset

    def delete_model(self, request: HttpRequest, obj: User) -> None:
        """Route the single-object delete button through soft deletion."""
        obj.delete()

    def delete_queryset(self, request: HttpRequest, queryset: QuerySet[Any]) -> None:
        """Route the built-in ``delete_selected`` action through soft deletion."""
        queryset.delete()

    @admin.action(
        description=_("Soft delete selected users"),
        permissions=["delete"],
    )
    def soft_delete_selected(
        self,
        request: HttpRequest,
        queryset: QuerySet[Any],
    ) -> None:
        count, _labels = queryset.delete()
        self.message_user(
            request,
            ngettext(
                "%(count)d account was soft deleted.",
                "%(count)d accounts were soft deleted.",
                count,
            )
            % {"count": count},
            messages.SUCCESS,
        )

    @admin.action(
        description=_("Restore selected users"),
        permissions=["change"],
    )
    def restore_selected(
        self,
        request: HttpRequest,
        queryset: QuerySet[Any],
    ) -> None:
        count = cast("UserQuerySet", queryset).restore()
        self.message_user(
            request,
            ngettext(
                "%(count)d account was restored.",
                "%(count)d accounts were restored.",
                count,
            )
            % {"count": count},
            messages.SUCCESS,
        )
