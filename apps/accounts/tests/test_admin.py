"""Django admin integration, including the soft-delete affordances."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from django.contrib import admin
from django.test import Client, RequestFactory
from django.urls import reverse

from apps.accounts.admin import UserAdmin

if TYPE_CHECKING:
    from apps.accounts.models import User

pytestmark = pytest.mark.django_db

CHANGELIST_URL = "admin:accounts_user_changelist"
STRONG_PASSWORD = "s3cure-Passw0rd!"


@pytest.fixture
def user_admin(user_model: type[User]) -> UserAdmin:
    return UserAdmin(user_model, admin.site)


def action_payload(target: User, action: str) -> dict[str, object]:
    return {
        "action": action,
        "index": 0,
        "select_across": 0,
        "_selected_action": [str(target.pk)],
    }


class TestRegistration:
    def test_the_user_model_is_registered(self, user_model: type[User]) -> None:
        assert user_model in admin.site._registry

    def test_it_uses_our_admin_class(self, user_model: type[User]) -> None:
        assert isinstance(admin.site._registry[user_model], UserAdmin)

    def test_admin_checks_pass(self, user_admin: UserAdmin) -> None:
        assert user_admin.check() == []


class TestQuerysetScoping:
    def test_get_queryset_sees_deleted_users(
        self, user_admin: UserAdmin, deleted_user: User, superuser: User
    ) -> None:
        request = RequestFactory().get("/")
        request.user = superuser

        assert deleted_user in user_admin.get_queryset(request)

    def test_changelist_hides_deleted_users_by_default(
        self, admin_client: Client, user: User, deleted_user: User
    ) -> None:
        response = admin_client.get(reverse(CHANGELIST_URL))

        assert response.status_code == 200
        assert user.email in response.content.decode()
        assert deleted_user.email not in response.content.decode()

    def test_changelist_shows_deleted_users_on_request(
        self, admin_client: Client, user: User, deleted_user: User
    ) -> None:
        response = admin_client.get(
            reverse(CHANGELIST_URL),
            {"deletion_status": "deleted"},
        )

        content = response.content.decode()
        assert deleted_user.email in content
        assert user.email not in content

    def test_changelist_can_show_everything(
        self, admin_client: Client, user: User, deleted_user: User
    ) -> None:
        response = admin_client.get(
            reverse(CHANGELIST_URL),
            {"deletion_status": "all"},
        )

        content = response.content.decode()
        assert user.email in content
        assert deleted_user.email in content


class TestViews:
    def test_changelist_renders(self, admin_client: Client, user: User) -> None:
        assert admin_client.get(reverse(CHANGELIST_URL)).status_code == 200

    def test_add_view_renders(self, admin_client: Client) -> None:
        response = admin_client.get(reverse("admin:accounts_user_add"))

        assert response.status_code == 200
        assert "password1" in response.content.decode()

    def test_add_view_creates_a_user(
        self, admin_client: Client, user_model: type[User]
    ) -> None:
        response = admin_client.post(
            reverse("admin:accounts_user_add"),
            {
                "email": "fresh@example.com",
                "first_name": "Fresh",
                "last_name": "Start",
                "password1": STRONG_PASSWORD,
                "password2": STRONG_PASSWORD,
            },
        )

        assert response.status_code == 302
        created = user_model.objects.get(email="fresh@example.com")
        assert created.check_password(STRONG_PASSWORD) is True

    def test_change_view_renders(self, admin_client: Client, user: User) -> None:
        response = admin_client.get(
            reverse("admin:accounts_user_change", args=[user.pk])
        )

        assert response.status_code == 200

    def test_change_view_does_not_leak_the_hash_as_an_editable_value(
        self, admin_client: Client, user: User
    ) -> None:
        response = admin_client.get(
            reverse("admin:accounts_user_change", args=[user.pk])
        )

        content = response.content.decode()
        assert f'value="{user.password}"' not in content

    def test_password_change_view_renders(
        self, admin_client: Client, user: User
    ) -> None:
        response = admin_client.get(
            reverse("admin:auth_user_password_change", args=[user.pk])
        )

        assert response.status_code == 200

    def test_deleted_users_are_still_editable(
        self, admin_client: Client, deleted_user: User
    ) -> None:
        # Restoring an account requires reaching its change page.
        response = admin_client.get(
            reverse("admin:accounts_user_change", args=[deleted_user.pk])
        )

        assert response.status_code == 200


class TestSoftDeleteIntegration:
    def test_delete_model_soft_deletes(
        self, user_admin: UserAdmin, user: User, superuser: User
    ) -> None:
        request = RequestFactory().post("/")
        request.user = superuser

        user_admin.delete_model(request, user)

        user.refresh_from_db()
        assert user.is_deleted is True

    def test_delete_queryset_soft_deletes(
        self, user_admin: UserAdmin, user: User, user_model: type[User]
    ) -> None:
        request = RequestFactory().post("/")

        user_admin.delete_queryset(request, user_model.objects.filter(pk=user.pk))

        assert user_model.all_objects.filter(pk=user.pk).exists()
        user.refresh_from_db()
        assert user.is_deleted is True

    def test_delete_confirmation_view_soft_deletes(
        self, admin_client: Client, user: User, user_model: type[User]
    ) -> None:
        response = admin_client.post(
            reverse("admin:accounts_user_delete", args=[user.pk]),
            {"post": "yes"},
        )

        assert response.status_code == 302
        assert user_model.all_objects.filter(pk=user.pk).exists()
        assert not user_model.objects.filter(pk=user.pk).exists()

    def test_soft_delete_action(self, admin_client: Client, user: User) -> None:
        response = admin_client.post(
            reverse(CHANGELIST_URL),
            action_payload(user, "soft_delete_selected"),
            follow=True,
        )

        assert response.status_code == 200
        user.refresh_from_db()
        assert user.is_deleted is True

    def test_restore_action(self, admin_client: Client, deleted_user: User) -> None:
        # The action operates on the filtered changelist, so surface the
        # deleted rows first.
        response = admin_client.post(
            f"{reverse(CHANGELIST_URL)}?deletion_status=deleted",
            action_payload(deleted_user, "restore_selected"),
            follow=True,
        )

        assert response.status_code == 200
        deleted_user.refresh_from_db()
        assert deleted_user.is_deleted is False
        assert deleted_user.is_active is True


class TestListDisplay:
    def test_is_deleted_column_reflects_state(
        self, user_admin: UserAdmin, user: User, deleted_user: User
    ) -> None:
        assert user_admin.is_deleted(user) is False
        assert user_admin.is_deleted(deleted_user) is True

    def test_username_is_not_displayed_anywhere(self, user_admin: UserAdmin) -> None:
        assert "username" not in user_admin.list_display
        assert "username" not in user_admin.search_fields
