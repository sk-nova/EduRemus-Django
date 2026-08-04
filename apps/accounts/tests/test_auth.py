"""Authentication behaviour through the standard ModelBackend."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from django.contrib.auth import authenticate

if TYPE_CHECKING:
    from apps.accounts.models import User

pytestmark = pytest.mark.django_db

PASSWORD = "s3cure-Passw0rd!"


class TestAuthenticate:
    def test_correct_credentials_succeed(self, user: User) -> None:
        assert authenticate(username=user.email, password=PASSWORD) == user

    def test_email_is_matched_case_insensitively(self, user: User) -> None:
        assert authenticate(username="MEMBER@EXAMPLE.COM", password=PASSWORD) == user

    def test_surrounding_whitespace_is_tolerated(self, user: User) -> None:
        assert authenticate(username=" member@example.com ", password=PASSWORD) == user

    def test_wrong_password_fails(self, user: User) -> None:
        assert authenticate(username=user.email, password="wrong") is None

    def test_unknown_email_fails(self, db: None) -> None:
        assert authenticate(username="nobody@example.com", password=PASSWORD) is None

    def test_inactive_users_cannot_authenticate(self, user: User) -> None:
        user.is_active = False
        user.save(update_fields=["is_active"])

        assert authenticate(username=user.email, password=PASSWORD) is None

    def test_soft_deleted_users_cannot_authenticate(self, deleted_user: User) -> None:
        # Two independent guards: the default manager hides the row from
        # get_by_natural_key(), and the row is also is_active=False.
        assert authenticate(username=deleted_user.email, password=PASSWORD) is None

    def test_restored_users_can_authenticate_again(self, deleted_user: User) -> None:
        deleted_user.restore()

        assert authenticate(username=deleted_user.email, password=PASSWORD) is not None

    def test_users_without_a_usable_password_cannot_authenticate(
        self, user_model: type[User]
    ) -> None:
        invited = user_model.objects.create_user(email="invited@example.com")

        assert authenticate(username=invited.email, password="") is None


class TestPermissions:
    def test_superusers_have_every_permission(self, superuser: User) -> None:
        assert superuser.has_perm("accounts.delete_user") is True

    def test_ordinary_users_have_no_permissions(self, user: User) -> None:
        assert user.has_perm("accounts.delete_user") is False

    def test_group_permissions_are_honoured(self, user: User) -> None:
        from django.contrib.auth.models import Group, Permission

        group = Group.objects.create(name="Registrars")
        group.permissions.add(
            Permission.objects.get(
                codename="change_user",
                content_type__app_label="accounts",
            )
        )
        user.groups.add(group)

        # Permissions are cached per instance; re-fetch to see the change.
        refreshed = type(user).objects.get(pk=user.pk)
        assert refreshed.has_perm("accounts.change_user") is True
