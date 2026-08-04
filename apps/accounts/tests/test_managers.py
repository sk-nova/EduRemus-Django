"""UserManager: creation entry points and queryset scoping."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from django.core.exceptions import ValidationError
from django.core.management import call_command

from apps.accounts.managers import UserManager

if TYPE_CHECKING:
    from apps.accounts.models import User

pytestmark = pytest.mark.django_db


class TestNormalizeEmail:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("USER@EXAMPLE.COM", "user@example.com"),
            ("User@Example.Com", "user@example.com"),
            ("  padded@example.com\t", "padded@example.com"),
            ("MiXeD.LoCaL@example.com", "mixed.local@example.com"),
        ],
    )
    def test_the_whole_address_is_folded(self, raw: str, expected: str) -> None:
        # Django's default only lowercases the domain; we fold the local part
        # too, which is what makes unique=True behave case-insensitively.
        assert UserManager.normalize_email(raw) == expected


class TestCreateUser:
    def test_creates_an_ordinary_account(self, user_model: type[User]) -> None:
        account = user_model.objects.create_user(
            email="new@example.com",
            password="s3cure-Passw0rd!",
        )

        assert account.is_active is True
        assert account.is_staff is False
        assert account.is_superuser is False
        assert account.is_deleted is False

    def test_password_is_hashed(self, user_model: type[User]) -> None:
        account = user_model.objects.create_user(
            email="hashed@example.com",
            password="s3cure-Passw0rd!",
        )

        assert account.password != "s3cure-Passw0rd!"
        assert account.check_password("s3cure-Passw0rd!") is True

    def test_email_is_normalised(self, user_model: type[User]) -> None:
        account = user_model.objects.create_user(
            email="  Loud@Example.COM ",
            password="s3cure-Passw0rd!",
        )

        assert account.email == "loud@example.com"

    def test_omitting_the_password_marks_it_unusable(
        self, user_model: type[User]
    ) -> None:
        # Invite-pending and SSO-provisioned accounts land here.
        account = user_model.objects.create_user(email="invited@example.com")

        assert account.has_usable_password() is False

    def test_extra_fields_are_applied(self, user_model: type[User]) -> None:
        account = user_model.objects.create_user(
            email="named@example.com",
            password="s3cure-Passw0rd!",
            first_name="Grace",
            last_name="Hopper",
        )

        assert account.get_full_name() == "Grace Hopper"

    @pytest.mark.parametrize("email", ["", None])
    def test_missing_email_is_rejected(
        self, user_model: type[User], email: Any
    ) -> None:
        with pytest.raises(ValueError, match="email address"):
            user_model.objects.create_user(email=email, password="x")

    def test_malformed_email_is_rejected(self, user_model: type[User]) -> None:
        with pytest.raises(ValueError, match="valid email"):
            user_model.objects.create_user(
                email="definitely-not-an-email",
                password="s3cure-Passw0rd!",
            )

    def test_duplicate_email_raises_validation_error_not_integrity_error(
        self, user: User, user_model: type[User]
    ) -> None:
        # A ValidationError leaves the surrounding transaction usable.
        with pytest.raises(ValidationError):
            user_model.objects.create_user(
                email=user.email.upper(),
                password="s3cure-Passw0rd!",
            )


class TestCreateSuperuser:
    def test_sets_both_privilege_flags(self, user_model: type[User]) -> None:
        account = user_model.objects.create_superuser(
            email="admin@example.com",
            password="s3cure-Passw0rd!",
        )

        assert account.is_staff is True
        assert account.is_superuser is True
        assert account.is_active is True

    def test_rejects_is_staff_false(self, user_model: type[User]) -> None:
        with pytest.raises(ValueError, match="is_staff=True"):
            user_model.objects.create_superuser(
                email="admin@example.com",
                password="s3cure-Passw0rd!",
                is_staff=False,
            )

    def test_rejects_is_superuser_false(self, user_model: type[User]) -> None:
        with pytest.raises(ValueError, match="is_superuser=True"):
            user_model.objects.create_superuser(
                email="admin@example.com",
                password="s3cure-Passw0rd!",
                is_superuser=False,
            )


class TestCreatesuperuserCommand:
    """The manage.py flow, which is where a missing USERNAME_FIELD shows up."""

    def test_it_creates_a_superuser_from_an_email_alone(
        self, user_model: type[User]
    ) -> None:
        call_command(
            "createsuperuser",
            email="cli@example.com",
            interactive=False,
            verbosity=0,
        )

        account = user_model.objects.get(email="cli@example.com")
        assert account.is_superuser is True
        assert account.is_staff is True

    def test_non_interactive_creation_leaves_the_password_unusable(
        self, user_model: type[User]
    ) -> None:
        call_command(
            "createsuperuser",
            email="cli@example.com",
            interactive=False,
            verbosity=0,
        )

        account = user_model.objects.get(email="cli@example.com")
        assert account.has_usable_password() is False

    def test_it_rejects_a_username_argument(self, user_model: type[User]) -> None:
        # There is no username field, so the option must not exist.
        with pytest.raises(TypeError):
            call_command(
                "createsuperuser",
                username="someone",
                interactive=False,
                verbosity=0,
            )


class TestNaturalKeyLookup:
    def test_lookup_is_case_insensitive(
        self, user: User, user_model: type[User]
    ) -> None:
        found = user_model.objects.get_by_natural_key("MEMBER@EXAMPLE.COM")

        assert found.pk == user.pk

    def test_lookup_ignores_whitespace(
        self, user: User, user_model: type[User]
    ) -> None:
        found = user_model.objects.get_by_natural_key(" member@example.com ")

        assert found.pk == user.pk

    def test_deleted_users_are_not_found(
        self, deleted_user: User, user_model: type[User]
    ) -> None:
        with pytest.raises(user_model.DoesNotExist):
            user_model.objects.get_by_natural_key(deleted_user.email)


class TestQuerysetScoping:
    def test_default_manager_hides_deleted_users(
        self, user: User, deleted_user: User, user_model: type[User]
    ) -> None:
        assert list(user_model.objects.all()) == [user]

    def test_all_objects_sees_everything(
        self, user: User, deleted_user: User, user_model: type[User]
    ) -> None:
        assert user_model.all_objects.count() == 2

    def test_dead_returns_only_deleted_users(
        self, user: User, deleted_user: User, user_model: type[User]
    ) -> None:
        assert list(user_model.all_objects.dead()) == [deleted_user]

    def test_alive_returns_only_live_users(
        self, user: User, deleted_user: User, user_model: type[User]
    ) -> None:
        assert list(user_model.all_objects.alive()) == [user]

    def test_active_excludes_deactivated_accounts(
        self, user: User, other_user: User, user_model: type[User]
    ) -> None:
        other_user.is_active = False
        other_user.save(update_fields=["is_active"])

        assert list(user_model.objects.active()) == [user]

    def test_staff_filters_on_the_staff_flag(
        self, user: User, superuser: User, user_model: type[User]
    ) -> None:
        assert list(user_model.objects.staff()) == [superuser]
