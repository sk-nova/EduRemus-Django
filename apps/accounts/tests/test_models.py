"""Model-level guarantees: identity, email invariants and schema shape."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest
from django.conf import settings
from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.db import IntegrityError, transaction

from apps.accounts.managers import UserManager

if TYPE_CHECKING:
    from apps.accounts.models import User

pytestmark = pytest.mark.django_db


class TestIdentity:
    def test_primary_key_is_a_uuid(self, user: User) -> None:
        assert isinstance(user.pk, uuid.UUID)

    def test_primary_key_uses_uuid7(self, user: User) -> None:
        # Time-ordered UUIDs are what keep the PK index from fragmenting.
        assert user.pk.version == 7

    def test_primary_keys_are_unique(self, user: User, other_user: User) -> None:
        assert user.pk != other_user.pk

    def test_primary_key_is_assigned_before_insert(
        self, user_model: type[User]
    ) -> None:
        unsaved = user_model(email="pending@example.com")
        assert isinstance(unsaved.pk, uuid.UUID)


class TestSchema:
    def test_auth_user_model_setting(self) -> None:
        assert settings.AUTH_USER_MODEL == "accounts.User"

    def test_there_is_no_username_field(self, user_model: type[User]) -> None:
        # Indirected through a variable so the django-stubs plugin does not
        # reject the lookup at type-check time -- that is the assertion.
        field_name = "username"

        with pytest.raises(FieldDoesNotExist):
            user_model._meta.get_field(field_name)

    def test_email_is_the_username_field(self, user_model: type[User]) -> None:
        assert user_model.USERNAME_FIELD == "email"
        assert user_model.EMAIL_FIELD == "email"

    def test_required_fields_is_empty(self, user_model: type[User]) -> None:
        # createsuperuser prompts for USERNAME_FIELD and password separately.
        assert user_model.REQUIRED_FIELDS == []

    def test_email_is_unique(self, user_model: type[User]) -> None:
        assert user_model._meta.get_field("email").unique

    def test_base_manager_is_unfiltered(self, user_model: type[User]) -> None:
        # Related-object traversal must still resolve soft-deleted users.
        base_manager = user_model._base_manager

        assert isinstance(base_manager, UserManager)
        assert base_manager.name == "all_objects"
        assert base_manager.alive_only is False

    def test_default_manager_hides_deleted_rows(self, user_model: type[User]) -> None:
        default_manager = user_model._default_manager

        assert isinstance(default_manager, UserManager)
        assert default_manager.name == "objects"
        assert default_manager.alive_only is True


class TestEmailNormalisation:
    def test_save_lowercases_the_whole_address(self, user_model: type[User]) -> None:
        account = user_model(email="Mixed.Case@Example.COM")
        account.set_password("irrelevant")
        account.save()

        account.refresh_from_db()
        assert account.email == "mixed.case@example.com"

    def test_save_strips_surrounding_whitespace(self, user_model: type[User]) -> None:
        account = user_model(email="  spaced@example.com  ")
        account.set_password("irrelevant")
        account.save()

        assert account.email == "spaced@example.com"

    def test_clean_normalises_the_address(self, user_model: type[User]) -> None:
        account = user_model(email="Clean@Example.com")
        account.full_clean(exclude=["password"])

        assert account.email == "clean@example.com"

    def test_duplicate_email_is_rejected_case_insensitively(
        self, user: User, user_model: type[User]
    ) -> None:
        duplicate = user_model(email=user.email.upper())
        duplicate.set_password("irrelevant")

        with pytest.raises(IntegrityError), transaction.atomic():
            duplicate.save()

    def test_database_rejects_uppercase_written_behind_the_models_back(
        self, user: User, user_model: type[User]
    ) -> None:
        # queryset.update() bypasses Model.save(), so only the CHECK
        # constraint stands between us and a mixed-case row.
        with pytest.raises(IntegrityError), transaction.atomic():
            user_model.all_objects.filter(pk=user.pk).update(
                email="SHOUTING@example.com"
            )

    def test_invalid_email_fails_validation(self, user_model: type[User]) -> None:
        account = user_model(email="not-an-email")

        with pytest.raises(ValidationError) as excinfo:
            account.full_clean(exclude=["password"])

        assert "email" in excinfo.value.error_dict


class TestDisplayHelpers:
    def test_str_is_the_email(self, user: User) -> None:
        assert str(user) == "member@example.com"

    def test_get_full_name(self, user: User) -> None:
        assert user.get_full_name() == "Ada Lovelace"

    def test_get_full_name_falls_back_to_email(self, other_user: User) -> None:
        assert other_user.get_full_name() == other_user.email

    def test_get_full_name_with_only_a_last_name(self, user: User) -> None:
        user.first_name = ""
        assert user.get_full_name() == "Lovelace"


class TestTimestamps:
    def test_created_and_updated_are_populated(self, user: User) -> None:
        assert user.created_at is not None
        assert user.updated_at is not None

    def test_updated_at_advances_on_save(self, user: User) -> None:
        original = user.updated_at

        user.first_name = "Augusta"
        user.save(update_fields=["first_name", "updated_at"])
        user.refresh_from_db()

        assert user.updated_at > original

    def test_new_users_are_not_deleted(self, user: User) -> None:
        assert user.deleted_at is None
        assert user.is_deleted is False
