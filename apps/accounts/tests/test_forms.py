"""Form validation for account creation and editing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from apps.accounts.forms import UserChangeForm, UserCreationForm

if TYPE_CHECKING:
    from apps.accounts.models import User

pytestmark = pytest.mark.django_db

STRONG_PASSWORD = "s3cure-Passw0rd!"


def creation_data(**overrides: Any) -> dict[str, Any]:
    data = {
        "email": "signup@example.com",
        "first_name": "Ada",
        "last_name": "Lovelace",
        "password1": STRONG_PASSWORD,
        "password2": STRONG_PASSWORD,
    }
    data.update(overrides)
    return data


def change_data(user: User, **overrides: Any) -> dict[str, Any]:
    data = {
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "groups": [],
        "user_permissions": [],
    }
    data.update(overrides)
    return data


class TestUserCreationForm:
    def test_valid_data_is_accepted(self) -> None:
        form = UserCreationForm(data=creation_data())

        assert form.is_valid(), form.errors

    def test_save_hashes_the_password(self) -> None:
        form = UserCreationForm(data=creation_data())
        assert form.is_valid(), form.errors

        account = form.save()

        assert account.password != STRONG_PASSWORD
        assert account.check_password(STRONG_PASSWORD) is True

    def test_save_persists_the_account(self, user_model: type[User]) -> None:
        form = UserCreationForm(data=creation_data())
        assert form.is_valid(), form.errors

        account = form.save()

        assert user_model.objects.filter(pk=account.pk).exists()

    def test_save_without_commit_does_not_touch_the_database(
        self, user_model: type[User]
    ) -> None:
        form = UserCreationForm(data=creation_data())
        assert form.is_valid(), form.errors

        account = form.save(commit=False)

        assert not user_model.all_objects.filter(pk=account.pk).exists()
        assert account.check_password(STRONG_PASSWORD) is True

    def test_email_is_normalised(self) -> None:
        form = UserCreationForm(data=creation_data(email="  Signup@Example.COM "))
        assert form.is_valid(), form.errors

        assert form.cleaned_data["email"] == "signup@example.com"

    def test_email_is_required(self) -> None:
        form = UserCreationForm(data=creation_data(email=""))

        assert form.is_valid() is False
        assert "email" in form.errors

    def test_mismatched_passwords_are_rejected(self) -> None:
        form = UserCreationForm(data=creation_data(password2="something-else"))

        assert form.is_valid() is False
        assert form.has_error("password2", code="password_mismatch")

    @pytest.mark.parametrize(
        "weak",
        [
            "password",  # CommonPasswordValidator
            "12345678",  # NumericPasswordValidator
            "abc",  # MinimumLengthValidator
        ],
    )
    def test_weak_passwords_are_rejected(self, weak: str) -> None:
        form = UserCreationForm(
            data=creation_data(password1=weak, password2=weak),
        )

        assert form.is_valid() is False
        assert "password2" in form.errors

    def test_password_too_similar_to_email_is_rejected(self) -> None:
        # Only reachable because validation runs against the populated
        # instance, not against the raw POST data.
        form = UserCreationForm(
            data=creation_data(
                email="ada.lovelace@example.com",
                password1="ada.lovelace",
                password2="ada.lovelace",
            ),
        )

        assert form.is_valid() is False
        assert "password2" in form.errors

    def test_duplicate_email_is_rejected(self, user: User) -> None:
        form = UserCreationForm(data=creation_data(email=user.email))

        assert form.is_valid() is False
        assert form.has_error("email", code="email_taken")

    def test_duplicate_email_is_rejected_case_insensitively(self, user: User) -> None:
        form = UserCreationForm(data=creation_data(email=user.email.upper()))

        assert form.is_valid() is False
        assert form.has_error("email", code="email_taken")

    def test_email_held_by_a_deleted_account_gets_its_own_message(
        self, deleted_user: User
    ) -> None:
        # The address stays reserved: the row -- and the unique index entry --
        # still exist, so staff are told to restore rather than recreate.
        form = UserCreationForm(data=creation_data(email=deleted_user.email))

        assert form.is_valid() is False
        assert form.has_error("email", code="email_taken_by_deleted")
        assert "Restore" in str(form.errors["email"])

    def test_there_is_no_username_field(self) -> None:
        assert "username" not in UserCreationForm().fields


class TestUserChangeForm:
    def test_unchanged_data_is_valid(self, user: User) -> None:
        form = UserChangeForm(instance=user, data=change_data(user))

        assert form.is_valid(), form.errors

    def test_own_email_does_not_count_as_a_duplicate(self, user: User) -> None:
        form = UserChangeForm(instance=user, data=change_data(user))
        assert form.is_valid(), form.errors

        assert form.cleaned_data["email"] == user.email

    def test_another_users_email_is_rejected(
        self, user: User, other_user: User
    ) -> None:
        form = UserChangeForm(
            instance=user,
            data=change_data(user, email=other_user.email),
        )

        assert form.is_valid() is False
        assert form.has_error("email", code="email_taken")

    def test_a_deleted_users_email_is_rejected(
        self, user: User, deleted_user: User
    ) -> None:
        form = UserChangeForm(
            instance=user,
            data=change_data(user, email=deleted_user.email),
        )

        assert form.is_valid() is False
        assert form.has_error("email", code="email_taken_by_deleted")

    def test_email_is_normalised_on_change(self, user: User) -> None:
        form = UserChangeForm(
            instance=user,
            data=change_data(user, email="Renamed@Example.COM"),
        )
        assert form.is_valid(), form.errors

        account = form.save()

        assert account.email == "renamed@example.com"

    def test_superuser_without_staff_status_is_rejected(self, user: User) -> None:
        form = UserChangeForm(
            instance=user,
            data=change_data(user, is_superuser=True, is_staff=False),
        )

        assert form.is_valid() is False
        assert form.has_error("is_staff", code="superuser_requires_staff")

    def test_superuser_with_staff_status_is_accepted(self, user: User) -> None:
        form = UserChangeForm(
            instance=user,
            data=change_data(user, is_superuser=True, is_staff=True),
        )

        assert form.is_valid(), form.errors

    def test_password_field_is_read_only(self, user: User) -> None:
        form = UserChangeForm(instance=user)

        assert form.fields["password"].disabled is True

    def test_password_hash_survives_an_edit(self, user: User) -> None:
        original_hash = user.password

        form = UserChangeForm(
            instance=user,
            data=change_data(user, first_name="Augusta"),
        )
        assert form.is_valid(), form.errors
        account = form.save()

        account.refresh_from_db()
        assert account.password == original_hash
        assert account.check_password("s3cure-Passw0rd!") is True

    def test_password_help_text_links_to_the_change_form(self, user: User) -> None:
        form = UserChangeForm(instance=user)

        assert "../password/" in form.fields["password"].help_text

    def test_there_is_no_username_field(self, user: User) -> None:
        assert "username" not in UserChangeForm(instance=user).fields
