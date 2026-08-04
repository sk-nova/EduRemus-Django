"""Soft deletion: instance-level, bulk, and the escape hatches."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from apps.accounts.models import User

pytestmark = pytest.mark.django_db


class TestInstanceDelete:
    def test_delete_keeps_the_row(self, user: User, user_model: type[User]) -> None:
        user.delete()

        assert user_model.all_objects.filter(pk=user.pk).exists()

    def test_delete_stamps_deleted_at(self, user: User) -> None:
        user.delete()
        user.refresh_from_db()

        assert user.deleted_at is not None
        assert user.is_deleted is True

    def test_delete_also_deactivates(self, user: User) -> None:
        # One UPDATE makes "cannot sign in" true for both the soft-delete
        # filter and any code that only inspects is_active.
        user.delete()
        user.refresh_from_db()

        assert user.is_active is False

    def test_delete_reports_django_style_counts(self, user: User) -> None:
        count, per_label = user.delete()

        assert count == 1
        assert per_label == {"accounts.User": 1}

    def test_delete_is_idempotent(self, user: User) -> None:
        user.delete()
        user.refresh_from_db()
        first_stamp = user.deleted_at

        count, per_label = user.delete()

        user.refresh_from_db()
        assert (count, per_label) == (0, {})
        assert user.deleted_at == first_stamp

    def test_delete_hides_the_user_from_the_default_manager(
        self, user: User, user_model: type[User]
    ) -> None:
        user.delete()

        assert not user_model.objects.filter(pk=user.pk).exists()


class TestRestore:
    def test_restore_clears_the_stamp(self, deleted_user: User) -> None:
        deleted_user.restore()
        deleted_user.refresh_from_db()

        assert deleted_user.deleted_at is None
        assert deleted_user.is_deleted is False

    def test_restore_reactivates(self, deleted_user: User) -> None:
        deleted_user.restore()
        deleted_user.refresh_from_db()

        assert deleted_user.is_active is True

    def test_restored_users_reappear(
        self, deleted_user: User, user_model: type[User]
    ) -> None:
        deleted_user.restore()

        assert user_model.objects.filter(pk=deleted_user.pk).exists()

    def test_restoring_a_live_user_is_a_no_op(self, user: User) -> None:
        user.restore()
        user.refresh_from_db()

        assert user.deleted_at is None


class TestHardDelete:
    def test_hard_delete_removes_the_row(
        self, user: User, user_model: type[User]
    ) -> None:
        user.hard_delete()

        assert not user_model.all_objects.filter(pk=user.pk).exists()

    def test_delete_with_hard_flag_removes_the_row(
        self, user: User, user_model: type[User]
    ) -> None:
        user.delete(hard=True)

        assert not user_model.all_objects.filter(pk=user.pk).exists()

    def test_hard_delete_works_on_already_soft_deleted_rows(
        self, deleted_user: User, user_model: type[User]
    ) -> None:
        deleted_user.hard_delete()

        assert not user_model.all_objects.filter(pk=deleted_user.pk).exists()


class TestQuerysetDelete:
    def test_bulk_delete_is_soft(
        self, user: User, other_user: User, user_model: type[User]
    ) -> None:
        count, _labels = user_model.objects.all().delete()

        assert count == 2
        assert user_model.all_objects.count() == 2
        assert user_model.objects.count() == 0

    def test_bulk_delete_deactivates(self, user: User, user_model: type[User]) -> None:
        user_model.objects.all().delete()
        user.refresh_from_db()

        assert user.is_active is False

    def test_bulk_delete_preserves_existing_stamps(
        self, deleted_user: User, user: User, user_model: type[User]
    ) -> None:
        original_stamp = deleted_user.deleted_at

        count, _labels = user_model.all_objects.all().delete()

        deleted_user.refresh_from_db()
        assert count == 1  # only the live user was affected
        assert deleted_user.deleted_at == original_stamp

    def test_bulk_hard_delete_removes_rows(
        self, user: User, other_user: User, user_model: type[User]
    ) -> None:
        user_model.all_objects.all().hard_delete()

        assert user_model.all_objects.count() == 0

    def test_bulk_restore(self, deleted_user: User, user_model: type[User]) -> None:
        restored = user_model.all_objects.restore()

        deleted_user.refresh_from_db()
        assert restored == 1
        assert deleted_user.is_deleted is False
        assert deleted_user.is_active is True
