"""The reusable soft-delete layer, exercised on its own terms.

``apps.core`` declares no concrete models, so rather than invent a test-only
table (and the migration that comes with it) these tests bind the *generic*
manager to the one model in the project that uses the mixin. What is under
test is therefore the shared base-class behaviour -- not the accounts-specific
overrides, which ``apps.accounts.tests.test_soft_delete`` covers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from django.contrib.auth import get_user_model

from apps.core.managers import SoftDeleteManager, SoftDeleteQuerySet

if TYPE_CHECKING:
    from apps.accounts.models import User

pytestmark = pytest.mark.django_db


@pytest.fixture
def model() -> type[User]:
    return get_user_model()


def bind(alive_only: bool) -> SoftDeleteManager[User]:
    """Instantiate the generic manager outside of a model declaration."""
    manager: SoftDeleteManager[User] = SoftDeleteManager(alive_only=alive_only)
    manager.model = get_user_model()
    return manager


@pytest.fixture
def live_user(model: type[User]) -> User:
    return model.objects.create_user(email="live@example.com", password="pw-1234!")


@pytest.fixture
def dead_user(model: type[User]) -> User:
    account = model.objects.create_user(email="dead@example.com", password="pw-1234!")
    account.delete()
    return account


class TestManagerScoping:
    def test_alive_only_manager_hides_deleted_rows(
        self, live_user: User, dead_user: User
    ) -> None:
        assert list(bind(alive_only=True).get_queryset()) == [live_user]

    def test_unfiltered_manager_sees_everything(
        self, live_user: User, dead_user: User
    ) -> None:
        assert bind(alive_only=False).get_queryset().count() == 2

    def test_all_returns_a_soft_delete_queryset(self, live_user: User) -> None:
        # The narrowed return type is the point: helpers survive .all().
        assert isinstance(bind(alive_only=True).all(), SoftDeleteQuerySet)

    def test_alive_helper(self, live_user: User, dead_user: User) -> None:
        assert list(bind(alive_only=False).alive()) == [live_user]

    def test_dead_helper(self, live_user: User, dead_user: User) -> None:
        assert list(bind(alive_only=False).dead()) == [dead_user]


class TestManagerMutations:
    def test_restore_through_the_manager(
        self, dead_user: User, model: type[User]
    ) -> None:
        restored = bind(alive_only=False).restore()

        dead_user.refresh_from_db()
        assert restored == 1
        assert dead_user.is_deleted is False

    def test_hard_delete_through_the_manager(
        self, live_user: User, dead_user: User, model: type[User]
    ) -> None:
        bind(alive_only=False).hard_delete()

        assert model.all_objects.count() == 0

    def test_hard_delete_respects_the_managers_scope(
        self, live_user: User, dead_user: User, model: type[User]
    ) -> None:
        bind(alive_only=True).hard_delete()

        assert list(model.all_objects.all()) == [dead_user]


class TestGenericQuerysetContract:
    def test_the_base_queryset_only_stamps_deleted_at(
        self, live_user: User, model: type[User]
    ) -> None:
        # The generic layer knows nothing about is_active; that extra column
        # comes from UserQuerySet.soft_delete_values().
        queryset: SoftDeleteQuerySet[User] = SoftDeleteQuerySet(model)

        assert queryset.soft_delete_values().keys() == {"deleted_at"}
        assert queryset.restore_values() == {"deleted_at": None}

    def test_bulk_delete_reports_the_model_label(
        self, live_user: User, model: type[User]
    ) -> None:
        count, per_label = bind(alive_only=True).all().delete()

        assert count == 1
        assert per_label == {"accounts.User": 1}
