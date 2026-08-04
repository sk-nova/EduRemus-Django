"""Shared fixtures for the accounts suite.

Everything reaches the user model through ``get_user_model()`` so these tests
keep passing if ``AUTH_USER_MODEL`` is ever repointed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from django.contrib.auth import get_user_model

if TYPE_CHECKING:
    from apps.accounts.models import User

PASSWORD = "s3cure-Passw0rd!"


@pytest.fixture
def user_model() -> type[User]:
    return get_user_model()


@pytest.fixture
def password() -> str:
    return PASSWORD


@pytest.fixture
def user(db: None, user_model: type[User]) -> User:
    return user_model.objects.create_user(
        email="member@example.com",
        password=PASSWORD,
        first_name="Ada",
        last_name="Lovelace",
    )


@pytest.fixture
def other_user(db: None, user_model: type[User]) -> User:
    return user_model.objects.create_user(
        email="other@example.com",
        password=PASSWORD,
    )


@pytest.fixture
def deleted_user(db: None, user_model: type[User]) -> User:
    account = user_model.objects.create_user(
        email="gone@example.com",
        password=PASSWORD,
    )
    account.delete()
    return account


@pytest.fixture
def superuser(db: None, user_model: type[User]) -> User:
    return user_model.objects.create_superuser(
        email="root@example.com",
        password=PASSWORD,
    )
