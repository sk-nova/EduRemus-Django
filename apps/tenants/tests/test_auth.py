"""Authentication is per tenant.

A schema owns its own ``accounts_user`` and ``django_session`` tables, so an
account and the session it produces are meaningless in any other schema. These
tests drive the full HTTP stack -- middleware included -- because that is where
a leak would actually show up.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from django.contrib.auth import get_user_model
from django.test import Client as HttpClient
from django_tenants.utils import tenant_context

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.tenants.models import Tenant

PASSWORD = "s3cure-Passw0rd!"
ADMIN_INDEX = "/admin/"


def create_staff(email: str) -> User:
    return get_user_model().objects.create_superuser(email=email, password=PASSWORD)


@pytest.fixture
def acme_staff(acme: Tenant) -> User:
    with tenant_context(acme):
        return create_staff("head@acme.test")


@pytest.mark.django_db
class TestPerTenantAccounts:
    def test_the_same_address_is_a_different_account_per_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        with tenant_context(acme):
            first = create_staff("head@example.test")
        with tenant_context(beta):
            second = create_staff("head@example.test")

        # Same email, two unrelated accounts -- and two unrelated UUIDs.
        assert first.pk != second.pk

    def test_credentials_do_not_work_on_another_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_staff: User,
    ) -> None:
        http = HttpClient()

        response = http.post(
            "/admin/login/",
            {"username": "head@acme.test", "password": PASSWORD},
            headers={"host": "beta.testserver"},
        )

        # No such user in beta's schema, so the login form comes back.
        assert response.status_code == 200
        assert "_auth_user_id" not in http.session

    def test_login_succeeds_on_the_owning_tenant(
        self,
        acme: Tenant,
        acme_staff: User,
    ) -> None:
        http = HttpClient()

        login = http.post(
            "/admin/login/",
            {"username": "head@acme.test", "password": PASSWORD, "next": ADMIN_INDEX},
            headers={"host": "acme.testserver"},
        )
        assert login.status_code == 302

        response = http.get(ADMIN_INDEX, headers={"host": "acme.testserver"})

        assert response.status_code == 200
        assert response.wsgi_request.user.is_authenticated
        assert response.wsgi_request.user.email == "head@acme.test"


def signed_in_client(host: str, email: str) -> HttpClient:
    """A test client holding a valid session for ``host``."""
    http = HttpClient()
    http.post(
        "/admin/login/",
        {"username": email, "password": PASSWORD, "next": ADMIN_INDEX},
        headers={"host": host},
    )
    return http


@pytest.mark.django_db
class TestSessionIsolation:
    def test_a_replayed_session_cookie_does_not_authenticate_elsewhere(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_staff: User,
    ) -> None:
        http = signed_in_client("acme.testserver", "head@acme.test")
        assert "_auth_user_id" in http.session

        # A second client carrying acme's cookie, which is what an attacker
        # replaying it at beta's hostname would have. Real browsers keep the
        # jars apart because SESSION_COOKIE_DOMAIN is unset; this skips that
        # protection to test the one behind it.
        replay = HttpClient()
        replay.cookies.update(http.cookies)

        response = replay.get(ADMIN_INDEX, headers={"host": "beta.testserver"})

        # beta's django_session table has no such row, so the request is
        # anonymous no matter how valid the cookie looks.
        assert not response.wsgi_request.user.is_authenticated

    def test_the_original_session_is_unaffected_by_the_replay(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_staff: User,
    ) -> None:
        http = signed_in_client("acme.testserver", "head@acme.test")
        replay = HttpClient()
        replay.cookies.update(http.cookies)
        replay.get(ADMIN_INDEX, headers={"host": "beta.testserver"})

        response = http.get(ADMIN_INDEX, headers={"host": "acme.testserver"})

        assert response.wsgi_request.user.is_authenticated


@pytest.mark.django_db
class TestPublicSchemaAccounts:
    def test_platform_staff_live_in_the_public_schema(
        self,
        public_tenant: Tenant,
        acme: Tenant,
    ) -> None:
        operator = create_staff("ops@eduremus.test")

        assert operator.pk is not None
        with tenant_context(acme):
            assert (
                not get_user_model().objects.filter(email="ops@eduremus.test").exists()
            )

    def test_platform_staff_cannot_log_in_to_a_tenant(
        self,
        public_tenant: Tenant,
        acme: Tenant,
    ) -> None:
        create_staff("ops@eduremus.test")
        http = HttpClient()

        response = http.post(
            "/admin/login/",
            {"username": "ops@eduremus.test", "password": PASSWORD},
            headers={"host": "acme.testserver"},
        )

        assert response.status_code == 200
        assert "_auth_user_id" not in http.session
