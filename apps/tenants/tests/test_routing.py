"""Hostname routing: which schema and which URLconf a request lands on.

These go through the real ``TenantMainMiddleware`` -- the requests are made
with a plain ``django.test.Client`` and an explicit ``Host`` header, not with
``TenantClient``, which would short-circuit the very code under test by
assigning ``request.tenant`` itself.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest
from django.conf import settings
from django.http import HttpRequest
from django.test import Client as HttpClient

from apps.tenants.models import Domain
from apps.tenants.utils import current_schema_name

if TYPE_CHECKING:
    from apps.tenants.models import Tenant

ADMIN_LOGIN = "/admin/login/"


@pytest.fixture
def http() -> HttpClient:
    return HttpClient()


@pytest.mark.django_db
class TestHostnameResolution:
    def test_tenant_host_activates_its_schema(
        self,
        http: HttpClient,
        acme: Tenant,
    ) -> None:
        response = http.get(ADMIN_LOGIN, headers={"host": "acme.testserver"})

        assert response.status_code == 200
        assert response.wsgi_request.tenant.schema_name == "acme"

    def test_each_host_selects_its_own_schema(
        self,
        http: HttpClient,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        first = http.get(ADMIN_LOGIN, headers={"host": "acme.testserver"})
        second = http.get(ADMIN_LOGIN, headers={"host": "beta.testserver"})

        assert first.wsgi_request.tenant.schema_name == "acme"
        assert second.wsgi_request.tenant.schema_name == "beta"

    def test_public_host_activates_the_public_schema(
        self,
        http: HttpClient,
        public_tenant: Tenant,
    ) -> None:
        response = http.get(ADMIN_LOGIN, headers={"host": "public.testserver"})

        assert response.status_code == 200
        assert response.wsgi_request.tenant.schema_name == "public"

    def test_unknown_host_is_404_not_a_fallback_to_public(
        self,
        http: HttpClient,
        public_tenant: Tenant,
    ) -> None:
        # SHOW_PUBLIC_IF_NO_TENANT_FOUND is off: an unrouted hostname must not
        # quietly render the platform's own site.
        response = http.get(ADMIN_LOGIN, headers={"host": "nobody.testserver"})

        assert response.status_code == 404

    def test_host_matching_is_case_insensitive(
        self,
        http: HttpClient,
        acme: Tenant,
    ) -> None:
        response = http.get(ADMIN_LOGIN, headers={"host": "ACME.testserver"})

        assert response.status_code == 200
        assert response.wsgi_request.tenant.schema_name == "acme"

    def test_port_is_ignored(self, http: HttpClient, acme: Tenant) -> None:
        response = http.get(ADMIN_LOGIN, headers={"host": "acme.testserver:8000"})

        assert response.status_code == 200

    def test_alias_domain_reaches_the_same_tenant(
        self,
        http: HttpClient,
        acme: Tenant,
    ) -> None:
        Domain.objects.create(tenant=acme, domain="alias.testserver", is_primary=False)

        response = http.get(ADMIN_LOGIN, headers={"host": "alias.testserver"})

        assert response.wsgi_request.tenant.schema_name == "acme"


@pytest.mark.django_db
class TestSuspendedTenant:
    def test_suspended_tenant_is_refused(
        self,
        http: HttpClient,
        acme: Tenant,
    ) -> None:
        acme.is_active = False
        acme.save()

        response = http.get(ADMIN_LOGIN, headers={"host": "acme.testserver"})

        # Indistinguishable from an unknown host, on purpose: telling the two
        # apart would confirm a customer exists to anyone guessing subdomains.
        assert response.status_code == 404

    def test_suspension_does_not_touch_the_schema(
        self,
        acme: Tenant,
        schema_tables: Callable[[str], set[str]],
    ) -> None:
        acme.is_active = False
        acme.save()

        assert "accounts_user" in schema_tables("acme")


def effective_urlconf(request: HttpRequest) -> str:
    """URLconf Django will resolve against for this request.

    ``TenantMainMiddleware`` only sets ``request.urlconf`` when it needs to
    *override* the default, i.e. for the public schema; tenant requests fall
    through to ``ROOT_URLCONF``.
    """
    return getattr(request, "urlconf", settings.ROOT_URLCONF)


@pytest.mark.django_db
class TestUrlconfSelection:
    def test_tenant_request_uses_the_tenant_urlconf(
        self,
        http: HttpClient,
        acme: Tenant,
    ) -> None:
        response = http.get(ADMIN_LOGIN, headers={"host": "acme.testserver"})

        assert effective_urlconf(response.wsgi_request) == "config.urls"

    def test_public_request_uses_the_public_urlconf(
        self,
        http: HttpClient,
        public_tenant: Tenant,
    ) -> None:
        response = http.get(ADMIN_LOGIN, headers={"host": "public.testserver"})

        assert effective_urlconf(response.wsgi_request) == "config.urls_public"

    def test_the_two_urlconfs_are_actually_different_modules(self) -> None:
        assert settings.ROOT_URLCONF != settings.PUBLIC_SCHEMA_URLCONF


@pytest.mark.django_db
class TestConnectionState:
    def test_connection_starts_on_public(self) -> None:
        assert current_schema_name() == "public"

    def test_middleware_leaves_the_tenant_active_for_the_request(
        self,
        http: HttpClient,
        acme: Tenant,
    ) -> None:
        response = http.get(ADMIN_LOGIN, headers={"host": "acme.testserver"})

        # request.tenant is the model instance, not a FakeTenant, so views can
        # read tenant attributes without another query.
        tenant = response.wsgi_request.tenant
        assert tenant.pk == acme.pk
        assert tenant.name == "Acme Institute"
