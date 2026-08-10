"""The admin is per tenant, and the catalogue is public-only.

Two properties matter here:

* Inside a tenant, the admin shows that tenant's rows -- ``UserAdmin`` on
  ``acme.example.com`` lists acme's users and nobody else's.
* :class:`~apps.tenants.models.Tenant` and :class:`~apps.tenants.models.Domain`
  are not reachable from a tenant's admin at all. Their tables only exist in
  public, so without this a tenant administrator would meet a 500 -- or worse,
  read the public rows through the shared search_path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from django.contrib import admin as django_admin
from django.contrib.auth import get_user_model
from django.test import Client as HttpClient
from django.urls import reverse
from django_tenants.utils import schema_exists, tenant_context

from apps.tenants.admin import TenantAdmin
from apps.tenants.models import Tenant as TenantModel

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.tenants.models import Tenant

PASSWORD = "s3cure-Passw0rd!"
TENANT_CHANGELIST = "/admin/tenants/tenant/"
DOMAIN_CHANGELIST = "/admin/tenants/domain/"
USER_CHANGELIST = "/admin/accounts/user/"


def create_staff(email: str) -> User:
    return get_user_model().objects.create_superuser(email=email, password=PASSWORD)


def signed_in(host: str, email: str) -> HttpClient:
    http = HttpClient()
    http.post(
        "/admin/login/",
        {"username": email, "password": PASSWORD, "next": "/admin/"},
        headers={"host": host},
    )
    return http


@pytest.fixture
def acme_admin(acme: Tenant) -> HttpClient:
    with tenant_context(acme):
        create_staff("head@acme.test")
    return signed_in("acme.testserver", "head@acme.test")


@pytest.fixture
def platform_admin(public_tenant: Tenant) -> HttpClient:
    create_staff("ops@eduremus.test")
    return signed_in("public.testserver", "ops@eduremus.test")


@pytest.mark.django_db
class TestCatalogueIsPublicOnly:
    def test_platform_admin_can_reach_the_tenant_changelist(
        self,
        platform_admin: HttpClient,
    ) -> None:
        response = platform_admin.get(
            TENANT_CHANGELIST,
            headers={"host": "public.testserver"},
        )

        assert response.status_code == 200

    def test_platform_admin_can_reach_the_domain_changelist(
        self,
        platform_admin: HttpClient,
    ) -> None:
        response = platform_admin.get(
            DOMAIN_CHANGELIST,
            headers={"host": "public.testserver"},
        )

        assert response.status_code == 200

    def test_tenant_admin_cannot_reach_the_tenant_changelist(
        self,
        acme_admin: HttpClient,
        beta: Tenant,
    ) -> None:
        response = acme_admin.get(
            TENANT_CHANGELIST,
            headers={"host": "acme.testserver"},
        )

        # PublicSchemaOnlyAdmin denies the permission, so the admin treats the
        # model as if it were never registered.
        assert response.status_code == 403

    def test_tenant_admin_index_does_not_list_the_tenants_app(
        self,
        acme_admin: HttpClient,
    ) -> None:
        response = acme_admin.get("/admin/", headers={"host": "acme.testserver"})
        app_labels = {app["app_label"] for app in response.context["available_apps"]}

        assert "tenants" not in app_labels
        assert "accounts" in app_labels

    def test_public_admin_index_lists_the_tenants_app(
        self,
        platform_admin: HttpClient,
    ) -> None:
        response = platform_admin.get("/admin/", headers={"host": "public.testserver"})
        app_labels = {app["app_label"] for app in response.context["available_apps"]}

        assert "tenants" in app_labels


@pytest.mark.django_db
class TestUserAdminIsScopedToTheSchema:
    def test_changelist_shows_only_this_tenants_users(
        self,
        acme_admin: HttpClient,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        with tenant_context(beta):
            create_staff("head@beta.test")

        response = acme_admin.get(
            USER_CHANGELIST,
            headers={"host": "acme.testserver"},
        )
        body = response.content.decode()

        assert "head@acme.test" in body
        assert "head@beta.test" not in body

    def test_another_tenants_user_cannot_be_opened_by_pk(
        self,
        acme_admin: HttpClient,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        with tenant_context(beta):
            outsider = create_staff("head@beta.test")

        url = reverse("admin:accounts_user_change", args=[outsider.pk])
        response = acme_admin.get(url, headers={"host": "acme.testserver"})

        # The pk simply does not exist in acme's accounts_user table.
        assert response.status_code == 302
        assert response["Location"].endswith("/admin/")


@pytest.fixture
def tenant_admin() -> TenantAdmin:
    return TenantAdmin(TenantModel, django_admin.site)


@pytest.mark.django_db
class TestTenantAdminSafety:
    def test_schema_name_is_editable_only_before_the_schema_exists(
        self,
        tenant_admin: TenantAdmin,
        platform_admin: HttpClient,
        acme: Tenant,
    ) -> None:
        request = platform_admin.get(
            "/admin/",
            headers={"host": "public.testserver"},
        ).wsgi_request

        # Renaming it on an existing row would leave the catalogue pointing at
        # a schema Postgres never renamed.
        assert "schema_name" in tenant_admin.get_readonly_fields(request, acme)
        assert "schema_name" not in tenant_admin.get_readonly_fields(request, None)

    def test_admin_delete_keeps_the_schema(
        self,
        tenant_admin: TenantAdmin,
        platform_admin: HttpClient,
        acme: Tenant,
    ) -> None:
        request = platform_admin.get(
            "/admin/",
            headers={"host": "public.testserver"},
        ).wsgi_request

        tenant_admin.delete_model(request, acme)

        # The row is gone, the customer's data is not: dropping a schema must
        # never be one mis-click away.
        assert not TenantModel.objects.filter(pk=acme.pk).exists()
        assert schema_exists("acme")

    def test_bulk_admin_delete_also_keeps_the_schemas(
        self,
        tenant_admin: TenantAdmin,
        platform_admin: HttpClient,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        request = platform_admin.get(
            "/admin/",
            headers={"host": "public.testserver"},
        ).wsgi_request
        queryset = TenantModel.objects.filter(pk__in=[acme.pk, beta.pk])

        tenant_admin.delete_queryset(request, queryset)

        assert not TenantModel.objects.filter(pk__in=[acme.pk, beta.pk]).exists()
        assert schema_exists("acme")
        assert schema_exists("beta")
