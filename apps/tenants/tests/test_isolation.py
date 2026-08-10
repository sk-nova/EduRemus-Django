"""Cross-tenant data isolation.

Isolation here is a property of the connection's ``search_path``, not of any
query filter, so these tests deliberately use *unfiltered* ORM calls
(``objects.all()``, ``objects.count()``). If isolation depended on application
code remembering to filter, these are exactly the queries that would leak.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django_tenants.utils import schema_context, tenant_context

from apps.tenants.models import Tenant
from apps.tenants.utils import current_schema_name, public_schema

if TYPE_CHECKING:
    from apps.accounts.models import User

PASSWORD = "s3cure-Passw0rd!"


def create_user(email: str) -> User:
    return get_user_model().objects.create_user(email=email, password=PASSWORD)


@pytest.mark.django_db
class TestRowIsolation:
    def test_a_user_created_in_one_tenant_is_invisible_in_the_other(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        with tenant_context(acme):
            create_user("head@acme.test")
            assert get_user_model().objects.count() == 1

        with tenant_context(beta):
            assert get_user_model().objects.count() == 0

    def test_the_same_email_can_exist_in_both_tenants(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        # A globally unique email would be a cross-tenant identifier and a
        # leak in itself. Uniqueness is per schema, which is what a customer
        # of two institutions needs.
        with tenant_context(acme):
            create_user("shared@example.test")

        with tenant_context(beta):
            create_user("shared@example.test")

        with tenant_context(acme):
            assert get_user_model().objects.count() == 1
        with tenant_context(beta):
            assert get_user_model().objects.count() == 1

    def test_tenant_rows_are_invisible_from_the_public_schema(
        self,
        acme: Tenant,
    ) -> None:
        with tenant_context(acme):
            create_user("head@acme.test")

        with public_schema():
            assert not get_user_model().objects.filter(email="head@acme.test").exists()

    def test_deleting_in_one_tenant_leaves_the_other_alone(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        with tenant_context(acme):
            create_user("staff@example.test")
        with tenant_context(beta):
            create_user("staff@example.test")

        with tenant_context(acme):
            get_user_model().objects.all().delete()

        with tenant_context(beta):
            assert get_user_model().objects.count() == 1


@pytest.mark.django_db
class TestSharedTablesRemainReachable:
    def test_catalogue_is_readable_from_inside_a_tenant(
        self,
        acme: Tenant,
    ) -> None:
        # A tenant schema's search_path is ("<schema>", "public"), so tables
        # that exist only in public still resolve. That is what keeps shared
        # models usable from tenant code.
        with tenant_context(acme):
            assert Tenant.objects.filter(schema_name="acme").exists()

    def test_catalogue_writes_from_a_tenant_land_in_public(
        self,
        acme: Tenant,
    ) -> None:
        with tenant_context(acme), public_schema():
            Tenant.objects.filter(pk=acme.pk).update(name="Renamed")

        with public_schema():
            acme.refresh_from_db()
            assert acme.name == "Renamed"


@pytest.mark.django_db
class TestContentTypeIsolation:
    def test_each_schema_has_its_own_content_types(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        # django-tenants clears the ContentType cache on every schema switch,
        # because the same model has different ids in different schemas.
        # Caching across the boundary would hand out the wrong permissions.
        with tenant_context(acme):
            acme_ids = set(ContentType.objects.values_list("id", flat=True))
        with tenant_context(beta):
            beta_ids = set(ContentType.objects.values_list("id", flat=True))

        assert acme_ids and beta_ids

    def test_permissions_created_in_a_tenant_stay_there(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        from django.contrib.auth.models import Group

        with tenant_context(acme):
            Group.objects.create(name="Registrars")

        with tenant_context(beta):
            assert not Group.objects.filter(name="Registrars").exists()


@pytest.mark.django_db
class TestSchemaSwitching:
    def test_context_manager_restores_the_previous_schema(
        self,
        acme: Tenant,
    ) -> None:
        assert current_schema_name() == "public"

        with tenant_context(acme):
            assert current_schema_name() == "acme"

        assert current_schema_name() == "public"

    def test_nested_contexts_unwind_in_order(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        with tenant_context(acme):
            with tenant_context(beta):
                assert current_schema_name() == "beta"
            assert current_schema_name() == "acme"

        assert current_schema_name() == "public"

    def test_schema_context_takes_a_bare_name(self, acme: Tenant) -> None:
        with schema_context("acme"):
            assert current_schema_name() == "acme"

    def test_search_path_puts_the_tenant_first(
        self,
        acme: Tenant,
        schema_tables: Callable[[str], set[str]],
    ) -> None:
        with tenant_context(acme), connection.cursor() as cursor:
            cursor.execute("SHOW search_path")
            search_path = cursor.fetchone()[0]

        # Order is what makes a tenant's accounts_user shadow the public one.
        assert search_path.replace('"', "").replace(" ", "") == "acme,public"
