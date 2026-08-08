"""The helpers background jobs and scripts use to pick a schema."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from django.contrib.auth import get_user_model
from django_tenants.utils import schema_context, tenant_context

from apps.tenants.utils import (
    current_schema_name,
    current_tenant,
    each_tenant,
    public_schema,
    run_in_every_schema,
)

if TYPE_CHECKING:
    from apps.tenants.models import Client

PASSWORD = "s3cure-Passw0rd!"


@pytest.mark.django_db
class TestCurrentSchema:
    def test_defaults_to_public(self) -> None:
        assert current_schema_name() == "public"

    def test_follows_tenant_context(self, acme: Client) -> None:
        with tenant_context(acme):
            assert current_schema_name() == "acme"

    def test_follows_schema_context(self, acme: Client) -> None:
        with schema_context("acme"):
            assert current_schema_name() == "acme"


@pytest.mark.django_db
class TestCurrentTenant:
    def test_returns_the_instance_under_tenant_context(self, acme: Client) -> None:
        with tenant_context(acme):
            tenant = current_tenant()

        assert tenant is not None
        assert tenant.pk == acme.pk
        assert tenant.name == "Acme Institute"

    def test_returns_none_under_schema_context(self, acme: Client) -> None:
        # schema_context() only knows a name, so django-tenants installs a
        # FakeTenant. Handing that back as if it were a Client would blow up on
        # the first attribute access far away from here.
        with schema_context("acme"):
            assert current_tenant() is None

    def test_returns_none_on_the_public_schema(self, db: None) -> None:
        assert current_tenant() is None


@pytest.mark.django_db
class TestPublicSchema:
    def test_switches_to_public_and_back(self, acme: Client) -> None:
        with tenant_context(acme):
            with public_schema():
                assert current_schema_name() == "public"
            assert current_schema_name() == "acme"

    def test_reads_the_catalogue_from_inside_a_tenant(self, acme: Client) -> None:
        from apps.tenants.models import Client as TenantModel

        with tenant_context(acme), public_schema():
            assert TenantModel.objects.filter(schema_name="acme").exists()


@pytest.mark.django_db
class TestEachTenant:
    def test_visits_every_active_tenant(self, acme: Client, beta: Client) -> None:
        visited = [client.schema_name for client in each_tenant()]

        assert "acme" in visited
        assert "beta" in visited

    def test_excludes_public_by_default(
        self,
        acme: Client,
        public_tenant: Client,
    ) -> None:
        assert "public" not in [client.schema_name for client in each_tenant()]

    def test_can_include_public(self, acme: Client, public_tenant: Client) -> None:
        visited = [c.schema_name for c in each_tenant(include_public=True)]

        assert "public" in visited

    def test_skips_suspended_tenants(self, acme: Client, beta: Client) -> None:
        beta.is_active = False
        beta.save()

        assert "beta" not in [client.schema_name for client in each_tenant()]

    def test_body_runs_inside_the_tenant_schema(
        self,
        acme: Client,
        beta: Client,
    ) -> None:
        seen = {}
        for client in each_tenant():
            seen[client.schema_name] = current_schema_name()

        assert seen == {schema: schema for schema in seen}

    def test_restores_the_public_schema_afterwards(self, acme: Client) -> None:
        list(each_tenant())

        assert current_schema_name() == "public"


@pytest.mark.django_db
class TestRunInEverySchema:
    def test_returns_a_result_per_schema(self, acme: Client, beta: Client) -> None:
        with tenant_context(acme):
            get_user_model().objects.create_user(
                email="only@acme.test",
                password=PASSWORD,
            )

        counts = run_in_every_schema(get_user_model().objects.count)

        assert counts["acme"] == 1
        assert counts["beta"] == 0
