"""Schema lifecycle and migration routing.

Asserts against ``information_schema`` rather than the ORM: the question is
what Postgres actually built in each schema, which is precisely what
``TenantSyncRouter`` is responsible for.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from django.conf import settings
from django.db import connection
from django_tenants.utils import schema_exists, tenant_context

from apps.tenants.models import Client, Domain

# Tables every tenant schema must own a private copy of.
TENANT_TABLES = frozenset(
    {
        "accounts_user",
        "auth_group",
        "auth_permission",
        "django_content_type",
        "django_session",
        "django_admin_log",
        "django_migrations",
    }
)

# Tables that must exist *only* in public.
SHARED_ONLY_TABLES = frozenset({"tenants_client", "tenants_domain"})


@pytest.mark.django_db
class TestSchemaCreation:
    def test_saving_a_new_tenant_creates_its_schema(
        self,
        make_tenant: Callable[..., Client],
    ) -> None:
        client = make_tenant("northgate")

        assert client.schema_name == "northgate"
        assert schema_exists("northgate")

    def test_new_schema_gets_the_tenant_tables(
        self,
        make_tenant: Callable[..., Client],
        schema_tables: Callable[[str], set[str]],
    ) -> None:
        make_tenant("southgate")

        assert schema_tables("southgate") >= TENANT_TABLES

    def test_new_schema_does_not_get_shared_only_tables(
        self,
        make_tenant: Callable[..., Client],
        schema_tables: Callable[[str], set[str]],
    ) -> None:
        # The router is what prevents this: apps.tenants is in SHARED_APPS
        # only, so a tenant admin can never reach the list of other tenants.
        make_tenant("westgate")

        assert not (SHARED_ONLY_TABLES & schema_tables("westgate"))

    def test_auto_create_schema_can_be_skipped(self, db: None) -> None:
        client = Client(name="Lazy", slug="lazy")
        client.auto_create_schema = False
        client.save()

        assert not schema_exists("lazy")

    def test_creating_a_tenant_outside_public_is_refused(
        self,
        acme: Client,
    ) -> None:
        # Tenant rows live in public; letting a tenant schema insert one would
        # write into a table it does not own.
        with tenant_context(acme), pytest.raises(Exception, match="public schema"):
            Client(name="Nested", slug="nested").save(verbosity=0)


@pytest.mark.django_db
class TestSchemaDeletion:
    def test_delete_keeps_the_schema_by_default(
        self,
        make_tenant: Callable[..., Client],
    ) -> None:
        client = make_tenant("keepme")

        client.delete()

        assert schema_exists("keepme")

    def test_force_drop_removes_the_schema(
        self,
        make_tenant: Callable[..., Client],
        flush_deferred_constraints: Callable[[], None],
    ) -> None:
        client = make_tenant("dropme")
        flush_deferred_constraints()

        client.delete(force_drop=True)

        assert not schema_exists("dropme")

    def test_deleting_a_tenant_cascades_to_its_domains(
        self,
        make_tenant: Callable[..., Client],
        flush_deferred_constraints: Callable[[], None],
    ) -> None:
        client = make_tenant("gone")
        Domain.objects.create(tenant=client, domain="gone.testserver")
        flush_deferred_constraints()

        client.delete(force_drop=True)

        assert not Domain.objects.filter(domain="gone.testserver").exists()


@pytest.mark.django_db
class TestMigrationRouting:
    def test_public_schema_has_both_shared_and_tenant_tables(
        self,
        public_tenant: Client,
        schema_tables: Callable[[str], set[str]],
    ) -> None:
        tables = schema_tables("public")

        assert tables >= SHARED_ONLY_TABLES
        # accounts is in *both* lists, so platform staff have a home in public.
        assert tables >= TENANT_TABLES

    def test_every_tenant_schema_is_fully_migrated(
        self,
        acme: Client,
        beta: Client,
        schema_tables: Callable[[str], set[str]],
    ) -> None:
        for schema in ("acme", "beta"):
            assert schema_tables(schema) >= TENANT_TABLES, schema

    def test_no_migrations_are_pending_in_a_tenant_schema(
        self,
        acme: Client,
    ) -> None:
        from django.db.migrations.executor import MigrationExecutor

        with tenant_context(acme):
            executor = MigrationExecutor(connection)
            targets = executor.loader.graph.leaf_nodes()
            plan = executor.migration_plan(targets)

        # Anything left in the plan is an app the router *did* let through but
        # that the schema has not caught up with.
        pending = {
            migration.app_label
            for migration, _backwards in plan
            if migration.app_label in {"accounts", "auth", "sessions", "admin"}
        }
        assert not pending

    def test_settings_split_the_apps_as_documented(self) -> None:
        assert "apps.tenants.apps.TenantsConfig" in settings.SHARED_APPS
        assert "apps.tenants.apps.TenantsConfig" not in settings.TENANT_APPS
        # contenttypes has to be in both: shared for django-tenants itself,
        # per-tenant so each schema's permissions point at their own rows.
        assert "django.contrib.contenttypes" in settings.SHARED_APPS
        assert "django.contrib.contenttypes" in settings.TENANT_APPS

    def test_installed_apps_is_the_union_without_duplicates(self) -> None:
        assert len(settings.INSTALLED_APPS) == len(set(settings.INSTALLED_APPS))
        for app in settings.SHARED_APPS + settings.TENANT_APPS:
            assert app in settings.INSTALLED_APPS

    def test_router_and_backend_are_wired_up(self) -> None:
        assert "django_tenants.routers.TenantSyncRouter" in settings.DATABASE_ROUTERS
        assert settings.DATABASES["default"]["ENGINE"] == (
            "django_tenants.postgresql_backend"
        )

    def test_tenant_middleware_runs_first(self) -> None:
        # Anything above it would query the database with the public schema
        # still selected.
        assert settings.MIDDLEWARE[0] == "apps.tenants.middleware.TenantMainMiddleware"
