"""The tenant management commands.

Every command is exercised through ``call_command`` with ``--verbosity 0``, so
these also assert that the commands stay non-interactive and scriptable.
"""

from __future__ import annotations

from collections.abc import Callable
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django_tenants.utils import schema_exists

from apps.tenants.models import Domain, Tenant


def run(command: str, *args: str, **options: object) -> str:
    """Call a management command and return everything it wrote to stdout."""
    out = StringIO()
    call_command(command, *args, stdout=out, verbosity=0, **options)
    return out.getvalue()


@pytest.mark.django_db
class TestTenantCreate:
    def test_creates_tenant_schema_and_domain(self) -> None:
        run(
            "tenant_create",
            name="Northgate Academy",
            slug="northgate",
            domain="Northgate.Example.COM",
        )

        tenant = Tenant.objects.get(slug="northgate")
        assert tenant.schema_name == "northgate"
        assert schema_exists("northgate")
        assert tenant.primary_domain_name() == "northgate.example.com"

    def test_schema_name_can_be_overridden(self) -> None:
        run(
            "tenant_create",
            name="Northgate",
            slug="northgate-academy",
            schema="ng",
            domain="ng.example.com",
        )

        assert Tenant.objects.get(slug="northgate-academy").schema_name == "ng"

    def test_inactive_flag_suspends_the_new_tenant(self) -> None:
        run(
            "tenant_create",
            name="Pending",
            slug="pending",
            domain="pending.example.com",
            inactive=True,
        )

        assert not Tenant.objects.get(slug="pending").is_active

    def test_duplicate_schema_is_refused(self, acme: Tenant) -> None:
        with pytest.raises(CommandError, match="already owns schema"):
            run(
                "tenant_create",
                name="Clash",
                slug="acme-two",
                schema="acme",
                domain="clash.example.com",
            )

    def test_duplicate_slug_is_refused(self, acme: Tenant) -> None:
        # Distinct schema, so the slug check is what has to catch this.
        with pytest.raises(CommandError, match="slug"):
            run(
                "tenant_create",
                name="Clash",
                slug="acme",
                schema="acme_clone",
                domain="clash.example.com",
            )

    def test_duplicate_domain_is_refused(self, acme: Tenant) -> None:
        with pytest.raises(CommandError, match="already routed"):
            run(
                "tenant_create",
                name="Clash",
                slug="clash",
                domain="acme.testserver",
            )

    def test_invalid_schema_name_is_refused(self, db: None) -> None:
        with pytest.raises(CommandError, match="lower-case"):
            run(
                "tenant_create",
                name="Bad",
                slug="bad",
                schema="Not Valid",
                domain="bad.example.com",
            )

    def test_orphaned_schema_is_refused(self, db: None) -> None:
        # A schema with no catalogue row means a half-finished creation or a
        # manual CREATE SCHEMA. Reusing it silently would hand a new customer
        # somebody else's tables.
        with connection.cursor() as cursor:
            cursor.execute('CREATE SCHEMA "orphaned"')

        with pytest.raises(CommandError, match="no tenant owns it"):
            run(
                "tenant_create",
                name="Orphan",
                slug="orphaned",
                domain="orphaned.example.com",
            )

    def test_public_tenant_row_is_created_without_rebuilding_public(
        self,
        db: None,
        public_tenant: Tenant,
        schema_tables: Callable[[str], set[str]],
    ) -> None:
        # The session fixture registers the public tenant the same way the
        # command does; what matters is that doing so left the schema, already
        # migrated by `migrate_schemas --shared`, untouched.
        assert public_tenant.schema_name == "public"
        assert "tenants_tenant" in schema_tables("public")


@pytest.mark.django_db
class TestTenantDomainAdd:
    def test_adds_an_alias(self, acme: Tenant) -> None:
        run("tenant_domain_add", "acme", domain="alias.example.com")

        alias = Domain.objects.get(domain="alias.example.com")
        assert alias.tenant_id == acme.pk
        assert not alias.is_primary
        assert acme.primary_domain_name() == "acme.testserver"

    def test_promoting_a_new_primary_demotes_the_old_one(self, acme: Tenant) -> None:
        run("tenant_domain_add", "acme", domain="new.example.com", primary=True)

        assert acme.primary_domain_name() == "new.example.com"
        assert Domain.objects.filter(tenant=acme, is_primary=True).count() == 1

    def test_unknown_tenant_is_refused(self, db: None) -> None:
        with pytest.raises(CommandError, match="No tenant owns schema"):
            run("tenant_domain_add", "nosuch", domain="x.example.com")

    def test_domain_owned_by_another_tenant_is_refused(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        with pytest.raises(CommandError, match="already routes to"):
            run("tenant_domain_add", "beta", domain="acme.testserver")


@pytest.mark.django_db
class TestTenantList:
    def test_lists_every_tenant(self, acme: Tenant, beta: Tenant) -> None:
        out = StringIO()
        call_command("tenant_list", stdout=out)
        listing = out.getvalue()

        assert "acme" in listing
        assert "beta" in listing
        assert "acme.testserver" in listing

    def test_active_filter_hides_suspended_tenants(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        beta.is_active = False
        beta.save()

        out = StringIO()
        call_command("tenant_list", "--active", stdout=out)

        assert "beta" not in out.getvalue()

    def test_schemas_only_prints_bare_names(self, acme: Tenant) -> None:
        out = StringIO()
        call_command("tenant_list", "--schemas-only", stdout=out)

        assert "acme" in out.getvalue().split()

    def test_suspended_tenants_are_labelled(self, acme: Tenant) -> None:
        acme.is_active = False
        acme.save()

        out = StringIO()
        call_command("tenant_list", stdout=out)

        assert "suspended" in out.getvalue()

    def test_empty_catalogue_says_so(self, db: None) -> None:
        Domain.objects.all().delete()
        Tenant.objects.all().delete()

        out = StringIO()
        call_command("tenant_list", stdout=out)

        assert "No tenants yet" in out.getvalue()

    def test_missing_schema_is_flagged(
        self,
        make_tenant: Callable[..., Tenant],
    ) -> None:
        tenant = make_tenant("orphan")
        tenant.auto_drop_schema = False
        Tenant.objects.filter(pk=tenant.pk).update(schema_name="never_created")

        out = StringIO()
        call_command("tenant_list", stdout=out)

        assert "MISSING SCHEMA" in out.getvalue()


@pytest.mark.django_db
class TestTenantDelete:
    def test_removes_the_row_and_keeps_the_schema(
        self,
        make_tenant: Callable[..., Tenant],
    ) -> None:
        make_tenant("keepschema")

        run("tenant_delete", "keepschema", interactive=False)

        assert not Tenant.objects.filter(schema_name="keepschema").exists()
        assert schema_exists("keepschema")

    def test_drop_schema_removes_everything(
        self,
        make_tenant: Callable[..., Tenant],
        flush_deferred_constraints: Callable[[], None],
    ) -> None:
        make_tenant("dropschema")
        flush_deferred_constraints()

        run("tenant_delete", "dropschema", drop_schema=True, interactive=False)

        assert not Tenant.objects.filter(schema_name="dropschema").exists()
        assert not schema_exists("dropschema")

    def test_public_tenant_cannot_be_deleted(self, public_tenant: Tenant) -> None:
        with pytest.raises(CommandError, match="public tenant"):
            run("tenant_delete", "public", interactive=False)

    def test_unknown_tenant_is_refused(self, db: None) -> None:
        with pytest.raises(CommandError, match="No tenant owns schema"):
            run("tenant_delete", "nosuch", interactive=False)


@pytest.mark.django_db
class TestTenantDeleteConfirmation:
    """The interactive guard in front of an irreversible operation."""

    def test_declining_the_prompt_deletes_nothing(
        self,
        make_tenant: Callable[..., Tenant],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        make_tenant("shy")
        monkeypatch.setattr("builtins.input", lambda _prompt: "n")

        out = StringIO()
        call_command("tenant_delete", "shy", stdout=out)

        assert "Aborted" in out.getvalue()
        assert Tenant.objects.filter(schema_name="shy").exists()

    def test_confirming_deletes_the_row(
        self,
        make_tenant: Callable[..., Tenant],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        make_tenant("willing")
        monkeypatch.setattr("builtins.input", lambda _prompt: "y")

        call_command("tenant_delete", "willing", stdout=StringIO())

        assert not Tenant.objects.filter(schema_name="willing").exists()

    def test_drop_schema_demands_the_schema_name_typed_out(
        self,
        make_tenant: Callable[..., Tenant],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A bare "y" is far too easy to type by reflex for something that
        # destroys a customer's entire dataset.
        make_tenant("precious")
        monkeypatch.setattr("builtins.input", lambda _prompt: "y")

        call_command("tenant_delete", "precious", "--drop-schema", stdout=StringIO())

        assert Tenant.objects.filter(schema_name="precious").exists()
        assert schema_exists("precious")

    def test_drop_schema_proceeds_when_the_name_matches(
        self,
        make_tenant: Callable[..., Tenant],
        flush_deferred_constraints: Callable[[], None],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        make_tenant("doomed")
        flush_deferred_constraints()
        monkeypatch.setattr("builtins.input", lambda _prompt: "doomed")

        call_command("tenant_delete", "doomed", "--drop-schema", stdout=StringIO())

        assert not Tenant.objects.filter(schema_name="doomed").exists()
        assert not schema_exists("doomed")
