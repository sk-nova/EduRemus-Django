"""Behaviour of the tenant catalogue models."""

from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from apps.tenants.models import Client, Domain


class TestSchemaNameDerivation:
    def test_hyphens_become_underscores(self) -> None:
        assert Client.schema_name_for("riverdale-high") == "riverdale_high"

    def test_leading_digit_is_prefixed(self) -> None:
        # Bare SQL identifiers may not start with a digit.
        assert Client.schema_name_for("2024-intake") == "t_2024_intake"

    def test_mixed_case_is_folded(self) -> None:
        assert Client.schema_name_for("Acme Institute") == "acme_institute"

    def test_result_fits_postgres_limit(self) -> None:
        assert len(Client.schema_name_for("x" * 200)) == 63


@pytest.mark.django_db
class TestClient:
    def test_schema_name_defaults_to_slug(self) -> None:
        client = Client(name="Northgate", slug="northgate-academy")
        client.full_clean()

        assert client.schema_name == "northgate_academy"

    def test_explicit_schema_name_is_kept(self) -> None:
        client = Client(name="Northgate", slug="northgate", schema_name="ng")
        client.full_clean()

        assert client.schema_name == "ng"

    def test_invalid_schema_name_is_rejected(self) -> None:
        client = Client(name="Bad", slug="bad", schema_name="Drop Table")

        with pytest.raises(ValidationError) as error:
            client.full_clean()

        assert "schema_name" in error.value.message_dict

    def test_check_constraint_blocks_bad_schema_name(self, db: None) -> None:
        # The constraint is what protects writes that skip full_clean().
        with pytest.raises(IntegrityError), transaction.atomic():
            Client.objects.create(
                name="Bad",
                slug="bad-raw",
                schema_name='ev"il',
            )

    def test_str_names_the_schema(self, acme: Client) -> None:
        assert str(acme) == "Acme Institute (acme)"

    def test_is_public_only_for_public_schema(
        self,
        acme: Client,
        public_tenant: Client,
    ) -> None:
        assert public_tenant.is_public
        assert not acme.is_public


@pytest.mark.django_db
class TestDomain:
    def test_hostname_is_folded_to_lower_case(self, acme: Client) -> None:
        domain = Domain.objects.create(tenant=acme, domain="ACME.Example.COM")

        assert domain.domain == "acme.example.com"

    def test_trailing_dot_is_stripped(self, acme: Client) -> None:
        domain = Domain.objects.create(tenant=acme, domain="acme.example.org.")

        assert domain.domain == "acme.example.org"

    def test_only_one_primary_domain_per_tenant(self, acme: Client) -> None:
        original = acme.get_primary_domain()
        assert original is not None

        Domain.objects.create(tenant=acme, domain="vanity.example.com", is_primary=True)

        original.refresh_from_db()
        assert not original.is_primary
        assert acme.domains.filter(is_primary=True).count() == 1

    def test_domains_are_globally_unique(self, acme: Client, beta: Client) -> None:
        with pytest.raises(IntegrityError), transaction.atomic():
            Domain.objects.create(tenant=beta, domain="acme.testserver")

    def test_primary_domain_name_helper(self, acme: Client) -> None:
        assert acme.primary_domain_name() == "acme.testserver"


@pytest.mark.django_db
class TestQuerySets:
    def test_active_and_suspended_partition_the_catalogue(
        self,
        acme: Client,
        beta: Client,
    ) -> None:
        beta.is_active = False
        beta.save()

        assert acme in Client.objects.active()
        assert beta in Client.objects.suspended()
        assert beta not in Client.objects.active()

    def test_tenants_only_excludes_the_public_tenant(
        self,
        acme: Client,
        public_tenant: Client,
    ) -> None:
        schemas = set(
            Client.objects.tenants_only().values_list("schema_name", flat=True)
        )

        assert "acme" in schemas
        assert "public" not in schemas

    def test_primary_selects_one_domain_per_tenant(self, acme: Client) -> None:
        Domain.objects.create(tenant=acme, domain="alias.example.com", is_primary=False)

        primary = Domain.objects.filter(tenant=acme).primary()

        assert [d.domain for d in primary] == ["acme.testserver"]
