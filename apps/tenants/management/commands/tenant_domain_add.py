"""Route an additional hostname to an existing tenant.

Tenants routinely need more than one: a vanity domain alongside the platform
subdomain, or a new one during a rename while the old one keeps working.
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from apps.tenants.models import Client, Domain


class Command(BaseCommand):
    """``manage.py tenant_domain_add acme --domain acme.edu --primary``"""

    help = "Add a domain to an existing tenant."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "schema_name",
            help="Schema name of the tenant the domain should route to.",
        )
        parser.add_argument(
            "--domain",
            required=True,
            help="Hostname to route, e.g. acme.example.com.",
        )
        parser.add_argument(
            "--primary",
            action="store_true",
            help=(
                "Make this the tenant's canonical domain. The previous primary "
                "keeps working as an alias."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        schema_name: str = options["schema_name"]
        domain_name = Domain.normalize(options["domain"])

        try:
            client = Client.objects.get(schema_name=schema_name)
        except Client.DoesNotExist as exc:
            raise CommandError(f"No tenant owns schema {schema_name!r}.") from exc

        existing = Domain.objects.filter(domain=domain_name).select_related("tenant")
        if (clash := existing.first()) is not None:
            raise CommandError(
                f"Domain {domain_name!r} already routes to "
                f"{clash.tenant.schema_name!r}."
            )

        domain = Domain(
            tenant=client, domain=domain_name, is_primary=options["primary"]
        )
        try:
            domain.full_clean()
        except ValidationError as exc:
            raise CommandError("; ".join(exc.messages)) from exc

        # DomainMixin.save() demotes any other primary domain for this tenant
        # inside its own transaction, so at most one stays primary.
        domain.save()

        role = "primary domain" if domain.is_primary else "alias"
        self.stdout.write(
            self.style.SUCCESS(
                f"Added {domain_name} as {role} for tenant {client.schema_name!r}."
            )
        )
