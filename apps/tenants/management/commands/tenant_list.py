"""List the tenant catalogue.

There is no equivalent in django-tenants, and "which schemas exist and which
domains reach them" is the first question anyone asks when a request lands on
the wrong tenant.
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand
from django_tenants.utils import schema_exists

from apps.tenants.models import Client

_HEADERS = ("SCHEMA", "SLUG", "NAME", "PRIMARY DOMAIN", "STATUS")


class Command(BaseCommand):
    """``manage.py tenant_list [--active] [--schemas-only]``"""

    help = "List every tenant with its schema, primary domain and status."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--active",
            action="store_true",
            help="Only tenants that are allowed to serve requests.",
        )
        parser.add_argument(
            "--schemas-only",
            action="store_true",
            help="Print bare schema names, one per line, for piping into xargs.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        clients = Client.objects.prefetch_related("domains").order_by("schema_name")
        if options["active"]:
            clients = clients.active()

        catalogue = list(clients)

        if options["schemas_only"]:
            for client in catalogue:
                self.stdout.write(client.schema_name)
            return

        if not catalogue:
            self.stdout.write(
                self.style.WARNING(
                    "No tenants yet. Create one with `manage.py tenant_create`."
                )
            )
            return

        rows = [_HEADERS, *(self._row(client) for client in catalogue)]
        widths = [max(len(row[i]) for row in rows) for i in range(len(_HEADERS))]

        for index, row in enumerate(rows):
            line = "  ".join(
                cell.ljust(width) for cell, width in zip(row, widths, strict=True)
            )
            self.stdout.write(self.style.MIGRATE_HEADING(line) if index == 0 else line)

        self.stdout.write("")
        self.stdout.write(f"{len(catalogue)} tenant(s).")

    def _row(self, client: Client) -> tuple[str, str, str, str, str]:
        if not schema_exists(client.schema_name):
            # A row without a schema means someone dropped the schema by hand,
            # or a creation failed halfway. Surfacing it beats a 500 later.
            status = "MISSING SCHEMA"
        elif client.is_active:
            status = "active"
        else:
            status = "suspended"

        return (
            client.schema_name,
            client.slug,
            client.name,
            client.primary_domain_name() or "-",
            status,
        )
