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

from apps.tenants.models import Tenant

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
        tenants = Tenant.objects.prefetch_related("domains").order_by("schema_name")
        if options["active"]:
            tenants = tenants.active()

        catalogue = list(tenants)

        if options["schemas_only"]:
            for tenant in catalogue:
                self.stdout.write(tenant.schema_name)
            return

        if not catalogue:
            self.stdout.write(
                self.style.WARNING(
                    "No tenants yet. Create one with `manage.py tenant_create`."
                )
            )
            return

        rows = [_HEADERS, *(self._row(tenant) for tenant in catalogue)]
        widths = [max(len(row[i]) for row in rows) for i in range(len(_HEADERS))]

        for index, row in enumerate(rows):
            line = "  ".join(
                cell.ljust(width) for cell, width in zip(row, widths, strict=True)
            )
            self.stdout.write(self.style.MIGRATE_HEADING(line) if index == 0 else line)

        self.stdout.write("")
        self.stdout.write(f"{len(catalogue)} tenant(s).")

    def _row(self, tenant: Tenant) -> tuple[str, str, str, str, str]:
        if not schema_exists(tenant.schema_name):
            # A row without a schema means someone dropped the schema by hand,
            # or a creation failed halfway. Surfacing it beats a 500 later.
            status = "MISSING SCHEMA"
        elif tenant.is_active:
            status = "active"
        else:
            status = "suspended"

        return (
            tenant.schema_name,
            tenant.slug,
            tenant.name,
            tenant.primary_domain_name() or "-",
            status,
        )
