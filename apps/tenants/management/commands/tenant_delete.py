"""Remove a tenant, optionally dropping its schema.

Dropping a schema is irreversible and takes every row the institution owns
with it, so the destructive half is opt-in (``--drop-schema``) *and* confirmed
interactively unless ``--noinput`` is passed.
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django_tenants.utils import get_public_schema_name

from apps.tenants.models import Client


class Command(BaseCommand):
    """``manage.py tenant_delete acme --drop-schema``"""

    help = "Delete a tenant's catalogue row, and optionally drop its schema."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "schema_name",
            help="Schema name of the tenant to remove.",
        )
        parser.add_argument(
            "--drop-schema",
            action="store_true",
            help=(
                "Also DROP SCHEMA ... CASCADE. Destroys every row the tenant "
                "owns. Without this the schema is left in place and can be "
                "re-attached by recreating the tenant with the same --schema."
            ),
        )
        parser.add_argument(
            "--noinput",
            "--no-input",
            action="store_false",
            dest="interactive",
            help="Do not prompt for confirmation.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        schema_name: str = options["schema_name"]
        drop_schema: bool = options["drop_schema"]

        # Validation to avoid dropping public schema
        if schema_name == get_public_schema_name():
            raise CommandError(
                "Refusing to delete the public tenant: it owns the tenant "
                "catalogue itself and every shared table."
            )

        try:
            client = Client.objects.get(schema_name=schema_name)
        except Client.DoesNotExist as exc:
            raise CommandError(f"No tenant owns schema {schema_name!r}.") from exc

        if options["interactive"] and not self._confirm(
            client, drop_schema=drop_schema
        ):
            self.stdout.write("Aborted.")
            return

        # Domains cascade with the row; the schema only goes if asked for.
        client.delete(force_drop=drop_schema)

        if drop_schema:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Deleted tenant {schema_name!r} and dropped its schema."
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Deleted tenant {schema_name!r}. Schema {schema_name!r} was "
                    "left in place -- drop it manually or re-attach it later."
                )
            )

    def _confirm(self, client: Client, *, drop_schema: bool) -> bool:
        """This method validates and ensure the deletion of either
        tenant or tenant & schema both based on the user inputs
        """

        if drop_schema:
            self.stdout.write(
                self.style.WARNING(
                    f"This will permanently destroy all data for {client.name!r} "
                    f"in schema {client.schema_name!r}."
                )
            )
            prompt = f"Type the schema name to confirm [{client.schema_name}]: "
            return input(prompt).strip() == client.schema_name

        prompt = f"Delete tenant {client.schema_name!r}, keeping its schema? [y/N]: "
        return input(prompt).strip().lower() in {"y", "yes"}
