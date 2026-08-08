"""Create a tenant and its first domain in one non-interactive step.

django-tenants ships ``create_tenant``, which prompts for every editable field
in turn. This command is the scriptable counterpart: it takes everything on the
command line, derives the schema name from the slug, and is safe to run from a
Makefile, an entrypoint or CI.
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django_tenants.utils import get_public_schema_name, schema_exists

from apps.tenants.models import Client, Domain


class Command(BaseCommand):
    """Create a tenant non-interactively.

    ``manage.py tenant_create --name "Acme" --slug acme --domain acme.example.com``
    """

    help = "Create a tenant (and its Postgres schema) together with a primary domain."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--name",
            required=True,
            help="Display name of the institution.",
        )
        parser.add_argument(
            "--slug",
            required=True,
            help="URL-safe identifier; seeds the schema name unless --schema is given.",
        )
        parser.add_argument(
            "--domain",
            required=True,
            help="Primary hostname routing to this tenant, e.g. acme.example.com.",
        )
        parser.add_argument(
            "--schema",
            default="",
            help=(
                "Postgres schema name. Defaults to the slug with hyphens "
                "replaced by underscores. Pass 'public' to register the "
                "platform's own tenant."
            ),
        )
        parser.add_argument(
            "--inactive",
            action="store_true",
            help="Create the tenant suspended; its domains will not serve requests.",
        )
        parser.add_argument(
            "--if-not-exists",
            action="store_true",
            help=(
                "Succeed quietly when the schema is already registered, so the "
                "command can be run unconditionally from an entrypoint."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        name: str = options["name"]
        slug: str = options["slug"]
        domain_name = Domain.normalize(options["domain"])
        schema_name: str = options["schema"] or Client.schema_name_for(slug)

        if Client.objects.filter(schema_name=schema_name).exists():
            if options["if_not_exists"]:
                self.stdout.write(f"Tenant {schema_name!r} already exists; skipping.")
                return
            raise CommandError(f"A tenant already owns schema {schema_name!r}.")
        if Client.objects.filter(slug=slug).exists():
            raise CommandError(f"A tenant already uses slug {slug!r}.")
        if Domain.objects.filter(domain=domain_name).exists():
            raise CommandError(f"Domain {domain_name!r} is already routed.")

        is_public = schema_name == get_public_schema_name()
        if not is_public and schema_exists(schema_name):
            raise CommandError(
                f"Schema {schema_name!r} already exists in the database but no "
                "tenant owns it. Drop it or pass a different --schema."
            )

        client = Client(
            name=name,
            slug=slug,
            schema_name=schema_name,
            is_active=not options["inactive"],
        )

        try:
            client.full_clean()
        except ValidationError as exc:
            raise CommandError("; ".join(exc.messages)) from exc

        # Deliberately *outside* a transaction wrapping the schema creation:
        # TenantMixin.save() runs migrate_schemas for the new schema, and
        # holding a transaction open across a full migration run would keep
        # heavy DDL locks for as long as it takes. The mixin already rolls the
        # row and schema back itself if migrating fails.
        client.save(verbosity=options["verbosity"])

        with transaction.atomic():
            Domain.objects.create(tenant=client, domain=domain_name, is_primary=True)

        self.stdout.write(
            self.style.SUCCESS(
                f"Created tenant {client.name!r} "
                f"(schema {client.schema_name}, domain {domain_name})."
            )
        )
        if is_public:
            self.stdout.write(
                "Public tenant registered; the public schema was already "
                "migrated by `migrate_schemas --shared`."
            )
