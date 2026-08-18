"""Delete refresh tokens that can no longer be redeemed, schema by schema.

Run daily. The table grows by one row per refresh, per session, per user, and
nothing sweeps it on a timer.

What is *not* pruned matters more than what is. Rows are selected by
``expires_at`` alone -- never by status. A ``ROTATED`` row is exactly what
reuse detection matches a replayed token against: delete it early
and the replay becomes indistinguishable from an invented token, so the family
is never torn down and the detection quietly stops working while every test
that mocks it still passes.
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import TYPE_CHECKING, Any, Final

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.authentication.models import RefreshToken
from apps.tenants.utils import (
    each_tenant,
    get_public_schema_name,
    public_schema,
    schema_context,
    schema_exists,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

# Deleted in chunks so a year of accumulation in one large tenant does not
# hold a single transaction -- and the locks that come with it -- open for the
# whole run.
_BATCH_SIZE: Final = 1_000


class Command(BaseCommand):
    """``manage.py prune_expired_tokens [--dry-run] [--schema acme]``"""

    help = "Delete expired refresh tokens from the public schema and every tenant."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be deleted without deleting it.",
        )
        parser.add_argument(
            "--schema",
            action="append",
            default=[],
            metavar="SCHEMA",
            help=(
                "Restrict to one schema. Repeat for several. Without it every "
                "active tenant and the public schema are processed."
            ),
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=_BATCH_SIZE,
            help=f"Rows deleted per transaction (default {_BATCH_SIZE}).",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run: bool = options["dry_run"]
        batch_size: int = options["batch_size"]

        if batch_size < 1:
            raise CommandError("--batch-size must be at least 1.")

        # One cutoff for the whole run, so the report is a consistent snapshot
        # rather than drifting forward as the slower schemas are reached.
        cutoff = timezone.now()
        total = 0

        for schema in self._schemas(options["schema"]):
            total += self._prune(
                schema, cutoff=cutoff, dry_run=dry_run, size=batch_size
            )

        verb = "Would delete" if dry_run else "Deleted"
        self.stdout.write(self.style.SUCCESS(f"{verb} {total} expired token(s)."))

    # -- schema selection ----------------------------------------------

    def _schemas(self, requested: list[str]) -> Iterator[str]:
        """Yield schema names with the connection already switched to each.

        There is no implicit schema outside a request: nothing here runs
        against whichever search_path the connection happened to hold.
        """
        if requested:
            for name in requested:
                if not schema_exists(name):
                    raise CommandError(f"Schema {name!r} does not exist.")
            for name in requested:
                with schema_context(name):
                    yield name
            return

        with public_schema():
            yield get_public_schema_name()

        for tenant in each_tenant():
            yield tenant.schema_name

    # -- work ----------------------------------------------------------

    def _prune(self, schema: str, *, cutoff: datetime, dry_run: bool, size: int) -> int:
        """Delete every row past ``expires_at`` in the active schema."""
        expired = RefreshToken.objects.filter(expires_at__lt=cutoff)
        count = expired.count()

        if not dry_run:
            self._delete_in_batches(cutoff, size=size)

        self.stdout.write(f"  {schema}: {count}")
        return count

    @staticmethod
    def _delete_in_batches(cutoff: datetime, *, size: int) -> None:
        while True:
            batch = list(
                RefreshToken.objects.filter(expires_at__lt=cutoff).values_list(
                    "pk", flat=True
                )[:size]
            )
            if not batch:
                return
            RefreshToken.objects.filter(pk__in=batch).delete()
