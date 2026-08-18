"""Force one account out of every session, in one named schema.

The support-desk and incident-response entry point to
:class:`~apps.authentication.services.revocation.RevocationService`: it bumps
``token_version`` (killing every outstanding access token on the next
request), marks the refresh rows revoked, ends the device sessions, drops the
cached user and denylists what is still live -- as one operation, so none of
those can be forgotten.

``--schema`` is mandatory and has no default. An account is a row inside one
institution's schema; the same address can legitimately exist in several, and
guessing which one was meant is how the wrong person gets logged out.
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from apps.authentication.models import AuthEventType, RevocationReason
from apps.authentication.services.revocation import RevocationService
from apps.tenants.utils import schema_context, schema_exists

UserModel = get_user_model()

# Reasons an operator can plausibly be acting on from a terminal. The rest of
# the enum is set by the flows that own it -- a logout is recorded by the
# logout endpoint, not by hand.
_REASONS = (
    RevocationReason.ADMIN_REVOKED,
    RevocationReason.USER_DEACTIVATED,
    RevocationReason.PASSWORD_CHANGED,
    RevocationReason.REUSE_DETECTED,
)


class Command(BaseCommand):
    """``manage.py revoke_user_tokens --schema acme --email priya@acme.edu``"""

    help = "Revoke every token and session one account holds in one schema."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--schema",
            required=True,
            help="Schema the account lives in. No default, deliberately.",
        )
        parser.add_argument(
            "--email",
            required=True,
            help="Address of the account to revoke. Matched case-insensitively.",
        )
        parser.add_argument(
            "--reason",
            choices=[str(reason) for reason in _REASONS],
            default=str(RevocationReason.ADMIN_REVOKED),
            help="Recorded on every revoked row and in the audit trail.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        schema: str = options["schema"]
        email: str = options["email"].strip().lower()
        reason = RevocationReason(options["reason"])

        if not schema_exists(schema):
            raise CommandError(f"Schema {schema!r} does not exist.")

        with schema_context(schema):
            # all_objects, not objects: a soft-deleted account is precisely the
            # one whose credentials most need killing, and the default manager
            # filters it out.
            user = UserModel.all_objects.filter(email=email).first()
            if user is None:
                raise CommandError(f"No account {email!r} in schema {schema!r}.")

            revoked = RevocationService().revoke_all_for_user(
                user,
                reason=reason,
                event=AuthEventType.FORCE_LOGOUT,
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Revoked {revoked} refresh token(s) for {email} in {schema}; "
                "every access token that account holds fails on its next request."
            )
        )
