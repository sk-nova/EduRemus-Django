"""Decode a token and print what it claims. For support and incident work.

Answers the question every authentication ticket starts with -- "what is
actually in this token?" -- without anyone pasting it into a website. Nothing
here mints, revokes or modifies.

By default the signature is **not** checked, because a token worth inspecting
is usually one that failed: expired, foreign, malformed, signed by a retired
key. Every line of that output is therefore attacker-supplied and is labelled
as such. ``--verify`` runs the real validator instead, against a named schema,
and reports the first check that rejects it.

The token is a live credential for as long as it is unexpired. Prefer
``--file`` or a pipe over ``--token``: an argument lands in the shell history
and in the process list, where the next person to run ``ps`` reads it.
"""

from __future__ import annotations

import sys
from argparse import ArgumentParser
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import jwt
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.authentication.exceptions import ServiceUnavailable, TokenError
from apps.authentication.models import RefreshToken
from apps.authentication.tokens import claims as C
from apps.authentication.tokens.denylist import is_denylisted
from apps.authentication.tokens.validator import TenantTokenValidator
from apps.authentication.utils.hashing import token_digest
from apps.tenants.utils import schema_context, schema_exists

# Claims rendered as instants rather than as the integers they are stored as.
_TIME_CLAIMS: Final = (
    C.CLAIM_ISSUED_AT,
    C.CLAIM_NOT_BEFORE,
    C.CLAIM_EXPIRES_AT,
    C.CLAIM_AUTH_TIME,
)

_LABEL_WIDTH: Final = 14


class Command(BaseCommand):
    """``manage.py jwt_inspect --file token.txt --schema acme --verify``"""

    help = "Decode a JWT and print its header, claims and current standing."

    def add_arguments(self, parser: ArgumentParser) -> None:
        source = parser.add_mutually_exclusive_group()
        source.add_argument(
            "--token",
            help=(
                "The serialised token. Recorded in shell history and visible "
                "in the process list -- prefer --file or a pipe."
            ),
        )
        source.add_argument(
            "--file",
            help="Path to a file holding the token. '-' reads standard input.",
        )
        parser.add_argument(
            "--schema",
            help=(
                "Schema to inspect the token against: enables the stored "
                "refresh row, the denylist check and --verify."
            ),
        )
        parser.add_argument(
            "--verify",
            action="store_true",
            help=(
                "Run the real validator -- signature, issuer, audience, "
                "expiry, claim version, type and tenancy. Requires --schema."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        raw = self._read_token(options)
        schema: str | None = options["schema"]
        verify: bool = options["verify"]

        if verify and not schema:
            raise CommandError(
                "--verify needs --schema: the tenancy check compares the "
                "token's `sch` claim against the live connection, and there is "
                "no live connection to compare against outside a schema."
            )
        if schema and not schema_exists(schema):
            raise CommandError(f"Schema {schema!r} does not exist.")

        header = self._header(raw)
        payload = self._payload(raw)

        self._print_header(header)
        self._print_claims(payload)
        self._print_timing(payload)

        if schema:
            with schema_context(schema):
                self._print_standing(raw, payload, schema=schema)
                if verify:
                    self._print_verification(raw, payload)

    # -- input ---------------------------------------------------------

    def _read_token(self, options: dict[str, Any]) -> str:
        if options["token"]:
            raw = str(options["token"])
        elif options["file"] == "-" or not options["file"]:
            if sys.stdin.isatty():
                raise CommandError(
                    "No token given. Pass --token, --file PATH, or pipe the "
                    "token in on standard input."
                )
            raw = sys.stdin.read()
        else:
            try:
                with open(options["file"], encoding="ascii") as handle:
                    raw = handle.read()
            except OSError as exc:
                raise CommandError(f"Cannot read {options['file']}: {exc}") from exc

        # A copied token routinely arrives wrapped in quotes or prefixed with
        # the header it was pulled out of.
        raw = raw.strip().strip('"').strip("'")
        if raw.lower().startswith("bearer "):
            raw = raw[len("bearer ") :].strip()

        if not raw:
            raise CommandError("The token is empty.")
        return raw

    @staticmethod
    def _header(raw: str) -> dict[str, Any]:
        try:
            return jwt.get_unverified_header(raw)
        except jwt.PyJWTError as exc:
            raise CommandError(f"Not a decodable JWT header: {exc}") from exc

    @staticmethod
    def _payload(raw: str) -> dict[str, Any]:
        """Decode the claims without verifying anything about them."""
        try:
            return jwt.decode(
                raw,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise CommandError(f"Not a decodable JWT payload: {exc}") from exc

    # -- output --------------------------------------------------------

    def _print_header(self, header: dict[str, Any]) -> None:
        self.stdout.write(self.style.MIGRATE_HEADING("Header"))
        for name, value in sorted(header.items()):
            self._line(name, value)

        if str(header.get("alg", "")).lower() == "none":
            self.stdout.write(
                self.style.ERROR(
                    "  alg is 'none' -- an unsigned token. The validator fixes "
                    "the algorithm from settings, so this was rejected before "
                    "any key was applied."
                )
            )

    def _print_claims(self, payload: dict[str, Any]) -> None:
        self.stdout.write("")
        self.stdout.write(
            self.style.MIGRATE_HEADING("Claims (unverified -- as presented)")
        )
        for name, value in sorted(payload.items()):
            if name in _TIME_CLAIMS:
                continue
            self._line(name, value)

    def _print_timing(self, payload: dict[str, Any]) -> None:
        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("Timing"))
        now = timezone.now()

        for name in _TIME_CLAIMS:
            if name not in payload:
                continue
            moment = _instant(payload[name])
            if moment is None:
                self._line(name, f"{payload[name]!r} (not a timestamp)")
                continue
            self._line(
                name, f"{moment:%Y-%m-%d %H:%M:%S %Z}  ({_relative(moment, now)})"
            )

        expires = _instant(payload.get(C.CLAIM_EXPIRES_AT))
        if expires is not None:
            expired = expires <= now
            style = self.style.ERROR if expired else self.style.SUCCESS
            self.stdout.write(
                style(f"  {'EXPIRED' if expired else 'within its lifetime'}")
            )

    def _print_standing(
        self, raw: str, payload: dict[str, Any], *, schema: str
    ) -> None:
        """What this schema currently records about the token."""
        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING(f"Standing in {schema}"))

        token_schema = payload.get(C.CLAIM_SCHEMA)
        if token_schema != schema:
            self.stdout.write(
                self.style.ERROR(
                    f"  `sch` claim is {token_schema!r}, not {schema!r} -- this "
                    "token is not valid here and would be rejected as "
                    "token_wrong_tenant."
                )
            )

        digest = token_digest(raw)
        self._line("token sha256", digest)

        stored = RefreshToken.objects.filter(token_hash=digest).first()
        if stored is not None:
            self._line("refresh row", str(stored.pk))
            self._line("status", stored.status)
            self._line("generation", stored.generation)
            self._line("family", str(stored.family_id))
            self._line("revocation", stored.revocation_reason or "-")
            self._line("replaced by", str(stored.replaced_by_id or "-"))
        elif payload.get(C.CLAIM_TOKEN_TYPE) == C.TOKEN_TYPE_REFRESH:
            self.stdout.write(
                self.style.WARNING(
                    "  no refresh row matches this digest in this schema -- "
                    "already pruned, minted elsewhere, or invented."
                )
            )

        jti = payload.get(C.CLAIM_JWT_ID)
        if jti:
            try:
                denied = is_denylisted(str(jti))
            except ServiceUnavailable:
                # The denylist fails closed for a request; for an inspection
                # it reports, because "cannot tell" is itself the finding.
                self._line("denylist", "unavailable (Redis unreachable)")
            else:
                self._line("denylist", "REVOKED" if denied else "not listed")

    def _print_verification(self, raw: str, payload: dict[str, Any]) -> None:
        """Run the real validator and report its verdict."""
        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("Verification"))

        expected = str(payload.get(C.CLAIM_TOKEN_TYPE, C.TOKEN_TYPE_ACCESS))
        if expected not in C.AUDIENCE_BY_TOKEN_TYPE:
            self.stdout.write(
                self.style.ERROR(f"  unknown `typ` {expected!r} -- nothing to verify.")
            )
            return

        try:
            TenantTokenValidator().decode(raw, expected_type=expected)
        except TokenError as exc:
            self.stdout.write(
                self.style.ERROR(f"  rejected: {exc.detail} ({exc.get_codes()})")
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(f"  accepted here as a valid {expected} token.")
            )

    def _line(self, label: str, value: object) -> None:
        self.stdout.write(f"  {label:<{_LABEL_WIDTH}} {value}")


def _instant(value: object) -> datetime | None:
    """A NumericDate claim as an aware datetime, or ``None`` if it is not one."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=UTC)
    except OverflowError, OSError, ValueError:
        return None


def _relative(moment: datetime, now: datetime) -> str:
    """Render the offset as ``in 12m`` / ``3d ago``, how a timeline reads."""
    delta = moment - now
    magnitude = _humanise(abs(delta))
    return f"in {magnitude}" if delta.total_seconds() >= 0 else f"{magnitude} ago"


def _humanise(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    for size, suffix in ((86_400, "d"), (3_600, "h"), (60, "m")):
        if seconds >= size:
            return f"{seconds // size}{suffix}"
    return f"{seconds}s"
