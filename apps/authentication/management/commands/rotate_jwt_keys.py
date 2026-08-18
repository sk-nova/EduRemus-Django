"""Generate and stage a new RSA signing key.

Generation and promotion are deliberately separate steps. A key must be
visible to every verifier *before* anything signs with it: promote in the same
breath as you generate, and tokens go out signed by a key some verifiers have
not fetched yet, which they will correctly reject. ``--activate`` therefore
prints the promotion instructions and changes nothing.

The full five-phase procedure -- generate, propagate, promote, overlap, retire
-- is in ``docs/jwt-key-management-runbook.md``. This command implements phase
one and reports the dates the remaining phases have to respect.
"""

from __future__ import annotations

import json
import os
import re
from argparse import ArgumentParser
from datetime import timedelta
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, connection
from django.utils import timezone

from apps.authentication.models import AuthEventType
from apps.authentication.services import audit
from apps.authentication.tokens.keys import Keyring
from apps.tenants.utils import public_schema

# The kid becomes three filenames, so it is validated as a filename and not
# merely as an identifier. Anything carrying a separator, a traversal segment
# or a leading dot is rejected before it reaches a path.
_KID_PATTERN: Final = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")

# RSA below 2048 bits is not signing anything this platform trusts.
_MIN_KEY_SIZE: Final = 2048

# 90 days of signing plus a 31-day overlap: one day more than the maximum
# refresh lifetime, so no token signed by a retiring key can outlive it.
_DEFAULT_VALID_DAYS: Final = 121

_PRIVATE_MODE: Final = 0o400
_PRIVATE_CREATE_MODE: Final = 0o600
_READABLE_MODE: Final = 0o444


class Command(BaseCommand):
    """``manage.py rotate_jwt_keys --kid 2026-Q4-a``"""

    help = "Generate and stage a new JWT signing key. Does not promote it."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--kid",
            required=True,
            help=(
                "Identifier for the new key, e.g. 2026-Q4-a. Becomes the "
                "filename stem and the `kid` header of every token it signs, "
                "so it is permanent and public."
            ),
        )
        parser.add_argument(
            "--key-size",
            type=int,
            default=_MIN_KEY_SIZE,
            help=f"RSA modulus size in bits (minimum {_MIN_KEY_SIZE}).",
        )
        parser.add_argument(
            "--valid-days",
            type=int,
            default=_DEFAULT_VALID_DAYS,
            help=(
                f"Length of the validity window (default {_DEFAULT_VALID_DAYS}: "
                "90 days signing plus a 31-day verify-only overlap)."
            ),
        )
        parser.add_argument(
            "--activate",
            action="store_true",
            help=(
                "Print the promotion instructions. Promotion itself is a "
                "separate, deliberate step -- this flag never performs it."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        kid: str = options["kid"]
        key_size: int = options["key_size"]
        valid_days: int = options["valid_days"]

        self._validate_kid(kid)
        self._validate_key_size(key_size)
        overlap = self._required_overlap(valid_days)

        directory = self._key_directory()
        paths = _KeyPaths(directory, kid)
        paths.assert_absent()

        not_before = timezone.now()
        not_after = not_before + timedelta(days=valid_days)

        private = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        private_pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        _write_private(paths.private, private_pem)
        _write_readable(paths.public, public_pem)
        _write_readable(
            paths.metadata,
            _metadata(
                kid=kid,
                key_size=key_size,
                not_before=not_before,
                not_after=not_after,
            ),
        )

        # This process only. Every other worker picks the new key up within the
        # keyring TTL, which is what makes rotation a no-restart operation.
        ring = Keyring.load(force=True)

        self._audit(kid=kid, key_size=key_size, not_after=not_after)

        self._report(
            kid=kid,
            directory=directory,
            not_before=not_before,
            not_after=not_after,
            overlap=overlap,
            ring=ring,
        )
        self._warn_if_auto_promoting(kid, ring)

        if options["activate"]:
            self.stdout.write("")
            self.stdout.write(
                self.style.WARNING(
                    "Promotion is manual and deliberate. Confirm every verifier "
                    "has refetched /.well-known/jwks.json -- allow 48 hours -- "
                    f"then set JWT_ACTIVE_KEY_ID={kid} and either restart or "
                    "wait out the 5-minute keyring TTL."
                )
            )

    # -- validation ----------------------------------------------------

    @staticmethod
    def _validate_kid(kid: str) -> None:
        if not _KID_PATTERN.fullmatch(kid):
            raise CommandError(
                f"Invalid --kid {kid!r}. Use letters, digits, dot, dash or "
                "underscore, starting with a letter or digit, at most 64 "
                "characters -- the kid becomes a filename."
            )

    @staticmethod
    def _validate_key_size(key_size: int) -> None:
        if key_size < _MIN_KEY_SIZE:
            raise CommandError(
                f"--key-size {key_size} is below the {_MIN_KEY_SIZE}-bit minimum."
            )

    @staticmethod
    def _required_overlap(valid_days: int) -> timedelta:
        """Return the overlap this window has to afford, refusing one too short.

        A key must remain verifiable for longer than the maximum refresh
        lifetime after it stops signing; otherwise retiring it strands
        credentials that were still redeemable, and rotation stops being the
        invisible operation it is supposed to be.
        """
        refresh_lifetime: timedelta = settings.JWT_AUTH["REFRESH_ABSOLUTE_LIFETIME"]

        if timedelta(days=valid_days) <= refresh_lifetime:
            raise CommandError(
                f"--valid-days {valid_days} does not exceed the "
                f"{refresh_lifetime.days}-day maximum refresh lifetime, so no "
                "overlap can satisfy it. Retiring this key would invalidate "
                "refresh tokens that were still redeemable."
            )

        return refresh_lifetime + timedelta(days=1)

    # -- recording -----------------------------------------------------

    def _audit(self, *, kid: str, key_size: int, not_after: Any) -> None:
        """Record the staging, in the public schema.

        Key material is platform-wide, so the record belongs in ``public``
        rather than in whichever tenant happens to be active.

        Connectivity is checked first because this command legitimately runs
        where no database is reachable -- an operator generating a key into a
        scratch directory to push to the secret store. That is a missing audit
        row worth one line of warning, not a stack trace on a run that
        succeeded.
        """
        try:
            connection.ensure_connection()
        except DatabaseError:
            self.stdout.write(
                self.style.WARNING(
                    "No database reachable: the key was staged but no "
                    "key_rotated audit event was recorded. Note the rotation "
                    "in the change record by hand."
                )
            )
            return

        with public_schema():
            audit.record(
                AuthEventType.KEY_ROTATED,
                detail={
                    "action": "staged",
                    "kid": kid,
                    "key_size": key_size,
                    "not_after": not_after.isoformat(),
                },
            )

    # -- output --------------------------------------------------------

    def _report(
        self,
        *,
        kid: str,
        directory: Path,
        not_before: Any,
        not_after: Any,
        overlap: timedelta,
        ring: Keyring,
    ) -> None:
        self.stdout.write(self.style.SUCCESS(f"Staged key {kid!r} in {directory}."))
        self.stdout.write(f"  valid from    {not_before:%Y-%m-%d %H:%M %Z}")
        self.stdout.write(f"  valid until   {not_after:%Y-%m-%d %H:%M %Z}")
        self.stdout.write(
            f"  promote by    {not_after - overlap:%Y-%m-%d} "
            f"(leaves the full {overlap.days}-day overlap)"
        )
        self.stdout.write(f"  keyring holds {', '.join(ring.kids)}")

    def _warn_if_auto_promoting(self, kid: str, ring: Keyring) -> None:
        """Warn when the new key will start signing without being promoted.

        With ``JWT_ACTIVE_KEY_ID`` unset the keyring falls back to the newest
        signable key -- which is now this one. That collapses phases 1 to 3
        into a single step and skips propagation entirely.
        """
        if settings.JWT_AUTH["ACTIVE_KEY_ID"]:
            return

        self.stdout.write("")

        if len(ring.kids) > 1:
            self.stdout.write(
                self.style.ERROR(
                    "JWT_ACTIVE_KEY_ID is unset, so the keyring signs with the "
                    f"newest valid key -- {kid} begins signing within 5 minutes, "
                    "before verifiers have refetched the JWKS. Pin the outgoing "
                    "key with JWT_ACTIVE_KEY_ID now, then promote deliberately."
                )
            )
        else:
            self.stdout.write(
                self.style.WARNING(
                    f"JWT_ACTIVE_KEY_ID is unset. Set JWT_ACTIVE_KEY_ID={kid} so "
                    "the signing key is explicit rather than inferred."
                )
            )

    # -- helpers -------------------------------------------------------

    @staticmethod
    def _key_directory() -> Path:
        """The mounted secret directory, which must already exist.

        Not created here on purpose: a typo in ``JWT_KEY_DIRECTORY`` would
        otherwise produce an empty directory on the container filesystem and a
        signing key written outside the secret store, and both look like
        success.
        """
        directory = Path(settings.JWT_AUTH["KEY_DIRECTORY"])
        if not directory.is_dir():
            raise CommandError(
                f"JWT key directory {directory} does not exist. It is a mount "
                "from the secret store; create or mount it first "
                f"(locally: mkdir -p {directory} && chmod 700 {directory})."
            )
        return directory


class _KeyPaths:
    """The three files one key is made of."""

    def __init__(self, directory: Path, kid: str) -> None:
        self.private = directory / f"{kid}.private.pem"
        self.public = directory / f"{kid}.public.pem"
        self.metadata = directory / f"{kid}.json"

    def assert_absent(self) -> None:
        """Refuse to touch an existing kid.

        Overwriting one invalidates every unexpired token it signed, and there
        is no undo: the private key it was signed with is gone.
        """
        for path in (self.private, self.public, self.metadata):
            if path.exists():
                raise CommandError(
                    f"{path.name} already exists. Choose a new kid -- a kid is "
                    "never reused."
                )


def _metadata(*, kid: str, key_size: int, not_before: Any, not_after: Any) -> bytes:
    """The sidecar the keyring reads to learn a key's validity window."""
    document = {
        "kid": kid,
        "algorithm": "RS256",
        "key_size": key_size,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
    }
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def _write_private(path: Path, pem: bytes) -> None:
    """Write the signing key restricted from the moment it exists.

    Created through ``os.open`` with an explicit mode rather than written and
    then chmod'ed: between those two calls the private key would be readable
    by whatever the umask allowed.
    """
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _PRIVATE_CREATE_MODE
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    path.chmod(_PRIVATE_MODE)


def _write_readable(path: Path, content: bytes) -> None:
    """Write a public artefact -- readable by all, writable by none."""
    path.write_bytes(content)
    path.chmod(_READABLE_MODE)
