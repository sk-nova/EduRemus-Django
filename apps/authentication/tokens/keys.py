"""Signing and verification key management.

Keys are read from a mounted secret directory at first use and cached in
process with a short TTL, so a rotation reaches every worker without a
redeploy or a restart. That is what makes rotation cheap enough to actually
perform on schedule -- and a key whose rotation has never been performed is a
key whose rotation procedure has never been tested.

The active key signs. *Every* key in the ring verifies, which is what allows an
outgoing key to keep validating tokens already in circulation while the
incoming one takes over signing.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from apps.authentication.exceptions import TokenUnknownKey

logger = logging.getLogger("eduremus.auth")

__all__ = ["Keyring", "SigningKey"]

# Long enough that the filesystem is not read on every request, short enough
# that a rotation propagates while the operator is still watching it.
_CACHE_TTL: Final = timedelta(minutes=5)

_ALGORITHM: Final = "RS256"


@dataclass(frozen=True, slots=True)
class SigningKey:
    """One RSA keypair with its identifier and validity window."""

    kid: str
    private_pem: bytes
    public_pem: bytes
    not_before: datetime
    not_after: datetime

    @property
    def is_usable_for_signing(self) -> bool:
        return self.not_before <= timezone.now() < self.not_after


class Keyring:
    """The set of keys this deployment trusts.

    Thread-safe and process-cached. Construct through :meth:`load`; the
    constructor is public only so tests can build a ring from keys they
    generated in memory.
    """

    _instance: Keyring | None = None
    _lock: Final = threading.Lock()

    def __init__(self, keys: dict[str, SigningKey], active_kid: str) -> None:
        self._keys = keys
        self._active_kid = active_kid
        self._loaded_at = timezone.now()

    # -- construction --------------------------------------------------

    @classmethod
    def load(cls, *, force: bool = False) -> Keyring:
        """The cached ring, re-read from the store once the TTL has passed."""
        with cls._lock:
            instance = cls._instance
            if (
                instance is None
                or force
                or timezone.now() - instance._loaded_at > _CACHE_TTL
            ):
                instance = cls._read_from_store()
                cls._instance = instance
            return instance

    @classmethod
    def reset(cls) -> None:
        """Drop the cached ring. For tests and for ``rotate_jwt_keys``."""
        with cls._lock:
            cls._instance = None

    @classmethod
    def _read_from_store(cls) -> Keyring:
        """Read every key from the mounted secret directory.

        The directory is a tmpfs mount populated by the secret store's agent
        (Vault Agent, the AWS Secrets Manager CSI driver, or equivalent). Keys
        never touch the image and never touch a persistent disk.
        """
        directory = Path(settings.JWT_AUTH["KEY_DIRECTORY"])
        if not directory.is_dir():
            raise ImproperlyConfigured(f"JWT key directory not found: {directory}")

        keys: dict[str, SigningKey] = {}
        for metadata_path in sorted(directory.glob("*.json")):
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            kid = str(metadata["kid"])
            keys[kid] = SigningKey(
                kid=kid,
                private_pem=(directory / f"{kid}.private.pem").read_bytes(),
                public_pem=(directory / f"{kid}.public.pem").read_bytes(),
                not_before=_aware(metadata["not_before"]),
                not_after=_aware(metadata["not_after"]),
            )

        if not keys:
            raise ImproperlyConfigured(f"No JWT signing keys found in {directory}.")

        active = settings.JWT_AUTH["ACTIVE_KEY_ID"] or _newest_signable(keys)

        if active not in keys:
            raise ImproperlyConfigured(f"Active key {active!r} is not in the keyring.")

        logger.info("keyring_loaded", extra={"kids": sorted(keys), "active": active})
        return cls(keys, active)

    # -- use -----------------------------------------------------------

    def active(self) -> SigningKey:
        """The key new tokens are signed with."""
        return self._keys[self._active_kid]

    def public_for(self, kid: str) -> bytes:
        """Verification key for a given ``kid``.

        The ``kid`` arrives in an unverified token header and is therefore
        attacker-controlled. It selects from this closed mapping and is never
        used to build a filesystem path or a URL -- an unknown ``kid`` is a
        rejection, never a fetch.
        """
        try:
            return self._keys[kid].public_pem
        except KeyError as exc:
            logger.warning("token_unknown_kid", extra={"kid": kid})
            raise TokenUnknownKey from exc

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """RFC 7517 document containing every trusted public key.

        Every key, not only the active one: a verifier that fetched this
        document must be able to check tokens signed by the outgoing key for
        as long as any remain in circulation.
        """
        return {"keys": [self._as_jwk(key) for key in self._keys.values()]}

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    @staticmethod
    def _as_jwk(key: SigningKey) -> dict[str, str]:
        public = serialization.load_pem_public_key(key.public_pem)
        if not isinstance(public, rsa.RSAPublicKey):
            raise ImproperlyConfigured(f"Key {key.kid} is not an RSA public key.")

        numbers = public.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": _ALGORITHM,
            "kid": key.kid,
            "n": _b64u_uint(numbers.n),
            "e": _b64u_uint(numbers.e),
        }


def _newest_signable(keys: dict[str, SigningKey]) -> str:
    """The most recently valid key, when no active kid is configured."""
    signable = [key for key in keys.values() if key.is_usable_for_signing]
    if not signable:
        raise ImproperlyConfigured(
            "No JWT signing key is currently within its validity window."
        )
    return max(signable, key=lambda key: key.not_before).kid


def _aware(value: str) -> datetime:
    """Parse an ISO timestamp, treating a naive one as UTC.

    A naive value would raise on the first comparison against ``timezone.now()``
    -- at signing time, in production. Normalising here turns a metadata defect
    into something the validity window simply reports.
    """
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _b64u_uint(value: int) -> str:
    """Base64url-encode an unsigned integer, per RFC 7518 6.3.1."""
    length = (value.bit_length() + 7) // 8
    encoded = base64.urlsafe_b64encode(value.to_bytes(length, "big"))
    return encoded.rstrip(b"=").decode("ascii")
