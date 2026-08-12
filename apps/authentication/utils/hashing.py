"""Digest and comparison helpers.

Refresh tokens are stored as digests, never as the raw value, so a database
disclosure yields nothing redeemable. The token is a signed JWT and therefore
already high-entropy, which is why a plain SHA-256 is right here and a password
hash (bcrypt, argon2) is not: there is no low-entropy secret to slow an
attacker down against, and the digest sits on the refresh hot path where a
deliberately expensive hash would cost real latency.
"""

from __future__ import annotations

import hashlib
import secrets

from django.utils.crypto import constant_time_compare

__all__ = [
    "constant_time_equal",
    "random_token",
    "sha256_hex",
    "token_digest",
]


def sha256_hex(value: str) -> str:
    """SHA-256 of a UTF-8 string, as lower-case hex."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def token_digest(raw_token: str) -> str:
    """Digest of a serialised JWT, as stored in ``RefreshToken.token_hash``.

    Encoded as ASCII rather than UTF-8: a JWT is base64url by construction, so
    anything outside ASCII is malformed and should fail loudly here rather than
    hash to a value that will simply never match a stored row.
    """
    return hashlib.sha256(raw_token.encode("ascii")).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    """Compare two secrets without leaking their prefix through timing."""
    return constant_time_compare(left, right)


def random_token(length: int = 32) -> str:
    """A URL-safe random string, for CSRF values and similar opaque tokens."""
    return secrets.token_urlsafe(length)
