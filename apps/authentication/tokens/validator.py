"""Decode and verify. Never mint.

The single rule this module exists to enforce: **the verifier decides the
algorithm, never the token**. Both classic JWT forgeries follow from breaking
it. ``alg: none`` strips the signature and asks the library to accept the
result. The RS256-to-HS256 substitution takes the public key -- published at
the JWKS endpoint, by design -- and uses it as an HMAC secret; a verifier that
reads ``alg`` from the header and fetches "the key" will HMAC-verify with a
public value and succeed. Passing an explicit one-element allow-list to
``algorithms=`` defeats both before any key is applied.

The ``kid`` header is treated the same way: attacker-controlled input that may
select from a closed mapping and may never become a path or a URL.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Final

import jwt
from django.conf import settings

from apps.authentication.exceptions import (
    TokenExpired,
    TokenInvalid,
    TokenInvalidAlgorithm,
    TokenInvalidAudience,
    TokenInvalidIssuer,
    TokenMalformed,
    TokenVersionUnsupported,
    TokenWrongTenant,
    TokenWrongType,
)
from apps.authentication.tokens import claims as C
from apps.authentication.tokens.keys import Keyring
from apps.tenants.utils import current_schema_name

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger("eduremus.auth")

__all__ = ["TenantTokenValidator"]

# PyJWT failures, narrowest first: several are subclasses of one another, so
# order decides which taxonomy code a client sees.
_PYJWT_ERRORS: Final[tuple[tuple[type[Exception], type[Exception]], ...]] = (
    (jwt.ExpiredSignatureError, TokenExpired),
    (jwt.InvalidAudienceError, TokenInvalidAudience),
    (jwt.InvalidIssuerError, TokenInvalidIssuer),
    (jwt.InvalidAlgorithmError, TokenInvalidAlgorithm),
    (jwt.ImmatureSignatureError, TokenInvalid),
    (jwt.InvalidSignatureError, TokenInvalid),
    (jwt.MissingRequiredClaimError, TokenInvalid),
    (jwt.DecodeError, TokenMalformed),
)


class TenantTokenValidator:
    """Verifies a token cryptographically, then verifies it belongs *here*.

    The cryptographic half is not tenant-specific: one platform-wide signing
    key means every tenant's tokens verify successfully everywhere. Everything
    that makes a token valid *for this institution* rather than merely
    well-signed is the second half.
    """

    def __init__(self, keyring: Keyring | None = None) -> None:
        self._keyring = keyring
        self._jwt = settings.SIMPLE_JWT

    # -- public --------------------------------------------------------

    def decode(self, raw_token: str, *, expected_type: str) -> dict[str, Any]:
        """Fully verify a token and return its payload.

        Runs in the order failures should be discovered: signature and
        registered claims first (a forged token is rejected before any of its
        contents are read), then the claim schema version, then the token
        type, then tenancy.
        """
        payload = self._decode_signed(raw_token, expected_type=expected_type)

        self.assert_claim_version(payload)
        self.assert_token_type(payload, expected=expected_type)
        self._assert_type_specific_claims(payload, expected_type=expected_type)
        self.assert_schema_binding(payload)

        return payload

    def assert_claim_version(self, payload: Mapping[str, Any]) -> None:
        """Reject a claim schema this build cannot interpret."""
        if payload.get(C.CLAIM_VERSION) not in C.SUPPORTED_CLAIM_VERSIONS:
            raise TokenVersionUnsupported

    def assert_token_type(self, payload: Mapping[str, Any], *, expected: str) -> None:
        """Reject a refresh token presented as an access token, or vice versa.

        The differing audience already makes this impossible, and the check
        stays because the two are independent and both cost nothing. A control
        that is merely redundant today stops being redundant the moment the
        audiences are ever unified.
        """
        if payload.get(C.CLAIM_TOKEN_TYPE) != expected:
            raise TokenWrongType

    def assert_schema_binding(self, payload: Mapping[str, Any]) -> None:
        """Reject a token minted for a different tenant.

        Compared against the *live connection*, not against anything else in
        the token. The schema was selected by ``TenantMainMiddleware`` from the
        Host header before this code ran, so the two values have genuinely
        independent origins -- which is the entire strength of the check.
        """
        active = current_schema_name()
        token_schema = payload.get(C.CLAIM_SCHEMA)

        if token_schema != active:
            # A legitimate client cannot reach here: the token and the Host
            # header are set by the same code in the same request. Every
            # occurrence is a probe or a client defect, and both are worth
            # knowing about.
            logger.warning(
                "cross_tenant_token_rejected",
                extra={
                    "reason": "schema_mismatch",
                    "token_schema": token_schema,
                    "active_schema": active,
                },
            )
            raise TokenWrongTenant

    def assert_tenant_binding(self, payload: Mapping[str, Any], tenant_pk: Any) -> None:
        """Corroborate the schema check against the resolved tenant row.

        ``current_schema_name()`` reads the database connection;
        ``request.tenant`` is the instance the middleware resolved from the
        hostname. A defect that desynchronises one is caught by the other, so
        both are checked rather than either being trusted alone.
        """
        token_tid = payload.get(C.CLAIM_TENANT_ID)

        if str(token_tid) != str(tenant_pk):
            logger.warning(
                "cross_tenant_token_rejected",
                extra={
                    "reason": "tenant_id_mismatch",
                    "token_tid": token_tid,
                    "tenant_pk": tenant_pk,
                },
            )
            raise TokenWrongTenant

    # -- internal ------------------------------------------------------

    @staticmethod
    def _assert_type_specific_claims(
        payload: Mapping[str, Any], *, expected_type: str
    ) -> None:
        """Require the claims that only this token type carries."""
        missing = [
            claim
            for claim in C.REQUIRED_CLAIMS_BY_TOKEN_TYPE[expected_type]
            if claim not in payload
        ]
        if missing:
            logger.warning(
                "token_missing_claims",
                extra={"token_type": expected_type, "missing": missing},
            )
            raise TokenInvalid

    def _decode_signed(self, raw_token: str, *, expected_type: str) -> dict[str, Any]:
        key = self._verification_key(raw_token)

        try:
            return jwt.decode(
                raw_token,
                key,
                # An allow-list of exactly one, read from settings rather than
                # from the token. This single argument is what defeats both
                # `alg: none` and the RS256-to-HS256 substitution.
                algorithms=[self._jwt["ALGORITHM"]],
                audience=C.AUDIENCE_BY_TOKEN_TYPE[expected_type],
                issuer=self._jwt["ISSUER"],
                leeway=self._jwt["LEEWAY"],
                options={
                    "require": list(C.REQUIRED_COMMON_CLAIMS),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise _translate(exc) from exc

    def _verification_key(self, raw_token: str) -> bytes:
        """Resolve the public key named by the token's ``kid`` header."""
        try:
            header = jwt.get_unverified_header(raw_token)
        except jwt.PyJWTError as exc:
            raise TokenMalformed from exc

        keyring = self._keyring or Keyring.load()
        return keyring.public_for(str(header.get("kid", "")))


def _translate(exc: jwt.PyJWTError) -> Exception:
    """Map a PyJWT failure onto this application's error taxonomy."""
    for pyjwt_type, mapped in _PYJWT_ERRORS:
        if isinstance(exc, pyjwt_type):
            return mapped()
    return TokenInvalid()
