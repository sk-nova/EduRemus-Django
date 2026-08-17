"""The SimpleJWT integration point.

``JWTAuthentication.get_validated_token()`` walks ``AUTH_TOKEN_CLASSES`` and
constructs each in turn, so this class is where SimpleJWT's machinery hands
control to this application's validator. Decoding is delegated rather than
duplicated: SimpleJWT's own ``TokenBackend`` takes a single static verifying
key from settings and has no concept of a ``kid``, which makes it unable to
verify anything during a rotation overlap -- the exact window in which two keys
are simultaneously valid.

Minting does not go through this class. ``generator.TokenService`` builds the
full claim set, and there is deliberately no second code path that can produce
a token with a different one.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from rest_framework_simplejwt.tokens import Token

from apps.authentication.tokens import claims as C
from apps.authentication.tokens.validator import TenantTokenValidator

__all__ = ["TenantAccessToken", "TenantRefreshToken"]


class _ValidatedToken(Token):
    """A ``Token`` whose payload came from :class:`TenantTokenValidator`.

    Note that the validator raises this application's DRF exceptions, which
    are *not* SimpleJWT ``TokenError``s. ``get_validated_token()`` only catches
    the latter, so these propagate straight out with their precise taxonomy
    code instead of being flattened into "Given token not valid for any token
    type". That is intentional, and it holds only because exactly one class is
    configured in ``AUTH_TOKEN_CLASSES``: a second entry would never be tried.
    """

    def __init__(self, token: Any = None, verify: bool = True) -> None:
        if token is None:
            raise TypeError(
                f"{type(self).__name__} wraps an existing token; "
                "mint through tokens.generator.TokenService instead."
            )

        # SimpleJWT's get_raw_token() returns bytes, and str() on bytes yields
        # the repr -- "b'eyJhbGci...'" -- which is not a JWT and fails to parse
        # in a way that looks like a malformed token rather than a decoding
        # mistake. Decoded explicitly, once, here. Kept beside self.token
        # rather than replacing it, because the base class declares that
        # attribute with a different type.
        self.token = token
        self.raw_token: str = _as_text(token)
        self.current_time = self._now()
        self.payload = TenantTokenValidator().decode(
            self.raw_token, expected_type=self._expected_type()
        )

    @classmethod
    def _expected_type(cls) -> str:
        """The ``typ`` this class accepts, as a non-optional value.

        ``Token.token_type`` is declared optional upstream; every concrete
        subclass here sets it.
        """
        token_type = cls.token_type
        if token_type is None:  # pragma: no cover - subclasses always set it
            raise TypeError(f"{cls.__name__} must define token_type")
        return token_type

    def verify(self) -> None:
        """No-op: the validator verified everything before this object existed.

        Left explicit rather than inherited. ``Token.verify()`` re-checks
        expiry and token type against ``api_settings``, which would duplicate
        the work with a *different* configuration source and quietly disagree
        with the validator if the two ever drift.
        """

    def __str__(self) -> str:
        """The token exactly as received.

        ``Token.__str__`` re-encodes the payload through SimpleJWT's backend,
        which here would sign with the wrong key and produce something that was
        never issued.
        """
        return self.raw_token

    @staticmethod
    def _now() -> Any:
        from rest_framework_simplejwt.utils import aware_utcnow

        return aware_utcnow()


def _as_text(token: Any) -> str:
    """Normalise a raw token to text, whatever the caller passed."""
    if isinstance(token, bytes):
        return token.decode("ascii")
    return str(token)


class TenantAccessToken(_ValidatedToken):
    """A Bearer credential, verified against the active schema."""

    token_type = C.TOKEN_TYPE_ACCESS
    lifetime = settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"]


class TenantRefreshToken(_ValidatedToken):
    """A refresh credential.

    Not listed in ``AUTH_TOKEN_CLASSES``: a refresh token must never
    authenticate a request. It exists so the refresh endpoint can decode one
    through the same path.
    """

    token_type = C.TOKEN_TYPE_REFRESH
    lifetime = settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]
