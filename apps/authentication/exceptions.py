"""Error codes, exception types and the single response envelope.

Every error the API emits looks the same::

    {
        "error": "token_expired",
        "message": "The access token has expired.",
        "request_id": "018f3c6a-c134-7e55-f607-081920314253"
    }

The ``error`` code is the contract; ``message`` is for humans and may be
reworded at any time. Nothing here leaks internal state -- a client learns that
its credential is unusable and, for exactly one code, that refreshing is worth
trying.

``token_expired`` is that code. Every other 401 means the credential must be
discarded and the user re-authenticated. A client that retries refresh on
``token_revoked`` spins against the refresh endpoint until the throttle turns
it into a 429, which presents to the user as a hanging application rather than
a login prompt.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import (
    APIException,
    AuthenticationFailed,
    PermissionDenied,
    ValidationError,
)

from apps.authentication.utils.request_meta import request_id

if TYPE_CHECKING:
    from rest_framework.response import Response

__all__ = [
    "AccountLocked",
    "AuthErrorCode",
    "CSRFFailed",
    "InsufficientScope",
    "PasswordReused",
    "ServiceUnavailable",
    "TokenError",
    "TokenExpired",
    "TokenInvalid",
    "TokenInvalidAlgorithm",
    "TokenInvalidAudience",
    "TokenInvalidIssuer",
    "TokenMalformed",
    "TokenReuseDetected",
    "TokenRevoked",
    "TokenSuperseded",
    "TokenUnknownKey",
    "TokenVersionUnsupported",
    "TokenWrongTenant",
    "TokenWrongType",
    "UserInactive",
    "auth_exception_handler",
]


class AuthErrorCode(StrEnum):
    """The complete error vocabulary. Clients may branch on these."""

    # 400
    VALIDATION_ERROR = "validation_error"
    PASSWORD_REUSED = "password_reused"
    # 401
    NOT_AUTHENTICATED = "not_authenticated"
    AUTHENTICATION_FAILED = "authentication_failed"
    TOKEN_MALFORMED = "token_malformed"
    TOKEN_INVALID = "token_invalid"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_INVALID_ISSUER = "token_invalid_issuer"
    TOKEN_INVALID_AUDIENCE = "token_invalid_audience"
    TOKEN_INVALID_ALGORITHM = "token_invalid_algorithm"
    TOKEN_UNKNOWN_KEY = "token_unknown_key"
    TOKEN_WRONG_TYPE = "token_wrong_type"
    TOKEN_WRONG_TENANT = "token_wrong_tenant"
    TOKEN_VERSION_UNSUPPORTED = "token_version_unsupported"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_SUPERSEDED = "token_superseded"
    TOKEN_REUSE_DETECTED = "token_reuse_detected"
    USER_INACTIVE = "user_inactive"
    # 403
    PERMISSION_DENIED = "permission_denied"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    CSRF_FAILED = "csrf_failed"
    # 404
    NOT_FOUND = "not_found"
    # 423 / 429
    ACCOUNT_LOCKED = "account_locked"
    THROTTLED = "throttled"
    # 5xx
    SERVER_ERROR = "server_error"
    SERVICE_UNAVAILABLE = "service_unavailable"


HTTP_423_LOCKED: Final = 423


# ---------------------------------------------------------------------
# 401 -- the credential is unusable
# ---------------------------------------------------------------------


class TokenError(AuthenticationFailed):
    """Base for every rejected credential.

    Subclasses AuthenticationFailed so DRF's own 401 handling, and SimpleJWT's
    expectations of an authentication class, both continue to hold.
    """

    default_detail = _("The credential presented is not valid.")
    default_code = AuthErrorCode.TOKEN_INVALID


class TokenMalformed(TokenError):
    default_detail = _("The token is not a well-formed JWT.")
    default_code = AuthErrorCode.TOKEN_MALFORMED


class TokenInvalid(TokenError):
    default_detail = _("The token signature or claims are invalid.")
    default_code = AuthErrorCode.TOKEN_INVALID


class TokenExpired(TokenError):
    """The one 401 a client should answer by refreshing."""

    default_detail = _("The access token has expired.")
    default_code = AuthErrorCode.TOKEN_EXPIRED


class TokenInvalidIssuer(TokenError):
    default_detail = _("The token was issued by an unrecognised issuer.")
    default_code = AuthErrorCode.TOKEN_INVALID_ISSUER


class TokenInvalidAudience(TokenError):
    default_detail = _("The token was not issued for this audience.")
    default_code = AuthErrorCode.TOKEN_INVALID_AUDIENCE


class TokenInvalidAlgorithm(TokenError):
    default_detail = _("The token signing algorithm is not permitted.")
    default_code = AuthErrorCode.TOKEN_INVALID_ALGORITHM


class TokenUnknownKey(TokenError):
    default_detail = _("The token was signed with an unknown key.")
    default_code = AuthErrorCode.TOKEN_UNKNOWN_KEY


class TokenWrongType(TokenError):
    default_detail = _("A refresh token cannot be used as an access token.")
    default_code = AuthErrorCode.TOKEN_WRONG_TYPE


class TokenWrongTenant(TokenError):
    """Cross-tenant replay.

    The message deliberately does not name the tenant the token belongs to.
    A caller holding a token for another institution learns only that it does
    not work here.

    ``token_schema`` travels on the exception so the audit row can name both
    sides of the rejection. It never reaches the client -- the response body
    is built from ``default_detail`` -- but "acme presented at beta" is the
    difference between an actionable security event and a log line saying
    something was rejected.
    """

    default_detail = _("The token was not issued for this tenant.")
    default_code = AuthErrorCode.TOKEN_WRONG_TENANT

    def __init__(
        self,
        detail: Any = None,
        code: str | None = None,
        token_schema: str = "",
    ) -> None:
        super().__init__(detail, code)
        self.token_schema = token_schema


class TokenVersionUnsupported(TokenError):
    default_detail = _("The token claim schema is no longer supported.")
    default_code = AuthErrorCode.TOKEN_VERSION_UNSUPPORTED


class TokenRevoked(TokenError):
    default_detail = _("The token has been revoked.")
    default_code = AuthErrorCode.TOKEN_REVOKED


class TokenSuperseded(TokenError):
    default_detail = _("The token has been superseded and is no longer valid.")
    default_code = AuthErrorCode.TOKEN_SUPERSEDED


class TokenReuseDetected(TokenError):
    default_detail = _("This session has been ended for security reasons.")
    default_code = AuthErrorCode.TOKEN_REUSE_DETECTED


class UserInactive(TokenError):
    default_detail = _("This account is not active.")
    default_code = AuthErrorCode.USER_INACTIVE


# ---------------------------------------------------------------------
# 403 -- authenticated, but not permitted
# ---------------------------------------------------------------------


class InsufficientScope(PermissionDenied):
    default_detail = _("The token does not carry the required scope.")
    default_code = AuthErrorCode.INSUFFICIENT_SCOPE


class CSRFFailed(PermissionDenied):
    default_detail = _("CSRF verification failed.")
    default_code = AuthErrorCode.CSRF_FAILED


# ---------------------------------------------------------------------
# Everything else
# ---------------------------------------------------------------------


class PasswordReused(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _("This password has been used recently. Choose another.")
    default_code = AuthErrorCode.PASSWORD_REUSED


class AccountLocked(APIException):
    """Too many failed attempts.

    Carries ``wait`` so the handler can emit ``Retry-After``; a client that
    honours it stops adding failures that would extend its own lockout.
    """

    status_code = HTTP_423_LOCKED
    default_detail = _("This account is temporarily locked. Try again later.")
    default_code = AuthErrorCode.ACCOUNT_LOCKED

    def __init__(
        self,
        detail: Any = None,
        code: str | None = None,
        wait: int | None = None,
    ) -> None:
        super().__init__(detail, code)
        self.wait = wait


class ServiceUnavailable(APIException):
    """A dependency the authentication path cannot proceed without.

    Raised where the alternative would be to fail *open* -- a denylist that
    cannot be consulted must reject, not admit.
    """

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = _("The service is temporarily unavailable.")
    default_code = AuthErrorCode.SERVICE_UNAVAILABLE


# ---------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------

# DRF and SimpleJWT ship their own codes for conditions this taxonomy names
# differently. Translated rather than passed through, so a client never has to
# know which library produced a given failure.
_CODE_ALIASES: Final[dict[str, AuthErrorCode]] = {
    "token_not_valid": AuthErrorCode.TOKEN_INVALID,
    "invalid": AuthErrorCode.VALIDATION_ERROR,
    "required": AuthErrorCode.VALIDATION_ERROR,
    "null": AuthErrorCode.VALIDATION_ERROR,
    "blank": AuthErrorCode.VALIDATION_ERROR,
    "parse_error": AuthErrorCode.VALIDATION_ERROR,
}

_STATUS_FALLBACKS: Final[dict[int, AuthErrorCode]] = {
    status.HTTP_400_BAD_REQUEST: AuthErrorCode.VALIDATION_ERROR,
    status.HTTP_401_UNAUTHORIZED: AuthErrorCode.NOT_AUTHENTICATED,
    status.HTTP_403_FORBIDDEN: AuthErrorCode.PERMISSION_DENIED,
    status.HTTP_404_NOT_FOUND: AuthErrorCode.NOT_FOUND,
    HTTP_423_LOCKED: AuthErrorCode.ACCOUNT_LOCKED,
    status.HTTP_429_TOO_MANY_REQUESTS: AuthErrorCode.THROTTLED,
    status.HTTP_503_SERVICE_UNAVAILABLE: AuthErrorCode.SERVICE_UNAVAILABLE,
}

_REALM: Final = "eduremus"


def auth_exception_handler(exc: Exception, context: dict[str, Any]) -> Response | None:
    """Reshape every DRF error into the one envelope.

    Returns ``None`` for exceptions DRF does not handle, which lets them
    propagate to Django's 500 path -- an unexpected exception must not be
    quietly rendered as a tidy JSON error, because that is how an internal
    failure gets mistaken for a client one.
    """
    # Imported here, not at module scope, to break a genuine import cycle:
    # rest_framework.views resolves DEFAULT_AUTHENTICATION_CLASSES while it is
    # still being imported, which pulls in this app's authentication module,
    # which imports the exception types defined above. At module scope that
    # lands on a half-initialised module; by the time a request raises, every
    # participant is fully imported.
    from rest_framework.views import exception_handler as drf_exception_handler

    response = drf_exception_handler(exc, context)
    if response is None:
        return None

    request = context.get("request")
    identifier = request_id(request)
    code = _code_for(exc, response.status_code)

    payload: dict[str, Any] = {
        "error": str(code),
        "message": _message_for(exc, code),
        "request_id": identifier,
    }

    # Field-level errors are the exception to the three-key envelope: a client
    # cannot render a usable form without knowing which field was rejected.
    if isinstance(exc, ValidationError):
        payload["details"] = exc.detail

    response.data = payload

    # Authentication responses are never cacheable -- not by the browser, not
    # by an intermediary.
    response["Cache-Control"] = "no-store"
    response["X-Request-Id"] = identifier

    if response.status_code == status.HTTP_401_UNAUTHORIZED:
        response["WWW-Authenticate"] = (
            f'Bearer realm="{_REALM}", error="{code}", '
            f'error_description="{_header_safe(payload["message"])}"'
        )

    wait = getattr(exc, "wait", None)
    if wait is not None and "Retry-After" not in response:
        response["Retry-After"] = str(int(wait))

    return response


def _code_for(exc: Exception, status_code: int) -> AuthErrorCode | str:
    """Resolve the machine-readable code for an exception."""
    if isinstance(exc, ValidationError):
        return AuthErrorCode.VALIDATION_ERROR

    detail = getattr(exc, "detail", None)
    raw = getattr(detail, "code", None) or getattr(exc, "default_code", None)

    if isinstance(raw, AuthErrorCode):
        return raw
    if isinstance(raw, str):
        return _CODE_ALIASES.get(raw, raw)

    return _STATUS_FALLBACKS.get(status_code, AuthErrorCode.SERVER_ERROR)


def _message_for(exc: Exception, code: AuthErrorCode | str) -> str:
    """A human-readable sentence, never a serialised structure."""
    if isinstance(exc, ValidationError):
        return str(_("The request could not be processed as submitted."))

    detail = getattr(exc, "detail", None)
    if isinstance(detail, str):
        return str(detail)

    return str(code).replace("_", " ").capitalize()


def _header_safe(value: str) -> str:
    """Strip what would break out of a quoted header parameter."""
    return value.replace('"', "'").replace("\r", " ").replace("\n", " ")
