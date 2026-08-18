"""HTTP binding for the authentication endpoints.

Every view here delegates. The rule is not stylistic: each of these flows has
to be reachable from a management command, a Celery task and a test without
constructing an HTTP request, and logic that leaks up into a view stops being
reusable the moment something other than a browser needs it.

What views *do* own is the HTTP contract -- status codes, cookies, and the
headers in :class:`AuthResponseMixin`, which apply to authentication responses
whether they succeed or fail.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import NotAuthenticated
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.authentication.exceptions import TokenError
from apps.authentication.models import AuthEventType, RevocationReason
from apps.authentication.serializers import (
    CurrentUserSerializer,
    DeviceSessionSerializer,
    LoginSerializer,
    PasswordChangeResponseSerializer,
    PasswordChangeSerializer,
    RevokeSessionSerializer,
    TokenPairResponseSerializer,
    TokenVerifyRequestSerializer,
    TokenVerifyResponseSerializer,
)
from apps.authentication.services.authentication import AuthenticationService
from apps.authentication.services.password import PasswordService
from apps.authentication.services.refresh import RefreshService
from apps.authentication.services.revocation import RevocationService
from apps.authentication.services.sessions import DeviceSessionService
from apps.authentication.throttling import (
    LoginRateThrottle,
    PasswordChangeRateThrottle,
    RefreshRateThrottle,
    TenantScopedEndpointThrottle,
)
from apps.authentication.tokens import claims as C
from apps.authentication.tokens.denylist import is_denylisted
from apps.authentication.tokens.keys import Keyring
from apps.authentication.tokens.validator import TenantTokenValidator
from apps.authentication.utils.cookies import (
    assert_csrf,
    clear_auth_cookies,
    issue_csrf_token,
    read_refresh_cookie,
    set_auth_cookies,
)
from apps.authentication.utils.request_meta import request_id

if TYPE_CHECKING:
    from rest_framework.request import Request

    from apps.authentication.tokens.generator import TokenPair

_REALM = "eduremus"

__all__ = [
    "CurrentUserView",
    "JWKSView",
    "LoginView",
    "LogoutAllView",
    "LogoutView",
    "PasswordChangeView",
    "RefreshView",
    "RevokeSessionView",
    "SessionListView",
    "VerifyTokenView",
]


class AuthResponseMixin:
    """Headers every authentication response carries.

    ``no-store`` rather than ``no-cache``: the latter permits storage with
    revalidation, which for a response containing an access token means the
    credential sits in a shared cache. Set in ``finalize_response`` so error
    responses are covered too.
    """

    def finalize_response(
        self, request: Request, response: Response, *args: Any, **kwargs: Any
    ) -> Response:
        response = super().finalize_response(request, response, *args, **kwargs)  # type: ignore[misc]
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        if not response.has_header("X-Request-Id"):
            response["X-Request-Id"] = request_id(request)
        return response

    def get_authenticate_header(self, request: Request) -> str:
        """The challenge that keeps a rejected credential a 401.

        DRF downgrades ``NotAuthenticated`` and ``AuthenticationFailed`` to 403
        when the view offers no authenticator to challenge with -- which is
        every unauthenticated endpoint here, since login and refresh carry no
        ``Authorization`` header by definition. The downgrade is wrong for this
        API: the taxonomy assigns 401 to bad credentials, and a client that
        sees 403 will not know to re-authenticate.
        """
        return f'Bearer realm="{_REALM}"'


# ---------------------------------------------------------------------
# Credential exchange
# ---------------------------------------------------------------------


class LoginView(AuthResponseMixin, APIView):
    """Exchange credentials for a token pair."""

    authentication_classes: ClassVar[tuple[()]] = ()
    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (AllowAny,)
    throttle_classes: ClassVar[tuple[Any, ...]] = (LoginRateThrottle,)
    serializer_class = LoginSerializer

    @extend_schema(
        request=LoginSerializer,
        responses={200: TokenPairResponseSerializer},
        summary="Log in",
    )
    def post(self, request: Request) -> Response:
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        result = AuthenticationService().login(
            email=data["email"],
            password=data["password"],
            request=request,
            device_name=data.get("device_name", ""),
        )

        body = _pair_body(result.pair)
        body["user"] = {
            "id": str(result.user.pk),
            "email": result.user.email,
            "name": result.user.get_full_name(),
            "roles": list(result.pair.roles),
            "is_staff": result.user.is_staff,
        }
        body["tenant"] = _tenant_summary(request)

        return _attach_cookies(Response(body, status=status.HTTP_200_OK), result.pair)


class RefreshView(AuthResponseMixin, APIView):
    """Rotate the refresh cookie and mint a new access token."""

    authentication_classes: ClassVar[tuple[()]] = ()
    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (AllowAny,)
    throttle_classes: ClassVar[tuple[Any, ...]] = (RefreshRateThrottle,)

    @extend_schema(
        request=None, responses={200: TokenPairResponseSerializer}, summary="Refresh"
    )
    def post(self, request: Request) -> Response:
        # The cookie is attached by the browser automatically, which makes
        # this the one endpoint CSRF actually reaches -- an Authorization
        # header is never sent without script deliberately setting it.
        assert_csrf(request)

        raw_token = read_refresh_cookie(request)
        if not raw_token:
            raise NotAuthenticated

        pair = RefreshService().rotate(raw_token=raw_token, request=request)
        return _attach_cookies(Response(_pair_body(pair)), pair)

    def handle_exception(self, exc: Exception) -> Response:
        """Clear the cookies whenever rotation fails.

        A rejected refresh token will never work again -- redemption is
        single-use and every failure here is terminal for that lineage.
        Leaving the cookie in place produces a client that retries a dead
        credential until the throttle turns it into a 429.
        """
        response = super().handle_exception(exc)  # type: ignore[misc]
        clear_auth_cookies(response)
        return response


# ---------------------------------------------------------------------
# Session teardown
# ---------------------------------------------------------------------


class LogoutView(AuthResponseMixin, APIView):
    """End the current session. Idempotent."""

    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (IsAuthenticated,)
    throttle_classes: ClassVar[tuple[Any, ...]] = (TenantScopedEndpointThrottle,)
    throttle_scope = "logout"

    @extend_schema(request=None, responses={204: None}, summary="Log out")
    def post(self, request: Request) -> Response:
        assert_csrf(request)

        payload = _payload(request)
        session_id = payload.get(C.CLAIM_SESSION_ID)

        if session_id:
            DeviceSessionService().end(
                str(session_id), user=request.user, reason=RevocationReason.LOGOUT
            )

        _denylist_presented_access_token(payload)

        # 204 whether or not anything was still live. A client retrying after
        # a network timeout must not be told its logout failed, and a uniform
        # response tells an attacker nothing either.
        response = Response(status=status.HTTP_204_NO_CONTENT)
        clear_auth_cookies(response)
        return response


class LogoutAllView(AuthResponseMixin, APIView):
    """End every session this principal holds."""

    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (IsAuthenticated,)
    throttle_classes: ClassVar[tuple[Any, ...]] = (TenantScopedEndpointThrottle,)
    throttle_scope = "logout_all"

    @extend_schema(request=None, responses={204: None}, summary="Log out everywhere")
    def post(self, request: Request) -> Response:
        RevocationService().revoke_all_for_user(
            request.user,
            reason=RevocationReason.LOGOUT_ALL,
            request=request,
            event=AuthEventType.LOGOUT_ALL,
        )
        _denylist_presented_access_token(_payload(request))

        response = Response(status=status.HTTP_204_NO_CONTENT)
        clear_auth_cookies(response)
        return response


class RevokeSessionView(AuthResponseMixin, APIView):
    """End one named session belonging to the caller.

    No scope is required. Ownership *is* the authorisation: the service filters
    by user as well as by id, so knowing a session identifier confers nothing.
    Gating this on ``sessions:revoke`` would make "sign out my other device" an
    administrator-only action, which is not what the session list is for.
    """

    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (IsAuthenticated,)
    throttle_classes: ClassVar[tuple[Any, ...]] = (TenantScopedEndpointThrottle,)
    throttle_scope = "revoke"

    @extend_schema(
        request=RevokeSessionSerializer, responses={204: None}, summary="Revoke session"
    )
    def post(self, request: Request) -> Response:
        serializer = RevokeSessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        DeviceSessionService().end(
            serializer.validated_data["session_id"],
            user=request.user,
            reason=RevocationReason.ADMIN_REVOKED,
        )
        # 204 regardless of whether anything matched, so the endpoint cannot
        # be used to discover which session ids exist.
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------


class VerifyTokenView(AuthResponseMixin, APIView):
    """Introspect an access token, RFC 7662 style."""

    authentication_classes: ClassVar[tuple[()]] = ()
    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (AllowAny,)
    throttle_classes: ClassVar[tuple[Any, ...]] = (TenantScopedEndpointThrottle,)
    throttle_scope = "verify"

    @extend_schema(
        request=TokenVerifyRequestSerializer,
        responses={200: TokenVerifyResponseSerializer},
        summary="Verify token",
    )
    def post(self, request: Request) -> Response:
        serializer = TokenVerifyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            payload = TenantTokenValidator().decode(
                serializer.validated_data["token"],
                expected_type=C.TOKEN_TYPE_ACCESS,
            )
        except TokenError:
            # Uniform by design. Reporting *why* would tell an unauthenticated
            # caller whether a token is merely expired, has been revoked, or
            # belongs to another institution. Note that a denylist outage
            # raises 503 from below rather than being reported as inactive --
            # "cannot tell" is not the same answer as "not valid".
            return Response({"active": False})

        if is_denylisted(str(payload.get(C.CLAIM_JWT_ID, ""))):
            return Response({"active": False})

        return Response(
            {
                "active": True,
                "sub": payload.get(C.CLAIM_SUBJECT),
                "tid": payload.get(C.CLAIM_TENANT_ID),
                "sch": payload.get(C.CLAIM_SCHEMA),
                "scope": payload.get(C.CLAIM_SCOPES, ""),
                "exp": payload.get(C.CLAIM_EXPIRES_AT),
                "iat": payload.get(C.CLAIM_ISSUED_AT),
                "token_type": payload.get(C.CLAIM_TOKEN_TYPE),
            }
        )


class CurrentUserView(AuthResponseMixin, APIView):
    """The authenticated principal and its tenant."""

    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (IsAuthenticated,)
    serializer_class = CurrentUserSerializer

    @extend_schema(responses={200: CurrentUserSerializer}, summary="Current user")
    def get(self, request: Request) -> Response:
        serializer = CurrentUserSerializer(request.user, context={"request": request})
        return Response(serializer.data)


class SessionListView(AuthResponseMixin, APIView):
    """Live sessions for the authenticated principal."""

    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (IsAuthenticated,)
    throttle_classes: ClassVar[tuple[Any, ...]] = (TenantScopedEndpointThrottle,)
    throttle_scope = "sessions"
    serializer_class = DeviceSessionSerializer

    @extend_schema(
        responses={200: DeviceSessionSerializer(many=True)}, summary="Sessions"
    )
    def get(self, request: Request) -> Response:
        payload = _payload(request)
        sessions = DeviceSessionService().live_for(request.user)

        serializer = DeviceSessionSerializer(
            sessions,
            many=True,
            context={
                "request": request,
                "current_session_id": payload.get(C.CLAIM_SESSION_ID),
            },
        )
        data = serializer.data
        return Response({"count": len(data), "results": data})


# ---------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------


class PasswordChangeView(AuthResponseMixin, APIView):
    """Change the password, keeping only this device signed in."""

    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (IsAuthenticated,)
    throttle_classes: ClassVar[tuple[Any, ...]] = (PasswordChangeRateThrottle,)
    serializer_class = PasswordChangeSerializer

    @extend_schema(
        request=PasswordChangeSerializer,
        responses={200: PasswordChangeResponseSerializer},
        summary="Change password",
    )
    def post(self, request: Request) -> Response:
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Counted before the change, since the change is what ends them.
        ended = DeviceSessionService().live_for(request.user).count()

        pair = PasswordService().change(
            user=request.user,
            current_password=serializer.validated_data["current_password"],
            new_password=serializer.validated_data["new_password"],
            request=request,
        )

        body = _pair_body(pair)
        body["sessions_revoked"] = ended
        return _attach_cookies(Response(body), pair)


# ---------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------


class JWKSView(APIView):
    """Public verification keys, RFC 7517.

    Served from the public URLconf only. Keys are platform-wide, so a
    per-tenant JWKS would imply per-tenant keys, which this design does not
    use. Every trusted key is published, not only the active one, so a
    verifier can still check tokens signed by an outgoing key throughout a
    rotation overlap.
    """

    authentication_classes: ClassVar[tuple[()]] = ()
    permission_classes: ClassVar[tuple[type[BasePermission], ...]] = (AllowAny,)
    throttle_classes: ClassVar[tuple[()]] = ()

    @extend_schema(responses={200: dict}, summary="JWKS")
    def get(self, request: Request) -> Response:
        response = Response(Keyring.load().jwks())
        # Cached at the edge for an hour. The rotation overlap is far longer,
        # so a verifier caching this long always learns about a new key well
        # before tokens signed with it arrive.
        response["Cache-Control"] = "public, max-age=3600"
        return response


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _payload(request: Request) -> dict[str, Any]:
    """Verified claims attached by the authenticator."""
    return getattr(request, "auth_payload", {}) or {}


def _pair_body(pair: TokenPair) -> dict[str, Any]:
    """The token-pair response body. Never includes the refresh token."""
    return {
        "access_token": pair.access_token,
        "token_type": "Bearer",
        "expires_in": pair.access_expires_in,
        "scope": pair.scope,
    }


def _attach_cookies(response: Response, pair: TokenPair) -> Response:
    """Set the refresh and CSRF cookies for a freshly issued pair.

    The CSRF value rotates with the refresh token rather than persisting, so a
    value captured from an earlier response cannot be replayed against the
    next rotation.
    """
    set_auth_cookies(
        response,
        refresh_token=pair.refresh_token,
        csrf_token=issue_csrf_token(),
        expires_at=pair.refresh_expires_at,
    )
    return response


def _tenant_summary(request: Request) -> dict[str, Any] | None:
    tenant = getattr(request, "tenant", None)
    if tenant is None:
        return None
    return {"id": tenant.pk, "slug": tenant.slug, "name": tenant.name}


def _denylist_presented_access_token(payload: dict[str, Any]) -> None:
    """Deny the access token that authorised this request.

    Without it, the presented token stays usable for the remainder of its
    lifetime -- up to fifteen minutes in which a "logged out" credential still
    works.
    """
    jti = payload.get(C.CLAIM_JWT_ID)
    expires_at = payload.get(C.CLAIM_EXPIRES_AT)
    if not jti or not expires_at:
        return

    RevocationService().revoke_access_token(
        str(jti), expires_at=datetime.fromtimestamp(int(expires_at), tz=UTC)
    )
