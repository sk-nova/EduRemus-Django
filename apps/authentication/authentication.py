"""DRF authentication that binds a token to the schema it was issued for.

``TenantMainMiddleware`` has already selected the schema by the time this runs,
so the authenticator *compares* the token's tenancy claims against the live
connection rather than deriving the tenant from them. The direction matters: a
token that could select its own schema would be a cross-tenant capability, and
the whole isolation model would rest on a claim the holder controls.

Two independent sources are checked. ``current_schema_name()`` reads the
database connection; ``request.tenant`` is the row the middleware resolved from
the Host header. A defect that desynchronises one is caught by the other.

Order is deliberate: every tenancy check completes **before** the user lookup,
so a token from another institution never causes a row to be read here at all.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework_simplejwt.authentication import JWTAuthentication

from apps.authentication.exceptions import (
    TokenInvalid,
    TokenRevoked,
    TokenSuperseded,
    TokenWrongTenant,
    UserInactive,
)
from apps.authentication.models import AuthEventType
from apps.authentication.services import audit
from apps.authentication.tokens import claims as C
from apps.authentication.tokens.denylist import is_denylisted
from apps.authentication.tokens.validator import TenantTokenValidator
from apps.authentication.utils.cache_keys import user_key

if TYPE_CHECKING:
    from rest_framework.request import Request
    from rest_framework_simplejwt.tokens import Token

    from apps.accounts.models import User

logger = logging.getLogger("eduremus.auth")
UserModel = get_user_model()

__all__ = ["TenantAwareJWTAuthentication", "tenant_user_authentication_rule"]


class TenantAwareJWTAuthentication(JWTAuthentication):
    """``JWTAuthentication`` plus the tenancy, revocation and version checks.

    The base class validates signature, issuer, audience, expiry and
    not-before. None of those are tenant-specific: one platform-wide signing
    key means every tenant's tokens verify successfully everywhere. Everything
    that makes a token valid *here* rather than merely well-signed is added
    below.
    """

    # The supertype annotates these with an unbound TypeVar over
    # (AbstractBaseUser, TokenUser) on a non-generic class, so narrowing to the
    # project's concrete user model cannot be expressed and is asserted here.
    def authenticate(  # type: ignore[override]
        self, request: Request
    ) -> tuple[User, Token] | None:
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        # Signature, registered claims, claim-schema version, token type and
        # the schema binding all happen here, inside TenantAccessToken.
        try:
            validated_token = self.get_validated_token(raw_token)
        except TokenWrongTenant:
            # The schema comparison lives in tokens/, which may not import
            # services -- so it logs and raises, and the audit row is written
            # here instead. Without this the single most security-relevant
            # event in the design would exist only as a log line.
            self._audit_cross_tenant(request, reason="schema_mismatch", detail={})
            raise

        payload: dict[str, Any] = dict(validated_token.payload)

        self._assert_tenant_binding(payload, request)
        self._assert_not_denylisted(payload)

        user = self.get_user(validated_token)
        self._assert_token_version(payload, user)

        # Claims the permission classes read. Attached rather than re-decoded,
        # so authorisation cannot disagree with authentication about what the
        # token said.
        request.auth_payload = payload  # type: ignore[attr-defined]
        return user, validated_token

    # -- claim checks --------------------------------------------------

    def _assert_tenant_binding(self, payload: dict[str, Any], request: Request) -> None:
        """Corroborate the token's tenant against the resolved tenant row.

        ``TenantAccessToken`` already compared ``sch`` with the live
        connection. This adds the second, independently sourced comparison.
        """
        tenant = getattr(request, "tenant", None)
        if tenant is None:
            return

        try:
            TenantTokenValidator().assert_tenant_binding(payload, tenant.pk)
        except TokenWrongTenant:
            self._audit_cross_tenant(
                request,
                reason="tenant_id_mismatch",
                detail={
                    "token_tid": str(payload.get(C.CLAIM_TENANT_ID, "")),
                    "tenant_pk": str(tenant.pk),
                },
            )
            raise

    @staticmethod
    def _audit_cross_tenant(
        request: Request, *, reason: str, detail: dict[str, Any]
    ) -> None:
        """Record a rejected cross-tenant token.

        A legitimate client cannot reach here: the token and the Host header
        are set by the same code in the same request. Every occurrence is a
        probe or a client defect, and both are worth knowing about.
        """
        audit.security_event(
            AuthEventType.CROSS_TENANT_TOKEN_REJECTED,
            request=request,
            detail={"reason": reason, **detail},
        )

    @staticmethod
    def _assert_not_denylisted(payload: dict[str, Any]) -> None:
        jti = payload.get(C.CLAIM_JWT_ID)
        if jti and is_denylisted(str(jti)):
            raise TokenRevoked

    @staticmethod
    def _assert_token_version(payload: dict[str, Any], user: User) -> None:
        """Reject a token superseded by a credential change.

        ``token_version`` is incremented on password change, force logout and
        tenant suspension. One UPDATE invalidates every outstanding token for
        the account without enumerating them, and this is where that takes
        effect.
        """
        presented = payload.get(C.CLAIM_TOKEN_VERSION)
        if presented is None or int(presented) != user.token_version:
            raise TokenSuperseded

    # -- user resolution -----------------------------------------------

    def get_user(self, validated_token: Token) -> User:  # type: ignore[override]
        """Resolve the subject to a user in the *currently active* schema.

        Reads through ``objects`` rather than ``all_objects``, so soft-deleted
        accounts are excluded. Stated explicitly because the manager story here
        is genuinely subtle: ``User.Meta.base_manager_name`` is ``all_objects``
        so that related-object traversal still resolves deleted users, which
        makes the right choice at *this* call site non-obvious.

        The cache key is schema-prefixed. An unprefixed one would serve one
        institution's ``User`` to another institution's request -- a
        cross-tenant identity leak through the cache rather than the database,
        and an ordinary-looking optimisation that rarely gets security review.
        """
        try:
            user_id = validated_token[C.CLAIM_SUBJECT]
        except KeyError as exc:
            raise TokenInvalid from exc

        cache_key = user_key(str(user_id))
        user: User | None = cache.get(cache_key)

        if user is None:
            try:
                user = UserModel.objects.get(pk=user_id)
            except (UserModel.DoesNotExist, ValueError, TypeError) as exc:
                raise UserInactive from exc
            cache.set(cache_key, user, settings.JWT_AUTH["USER_CACHE_TIMEOUT"])

        if not tenant_user_authentication_rule(user):
            raise UserInactive

        return user


def tenant_user_authentication_rule(user: User | None) -> bool:
    """SimpleJWT's ``USER_AUTHENTICATION_RULE`` hook.

    The default checks only ``is_active``. Soft deletion happens to set
    ``is_active`` to ``False`` as well, so the default would in fact catch a
    deleted account today -- but that is a consequence of
    ``UserQuerySet.soft_delete_values`` rather than a guarantee, and depending
    on it would break silently if that method ever changed. Both conditions
    are checked here.
    """
    return user is not None and user.is_active and user.deleted_at is None
