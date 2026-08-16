"""Mints access and refresh token pairs.

Builds and signs; it does not persist. The layering rule for this package is
that token construction stays a pure function of its inputs, so the claim set
can be asserted exhaustively without a database, a request, or a schema. The
caller -- ``services/`` -- owns the transaction that writes the resulting
``RefreshToken`` row, and :class:`TokenPair` carries everything that write
needs.

That extends to roles: they are a parameter rather than a lookup, because
``user.groups.values_list(...)`` is a query and a query here would make every
claim assertion require fixtures.

Every token carries ``tid`` and ``sch``. Those are the claims the authenticator
compares against the live connection, so a token minted without them is
unusable by design rather than by accident.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import jwt
from django.conf import settings
from django.utils import timezone

from apps.authentication.tokens import claims as C
from apps.authentication.tokens.keys import Keyring
from apps.authentication.utils.hashing import token_digest
from apps.authentication.utils.scopes import scopes_for_roles

if TYPE_CHECKING:
    from collections.abc import Sequence

    from apps.accounts.models import User
    from apps.authentication.models import DeviceSession, TokenFamily
    from apps.tenants.models import Tenant

__all__ = ["TokenPair", "TokenService"]


@dataclass(frozen=True, slots=True)
class TokenPair:
    """An issued pair, plus what the view and the persistence layer need.

    ``refresh_token_hash`` is included so the caller stores a digest without
    having to know how one is computed -- the raw token is never persisted.
    """

    access_token: str
    refresh_token: str
    access_expires_in: int
    access_jti: str
    refresh_jti: str
    refresh_token_hash: str
    refresh_expires_at: datetime
    generation: int
    scope: str
    roles: tuple[str, ...]


class TokenService:
    """Builds and signs tokens. Verifying them is ``validator``'s job."""

    def __init__(self, keyring: Keyring | None = None) -> None:
        self._keyring = keyring
        self._config = settings.JWT_AUTH
        self._jwt = settings.SIMPLE_JWT

    def issue_pair(
        self,
        *,
        user: User,
        tenant: Tenant,
        session: DeviceSession,
        family: TokenFamily,
        roles: Sequence[str],
        device_id: str,
        generation: int = 1,
        auth_methods: Sequence[str] | None = None,
        auth_time: int | None = None,
    ) -> TokenPair:
        """Mint one access token and one refresh token for a session."""
        now = timezone.now()
        issued_at = int(now.timestamp())
        role_names = tuple(sorted(roles))
        scope = scopes_for_roles(role_names)

        access_claims = self._access_claims(
            user=user,
            tenant=tenant,
            session=session,
            roles=list(role_names),
            scope=scope,
            device_id=device_id,
            issued_at=issued_at,
            auth_methods=list(auth_methods or ["pwd"]),
            auth_time=auth_time or issued_at,
        )
        refresh_claims = self._refresh_claims(
            user=user,
            tenant=tenant,
            session=session,
            family=family,
            device_id=device_id,
            issued_at=issued_at,
            generation=generation,
        )

        access = self._sign(access_claims)
        refresh = self._sign(refresh_claims)

        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            access_expires_in=int(self._access_lifetime.total_seconds()),
            access_jti=str(access_claims[C.CLAIM_JWT_ID]),
            refresh_jti=str(refresh_claims[C.CLAIM_JWT_ID]),
            refresh_token_hash=token_digest(refresh),
            refresh_expires_at=datetime.fromtimestamp(
                int(refresh_claims[C.CLAIM_EXPIRES_AT]), tz=UTC
            ),
            generation=generation,
            scope=scope,
            roles=role_names,
        )

    # -- claim construction --------------------------------------------

    def _access_claims(
        self,
        *,
        user: User,
        tenant: Tenant,
        session: DeviceSession,
        roles: list[str],
        scope: str,
        device_id: str,
        issued_at: int,
        auth_methods: list[str],
        auth_time: int,
    ) -> dict[str, Any]:
        return {
            C.CLAIM_ISSUER: self._jwt["ISSUER"],
            C.CLAIM_AUDIENCE: [C.AUDIENCE_API],
            # str() is explicit: User.id is a uuid7 UUID and json.dumps
            # cannot encode a UUID instance.
            C.CLAIM_SUBJECT: str(user.pk),
            C.CLAIM_ISSUED_AT: issued_at,
            C.CLAIM_NOT_BEFORE: issued_at,
            C.CLAIM_EXPIRES_AT: issued_at + int(self._access_lifetime.total_seconds()),
            C.CLAIM_JWT_ID: str(uuid.uuid7()),
            C.CLAIM_TOKEN_TYPE: C.TOKEN_TYPE_ACCESS,
            C.CLAIM_VERSION: C.CLAIM_SCHEMA_VERSION,
            C.CLAIM_TENANT_ID: tenant.pk,
            C.CLAIM_SCHEMA: tenant.schema_name,
            C.CLAIM_ORGANISATION: tenant.slug,
            C.CLAIM_ROLES: roles,
            C.CLAIM_SCOPES: scope,
            C.CLAIM_SESSION_ID: str(session.pk),
            C.CLAIM_DEVICE_ID: device_id,
            # Read from the user here rather than accepted as a parameter, so
            # a caller cannot pass a value captured before a revocation bumped
            # it -- minting with a stale jtv is what makes a "force logout"
            # hand back a token that outlives it.
            C.CLAIM_TOKEN_VERSION: user.token_version,
            C.CLAIM_AUTH_METHODS: auth_methods,
            C.CLAIM_AUTH_TIME: auth_time,
            C.CLAIM_EMAIL: user.email,
            C.CLAIM_NAME: user.get_full_name(),
            C.CLAIM_IS_STAFF: user.is_staff,
        }

    def _refresh_claims(
        self,
        *,
        user: User,
        tenant: Tenant,
        session: DeviceSession,
        family: TokenFamily,
        device_id: str,
        issued_at: int,
        generation: int,
    ) -> dict[str, Any]:
        """Refresh claims carry no roles, scopes or profile data.

        All of it is re-read from the database on every rotation, which is what
        lets a permission change take effect within one access-token lifetime
        rather than persisting for the refresh token's full seven days.
        """
        lifetime: timedelta = self._jwt["REFRESH_TOKEN_LIFETIME"]
        absolute: timedelta = self._config["REFRESH_ABSOLUTE_LIFETIME"]

        sliding_deadline = issued_at + int(lifetime.total_seconds())
        absolute_deadline = int((family.created_at + absolute).timestamp())

        return {
            C.CLAIM_ISSUER: self._jwt["ISSUER"],
            C.CLAIM_AUDIENCE: [C.AUDIENCE_AUTH],
            C.CLAIM_SUBJECT: str(user.pk),
            C.CLAIM_ISSUED_AT: issued_at,
            C.CLAIM_NOT_BEFORE: issued_at,
            # The absolute cap always wins. A sliding window on its own lets a
            # continuously refreshing session live forever, which is precisely
            # what a stolen lineage does.
            C.CLAIM_EXPIRES_AT: min(sliding_deadline, absolute_deadline),
            C.CLAIM_JWT_ID: str(uuid.uuid7()),
            C.CLAIM_TOKEN_TYPE: C.TOKEN_TYPE_REFRESH,
            C.CLAIM_VERSION: C.CLAIM_SCHEMA_VERSION,
            C.CLAIM_TENANT_ID: tenant.pk,
            C.CLAIM_SCHEMA: tenant.schema_name,
            C.CLAIM_SESSION_ID: str(session.pk),
            C.CLAIM_FAMILY: str(family.pk),
            C.CLAIM_GENERATION: generation,
            C.CLAIM_DEVICE_ID: device_id,
        }

    # -- signing -------------------------------------------------------

    def _sign(self, payload: dict[str, Any]) -> str:
        key = (self._keyring or Keyring.load()).active()
        return jwt.encode(
            payload,
            key.private_pem,
            algorithm=self._jwt["ALGORITHM"],
            # The kid is what lets a verifier pick the right public key during
            # a rotation overlap, when two keys are simultaneously trusted.
            headers={"kid": key.kid},
        )

    @property
    def _access_lifetime(self) -> timedelta:
        return self._jwt["ACCESS_TOKEN_LIFETIME"]
