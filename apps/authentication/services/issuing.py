"""The seam between minting a token pair and recording it.

``tokens.generator`` is deliberately pure: it takes its inputs, builds claims
and signs them, and touches neither the database nor the request. That leaves
two jobs for the service layer, both of which live here so the three flows
that issue tokens -- login, rotation and password change -- cannot drift apart:

* read the principal's roles, which is a query;
* persist the refresh token's digest, which is a write.

Only the digest is stored. The raw token exists in the response and in the
client's cookie and nowhere else.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils import timezone

from apps.authentication.models import RefreshToken, TokenStatus
from apps.authentication.tokens.generator import TokenPair, TokenService

if TYPE_CHECKING:
    from collections.abc import Sequence

    from django.http import HttpRequest
    from rest_framework.request import Request

    from apps.accounts.models import User
    from apps.authentication.models import DeviceSession, TokenFamily
    from apps.tenants.models import Tenant

    type AnyRequest = HttpRequest | Request

__all__ = ["issue_and_store", "roles_for", "tenant_for"]


def tenant_for(request: AnyRequest) -> Tenant:
    """The tenant this request resolved to.

    ``TenantMainMiddleware`` attaches it before any view runs, so its absence
    means the middleware was bypassed or reordered -- a misconfiguration, not
    a client error. Failing loudly here is better than minting a token with
    tenancy claims derived from nothing.
    """
    tenant: Tenant | None = getattr(request, "tenant", None)
    if tenant is None:
        raise RuntimeError(
            "No tenant on the request; TenantMainMiddleware must run first."
        )
    return tenant


def roles_for(user: User) -> list[str]:
    """The role names this user holds in the active schema.

    ``auth.Group`` is per-schema, so this reads the institution's own groups.
    A group with no entry in ``ROLE_SCOPES`` simply contributes no scopes --
    institutions may define their own groups without breaking issuance.
    """
    return sorted(user.groups.values_list("name", flat=True))


def issue_and_store(
    *,
    user: User,
    tenant: Tenant,
    session: DeviceSession,
    family: TokenFamily,
    device_id: str,
    generation: int = 1,
    roles: Sequence[str] | None = None,
    auth_methods: Sequence[str] | None = None,
    auth_time: int | None = None,
) -> TokenPair:
    """Mint a pair and record the refresh half.

    Call inside the caller's transaction: the row and whatever state prompted
    the issuance (a new session, a rotation) must commit or roll back together,
    or a client ends up holding a token with no matching row.
    """
    pair = TokenService().issue_pair(
        user=user,
        tenant=tenant,
        session=session,
        family=family,
        roles=roles if roles is not None else roles_for(user),
        device_id=device_id,
        generation=generation,
        auth_methods=auth_methods,
        auth_time=auth_time,
    )

    RefreshToken.objects.create(
        token_hash=pair.refresh_token_hash,
        jti=pair.refresh_jti,
        user=user,
        family=family,
        session=session,
        generation=generation,
        status=TokenStatus.ACTIVE,
        issued_at=timezone.now(),
        expires_at=pair.refresh_expires_at,
    )

    return pair
