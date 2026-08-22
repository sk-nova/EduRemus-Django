"""Refresh-token rotation with family-wide reuse detection.

Every redemption produces a new token and retires the one presented, so a
stolen refresh token is usable at most once. Whoever presents it second
reveals the theft: the legitimate client and the thief now hold values from
the same lineage, and exactly one of them will be told the token was already
spent.

The response to that is to invalidate the **whole family**, not just the
replayed generation. Once a token has been redeemed twice there is no way to
tell which holder is legitimate, so both are made to authenticate again. The
alternative -- revoking only the presented token -- leaves the thief holding a
valid successor whenever they redeem first.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.authentication import metrics
from apps.authentication.exceptions import (
    TokenExpired,
    TokenInvalid,
    TokenReuseDetected,
    TokenRevoked,
    TokenSuperseded,
    UserInactive,
)
from apps.authentication.models import (
    AuthEventType,
    RefreshToken,
    RevocationReason,
    TokenStatus,
)
from apps.authentication.services import audit
from apps.authentication.services.issuing import issue_and_store, tenant_for
from apps.authentication.services.revocation import RevocationService
from apps.authentication.tokens import claims as C
from apps.authentication.tokens.denylist import is_denylisted
from apps.authentication.tokens.validator import TenantTokenValidator
from apps.authentication.utils.hashing import token_digest
from apps.tenants.utils import current_schema_name

if TYPE_CHECKING:
    from django.http import HttpRequest
    from rest_framework.request import Request

    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant

    type AnyRequest = HttpRequest | Request

logger = logging.getLogger("eduremus.auth")

__all__ = ["RefreshService"]


class _Failure(StrEnum):
    """Why a redemption did not happen. Internal to this module."""

    NONE = ""
    UNKNOWN = "unknown"
    REUSE = "reuse"
    REVOKED = "revoked"
    EXPIRED = "expired"
    INACTIVE = "inactive"
    SUPERSEDED = "superseded"


@dataclass(frozen=True, slots=True)
class _Outcome:
    """The result of one redemption attempt, carried out of the transaction."""

    pair: TokenPair | None = None
    record: RefreshToken | None = None
    failure: _Failure = _Failure.NONE


class RefreshService:
    """Redeems a refresh token for a new pair, exactly once."""

    def __init__(self) -> None:
        self._validator = TenantTokenValidator()
        self._revocation = RevocationService()

    def rotate(self, *, raw_token: str, request: AnyRequest) -> TokenPair:
        """Verify, redeem and replace a refresh token."""
        # Signature, issuer, audience, expiry, claim version, token type and
        # the schema binding, in one place. Rotation mints new credentials, so
        # it gets the full check independently rather than assuming an earlier
        # layer applied one.
        payload = self._validator.decode(raw_token, expected_type=C.TOKEN_TYPE_REFRESH)
        tenant = tenant_for(request)
        self._validator.assert_tenant_binding(payload, tenant.pk)

        if is_denylisted(str(payload[C.CLAIM_JWT_ID])):
            raise TokenRevoked

        outcome = self._redeem(token_digest(raw_token), payload=payload, tenant=tenant)

        # Everything that reports a failure happens *after* the transaction
        # above has closed. Raising from inside it would roll back the very
        # writes the failure path depends on -- the audit row for an unknown
        # token, and, far worse, the whole family revocation that answers a
        # detected reuse. Both would be silently undone by the exception that
        # reports them.
        if outcome.failure != _Failure.NONE:
            metrics.record_refresh(result=str(outcome.failure))

        if outcome.failure == _Failure.UNKNOWN:
            audit.security_event(
                AuthEventType.REFRESH_UNKNOWN,
                request=request,
                detail={"jti": str(payload.get(C.CLAIM_JWT_ID, ""))},
            )
            raise TokenInvalid

        if outcome.failure == _Failure.REUSE and outcome.record is not None:
            self._handle_reuse(outcome.record, request)

        if outcome.failure == _Failure.EXPIRED:
            raise TokenExpired
        if outcome.failure == _Failure.INACTIVE:
            raise UserInactive
        if outcome.failure == _Failure.SUPERSEDED:
            raise TokenSuperseded
        if outcome.failure == _Failure.REVOKED:
            raise TokenRevoked

        if outcome.pair is None or outcome.record is None:  # pragma: no cover
            raise TokenInvalid

        metrics.record_refresh(result="success")
        audit.record(
            AuthEventType.TOKEN_REFRESHED,
            user=outcome.record.user,
            request=request,
            detail={
                "family": str(outcome.record.family_id),
                "generation": outcome.pair.generation,
            },
        )
        return outcome.pair

    # -- internals -----------------------------------------------------

    @transaction.atomic
    def _redeem(
        self, digest: str, *, payload: dict[str, Any], tenant: Tenant
    ) -> _Outcome:
        """Redeem the token if it is redeemable, reporting why if it is not.

        Returns rather than raises, so that a failure never unwinds this
        transaction. Note the one write that deliberately *does* commit on a
        failure path: stamping an overdue token EXPIRED.

        ``select_for_update`` serialises concurrent redemptions of the same
        token. Without it two parallel refreshes both observe ACTIVE, both
        rotate, and one login yields two live lineages -- which then look like
        reuse the moment either is redeemed again.
        """
        record = (
            RefreshToken.objects.select_for_update()
            .select_related("user", "family", "session")
            .filter(token_hash=digest)
            .first()
        )

        if record is None:
            # Correctly signed, correct tenant, no matching row: either a
            # pruned lineage or a token minted by a key this deployment no
            # longer has. Both are worth an event.
            return _Outcome(failure=_Failure.UNKNOWN)

        if record.status == TokenStatus.ROTATED:
            return _Outcome(failure=_Failure.REUSE, record=record)

        if record.status != TokenStatus.ACTIVE:
            return _Outcome(failure=_Failure.REVOKED, record=record)

        if record.expires_at <= timezone.now():
            record.status = TokenStatus.EXPIRED
            record.save(update_fields=["status", "updated_at"])
            return _Outcome(failure=_Failure.EXPIRED, record=record)

        if record.family.revoked_at is not None:
            return _Outcome(failure=_Failure.REVOKED, record=record)

        user = record.user
        if not user.is_active or user.deleted_at is not None:
            return _Outcome(failure=_Failure.INACTIVE, record=record)

        presented_version = payload.get(C.CLAIM_TOKEN_VERSION)
        if presented_version is not None and (
            int(presented_version) != user.token_version
        ):
            return _Outcome(failure=_Failure.SUPERSEDED, record=record)

        pair = issue_and_store(
            user=user,
            tenant=tenant,
            session=record.session,
            family=record.family,
            device_id=str(payload.get(C.CLAIM_DEVICE_ID, "")),
            generation=record.generation + 1,
        )

        # Marked ROTATED rather than deleted: the row is what makes the next
        # presentation of this value detectable as reuse.
        record.status = TokenStatus.ROTATED
        record.rotated_at = timezone.now()
        record.replaced_by = RefreshToken.objects.get(jti=pair.refresh_jti)
        record.save(update_fields=["status", "rotated_at", "replaced_by", "updated_at"])

        return _Outcome(pair=pair, record=record)

    def _handle_reuse(self, record: RefreshToken, request: AnyRequest) -> None:
        """A rotated token was presented again. Treat it as theft."""
        family = record.family

        metrics.record_reuse_detection()
        logger.critical(
            "refresh_token_reuse_detected",
            extra={
                "family": str(family.pk),
                "user": str(record.user_id),
                "schema": current_schema_name(),
                "generation": record.generation,
            },
        )

        # Its own transaction, which commits before the exception below is
        # raised. The revocation is the response to the incident; losing it to
        # the rollback of the request that detected it would leave the thief's
        # successor token live.
        with transaction.atomic():
            self._revocation.revoke_family(
                family.pk,
                reason=RevocationReason.REUSE_DETECTED,
                compromised=True,
            )

        audit.security_event(
            AuthEventType.REFRESH_REUSE_DETECTED,
            request=request,
            user=record.user,
            detail={"family": str(family.pk), "generation": record.generation},
        )

        raise TokenReuseDetected(
            _("Refresh token reuse detected. All sessions have been terminated.")
        )
