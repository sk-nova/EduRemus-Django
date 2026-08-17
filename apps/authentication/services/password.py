"""Password change, history and the revocation that follows it.

The ordering in :meth:`PasswordService.change` is load-bearing and easy to get
wrong. The version bump must happen **before** the replacement pair is minted.
Mint first and the new token carries the old ``jtv``, which the bump then
invalidates -- the user changes their password and is signed out instantly, on
the device that made the change. It looks like a session bug and is really an
ordering one.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import AuthenticationFailed, ValidationError

from apps.authentication.exceptions import PasswordReused
from apps.authentication.models import (
    AuthEventType,
    DeviceSession,
    PasswordHistory,
    RevocationReason,
    TokenFamily,
)
from apps.authentication.services import audit
from apps.authentication.services.issuing import issue_and_store, tenant_for
from apps.authentication.services.revocation import RevocationService
from apps.authentication.utils.request_meta import (
    client_ip,
    device_identifier,
    user_agent,
)

if TYPE_CHECKING:
    from django.http import HttpRequest
    from rest_framework.request import Request

    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair

    type AnyRequest = HttpRequest | Request

logger = logging.getLogger("eduremus.auth")

__all__ = ["PasswordService"]


class PasswordService:
    """Changes a password and re-establishes only the calling device."""

    def __init__(self) -> None:
        self._revocation = RevocationService()

    def change(
        self,
        *,
        user: User,
        current_password: str,
        new_password: str,
        request: AnyRequest,
    ) -> TokenPair:
        """Verify, replace, revoke everywhere, then re-issue for this device.

        Returns a fresh pair so the device that made the change stays signed
        in. Every other device is logged out -- the behaviour users expect,
        and the correct one if the change was prompted by suspected
        compromise.
        """
        if not check_password(current_password, user.password):
            audit.record(
                AuthEventType.LOGIN_FAILED,
                user=user,
                request=request,
                detail={"reason": "password_change_bad_current"},
            )
            raise AuthenticationFailed(
                _("Current password is incorrect."), code="authentication_failed"
            )

        self._validate(new_password, user)

        tenant = tenant_for(request)
        previous_hash = user.password

        with transaction.atomic():
            user.set_password(new_password)
            user.save(update_fields=["password", "updated_at"])

            PasswordHistory.objects.create(user=user, password_hash=previous_hash)
            self._trim_history(user)

            # Bump first. Everything minted after this point carries the new
            # version; everything minted before is now invalid.
            self._revocation.revoke_all_for_user(
                user,
                reason=RevocationReason.PASSWORD_CHANGED,
                request=request,
                event=AuthEventType.PASSWORD_CHANGED,
            )

            # Re-read so the in-memory instance carries the incremented
            # token_version -- the UPDATE above went round the instance.
            user.refresh_from_db(fields=["token_version"])

            device_id = device_identifier(request)
            session = DeviceSession.objects.create(
                user=user,
                device_id=device_id,
                user_agent=user_agent(request),
                ip_address=client_ip(request),
            )
            family = TokenFamily.objects.create(user=user, session=session)

            pair = issue_and_store(
                user=user,
                tenant=tenant,
                session=session,
                family=family,
                device_id=device_id,
                auth_methods=["pwd"],
            )

        return pair

    # -- internals -----------------------------------------------------

    @staticmethod
    def _validate(new_password: str, user: User) -> None:
        """Run the configured validators, mapping reuse to its own code."""
        try:
            validate_password(new_password, user)
        except DjangoValidationError as exc:
            # Reuse gets its own 400 code so a client can say "pick a
            # different one" rather than repeating a generic policy message.
            if "password_reused" in _codes(exc):
                raise PasswordReused from exc
            raise ValidationError({"new_password": list(exc.messages)}) from exc

    @staticmethod
    def _trim_history(user: User) -> None:
        """Keep only the configured number of previous hashes.

        Bounded on write rather than swept on a schedule: the table would
        otherwise grow without limit for an account that changes its password
        often, and only the most recent entries are ever consulted.
        """
        depth = int(settings.JWT_AUTH["PASSWORD_HISTORY_DEPTH"])
        keep = list(
            PasswordHistory.objects.filter(user=user)
            .order_by("-created_at")
            .values_list("pk", flat=True)[:depth]
        )
        PasswordHistory.objects.filter(user=user).exclude(pk__in=keep).delete()


def _codes(exc: DjangoValidationError) -> tuple[str, ...]:
    return tuple(error.code for error in exc.error_list if error.code)
