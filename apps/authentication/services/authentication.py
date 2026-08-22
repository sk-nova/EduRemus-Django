"""Credential verification and session establishment.

Every failure path returns the same message. Distinguishing "no such account"
from "wrong password" turns the login endpoint into an oracle for which
institution a person belongs to -- and on a per-tenant hostname, that is a
membership disclosure, not merely a username one.

Timing is held uniform for the same reason: an unknown address burns an
equivalent password hash so it cannot be identified by returning faster.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, NamedTuple

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import AuthenticationFailed

from apps.authentication import metrics
from apps.authentication.exceptions import AccountLocked
from apps.authentication.models import AuthEventType, LoginAttempt, TokenFamily
from apps.authentication.services import audit
from apps.authentication.services.issuing import issue_and_store, tenant_for
from apps.authentication.services.lockout import LockoutPolicy
from apps.authentication.services.sessions import DeviceSessionService
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
    from apps.tenants.models import Tenant

    type AnyRequest = HttpRequest | Request

logger = logging.getLogger("eduremus.auth")
UserModel = get_user_model()


class LoginResult(NamedTuple):
    """The issued pair plus the principal it was issued to.

    The user is returned rather than left for the caller to re-read: login
    runs unauthenticated, so there is no ``request.user``, and the alternative
    -- decoding the token that was just minted -- verifies a signature this
    process produced microseconds earlier.
    """

    user: User
    pair: TokenPair


# Hashed once at import so an unknown-email login costs the same as a
# wrong-password one. Calling check_password() against a random string instead
# would re-derive a hash on every failed attempt, which is the same work but
# paid per request.
_DUMMY_HASH = make_password("dummy-password-for-constant-time-comparison")

__all__ = ["AuthenticationService", "LoginResult"]


class AuthenticationService:
    """Verifies credentials and establishes a session in the active schema."""

    def __init__(self) -> None:
        self._lockout = LockoutPolicy()
        self._sessions = DeviceSessionService()

    def login(
        self,
        *,
        email: str,
        password: str,
        request: AnyRequest,
        device_name: str = "",
    ) -> LoginResult:
        """Exchange credentials for a token pair, or fail uniformly."""
        tenant = tenant_for(request)
        ip = client_ip(request)
        device_id = device_identifier(request)
        normalised = UserModel.objects.normalize_email(email)

        try:
            self._lockout.assert_not_locked(email=normalised, ip=ip)
        except AccountLocked:
            # Counted separately from a failure: a locked account is the
            # control working, and folding it into the failure ratio would
            # make a successful defence look like an incident.
            metrics.record_login(result="locked")
            raise

        user = self._resolve_user(normalised)

        if user is None or not check_password(password, user.password):
            self._record_failure(
                email=normalised,
                ip=ip,
                request=request,
                user=user,
                reason="bad_credentials",
            )
            raise self._rejection()

        if not user.is_active or user.deleted_at is not None:
            # Same response as a wrong password. A deactivated account must
            # not be distinguishable from one that never existed.
            self._record_failure(
                email=normalised,
                ip=ip,
                request=request,
                user=user,
                reason="inactive",
            )
            raise self._rejection()

        pair = self._establish_session(
            user=user,
            tenant=tenant,
            request=request,
            ip=ip,
            device_id=device_id,
            device_name=device_name,
        )
        metrics.record_login(result="success")
        return LoginResult(user=user, pair=pair)

    # -- internals -----------------------------------------------------

    def _resolve_user(self, email: str) -> User | None:
        """Look the account up, burning an equivalent hash when absent.

        Reads through ``objects``, which hides soft-deleted rows. A deleted
        account therefore takes the same path as an unknown address, including
        the dummy hash.
        """
        try:
            return UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            check_password("placeholder", _DUMMY_HASH)
            return None

    @transaction.atomic
    def _establish_session(
        self,
        *,
        user: User,
        tenant: Tenant,
        request: AnyRequest,
        ip: str | None,
        device_id: str,
        device_name: str,
    ) -> TokenPair:
        session = self._sessions.open(
            user=user,
            device_id=device_id,
            device_name=device_name,
            user_agent=user_agent(request),
            ip_address=ip,
        )
        family = TokenFamily.objects.create(user=user, session=session)

        LoginAttempt.objects.create(
            email=user.email,
            user=user,
            successful=True,
            ip_address=ip,
            user_agent=user_agent(request),
        )
        # Queryset update rather than user.save(): last_login is metadata and
        # writing it through the instance would also rewrite every other
        # column loaded a moment ago.
        UserModel.all_objects.filter(pk=user.pk).update(last_login=timezone.now())

        audit.record(
            AuthEventType.LOGIN_SUCCEEDED,
            user=user,
            request=request,
            detail={"session_id": str(session.pk), "device_id": device_id},
        )

        pair = issue_and_store(
            user=user,
            tenant=tenant,
            session=session,
            family=family,
            device_id=device_id,
            auth_methods=["pwd"],
        )

        # Only after everything above has succeeded. Clearing earlier would
        # let a failure between the check and the commit reset an attacker's
        # counter for free.
        transaction.on_commit(lambda: self._lockout.clear(email=user.email, ip=ip))
        return pair

    def _record_failure(
        self,
        *,
        email: str,
        ip: str | None,
        request: AnyRequest,
        user: User | None = None,
        reason: str = "",
    ) -> None:
        LoginAttempt.objects.create(
            email=email,
            user=user,
            successful=False,
            ip_address=ip,
            user_agent=user_agent(request),
            failure_reason=reason,
        )
        metrics.record_login(result="failure")
        audit.record(
            AuthEventType.LOGIN_FAILED,
            user=user,
            request=request,
            # The reason is recorded for operators and never returned to the
            # client -- that asymmetry is the point.
            detail={"email": email, "reason": reason},
        )

        if self._lockout.register_failure(email=email, ip=ip):
            # Emitted once, by the attempt that trips the lock. Every later
            # attempt is refused before reaching here.
            metrics.record_lockout()
            audit.record(
                AuthEventType.ACCOUNT_LOCKED,
                user=user,
                request=request,
                detail={"email": email, "reason": reason},
            )

    @staticmethod
    def _rejection() -> AuthenticationFailed:
        return AuthenticationFailed(
            _("Invalid credentials."), code="authentication_failed"
        )
