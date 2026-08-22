"""Rotation, reuse detection, and the family teardown that answers it.

Rotation is the mechanism that makes a stolen refresh token usable at most
once. Reuse detection is what turns "used twice" into an incident: whoever
presents a rotated token second reveals that two parties hold the lineage, and
since there is no way to tell which is legitimate, both are signed out.

The replay tests here go through the endpoint rather than the service, because
the cookie handling and the CSRF check are part of the control -- a rotation
that is correct but unreachable proves nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from django.conf import settings
from django.test import Client as HttpClient
from django.utils import timezone
from freezegun import freeze_time

from apps.authentication.models import (
    AuthAuditEvent,
    AuthEventType,
    RefreshToken,
    TokenStatus,
)
from apps.tenants.utils import tenant_context

from .conftest import ACME_HOST

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant

REFRESH = "/api/v1/auth/refresh/"
REFRESH_COOKIE = "__Host-eduremus_refresh"
CSRF_COOKIE = "eduremus_csrf"


def rotate(
    client: HttpClient, *, csrf: str | None = None, host: str = ACME_HOST
) -> Any:
    """Present whatever cookies the client holds, with a matching header."""
    if csrf is None:
        cookie = client.cookies.get(CSRF_COOKIE)
        csrf = cookie.value if cookie else ""
    return client.post(REFRESH, HTTP_HOST=host, headers={"X-CSRF-Token": csrf})


def present(client: HttpClient, refresh_token: str, *, csrf: str = "held-value") -> Any:
    """Rotate using a specific refresh token, as a holder of it would.

    Both cookies are set together because the CSRF value rotates *with* the
    refresh token: double submit proves the caller can read a cookie from this
    origin, and says nothing about freshness. A replayer holding an old
    refresh token holds the CSRF value that came with it.
    """
    client.cookies[REFRESH_COOKIE] = refresh_token
    client.cookies[CSRF_COOKIE] = csrf
    return client.post(REFRESH, HTTP_HOST=ACME_HOST, headers={"X-CSRF-Token": csrf})


@pytest.mark.django_db
class TestRotation:
    def test_it_returns_a_new_access_token(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        first = login(api_client).json()["access_token"]

        response = rotate(api_client)

        assert response.status_code == 200
        assert response.json()["access_token"] != first

    def test_it_replaces_the_refresh_cookie(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        original = login(api_client).cookies[REFRESH_COOKIE].value

        rotated = rotate(api_client).cookies[REFRESH_COOKIE].value

        assert rotated != original

    def test_it_rotates_the_csrf_value_too(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """A value captured from an earlier response must not survive to the
        next rotation."""
        original = login(api_client).cookies[CSRF_COOKIE].value

        assert rotate(api_client).cookies[CSRF_COOKIE].value != original

    def test_the_presented_token_is_marked_rotated_and_linked(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """The row is kept, not deleted: it is what makes reuse detectable."""
        login(api_client)

        rotate(api_client)

        with tenant_context(acme):
            first = RefreshToken.objects.get(generation=1)
            second = RefreshToken.objects.get(generation=2)

        assert first.status == TokenStatus.ROTATED
        assert first.rotated_at is not None
        assert first.replaced_by_id == second.pk
        assert second.status == TokenStatus.ACTIVE

    def test_the_session_survives_rotation(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """``sid`` is stable while ``jti`` changes -- that is what makes "sign
        out my other device" mean anything to a user."""
        login(api_client)

        rotate(api_client)

        with tenant_context(acme):
            sessions = {token.session_id for token in RefreshToken.objects.all()}
            families = {token.family_id for token in RefreshToken.objects.all()}

        assert len(sessions) == 1
        assert len(families) == 1

    def test_rotation_is_audited(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        login(api_client)

        rotate(api_client)

        with tenant_context(acme):
            event = AuthAuditEvent.objects.get(event_type=AuthEventType.TOKEN_REFRESHED)

        assert event.detail["generation"] == 2

    def test_the_new_token_reflects_a_role_change(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        grant_role: Callable[..., None],
    ) -> None:
        """Roles are re-read on every rotation rather than carried forward.

        That is what bounds the staleness of a permission change to one
        access-token lifetime instead of the refresh token's seven days.
        """
        assert "grades:write" not in login(api_client).json()["scope"]

        grant_role(acme_user, "faculty", tenant=acme)

        assert "grades:write" in rotate(api_client).json()["scope"]


@pytest.mark.django_db
class TestReuseDetection:
    def test_replaying_a_rotated_token_is_detected(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        original = login(api_client).cookies[REFRESH_COOKIE].value
        rotate(api_client)

        response = present(api_client, original)

        assert response.status_code == 401
        assert response.json()["error"] == "token_reuse_detected"

    def test_reuse_revokes_the_entire_family(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """Two holders, no way to tell which is legitimate: both are ended.

        Revoking only the replayed generation would leave the thief holding a
        valid successor whenever they redeemed first.
        """
        original = login(api_client).cookies[REFRESH_COOKIE].value
        successor = rotate(api_client).cookies[REFRESH_COOKIE].value

        present(api_client, original)

        response = present(api_client, successor)

        assert response.status_code == 401
        with tenant_context(acme):
            assert not RefreshToken.objects.active().exists()

    def test_the_family_is_marked_compromised_not_merely_revoked(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """The forensic record has to distinguish a teardown from a logout."""
        original = login(api_client).cookies[REFRESH_COOKIE].value
        rotate(api_client)

        present(api_client, original)

        with tenant_context(acme):
            assert RefreshToken.objects.compromised().exists()

    def test_reuse_is_recorded_as_a_critical_event(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        original = login(api_client).cookies[REFRESH_COOKIE].value
        rotate(api_client)

        present(api_client, original)

        with tenant_context(acme):
            event = AuthAuditEvent.objects.get(
                event_type=AuthEventType.REFRESH_REUSE_DETECTED
            )

        assert event.severity == "critical"
        assert event.detail["generation"] == 1

    def test_the_revocation_survives_the_rejection(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """The teardown commits in its own transaction before the 401 is
        raised. Rolled back with the failing request, the thief would keep a
        live successor and the detection would achieve nothing."""
        original = login(api_client).cookies[REFRESH_COOKIE].value
        rotate(api_client)

        present(api_client, original)

        with tenant_context(acme):
            assert RefreshToken.objects.filter(status=TokenStatus.COMPROMISED).count()
            assert not RefreshToken.objects.active().exists()

    def test_an_unknown_but_well_signed_token_is_reported(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
    ) -> None:
        """Correct signature, correct tenant, no row: a pruned lineage or a
        token minted by a key this deployment no longer has. Worth an event."""
        pair = issue_pair(user=acme_user, tenant=acme)
        with tenant_context(acme):
            RefreshToken.objects.all().delete()

        response = present(api_client, pair.refresh_token)

        assert response.status_code == 401
        with tenant_context(acme):
            assert AuthAuditEvent.objects.filter(
                event_type=AuthEventType.REFRESH_UNKNOWN
            ).exists()


@pytest.mark.django_db
class TestRefreshRejections:
    def test_a_missing_cookie_is_not_authenticated(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        api_client.cookies[CSRF_COOKIE] = "value"

        response = rotate(api_client, csrf="value")

        assert response.status_code == 401

    def test_a_missing_csrf_header_is_refused(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """The cookie is attached automatically, which makes this the one
        endpoint CSRF can actually reach."""
        login(api_client)

        response = rotate(api_client, csrf="")

        assert response.status_code == 403
        assert response.json()["error"] == "csrf_failed"

    def test_a_mismatched_csrf_header_is_refused(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        login(api_client)

        response = rotate(api_client, csrf="not-the-cookie-value")

        assert response.status_code == 403

    def test_a_failed_rotation_clears_the_cookies(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """A rejected refresh token will never work again, so leaving it in
        place produces a client that retries a dead credential until the
        throttle turns it into a 429."""
        original = login(api_client).cookies[REFRESH_COOKIE].value
        rotate(api_client)

        response = present(api_client, original)

        assert response.cookies[REFRESH_COOKIE].value == ""

    def test_an_expired_refresh_token_is_refused(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        with freeze_time(timezone.now()) as frozen:
            login(api_client)
            frozen.tick(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"] + timedelta(1))

            response = rotate(api_client)

        assert response.status_code == 401
        assert response.json()["error"] == "token_expired"

    def test_a_revoked_family_cannot_rotate(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        login(api_client)
        with tenant_context(acme):
            token = RefreshToken.objects.get()
            token.family.revoked_at = timezone.now()
            token.family.save(update_fields=["revoked_at"])

        response = rotate(api_client)

        assert response.status_code == 401
        assert response.json()["error"] == "token_revoked"

    def test_revoking_a_user_stops_rotation(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """Revocation reaches the refresh path through the row, not ``jtv``.

        A refresh token deliberately carries no ``jtv`` -- it carries no
        authorisation data at all, so there is nothing for a version to
        invalidate. What stops it is the durable ``RefreshToken`` row, which
        ``revoke_all_for_user`` marks alongside the ``token_version`` bump
        that kills the access tokens. Bumping the version alone would *not*
        stop a rotation, which is exactly why the two are one operation.
        """
        from apps.authentication.models import RevocationReason
        from apps.authentication.services.revocation import RevocationService

        login(api_client)

        with tenant_context(acme):
            RevocationService().revoke_all_for_user(
                acme_user, reason=RevocationReason.LOGOUT_ALL
            )

        response = rotate(api_client)

        assert response.status_code == 401
        assert response.json()["error"] == "token_revoked"

    def test_a_deactivated_user_cannot_rotate(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        login(api_client)
        with tenant_context(acme):
            type(acme_user).all_objects.filter(pk=acme_user.pk).update(is_active=False)

        response = rotate(api_client)

        assert response.status_code == 401
        assert response.json()["error"] == "user_inactive"

    def test_a_row_past_its_expiry_is_stamped_and_refused(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """The row expires independently of the token's own ``exp``.

        They normally agree, and the row is the authority: a lineage whose
        absolute deadline has passed must not rotate even if a signature is
        still technically valid. The status write commits on this failure
        path deliberately, so the row stops being redeemable rather than
        being re-evaluated on every attempt.
        """
        login(api_client)
        with tenant_context(acme):
            token = RefreshToken.objects.get()
            RefreshToken.objects.filter(pk=token.pk).update(
                issued_at=timezone.now() - timedelta(days=8),
                expires_at=timezone.now() - timedelta(minutes=1),
            )

        response = rotate(api_client)

        assert response.status_code == 401
        assert response.json()["error"] == "token_expired"
        with tenant_context(acme):
            assert RefreshToken.objects.get().status == TokenStatus.EXPIRED

    def test_a_refresh_token_carrying_a_stale_version_is_superseded(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
    ) -> None:
        """A refresh token carries no ``jtv`` today, and the guard that would
        read one is still checked.

        Kept because the claim set is versioned and may gain the claim: a
        guard that is only exercised by the claim it defends against is a
        guard nobody notices has stopped working.
        """
        import jwt

        from apps.authentication.tokens import claims as C
        from apps.authentication.utils.hashing import token_digest

        private_pem, _public = rsa_keypair
        pair = issue_pair(user=acme_user, tenant=acme)
        claims = jwt.decode(pair.refresh_token, options={"verify_signature": False})
        claims[C.CLAIM_TOKEN_VERSION] = 99
        forged = jwt.encode(
            claims, private_pem, algorithm="RS256", headers={"kid": "test-key"}
        )

        with tenant_context(acme):
            # Point the stored row at the re-signed value, so the lookup finds
            # it and the version check is what decides the outcome.
            RefreshToken.objects.filter(jti=pair.refresh_jti).update(
                token_hash=token_digest(forged)
            )

        response = present(api_client, forged)

        assert response.status_code == 401
        assert response.json()["error"] == "token_superseded"

    def test_an_access_token_cannot_be_presented_as_a_refresh_token(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        body = login(api_client)
        api_client.cookies[REFRESH_COOKIE] = body.json()["access_token"]

        response = rotate(api_client)

        assert response.status_code == 401
        assert response.json()["error"] == "token_invalid_audience"
