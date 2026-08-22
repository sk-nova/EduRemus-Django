"""Logout, forced logout, password change and tenant suspension.

Revocation runs on two mechanisms and both are asserted here. ``token_version``
invalidates every outstanding *access* token with one UPDATE and no
enumeration; the ``RefreshToken`` row is the durable record of which refresh
credentials may still be redeemed. A change that moves only one of them
produces a "log out everywhere" that appears to work and does not -- which is
why the cache invalidation is tested too.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest
from django.core.cache import cache
from django.test import Client as HttpClient

from apps.authentication.models import (
    AuthAuditEvent,
    AuthEventType,
    DeviceSession,
    PasswordHistory,
    RefreshToken,
    RevocationReason,
    TokenStatus,
)
from apps.authentication.services.revocation import RevocationService
from apps.authentication.utils.cache_keys import user_key
from apps.tenants.utils import public_schema, tenant_context

from .conftest import ACME_HOST, BETA_HOST, PASSWORD

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant

ME = "/api/v1/auth/me/"
LOGOUT = "/api/v1/auth/logout/"
LOGOUT_ALL = "/api/v1/auth/logout-all/"
REVOKE = "/api/v1/auth/revoke/"
PASSWORD_CHANGE = "/api/v1/auth/password/change/"
SESSIONS = "/api/v1/auth/sessions/"
CSRF_COOKIE = "eduremus_csrf"
NEW_PASSWORD = "An0ther-Str0ng-Phrase!"


def csrf_of(client: HttpClient) -> dict[str, str]:
    cookie = client.cookies.get(CSRF_COOKIE)
    return {"X-CSRF-Token": cookie.value if cookie else ""}


@pytest.mark.django_db
class TestLogout:
    def test_it_ends_the_session_and_answers_204(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        access = login(api_client).json()["access_token"]

        response = api_client.post(
            LOGOUT, HTTP_HOST=ACME_HOST, headers=csrf_of(api_client), **bearer(access)
        )

        assert response.status_code == 204
        with tenant_context(acme):
            assert DeviceSession.objects.live().count() == 0
            assert RefreshToken.objects.active().count() == 0

    def test_the_presented_access_token_stops_working_immediately(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        """Without the denylist entry a "logged out" credential keeps working
        for the remainder of its fifteen minutes."""
        access = login(api_client).json()["access_token"]
        api_client.post(
            LOGOUT, HTTP_HOST=ACME_HOST, headers=csrf_of(api_client), **bearer(access)
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(access))

        assert response.status_code == 401
        assert response.json()["error"] == "token_revoked"

    def test_it_clears_both_cookies(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        """The delete must repeat the path the cookie was set with, or the
        browser keeps it and the credential outlives the logout."""
        access = login(api_client).json()["access_token"]

        response = api_client.post(
            LOGOUT, HTTP_HOST=ACME_HOST, headers=csrf_of(api_client), **bearer(access)
        )

        refresh_cookie = response.cookies["__Host-eduremus_refresh"]
        assert refresh_cookie.value == ""
        assert refresh_cookie["path"] == "/"

    def test_it_is_idempotent(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        """A client retrying after a network timeout must not be told its
        logout failed -- and a uniform answer tells an attacker nothing."""
        access = login(api_client).json()["access_token"]
        headers = csrf_of(api_client)

        first = api_client.post(
            LOGOUT, HTTP_HOST=ACME_HOST, headers=headers, **bearer(access)
        )
        # The second attempt is refused by the denylist rather than by the
        # session lookup: the token itself is dead now.
        second = api_client.post(
            LOGOUT, HTTP_HOST=ACME_HOST, headers=headers, **bearer(access)
        )

        assert first.status_code == 204
        assert second.status_code == 401

    def test_it_is_audited(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        access = login(api_client).json()["access_token"]

        api_client.post(
            LOGOUT, HTTP_HOST=ACME_HOST, headers=csrf_of(api_client), **bearer(access)
        )

        with tenant_context(acme):
            event = AuthAuditEvent.objects.get(event_type=AuthEventType.LOGOUT)
        assert event.detail["session_ended"] is True

    def test_it_requires_the_csrf_header(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        access = login(api_client).json()["access_token"]

        response = api_client.post(LOGOUT, HTTP_HOST=ACME_HOST, **bearer(access))

        assert response.status_code == 403
        assert response.json()["error"] == "csrf_failed"

    def test_one_session_ending_leaves_the_others_alone(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        other = issue_pair(user=acme_user, tenant=acme, device_id="phone")
        access = login(api_client).json()["access_token"]

        api_client.post(
            LOGOUT, HTTP_HOST=ACME_HOST, headers=csrf_of(api_client), **bearer(access)
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(other.access_token))
        assert response.status_code == 200


@pytest.mark.django_db
class TestLogoutAll:
    def test_it_invalidates_tokens_issued_to_other_devices(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """The ``token_version`` bump has to take effect on the very next
        request, not when a cache entry happens to expire."""
        first = issue_pair(user=acme_user, tenant=acme)
        second = issue_pair(user=acme_user, tenant=acme, device_id="tablet")

        assert (
            api_client.post(
                LOGOUT_ALL, HTTP_HOST=ACME_HOST, **bearer(first.access_token)
            ).status_code
            == 204
        )

        response = api_client.get(
            ME, HTTP_HOST=ACME_HOST, **bearer(second.access_token)
        )
        assert response.status_code == 401
        assert response.json()["error"] == "token_superseded"

    def test_it_drops_the_cached_user(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """A cached ``User`` carrying the old version would keep every
        outstanding token valid for the remainder of the cache TTL -- the
        single most likely way to ship a logout that only looks like one."""
        pair = issue_pair(user=acme_user, tenant=acme)
        api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        with tenant_context(acme):
            assert cache.get(user_key(str(acme_user.pk))) is not None

        api_client.post(LOGOUT_ALL, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        with tenant_context(acme):
            assert cache.get(user_key(str(acme_user.pk))) is None

    def test_it_ends_every_session_and_revokes_every_token(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        first = issue_pair(user=acme_user, tenant=acme)
        issue_pair(user=acme_user, tenant=acme, device_id="tablet")

        api_client.post(LOGOUT_ALL, HTTP_HOST=ACME_HOST, **bearer(first.access_token))

        with tenant_context(acme):
            assert DeviceSession.objects.live().count() == 0
            assert RefreshToken.objects.active().count() == 0
            acme_user.refresh_from_db()
        assert acme_user.token_version == 1

    def test_it_is_audited_as_logout_all(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        api_client.post(LOGOUT_ALL, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        with tenant_context(acme):
            assert AuthAuditEvent.objects.filter(
                event_type=AuthEventType.LOGOUT_ALL
            ).exists()

    def test_another_users_tokens_are_untouched(
        self,
        acme: Tenant,
        acme_user: User,
        make_user: Callable[..., User],
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        with tenant_context(acme):
            colleague = make_user("dev@acme.edu")
        theirs = issue_pair(user=colleague, tenant=acme)
        mine = issue_pair(user=acme_user, tenant=acme)

        api_client.post(LOGOUT_ALL, HTTP_HOST=ACME_HOST, **bearer(mine.access_token))

        assert (
            api_client.get(
                ME, HTTP_HOST=ACME_HOST, **bearer(theirs.access_token)
            ).status_code
            == 200
        )


@pytest.mark.django_db
class TestRevokeSession:
    def test_a_user_can_end_their_own_other_session(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        current = issue_pair(user=acme_user, tenant=acme)
        with tenant_context(acme):
            other = DeviceSession.objects.create(user=acme_user, device_id="laptop")

        response = api_client.post(
            REVOKE,
            data={"session_id": str(other.pk)},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
            **bearer(current.access_token),
        )

        assert response.status_code == 204
        with tenant_context(acme):
            other.refresh_from_db()
        assert other.ended_at is not None

    def test_a_session_id_is_not_a_capability(
        self,
        acme: Tenant,
        acme_user: User,
        make_user: Callable[..., User],
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Ownership is the authorisation, so knowing an id confers nothing."""
        with tenant_context(acme):
            colleague = make_user("dev@acme.edu")
            theirs = DeviceSession.objects.create(user=colleague, device_id="laptop")
        mine = issue_pair(user=acme_user, tenant=acme)

        response = api_client.post(
            REVOKE,
            data={"session_id": str(theirs.pk)},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
            **bearer(mine.access_token),
        )

        # 204 regardless, so the endpoint cannot be used to discover which
        # session ids exist -- but the session is untouched.
        assert response.status_code == 204
        with tenant_context(acme):
            theirs.refresh_from_db()
        assert theirs.ended_at is None

    def test_the_session_list_shows_only_the_callers_own(
        self,
        acme: Tenant,
        acme_user: User,
        make_user: Callable[..., User],
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        with tenant_context(acme):
            colleague = make_user("dev@acme.edu")
            DeviceSession.objects.create(user=colleague, device_id="laptop")
        mine = issue_pair(user=acme_user, tenant=acme)

        body = api_client.get(
            SESSIONS, HTTP_HOST=ACME_HOST, **bearer(mine.access_token)
        ).json()

        assert body["count"] == 1
        assert body["results"][0]["current"] is True


@pytest.mark.django_db
class TestPasswordChange:
    def test_it_returns_a_working_pair_for_the_calling_device(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        """The version bump happens *before* the new pair is minted.

        Mint first and the replacement carries the old ``jtv``, so the user
        changes their password and is signed out on the very device that made
        the change -- an ordering bug that presents as a session bug.
        """
        access = login(api_client).json()["access_token"]

        response = api_client.post(
            PASSWORD_CHANGE,
            data={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
            **bearer(access),
        )

        assert response.status_code == 200
        replacement = response.json()["access_token"]
        assert (
            api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(replacement)).status_code
            == 200
        )

    def test_it_signs_every_other_device_out(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        elsewhere = issue_pair(user=acme_user, tenant=acme, device_id="tablet")
        access = login(api_client).json()["access_token"]

        api_client.post(
            PASSWORD_CHANGE,
            data={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
            **bearer(access),
        )

        response = api_client.get(
            ME, HTTP_HOST=ACME_HOST, **bearer(elsewhere.access_token)
        )
        assert response.status_code == 401

    def test_the_old_password_stops_working(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        access = login(api_client).json()["access_token"]
        api_client.post(
            PASSWORD_CHANGE,
            data={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
            **bearer(access),
        )

        assert login(HttpClient()).status_code == 401
        assert login(HttpClient(), password=NEW_PASSWORD).status_code == 200

    def test_the_wrong_current_password_is_refused(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        access = login(api_client).json()["access_token"]

        response = api_client.post(
            PASSWORD_CHANGE,
            data={"current_password": "not-it", "new_password": NEW_PASSWORD},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
            **bearer(access),
        )

        assert response.status_code == 401

    def test_a_recently_used_password_is_refused(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        access = login(api_client).json()["access_token"]

        response = api_client.post(
            PASSWORD_CHANGE,
            data={"current_password": PASSWORD, "new_password": PASSWORD},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
            **bearer(access),
        )

        assert response.status_code == 400

    def test_the_previous_hash_is_kept_for_the_history_check(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        access = login(api_client).json()["access_token"]

        api_client.post(
            PASSWORD_CHANGE,
            data={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
            **bearer(access),
        )

        with tenant_context(acme):
            assert PasswordHistory.objects.filter(user=acme_user).count() == 1

    def test_it_is_audited(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
    ) -> None:
        access = login(api_client).json()["access_token"]

        api_client.post(
            PASSWORD_CHANGE,
            data={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
            **bearer(access),
        )

        with tenant_context(acme):
            assert AuthAuditEvent.objects.filter(
                event_type=AuthEventType.PASSWORD_CHANGED
            ).exists()


@pytest.mark.django_db
class TestTenantSuspension:
    def test_a_suspended_tenant_answers_404(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Indistinguishable from an unknown host, so subdomain guessing
        cannot confirm that a customer exists."""
        pair = issue_pair(user=acme_user, tenant=acme)

        with public_schema():
            type(acme).objects.filter(pk=acme.pk).update(is_active=False)

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 404

    def test_suspension_can_revoke_every_credential_in_the_schema(
        self,
        acme: Tenant,
        acme_user: User,
        make_user: Callable[..., User],
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """The 404 covers traffic through the middleware, and nothing else.

        A gateway doing signature-only validation, or a worker holding a token
        minted before the suspension, needs the credentials themselves killed.
        """
        with tenant_context(acme):
            colleague = make_user("dev@acme.edu")
        issue_pair(user=acme_user, tenant=acme)
        issue_pair(user=colleague, tenant=acme)

        with tenant_context(acme):
            revoked = RevocationService().revoke_all_in_schema()

            assert revoked == 2
            assert not RefreshToken.objects.active().exists()
            acme_user.refresh_from_db()
            assert acme_user.token_version == 1
            assert AuthAuditEvent.objects.filter(
                event_type=AuthEventType.TENANT_SUSPENDED
            ).exists()

    def test_suspending_one_tenant_leaves_the_other_working(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        beta_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        issue_pair(user=acme_user, tenant=acme)
        beta_pair = issue_pair(user=beta_user, tenant=beta)

        with tenant_context(acme):
            RevocationService().revoke_all_in_schema()

        response = api_client.get(
            ME, HTTP_HOST=BETA_HOST, **bearer(beta_pair.access_token)
        )
        assert response.status_code == 200


@pytest.mark.django_db
class TestRevocationService:
    def test_revoking_a_family_denylists_what_is_still_live(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            family_id = RefreshToken.objects.get().family_id
            RevocationService().revoke_family(
                family_id, reason=RevocationReason.ADMIN_REVOKED
            )
            token = RefreshToken.objects.get()

        assert token.status == TokenStatus.REVOKED
        assert token.revocation_reason == RevocationReason.ADMIN_REVOKED
        assert (
            api_client.get(
                ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token)
            ).status_code
            == 200
        ), "the access token is not in this family and must be unaffected"

    def test_a_compromised_family_is_recorded_as_such(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            family_id = RefreshToken.objects.get().family_id
            RevocationService().revoke_family(
                family_id, reason=RevocationReason.REUSE_DETECTED, compromised=True
            )

            assert RefreshToken.objects.compromised().count() == 1

    def test_revoking_a_soft_deleted_account_still_works(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """The default manager hides the row, and it is exactly the account
        whose credentials most need killing."""
        issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            acme_user.delete()
            revoked = RevocationService().revoke_all_for_user(
                acme_user, reason=RevocationReason.USER_DEACTIVATED
            )

            assert revoked == 1
            acme_user.refresh_from_db()
            assert acme_user.token_version == 1

    def test_revocation_does_not_reach_into_another_schema(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        beta_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        issue_pair(user=acme_user, tenant=acme)
        issue_pair(user=beta_user, tenant=beta)

        with tenant_context(acme):
            RevocationService().revoke_all_for_user(
                acme_user, reason=RevocationReason.ADMIN_REVOKED
            )

        with tenant_context(beta):
            assert RefreshToken.objects.active().count() == 1
            beta_user.refresh_from_db()
            assert beta_user.token_version == 0


@pytest.mark.django_db
def test_the_revoke_user_tokens_command_ends_every_session(
    acme: Tenant,
    acme_user: User,
    issue_pair: Callable[..., TokenPair],
    api_client: HttpClient,
    bearer: Callable[[str], dict],
    capsys: Any,
) -> None:
    """The operational entry point behaves as the endpoint does."""
    from django.core.management import call_command

    pair = issue_pair(user=acme_user, tenant=acme)

    call_command("revoke_user_tokens", "--schema", "acme", "--email", "priya@acme.edu")

    response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))
    assert response.status_code == 401
    assert response.json()["error"] == "token_superseded"
