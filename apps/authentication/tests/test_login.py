"""Login: what it returns, what it records, and what it refuses to reveal.

The uniformity assertions are the ones with teeth. On a per-tenant hostname,
telling a caller that an address is unknown discloses that the person is not a
member of *that institution* -- which is a membership disclosure rather than
merely a username one, and it is why every failure path here returns the same
code, the same message and the same status.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest
from django.conf import settings
from django.test import Client as HttpClient

from apps.authentication.models import (
    AuthAuditEvent,
    AuthEventType,
    DeviceSession,
    LoginAttempt,
    RefreshToken,
    TokenFamily,
)
from apps.tenants.utils import tenant_context

from .conftest import ACME_HOST, BETA_HOST, PASSWORD

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.tenants.models import Tenant

LOGIN = "/api/v1/auth/login/"
REFRESH_COOKIE = "__Host-eduremus_refresh"
CSRF_COOKIE = "eduremus_csrf"


@pytest.mark.django_db
class TestSuccessfulLogin:
    def test_it_returns_an_access_token_and_its_metadata(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        response = login(api_client)

        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 15 * 60
        assert body["access_token"].count(".") == 2

    def test_it_describes_the_principal_and_the_tenant(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        body = login(api_client).json()

        assert body["user"]["email"] == "priya@acme.edu"
        assert body["user"]["name"] == "Priya Nair"
        assert body["tenant"]["slug"] == "acme"

    def test_the_refresh_token_never_appears_in_the_body(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """It travels in the HttpOnly cookie, so no script context holds it.

        Putting it in the body "for convenience" defeats the cookie entirely.
        """
        response = login(api_client)

        assert "refresh_token" not in response.json()
        assert "refresh" not in response.content.decode().lower().replace(
            "refresh_expires", ""
        )

    def test_the_refresh_cookie_is_set_with_the_protective_attributes(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        cookie = login(api_client).cookies[REFRESH_COOKIE]

        assert cookie["httponly"] is True
        assert cookie["secure"] is True
        assert cookie["samesite"] == "Strict"
        # __Host- requires Path=/; a browser silently drops the cookie if the
        # prefix and the path disagree, and the endpoint then sees nothing.
        assert cookie["path"] == "/"
        assert cookie["domain"] == ""

    def test_the_csrf_cookie_is_readable_by_script(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """Echoing it back in a header is the entire double-submit mechanism."""
        cookie = login(api_client).cookies[CSRF_COOKIE]

        assert cookie["httponly"] == ""
        assert cookie["secure"] is True

    def test_it_records_the_attempt_the_session_and_the_family(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        login(api_client)

        with tenant_context(acme):
            assert LoginAttempt.objects.filter(successful=True).count() == 1
            assert DeviceSession.objects.live().count() == 1
            assert TokenFamily.objects.count() == 1
            assert RefreshToken.objects.active().count() == 1

    def test_it_audits_the_success(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        login(api_client)

        with tenant_context(acme):
            event = AuthAuditEvent.objects.get(event_type=AuthEventType.LOGIN_SUCCEEDED)
            assert event.user_id == acme_user.pk
            assert event.detail["session_id"]

    def test_it_stamps_last_login(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        assert acme_user.last_login is None

        login(api_client)

        with tenant_context(acme):
            acme_user.refresh_from_db()
        assert acme_user.last_login is not None

    def test_the_address_is_matched_case_insensitively(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """Emails are folded to lower case on write, so login must fold too."""
        response = login(api_client, email="PRIYA@Acme.EDU")

        assert response.status_code == 200

    def test_only_the_refresh_digest_is_stored(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """A database disclosure must yield nothing redeemable."""
        response = login(api_client)
        raw = response.cookies[REFRESH_COOKIE].value

        with tenant_context(acme):
            stored = RefreshToken.objects.get()

        assert stored.token_hash != raw
        assert len(stored.token_hash) == 64


@pytest.mark.django_db
class TestFailedLogin:
    @pytest.mark.parametrize(
        "email,password",
        [
            ("priya@acme.edu", "wrong-password"),
            ("nobody@acme.edu", PASSWORD),
            ("nobody@acme.edu", "wrong-password"),
        ],
    )
    def test_every_failure_looks_identical(
        self,
        email: str,
        password: str,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
    ) -> None:
        """Wrong password, unknown address, both wrong -- one answer."""
        response = login(api_client, email=email, password=password)

        assert response.status_code == 401
        assert response.json()["error"] == "authentication_failed"
        assert response.json()["message"] == "Invalid credentials."

    def test_a_deactivated_account_is_indistinguishable_from_a_wrong_password(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        with tenant_context(acme):
            type(acme_user).all_objects.filter(pk=acme_user.pk).update(is_active=False)

        response = login(api_client)

        assert response.status_code == 401
        assert response.json()["error"] == "authentication_failed"

    def test_a_soft_deleted_account_takes_the_unknown_address_path(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        with tenant_context(acme):
            acme_user.delete()

        response = login(api_client)

        assert response.status_code == 401
        assert response.json()["error"] == "authentication_failed"

    def test_no_cookie_is_issued_on_failure(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        response = login(api_client, password="wrong-password")

        assert REFRESH_COOKIE not in response.cookies

    def test_the_failure_is_recorded_with_its_reason(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """The reason is for operators and is never returned to the client --
        that asymmetry is the point."""
        login(api_client, password="wrong-password")

        with tenant_context(acme):
            attempt = LoginAttempt.objects.get(successful=False)
            event = AuthAuditEvent.objects.get(event_type=AuthEventType.LOGIN_FAILED)

        assert attempt.failure_reason == "bad_credentials"
        assert attempt.email == "priya@acme.edu"
        assert event.detail["reason"] == "bad_credentials"

    def test_an_unknown_address_still_records_an_attempt(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        login(api_client, email="nobody@acme.edu")

        with tenant_context(acme):
            attempt = LoginAttempt.objects.get(successful=False)

        assert attempt.user_id is None
        assert attempt.email == "nobody@acme.edu"

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"email": "priya@acme.edu"},
            {"password": PASSWORD},
            {"email": "not-an-address", "password": PASSWORD},
        ],
    )
    def test_a_malformed_body_is_a_validation_error(
        self,
        payload: dict[str, Any],
        acme: Tenant,
        api_client: HttpClient,
    ) -> None:
        response = api_client.post(
            LOGIN, data=payload, content_type="application/json", HTTP_HOST=ACME_HOST
        )

        assert response.status_code == 400
        assert response.json()["error"] == "validation_error"
        assert "details" in response.json()


@pytest.mark.django_db
class TestLockout:
    def test_the_account_locks_after_the_threshold(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """Five failures inside the window, then 423 rather than 401."""
        for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"]):
            assert login(api_client, password="wrong").status_code == 401

        response = login(api_client, password="wrong")

        assert response.status_code == 423
        assert response.json()["error"] == "account_locked"

    def test_the_lock_tells_the_client_how_long_to_wait(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """A client that honours Retry-After stops extending its own lockout."""
        for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"]):
            login(api_client, password="wrong")

        response = login(api_client, password="wrong")

        assert response["Retry-After"] == str(
            int(settings.JWT_AUTH["LOCKOUT_DURATION"].total_seconds())
        )

    def test_the_correct_password_is_refused_while_locked(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"]):
            login(api_client, password="wrong")

        assert login(api_client).status_code == 423

    def test_the_lock_is_audited_once(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """Emitted by the attempt that trips it, not by every later one."""
        for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"] + 3):
            login(api_client, password="wrong")

        with tenant_context(acme):
            assert (
                AuthAuditEvent.objects.filter(
                    event_type=AuthEventType.ACCOUNT_LOCKED
                ).count()
                == 1
            )

    def test_a_successful_login_clears_the_counters_on_commit(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        django_capture_on_commit_callbacks: Callable[..., Any],
    ) -> None:
        """Cleared after the commit, never before it.

        Clearing earlier would let a failure between the credential check and
        the commit reset an attacker's counter for free -- which is why the
        clear is an ``on_commit`` callback, and why this test has to run those
        callbacks explicitly: the suite's surrounding transaction never
        commits, so nothing else would fire them.
        """
        for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"] - 1):
            login(api_client, password="wrong")

        with django_capture_on_commit_callbacks(execute=True) as callbacks:
            assert login(api_client).status_code == 200

        assert callbacks, "the lockout clear must be deferred to commit"

        for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"] - 1):
            assert login(api_client, password="wrong").status_code == 401

    def test_lockout_counters_are_not_shared_between_tenants(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        beta_user: User,
        api_client: HttpClient,
        login: Callable,
    ) -> None:
        """One institution must not be able to lock out another's accounts."""
        for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"] + 1):
            login(api_client, password="wrong")

        response = login(
            api_client, host=BETA_HOST, email="raj@beta.edu", password=PASSWORD
        )

        assert response.status_code == 200


@pytest.mark.django_db
class TestSessionCap:
    def test_the_oldest_session_is_retired_at_the_cap(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        settings: Any,
    ) -> None:
        """A cap that never trims is a cap in name only."""
        settings.JWT_AUTH = {**settings.JWT_AUTH, "MAX_ACTIVE_SESSIONS_PER_USER": 2}

        for _ in range(3):
            assert login(api_client).status_code == 200

        with tenant_context(acme):
            assert DeviceSession.objects.live().count() == 2
            assert DeviceSession.objects.count() == 3

    def test_the_retired_session_loses_its_refresh_token(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        settings: Any,
    ) -> None:
        settings.JWT_AUTH = {**settings.JWT_AUTH, "MAX_ACTIVE_SESSIONS_PER_USER": 1}

        login(api_client)
        login(api_client)

        with tenant_context(acme):
            assert RefreshToken.objects.active().count() == 1
            assert RefreshToken.objects.filter(status="revoked").count() == 1


@pytest.mark.django_db
class TestLockoutPolicy:
    """The counter itself, including what it does when Redis is not there."""

    @pytest.fixture
    def policy(self) -> Any:
        from apps.authentication.services.lockout import LockoutPolicy

        return LockoutPolicy()

    def test_it_counts_failures_per_address(self, acme: Tenant, policy: Any) -> None:
        with tenant_context(acme):
            policy.register_failure(email="a@acme.edu", ip="203.0.113.1")
            policy.register_failure(email="a@acme.edu", ip="203.0.113.1")

            assert policy.failure_count(email="a@acme.edu") == 2

    def test_it_reports_the_attempt_that_trips_the_lock(
        self, acme: Tenant, policy: Any
    ) -> None:
        with tenant_context(acme):
            tripped = [
                policy.register_failure(email="a@acme.edu", ip="203.0.113.1")
                for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"] + 2)
            ]

        # Exactly one True, at the threshold, so the event is emitted once per
        # lock rather than once per subsequent failure.
        assert tripped.count(True) == 1
        assert tripped[settings.JWT_AUTH["LOCKOUT_THRESHOLD"] - 1] is True

    def test_an_email_alone_never_locks_anything(
        self, acme: Tenant, policy: Any
    ) -> None:
        """Otherwise anyone who knows an address can lock its owner out at
        will, which turns a brute-force defence into a targeted denial of
        service."""
        with tenant_context(acme):
            for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"] + 2):
                assert policy.register_failure(email="a@acme.edu", ip=None) is False

            policy.assert_not_locked(email="a@acme.edu", ip=None)

    def test_clearing_resets_both_counters(self, acme: Tenant, policy: Any) -> None:
        with tenant_context(acme):
            for _ in range(settings.JWT_AUTH["LOCKOUT_THRESHOLD"]):
                policy.register_failure(email="a@acme.edu", ip="203.0.113.1")

            policy.clear(email="a@acme.edu", ip="203.0.113.1")

            policy.assert_not_locked(email="a@acme.edu", ip="203.0.113.1")
            assert policy.failure_count(email="a@acme.edu") == 0

    def test_an_unreachable_counter_fails_open(
        self, acme: Tenant, policy: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The opposite of the denylist, deliberately: a missed lockout costs
        an extra guess, and a counter outage must not become an
        authentication outage while the throttles and the WAF still apply."""

        def explode(*_args: Any, **_kwargs: Any) -> None:
            raise ConnectionError("redis is gone")

        monkeypatch.setattr(
            "django.core.cache.backends.locmem.LocMemCache.get", explode
        )
        monkeypatch.setattr(
            "django.core.cache.backends.locmem.LocMemCache.incr", explode
        )
        monkeypatch.setattr(
            "django.core.cache.backends.locmem.LocMemCache.set", explode
        )

        with tenant_context(acme):
            tripped = policy.register_failure(email="a@acme.edu", ip="203.0.113.1")
            assert tripped is False
            policy.assert_not_locked(email="a@acme.edu", ip="203.0.113.1")
