"""Cross-tenant rejection. The most important module in this suite.

Under the session model, isolation was structural: a cookie issued by one
institution had no session row in another, so there was nothing to assert.
Under JWT it becomes an explicit comparison between a claim and the live
connection -- and an explicit check needs a test that fails loudly the day
someone removes it.

Every negative here is paired with a positive. A suite that only proves
requests are *rejected* would still pass if authentication were broken
outright, which is the classic way an isolation test stops meaning anything.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client as HttpClient
from django.utils import timezone

from apps.authentication.models import AuthAuditEvent, AuthEventType, RefreshToken
from apps.authentication.tokens.denylist import denylist, is_denylisted
from apps.authentication.utils.cache_keys import denylist_key, tenant_key, user_key
from apps.tenants.utils import tenant_context

from .conftest import ACME_HOST, BETA_HOST, PASSWORD, PUBLIC_HOST

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant

ME = "/api/v1/auth/me/"


@pytest.mark.django_db
class TestTokenReplayAcrossTenants:
    def test_an_acme_token_is_rejected_at_beta(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """THE test. A valid token from one tenant must not work at another."""
        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.get(ME, HTTP_HOST=BETA_HOST, **bearer(pair.access_token))

        assert response.status_code == 401
        assert response.json()["error"] == "token_wrong_tenant"

    def test_the_same_token_works_in_its_own_tenant(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """The positive control. Without it the test above proves nothing."""
        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 200
        assert response.json()["email"] == "priya@acme.edu"

    def test_a_tenant_token_is_rejected_on_the_public_host(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """The platform is a schema like any other, and not a superset."""
        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.get(
            ME, HTTP_HOST=PUBLIC_HOST, **bearer(pair.access_token)
        )

        assert response.status_code == 401
        assert response.json()["error"] == "token_wrong_tenant"

    def test_a_platform_token_is_rejected_at_a_tenant(
        self,
        public_tenant: Tenant,
        acme: Tenant,
        make_user: Callable[..., User],
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """And the reverse: platform staff hold no authority inside a tenant."""
        with tenant_context(public_tenant):
            staff = make_user("ops@eduremus.com", is_staff=True)
        pair = issue_pair(user=staff, tenant=public_tenant)

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 401

    @pytest.mark.parametrize(
        "path,method",
        [
            (ME, "get"),
            ("/api/v1/auth/sessions/", "get"),
            ("/api/v1/auth/logout/", "post"),
            ("/api/v1/auth/logout-all/", "post"),
            ("/api/v1/auth/revoke/", "post"),
            ("/api/v1/auth/password/change/", "post"),
        ],
    )
    def test_every_authenticated_endpoint_rejects_a_foreign_token(
        self,
        path: str,
        method: str,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """One endpoint forgetting the check is the whole control gone."""
        pair = issue_pair(user=acme_user, tenant=acme)

        response = getattr(api_client, method)(
            path, HTTP_HOST=BETA_HOST, **bearer(pair.access_token)
        )

        assert response.status_code == 401, path
        assert response.json()["error"] == "token_wrong_tenant", path


@pytest.mark.django_db
class TestRejectionIsRecorded:
    def test_a_cross_tenant_attempt_is_audited_in_the_receiving_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """Silent rejection is not enough -- this is a security event."""
        pair = issue_pair(user=acme_user, tenant=acme)

        api_client.get(ME, HTTP_HOST=BETA_HOST, **bearer(pair.access_token))

        with tenant_context(beta):
            event = AuthAuditEvent.objects.filter(
                event_type=AuthEventType.CROSS_TENANT_TOKEN_REJECTED
            ).first()

            assert event is not None
            assert event.severity == "critical"
            assert event.detail["token_schema"] == "acme"
            assert event.detail["active_schema"] == "beta"

    def test_the_audit_row_lands_in_the_receiving_schema_only(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """The institution being probed is the one that gets the record."""
        pair = issue_pair(user=acme_user, tenant=acme)

        api_client.get(ME, HTTP_HOST=BETA_HOST, **bearer(pair.access_token))

        with tenant_context(acme):
            assert not AuthAuditEvent.objects.filter(
                event_type=AuthEventType.CROSS_TENANT_TOKEN_REJECTED
            ).exists()

    def test_the_rejection_names_no_tenant_to_the_caller(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """The detail goes to the audit trail, never into the response."""
        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.get(ME, HTTP_HOST=BETA_HOST, **bearer(pair.access_token))

        body = response.content.decode()
        assert "acme" not in body
        assert "beta" not in body


@pytest.mark.django_db
class TestIdentityCollisions:
    def test_a_colliding_user_uuid_does_not_authenticate_across_tenants(
        self,
        acme: Tenant,
        beta: Tenant,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """The scenario UUID uniqueness is wrongly assumed to prevent.

        Two schemas holding the same user UUID is entirely possible: a
        restore, a tenant clone, a fixture load. Without the ``sch`` check an
        acme token would authenticate as beta's identically-keyed user, and
        every uniqueness argument for why that cannot happen is an argument
        about probability rather than about a control.
        """
        shared_id = uuid.uuid7()
        user_model = get_user_model()

        with tenant_context(acme):
            acme_user = user_model.objects.create_user(
                email="same@acme.edu", password=PASSWORD
            )
            user_model.all_objects.filter(pk=acme_user.pk).update(id=shared_id)
            acme_user = user_model.objects.get(pk=shared_id)

        with tenant_context(beta):
            beta_user = user_model.objects.create_user(
                email="same@beta.edu", password=PASSWORD
            )
            user_model.all_objects.filter(pk=beta_user.pk).update(id=shared_id)

        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.get(ME, HTTP_HOST=BETA_HOST, **bearer(pair.access_token))

        assert response.status_code == 401, (
            "a colliding UUID must not authenticate across tenants"
        )

    def test_the_same_email_is_a_different_account_in_each_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
        make_user: Callable[..., User],
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """Email uniqueness is per schema, so one address is two accounts."""
        with tenant_context(acme):
            acme_user = make_user("shared@example.com")
        with tenant_context(beta):
            beta_user = make_user("shared@example.com")

        assert acme_user.pk != beta_user.pk

        pair = issue_pair(user=acme_user, tenant=acme)
        response = api_client.get(ME, HTTP_HOST=BETA_HOST, **bearer(pair.access_token))

        assert response.status_code == 401


@pytest.mark.django_db
class TestHeaderManipulation:
    def test_a_host_header_cannot_select_a_schema_for_the_token(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """An unknown Host is a 404 from the middleware, never a fallback."""
        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.get(
            ME, HTTP_HOST="nowhere.testserver", **bearer(pair.access_token)
        )

        assert response.status_code == 404

    @pytest.mark.parametrize(
        "header,value",
        [
            ("HTTP_X_TENANT", "acme"),
            ("HTTP_X_TENANT_ID", "1"),
            ("HTTP_X_SCHEMA", "acme"),
            ("HTTP_X_FORWARDED_HOST", ACME_HOST),
        ],
    )
    def test_no_header_can_override_the_resolved_tenant(
        self,
        header: str,
        value: str,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict[str, Any]],
    ) -> None:
        """Only the Host header selects a schema, and only via the catalogue."""
        pair = issue_pair(user=acme_user, tenant=acme)

        extra = {header: value} | bearer(pair.access_token)
        response = api_client.get(ME, HTTP_HOST=BETA_HOST, **extra)

        assert response.status_code == 401

    def test_rotation_rejects_a_refresh_cookie_from_another_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
    ) -> None:
        """Rotation mints credentials, so it runs the tenancy check itself."""
        pair = issue_pair(user=acme_user, tenant=acme)

        api_client.cookies[settings.JWT_AUTH["REFRESH_COOKIE_NAME"]] = (
            pair.refresh_token
        )
        api_client.cookies[settings.JWT_AUTH["CSRF_COOKIE_NAME"]] = "double-submit"

        response = api_client.post(
            "/api/v1/auth/refresh/",
            HTTP_HOST=BETA_HOST,
            headers={"X-CSRF-Token": "double-submit"},
        )

        assert response.status_code == 401
        assert response.json()["error"] == "token_wrong_tenant"


@pytest.mark.django_db
class TestStorageIsolation:
    def test_redis_keys_are_namespaced_by_schema(
        self, acme: Tenant, beta: Tenant
    ) -> None:
        """Redis has no search_path; the prefix is the only isolation there."""
        with tenant_context(acme):
            acme_key = tenant_key("denylist", "abc")
        with tenant_context(beta):
            beta_key = tenant_key("denylist", "abc")

        assert acme_key == "acme:jwt:denylist:abc"
        assert beta_key == "beta:jwt:denylist:abc"

    @pytest.mark.parametrize("builder", [denylist_key, user_key])
    def test_every_key_helper_carries_the_schema(
        self, builder: Callable[[str], str], acme: Tenant, beta: Tenant
    ) -> None:
        with tenant_context(acme):
            in_acme = builder("shared-value")
        with tenant_context(beta):
            in_beta = builder("shared-value")

        assert in_acme.startswith("acme:jwt:")
        assert in_beta.startswith("beta:jwt:")
        assert in_acme != in_beta

    def test_a_denylisted_jti_is_not_denylisted_in_another_tenant(
        self, acme: Tenant, beta: Tenant
    ) -> None:
        """Revocation is per tenant, in both directions.

        The same ``jti`` revoked in acme must neither leak the revocation into
        beta nor -- far worse -- be reported as *not* revoked back in acme
        because the key was written under someone else's prefix.
        """
        jti = str(uuid.uuid7())
        expires = timezone.now() + timedelta(minutes=15)

        with tenant_context(acme):
            denylist(jti, expires_at=expires)
            assert is_denylisted(jti) is True

        with tenant_context(beta):
            assert is_denylisted(jti) is False

    def test_token_rows_are_invisible_from_the_other_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """No filter is applied anywhere -- the search_path is the isolation."""
        issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            assert RefreshToken.objects.count() == 1
        with tenant_context(beta):
            assert RefreshToken.objects.count() == 0
