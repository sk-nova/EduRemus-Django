"""The HTTP contract: envelope, headers, throttles, CORS and introspection.

These are the assertions a client integration depends on. An error code is a
published contract -- a client branches on ``token_expired`` to decide whether
refreshing is worth trying -- so a change in shape here is a breaking change
even when every status code stays the same.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest
from django.test import Client as HttpClient

from apps.authentication.tokens import claims as C

from .conftest import ACME_HOST, PUBLIC_HOST

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant

ME = "/api/v1/auth/me/"
LOGIN = "/api/v1/auth/login/"
VERIFY = "/api/v1/auth/verify/"
SESSIONS = "/api/v1/auth/sessions/"


@pytest.mark.django_db
class TestErrorEnvelope:
    def test_every_error_has_the_same_three_keys(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        body = api_client.get(ME, HTTP_HOST=ACME_HOST).json()

        assert set(body) == {"error", "message", "request_id"}

    def test_a_validation_error_adds_the_field_details(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        """The one exception to the three-key envelope: a client cannot render
        a usable form without knowing which field was rejected."""
        response = api_client.post(
            LOGIN, data={}, content_type="application/json", HTTP_HOST=ACME_HOST
        )

        assert response.status_code == 400
        assert set(response.json()["details"]) == {"email", "password"}

    def test_the_message_is_a_sentence_and_not_a_structure(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        body = api_client.get(ME, HTTP_HOST=ACME_HOST).json()

        assert isinstance(body["message"], str)
        assert not body["message"].startswith(("[", "{"))

    def test_the_request_id_matches_the_response_header(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        """The whole point of the id: a user reporting an error names a value
        that finds the log lines for that request."""
        response = api_client.get(ME, HTTP_HOST=ACME_HOST)

        assert response.json()["request_id"] == response["X-Request-Id"]

    def test_a_client_supplied_request_id_is_honoured(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        """So a trace survives across service boundaries."""
        response = api_client.get(
            ME, HTTP_HOST=ACME_HOST, headers={"X-Request-Id": "upstream-42"}
        )

        assert response["X-Request-Id"] == "upstream-42"

    def test_a_malicious_request_id_is_replaced(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        """The value is echoed into a header and into logs, where an
        unvalidated string is header injection and log forging."""
        response = api_client.get(
            ME, HTTP_HOST=ACME_HOST, headers={"X-Request-Id": "a" * 200 + " evil"}
        )

        assert response["X-Request-Id"] != "a" * 200 + " evil"


@pytest.mark.django_db
class TestResponseHeaders:
    @pytest.mark.parametrize("path", [ME, SESSIONS])
    def test_authentication_responses_are_never_stored(
        self,
        path: str,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """``no-store``, not ``no-cache``: the latter permits storage with
        revalidation, which for a body holding a token means the credential
        sits in a shared cache."""
        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.get(
            path, HTTP_HOST=ACME_HOST, **bearer(pair.access_token)
        )

        assert response["Cache-Control"] == "no-store"

    def test_error_responses_are_never_stored_either(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        response = api_client.get(ME, HTTP_HOST=ACME_HOST)

        assert response["Cache-Control"] == "no-store"

    def test_a_401_carries_a_challenge(
        self, acme: Tenant, api_client: HttpClient, bearer: Callable[[str], dict]
    ) -> None:
        """DRF downgrades to 403 when a view offers no authenticator to
        challenge with, which is wrong for this API: the taxonomy assigns 401
        to a bad credential and a client seeing 403 will not re-authenticate.
        """
        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer("nonsense"))

        assert response.status_code == 401
        challenge = response["WWW-Authenticate"]
        assert challenge.startswith('Bearer realm="eduremus"')
        assert 'error="token_malformed"' in challenge

    def test_the_login_endpoint_answers_401_and_not_403(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """Login carries no Authorization header by definition, so this is the
        endpoint the DRF downgrade would silently break."""
        assert login(api_client, password="wrong").status_code == 401


@pytest.mark.django_db
class TestVerifyEndpoint:
    def test_a_live_token_introspects(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        body = api_client.post(
            VERIFY,
            data={"token": pair.access_token},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
        ).json()

        assert body["active"] is True
        assert body["sub"] == str(acme_user.pk)
        assert body["sch"] == "acme"
        assert body["token_type"] == C.TOKEN_TYPE_ACCESS

    def test_a_revoked_token_is_inactive(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)
        api_client.post(
            "/api/v1/auth/logout-all/", HTTP_HOST=ACME_HOST, **bearer(pair.access_token)
        )

        body = api_client.post(
            VERIFY,
            data={"token": pair.access_token},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
        ).json()

        assert body == {"active": False}

    def test_a_foreign_tenants_token_is_inactive_here(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        body = api_client.post(
            VERIFY,
            data={"token": pair.access_token},
            content_type="application/json",
            HTTP_HOST="beta.testserver",
        ).json()

        assert body == {"active": False}

    def test_it_needs_no_credential_of_its_own(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.post(
            VERIFY,
            data={"token": pair.access_token},
            content_type="application/json",
            HTTP_HOST=ACME_HOST,
        )

        assert response.status_code == 200


@pytest.mark.django_db
class TestCurrentUser:
    def test_it_reports_the_principal_its_roles_and_its_tenant(
        self,
        acme: Tenant,
        acme_user: User,
        grant_role: Callable[..., None],
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        grant_role(acme_user, "registrar", tenant=acme)
        pair = issue_pair(user=acme_user, tenant=acme)

        body = api_client.get(
            ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token)
        ).json()

        assert body["email"] == "priya@acme.edu"
        assert body["roles"] == ["registrar"]
        assert body["tenant"]["slug"] == "acme"

    def test_the_scopes_are_the_ones_the_token_carries(
        self,
        acme: Tenant,
        acme_user: User,
        grant_role: Callable[..., None],
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Not recomputed. The endpoint reports what the credential in hand
        can do, not what it would be granted if reissued now."""
        pair = issue_pair(user=acme_user, tenant=acme)
        grant_role(acme_user, "tenant_admin", tenant=acme)

        body = api_client.get(
            ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token)
        ).json()

        assert "users:admin" not in body["scopes"]
        assert body["roles"] == ["tenant_admin"]

    def test_it_exposes_no_password_material(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        body = api_client.get(
            ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token)
        ).json()

        assert "password" not in body
        assert "token_version" not in body


@pytest.mark.django_db
class TestThrottling:
    def test_login_is_throttled_per_address_and_email(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """Ten an hour. The lockout trips first, and the throttle is the layer
        that still applies when the lockout counter is unavailable."""
        for _ in range(10):
            login(api_client, email="throttled@acme.edu", password="wrong")

        response = login(api_client, email="throttled@acme.edu", password="wrong")

        assert response.status_code == 429
        assert response.json()["error"] == "throttled"

    def test_a_throttled_response_says_when_to_retry(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        for _ in range(10):
            login(api_client, email="throttled@acme.edu", password="wrong")

        response = login(api_client, email="throttled@acme.edu", password="wrong")

        assert int(response["Retry-After"]) > 0

    def test_the_bucket_is_per_email(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """So one attacked account cannot exhaust everyone else's budget."""
        for _ in range(10):
            login(api_client, email="throttled@acme.edu", password="wrong")

        response = login(api_client, email="another@acme.edu", password="wrong")

        assert response.status_code == 401

    def test_the_bucket_is_per_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        beta_user: User,
        api_client: HttpClient,
        login: Callable,
    ) -> None:
        """A shared bucket is a cross-tenant availability lever."""
        for _ in range(11):
            login(api_client, password="wrong")

        response = login(
            api_client,
            host="beta.testserver",
            email="raj@beta.edu",
            password="s3cure-Passw0rd!",
        )

        assert response.status_code == 200


@pytest.mark.django_db
class TestCors:
    def test_a_matching_origin_is_allowed_with_credentials(
        self, acme: Tenant, api_client: HttpClient, settings: Any
    ) -> None:
        """Credentials must be allowed or the refresh cookie is never sent."""
        settings.CORS_ALLOWED_ORIGIN_REGEXES = [r"^https://[a-z0-9-]+\.example\.com$"]

        response = api_client.options(
            LOGIN,
            HTTP_HOST=ACME_HOST,
            HTTP_ORIGIN="https://acme.example.com",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        )

        assert response["Access-Control-Allow-Origin"] == "https://acme.example.com"
        assert response["Access-Control-Allow-Credentials"] == "true"

    def test_a_lookalike_origin_is_refused(
        self, acme: Tenant, api_client: HttpClient, settings: Any
    ) -> None:
        """The regex is anchored at both ends. Unanchored, it would also match
        https://acme.example.com.attacker.example -- and with credentials
        allowed, that is a session hijack."""
        settings.CORS_ALLOWED_ORIGIN_REGEXES = [r"^https://[a-z0-9-]+\.example\.com$"]

        response = api_client.options(
            LOGIN,
            HTTP_HOST=ACME_HOST,
            HTTP_ORIGIN="https://acme.example.com.attacker.example",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        )

        assert not response.has_header("Access-Control-Allow-Origin")

    def test_the_correlation_header_is_exposed_to_the_browser(
        self, acme: Tenant, api_client: HttpClient, settings: Any
    ) -> None:
        settings.CORS_ALLOWED_ORIGIN_REGEXES = [r"^https://[a-z0-9-]+\.example\.com$"]

        response = api_client.options(
            LOGIN,
            HTTP_HOST=ACME_HOST,
            HTTP_ORIGIN="https://acme.example.com",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        )

        assert "x-request-id" in response["Access-Control-Expose-Headers"]


@pytest.mark.django_db
class TestMetricsEndpoint:
    def test_it_is_absent_unless_enabled(
        self, public_tenant: Tenant, api_client: HttpClient, settings: Any
    ) -> None:
        """404 rather than 403, so a probe cannot tell the route exists."""
        settings.PROMETHEUS_METRICS_ENABLED = False

        assert api_client.get("/metrics", HTTP_HOST=PUBLIC_HOST).status_code == 404

    def test_it_serves_the_registry_when_enabled(
        self, public_tenant: Tenant, api_client: HttpClient, settings: Any
    ) -> None:
        settings.PROMETHEUS_METRICS_ENABLED = True

        response = api_client.get("/metrics", HTTP_HOST=PUBLIC_HOST)

        assert response.status_code == 200
        assert b"eduremus_login_attempts_total" in response.content

    def test_it_is_not_served_from_a_tenant_host(
        self, acme: Tenant, api_client: HttpClient, settings: Any
    ) -> None:
        """The counters are labelled by schema, so a per-tenant copy would
        hand each institution every other institution's login rate."""
        settings.PROMETHEUS_METRICS_ENABLED = True

        assert api_client.get("/metrics", HTTP_HOST=ACME_HOST).status_code == 404


@pytest.mark.django_db
class TestMetrics:
    """The counters an alert reads. Each is labelled by schema, because a
    platform-wide rate hides the case that matters: one institution under
    attack while the other four hundred are fine."""

    @staticmethod
    def value(name: str, **labels: str) -> float:
        from prometheus_client import REGISTRY

        return REGISTRY.get_sample_value(name, labels) or 0.0

    def test_a_successful_login_is_counted_for_its_tenant(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        before = self.value(
            "eduremus_login_attempts_total", schema="acme", result="success"
        )

        login(api_client)

        assert (
            self.value("eduremus_login_attempts_total", schema="acme", result="success")
            == before + 1
        )

    def test_a_failure_is_counted_separately_from_a_lockout(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """Folding a lockout into the failure ratio would make a control
        working look like an incident."""
        failures = self.value(
            "eduremus_login_attempts_total", schema="acme", result="failure"
        )
        locks = self.value("eduremus_account_lockouts_total", schema="acme")

        for _ in range(6):
            login(api_client, password="wrong")

        assert (
            self.value("eduremus_login_attempts_total", schema="acme", result="failure")
            == failures + 5
        )
        assert self.value("eduremus_account_lockouts_total", schema="acme") == locks + 1

    def test_a_cross_tenant_rejection_is_counted_for_the_pair(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """The counter that pages on any non-zero value. It is also the only
        one of the three records that works when the database is the thing
        that is broken."""
        before = self.value(
            "eduremus_cross_tenant_rejections_total",
            token_schema="acme",
            active_schema="beta",
        )
        pair = issue_pair(user=acme_user, tenant=acme)

        api_client.get(ME, HTTP_HOST="beta.testserver", **bearer(pair.access_token))

        assert (
            self.value(
                "eduremus_cross_tenant_rejections_total",
                token_schema="acme",
                active_schema="beta",
            )
            == before + 1
        )

    def test_token_validation_is_timed(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        before = self.value(
            "eduremus_token_validations_total", schema="acme", result="success"
        )
        pair = issue_pair(user=acme_user, tenant=acme)

        api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert (
            self.value(
                "eduremus_token_validations_total", schema="acme", result="success"
            )
            == before + 1
        )
        assert self.value("eduremus_token_validation_seconds_count", schema="acme") > 0

    def test_a_request_with_no_credential_is_not_timed(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        """No validation happened, and counting it would dilute both the
        latency histogram and the failure ratio."""
        before = self.value("eduremus_token_validation_seconds_count", schema="acme")

        api_client.get(ME, HTTP_HOST=ACME_HOST)

        assert (
            self.value("eduremus_token_validation_seconds_count", schema="acme")
            == before
        )

    def test_the_signing_key_age_is_published(self) -> None:
        """What the rotation-due alert reads."""
        from apps.authentication.tokens.keys import Keyring

        Keyring.load(force=True)

        assert self.value("eduremus_signing_key_age_days", kid="test-key") >= 0


@pytest.mark.django_db
class TestSchema:
    def test_the_openapi_document_describes_every_endpoint(
        self, public_tenant: Tenant
    ) -> None:
        from drf_spectacular.generators import SchemaGenerator

        schema = SchemaGenerator().get_schema(request=None, public=True)
        paths = set(schema["paths"])

        for endpoint in (
            "/api/v1/auth/login/",
            "/api/v1/auth/refresh/",
            "/api/v1/auth/logout/",
            "/api/v1/auth/logout-all/",
            "/api/v1/auth/verify/",
            "/api/v1/auth/me/",
            "/api/v1/auth/sessions/",
            "/api/v1/auth/revoke/",
            "/api/v1/auth/password/change/",
        ):
            assert endpoint in paths, endpoint

    def test_the_bearer_scheme_is_published(self, public_tenant: Tenant) -> None:
        from drf_spectacular.generators import SchemaGenerator

        schema = SchemaGenerator().get_schema(request=None, public=True)

        assert "BearerAuth" in schema["components"]["securitySchemes"]
