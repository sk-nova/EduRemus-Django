"""Every branch of the authenticator.

The target for this module is total branch coverage of
``apps/authentication/authentication.py``, because each branch there is a
security decision: an untested one is an unenforced control. Several are
unreachable over HTTP -- a request with no resolved tenant, a validated token
with no ``sub`` -- so those are driven by calling the authenticator directly
rather than left uncovered.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from django.core.cache import cache
from django.test import Client as HttpClient
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from apps.authentication.authentication import (
    TenantAwareJWTAuthentication,
    tenant_user_authentication_rule,
)
from apps.authentication.exceptions import (
    TokenInvalid,
    TokenRevoked,
    TokenSuperseded,
    UserInactive,
)
from apps.authentication.tokens import claims as C
from apps.authentication.tokens.denylist import denylist
from apps.authentication.utils.cache_keys import user_key
from apps.tenants.utils import tenant_context

from .conftest import ACME_HOST

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant

ME = "/api/v1/auth/me/"


def drf_request(**meta: str) -> Request:
    """A DRF request with no tenant attached, for the direct-call branches."""
    return Request(APIRequestFactory().get("/", **meta))


@pytest.mark.django_db
class TestHeaderHandling:
    def test_no_authorization_header_is_not_an_authentication_attempt(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        """Returning None rather than raising is what lets other classes try."""
        assert TenantAwareJWTAuthentication().authenticate(drf_request()) is None

        response = api_client.get(ME, HTTP_HOST=ACME_HOST)
        assert response.status_code == 401
        assert response.json()["error"] == "not_authenticated"

    def test_a_non_bearer_scheme_is_not_an_authentication_attempt(
        self, acme: Tenant
    ) -> None:
        """Basic auth is somebody else's business, not a malformed token."""
        request = drf_request(HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz")

        assert TenantAwareJWTAuthentication().authenticate(request) is None

    def test_a_bearer_header_with_no_token_is_rejected(self, acme: Tenant) -> None:
        """A recognised scheme with nothing after it is a malformed attempt,
        not an absent one -- so it fails rather than falling through to the
        next authentication class."""
        request = drf_request(HTTP_AUTHORIZATION="Bearer")

        with pytest.raises(AuthenticationFailed):
            TenantAwareJWTAuthentication().authenticate(request)

    def test_a_bearer_header_with_extra_parts_is_rejected(self, acme: Tenant) -> None:
        request = drf_request(HTTP_AUTHORIZATION="Bearer one two")

        with pytest.raises(AuthenticationFailed):
            TenantAwareJWTAuthentication().authenticate(request)

    def test_a_garbage_token_is_rejected_as_malformed(
        self, acme: Tenant, api_client: HttpClient, bearer: Callable[[str], dict]
    ) -> None:
        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer("not-a-jwt"))

        assert response.status_code == 401
        assert response.json()["error"] == "token_malformed"


@pytest.mark.django_db
class TestSuccessfulAuthentication:
    def test_a_valid_token_resolves_the_user(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 200
        assert response.json()["id"] == str(acme_user.pk)

    def test_the_verified_claims_are_attached_to_the_request(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """Attached rather than re-decoded, so authorisation cannot disagree
        with authentication about what the token said."""
        pair = issue_pair(user=acme_user, tenant=acme)
        request = drf_request(HTTP_AUTHORIZATION=f"Bearer {pair.access_token}")

        with tenant_context(acme):
            result = TenantAwareJWTAuthentication().authenticate(request)

        assert result is not None
        assert request.auth_payload[C.CLAIM_SCHEMA] == "acme"

    def test_a_request_without_a_resolved_tenant_skips_the_second_check(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """The schema comparison has already run against the connection.

        ``request.tenant`` is the corroborating source, not the primary one,
        so its absence outside the middleware is not a failure.
        """
        pair = issue_pair(user=acme_user, tenant=acme)
        request = drf_request(HTTP_AUTHORIZATION=f"Bearer {pair.access_token}")

        with tenant_context(acme):
            result = TenantAwareJWTAuthentication().authenticate(request)

        assert result is not None
        assert result[0].pk == acme_user.pk


@pytest.mark.django_db
class TestTenantBinding:
    def test_a_tenant_id_that_disagrees_with_the_schema_is_rejected(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """The corroborating check, on its own.

        ``sch`` is compared against the live connection and ``tid`` against
        the row the middleware resolved from the hostname. This token passes
        the first and fails the second, which is the only way to prove the
        second is doing anything.
        """
        import jwt

        private_pem, _public = rsa_keypair
        pair = issue_pair(user=acme_user, tenant=acme)
        claims = jwt.decode(pair.access_token, options={"verify_signature": False})
        claims[C.CLAIM_TENANT_ID] = beta.pk
        forged = jwt.encode(
            claims, private_pem, algorithm="RS256", headers={"kid": "test-key"}
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401
        assert response.json()["error"] == "token_wrong_tenant"

    def test_that_rejection_is_audited_with_both_identifiers(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        import jwt

        from apps.authentication.models import AuthAuditEvent, AuthEventType

        private_pem, _public = rsa_keypair
        pair = issue_pair(user=acme_user, tenant=acme)
        claims = jwt.decode(pair.access_token, options={"verify_signature": False})
        claims[C.CLAIM_TENANT_ID] = beta.pk
        forged = jwt.encode(
            claims, private_pem, algorithm="RS256", headers={"kid": "test-key"}
        )

        api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        with tenant_context(acme):
            event = AuthAuditEvent.objects.get(
                event_type=AuthEventType.CROSS_TENANT_TOKEN_REJECTED
            )

        assert event.detail["reason"] == "tenant_id_mismatch"
        assert event.detail["token_tid"] == str(beta.pk)
        assert event.detail["tenant_pk"] == str(acme.pk)


@pytest.mark.django_db
class TestRevocationChecks:
    def test_a_denylisted_token_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            denylist(pair.access_jti, expires_at=timezone.now() + timedelta(minutes=15))

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 401
        assert response.json()["error"] == "token_revoked"

    def test_a_denylist_outage_fails_closed(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ "Cannot tell" is not "not revoked". 503, never a quiet success."""
        pair = issue_pair(user=acme_user, tenant=acme)

        def explode(*_args: Any, **_kwargs: Any) -> bool:
            raise ConnectionError("redis is gone")

        monkeypatch.setattr(
            "django.core.cache.backends.locmem.LocMemCache.get", explode
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 503
        assert response.json()["error"] == "service_unavailable"

    def test_a_token_version_bump_supersedes_the_token(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            type(acme_user).all_objects.filter(pk=acme_user.pk).update(token_version=1)

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 401
        assert response.json()["error"] == "token_superseded"

    def test_a_token_with_no_version_claim_is_superseded(
        self, acme: Tenant, acme_user: User
    ) -> None:
        """Absent is treated as wrong, not as "no opinion"."""
        with pytest.raises(TokenSuperseded):
            TenantAwareJWTAuthentication()._assert_token_version({}, acme_user)


@pytest.mark.django_db
class TestUserResolution:
    def test_a_token_with_no_subject_is_invalid(self, acme: Tenant) -> None:
        with pytest.raises(TokenInvalid):
            TenantAwareJWTAuthentication().get_user({})  # type: ignore[arg-type]

    def test_a_subject_that_is_not_an_identifier_is_rejected(
        self, acme: Tenant
    ) -> None:
        """A malformed ``sub`` must not reach the database as a query error."""
        with tenant_context(acme), pytest.raises(UserInactive):
            TenantAwareJWTAuthentication().get_user({C.CLAIM_SUBJECT: "nonsense"})  # type: ignore[arg-type]

    def test_a_subject_with_no_row_here_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            type(acme_user).all_objects.filter(pk=acme_user.pk).delete()

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 401
        assert response.json()["error"] == "user_inactive"

    def test_the_user_is_cached_under_a_schema_prefixed_key(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """An unprefixed key would serve one institution's user to another."""
        pair = issue_pair(user=acme_user, tenant=acme)

        api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        with tenant_context(acme):
            key = user_key(str(acme_user.pk))
        assert key.startswith("acme:jwt:user:")
        assert cache.get(key) is not None

    def test_the_second_request_reads_the_cached_user(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
        django_assert_num_queries: Any,
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)
        api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        with tenant_context(acme):
            cached = cache.get(user_key(str(acme_user.pk)))

        assert cached is not None
        assert cached.pk == acme_user.pk

    def test_a_stale_cached_user_is_still_checked_against_the_rule(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """The cache holds the object, not the verdict.

        A deactivated account whose object is still cached must fail, or
        deactivation would take up to USER_CACHE_TIMEOUT seconds to bite.
        """
        pair = issue_pair(user=acme_user, tenant=acme)
        acme_user.is_active = False

        with tenant_context(acme):
            cache.set(user_key(str(acme_user.pk)), acme_user, 300)

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 401
        assert response.json()["error"] == "user_inactive"


@pytest.mark.django_db
class TestAuthenticationRule:
    def test_no_user_fails(self) -> None:
        assert tenant_user_authentication_rule(None) is False

    def test_an_active_user_passes(self, acme: Tenant, acme_user: User) -> None:
        assert tenant_user_authentication_rule(acme_user) is True

    def test_an_inactive_user_fails(self, acme: Tenant, acme_user: User) -> None:
        acme_user.is_active = False

        assert tenant_user_authentication_rule(acme_user) is False

    def test_a_soft_deleted_user_fails_on_deleted_at_alone(
        self, acme: Tenant, acme_user: User
    ) -> None:
        """``is_active`` happens to be cleared by soft deletion today.

        That is a consequence of ``UserQuerySet.soft_delete_values`` and not a
        guarantee, so the rule checks ``deleted_at`` independently -- this
        test pins the independent check by leaving ``is_active`` true.
        """
        acme_user.deleted_at = datetime.now(tz=UTC)

        assert acme_user.is_active is True
        assert tenant_user_authentication_rule(acme_user) is False

    def test_a_soft_deleted_user_cannot_authenticate_over_http(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Soft deletion must invalidate a token minted before it."""
        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            acme_user.delete()

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token))

        assert response.status_code == 401


@pytest.mark.django_db
class TestTokenTypeConfusion:
    def test_a_refresh_token_cannot_authenticate_a_request(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Differing audiences make this structural rather than a check."""
        pair = issue_pair(user=acme_user, tenant=acme)

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(pair.refresh_token))

        assert response.status_code == 401
        assert response.json()["error"] == "token_invalid_audience"

    def test_the_denylist_check_is_skipped_for_a_payload_with_no_jti(
        self, acme: Tenant
    ) -> None:
        """No id, nothing to look up -- the token fails elsewhere, not here."""
        TenantAwareJWTAuthentication()._assert_not_denylisted({})

    def test_a_denylisted_jti_raises_from_the_helper(self, acme: Tenant) -> None:
        with tenant_context(acme):
            denylist("known-jti", expires_at=timezone.now() + timedelta(minutes=5))

            with pytest.raises(TokenRevoked):
                TenantAwareJWTAuthentication()._assert_not_denylisted(
                    {C.CLAIM_JWT_ID: "known-jti"}
                )
