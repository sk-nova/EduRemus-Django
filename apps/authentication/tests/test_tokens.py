"""The token layer in isolation: validator branches, denylist, token types.

``tokens/`` is pure by design -- it imports nothing from ``services/`` -- so
almost everything here can be driven directly, without a request. The branches
that a well-formed token can never reach are exactly the ones an attacker
tries, which is why they are exercised by hand rather than left to the
end-to-end tests.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from django.core.cache import caches
from django.utils import timezone

from apps.authentication.exceptions import (
    ServiceUnavailable,
    TokenInvalid,
    TokenMalformed,
    TokenWrongTenant,
    TokenWrongType,
)
from apps.authentication.tokens import claims as C
from apps.authentication.tokens.denylist import denylist, denylist_many, is_denylisted
from apps.authentication.tokens.types import TenantAccessToken, TenantRefreshToken
from apps.authentication.tokens.validator import TenantTokenValidator
from apps.authentication.utils.cache_keys import denylist_key, session_key
from apps.tenants.utils import tenant_context

from .conftest import TEST_KID

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant


def resign(claims: dict[str, Any], private_pem: bytes, *, kid: str = TEST_KID) -> str:
    """Sign an edited claim set with the key the ring trusts."""
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


def claims_of(token: str) -> dict[str, Any]:
    return jwt.decode(token, options={"verify_signature": False})


@pytest.mark.django_db
class TestValidatorBranches:
    def test_a_wrong_token_type_is_rejected(self, acme: Tenant) -> None:
        """Redundant with the audience check today, and free to keep.

        A control that is merely redundant stops being redundant the moment
        the two audiences are ever unified.
        """
        with pytest.raises(TokenWrongType):
            TenantTokenValidator().assert_token_type(
                {C.CLAIM_TOKEN_TYPE: C.TOKEN_TYPE_REFRESH},
                expected=C.TOKEN_TYPE_ACCESS,
            )

    def test_a_missing_type_specific_claim_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
    ) -> None:
        """``jtv`` is required of an access token but checked after the type,
        so a refresh token presented as one reports the audience mismatch that
        actually describes the mistake."""
        private_pem, _public = rsa_keypair
        pair = issue_pair(user=acme_user, tenant=acme)
        claims = claims_of(pair.access_token)
        del claims[C.CLAIM_TOKEN_VERSION]

        with tenant_context(acme), pytest.raises(TokenInvalid):
            TenantTokenValidator().decode(
                resign(claims, private_pem), expected_type=C.TOKEN_TYPE_ACCESS
            )

    def test_a_token_with_an_unreadable_header_is_malformed(self, acme: Tenant) -> None:
        with pytest.raises(TokenMalformed):
            TenantTokenValidator().decode("garbage", expected_type=C.TOKEN_TYPE_ACCESS)

    def test_a_tenant_id_mismatch_is_a_wrong_tenant(self, acme: Tenant) -> None:
        """The second, independently sourced comparison.

        ``sch`` is checked against the connection and ``tid`` against the row
        the middleware resolved from the hostname; a defect that desynchronises
        one is caught by the other.
        """
        with pytest.raises(TokenWrongTenant):
            TenantTokenValidator().assert_tenant_binding(
                {C.CLAIM_TENANT_ID: 999, C.CLAIM_SCHEMA: "acme"}, acme.pk
            )

    def test_an_unexpected_pyjwt_failure_maps_to_token_invalid(self) -> None:
        """The taxonomy has to answer for a library error it does not name."""
        from apps.authentication.tokens.validator import _translate

        assert isinstance(_translate(jwt.PyJWTError("something new")), TokenInvalid)

    def test_a_refresh_token_decodes_through_the_same_path(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            payload = TenantTokenValidator().decode(
                pair.refresh_token, expected_type=C.TOKEN_TYPE_REFRESH
            )

        assert payload[C.CLAIM_FAMILY]
        assert payload[C.CLAIM_TOKEN_TYPE] == C.TOKEN_TYPE_REFRESH


@pytest.mark.django_db
class TestTokenTypes:
    def test_the_access_token_class_wraps_an_existing_token(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            token = TenantAccessToken(pair.access_token)

        assert str(token) == pair.access_token
        assert token.payload[C.CLAIM_SCHEMA] == "acme"

    def test_it_refuses_to_mint(self, acme: Tenant) -> None:
        """There is deliberately one code path that produces a token, and it
        is ``TokenService`` -- a second could produce a different claim set."""
        with pytest.raises(TypeError, match="mint through"):
            TenantAccessToken()

    def test_it_accepts_the_bytes_simplejwt_hands_it(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """``get_raw_token`` returns bytes, and ``str()`` on bytes yields the
        repr -- which is not a JWT and fails in a way that looks like a
        malformed token rather than a decoding mistake."""
        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            token = TenantAccessToken(pair.access_token.encode("ascii"))

        assert str(token) == pair.access_token

    def test_verify_is_a_no_op(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """Re-checking through SimpleJWT's own settings would duplicate the
        work against a different configuration source."""
        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme):
            TenantAccessToken(pair.access_token).verify()

    def test_the_refresh_class_rejects_an_access_token(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """The audience differs, so the two are not interchangeable even
        through the class that decodes them."""
        from apps.authentication.exceptions import TokenInvalidAudience

        pair = issue_pair(user=acme_user, tenant=acme)

        with tenant_context(acme), pytest.raises(TokenInvalidAudience):
            TenantRefreshToken(pair.access_token)


@pytest.mark.django_db
class TestDenylist:
    def test_an_entry_expires_with_the_token(self, acme: Tenant) -> None:
        """No cleanup job exists, so none can be forgotten: the TTL is the
        token's own remaining lifetime."""
        jti = str(uuid.uuid7())

        with tenant_context(acme):
            denylist(jti, expires_at=timezone.now() + timedelta(minutes=5))
            key = denylist_key(jti)

            assert caches["denylist"].get(key) is True

    def test_an_already_expired_token_is_not_stored(self, acme: Tenant) -> None:
        """The signature check rejects it regardless, and an entry with a
        non-positive TTL is stored forever by some backends."""
        jti = str(uuid.uuid7())

        with tenant_context(acme):
            denylist(jti, expires_at=timezone.now() - timedelta(seconds=1))

            assert is_denylisted(jti) is False

    def test_a_family_can_be_denylisted_at_once(self, acme: Tenant) -> None:
        jtis = [str(uuid.uuid7()) for _ in range(3)]

        with tenant_context(acme):
            written = denylist_many(
                jtis, expires_at=timezone.now() + timedelta(minutes=5)
            )

            assert written == 3
            assert all(is_denylisted(jti) for jti in jtis)

    def test_denylisting_nothing_writes_nothing(self, acme: Tenant) -> None:
        with tenant_context(acme):
            assert (
                denylist_many([], expires_at=timezone.now() + timedelta(minutes=5)) == 0
            )

    def test_an_expired_batch_is_not_stored(self, acme: Tenant) -> None:
        with tenant_context(acme):
            assert (
                denylist_many(
                    ["a", "b"], expires_at=timezone.now() - timedelta(seconds=1)
                )
                == 0
            )

    def test_an_unreachable_denylist_raises_rather_than_answering(
        self, acme: Tenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The one place in the codebase that fails closed.

        Everywhere else a Redis outage degrades. Here, "cannot tell" answered
        as "not revoked" is the wrong answer in the one direction that matters.
        """

        def explode(*_args: Any, **_kwargs: Any) -> None:
            raise ConnectionError("redis is gone")

        monkeypatch.setattr(
            "django.core.cache.backends.locmem.LocMemCache.get", explode
        )

        with tenant_context(acme), pytest.raises(ServiceUnavailable):
            is_denylisted("any-jti")


@pytest.mark.django_db
class TestCacheKeys:
    def test_a_session_key_is_schema_scoped_like_every_other(
        self, acme: Tenant
    ) -> None:
        with tenant_context(acme):
            assert session_key("abc") == "acme:jwt:session:abc"
