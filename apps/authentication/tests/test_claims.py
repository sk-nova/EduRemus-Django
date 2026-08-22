"""Claim construction and the vocabulary it is built from.

Two questions are asked here, and they matter for different reasons. What a
minted token *contains* is a security property -- a missing ``sch`` disables
the isolation check, an extra ``permissions`` array is a privilege list frozen
for fifteen minutes. What it *does not* contain is the same property read the
other way, so the exclusions are asserted as explicitly as the inclusions.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import jwt
import pytest

from apps.authentication.tokens import claims as C
from apps.authentication.utils.scopes import (
    ALL_SCOPES,
    BASE_SCOPES,
    ROLE_SCOPES,
    scopes_for_roles,
)
from apps.tenants.utils import tenant_context

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant


def decode(token: str) -> dict[str, Any]:
    """Read a payload without verifying it. Inspection, not validation."""
    return jwt.decode(token, options={"verify_signature": False})


class TestVocabulary:
    def test_the_two_version_claims_are_distinct(self) -> None:
        """``ver`` is the payload shape; ``jtv`` is the account's generation.

        Routinely confused, and confusing them is how a claim-schema bump
        silently signs every user out.
        """
        assert C.CLAIM_VERSION == "ver"
        assert C.CLAIM_TOKEN_VERSION == "jtv"

    def test_each_token_type_has_its_own_audience(self) -> None:
        """Different audiences are what make token confusion structural."""
        assert C.AUDIENCE_BY_TOKEN_TYPE[C.TOKEN_TYPE_ACCESS] == C.AUDIENCE_API
        assert C.AUDIENCE_BY_TOKEN_TYPE[C.TOKEN_TYPE_REFRESH] == C.AUDIENCE_AUTH
        assert C.AUDIENCE_API != C.AUDIENCE_AUTH

    def test_the_tenancy_claims_are_required_of_every_token(self) -> None:
        """A token with no ``sch`` must fail to decode, not skip the check."""
        assert C.CLAIM_SCHEMA in C.REQUIRED_COMMON_CLAIMS
        assert C.CLAIM_TENANT_ID in C.REQUIRED_COMMON_CLAIMS

    def test_type_specific_claims_are_not_required_during_decode(self) -> None:
        """PyJWT checks required claims before audience.

        Requiring ``jtv`` up front would report a refresh token presented as
        an access token as "missing jtv" -- true, and far less useful than the
        audience mismatch that actually describes the mistake.
        """
        assert C.CLAIM_TOKEN_VERSION not in C.REQUIRED_COMMON_CLAIMS
        assert C.REQUIRED_CLAIMS_BY_TOKEN_TYPE[C.TOKEN_TYPE_ACCESS] == (
            C.CLAIM_TOKEN_VERSION,
        )

    def test_the_current_claim_version_is_accepted(self) -> None:
        assert C.CLAIM_SCHEMA_VERSION in C.SUPPORTED_CLAIM_VERSIONS


class TestScopeMapping:
    def test_every_principal_holds_the_base_scopes(self) -> None:
        assert set(scopes_for_roles([])) >= set()
        assert scopes_for_roles([]).split() == sorted(BASE_SCOPES)

    def test_roles_are_additive(self) -> None:
        """Two roles confer the union, never the intersection."""
        both = set(scopes_for_roles(["faculty", "course_coordinator"]).split())

        assert both >= ROLE_SCOPES["faculty"]
        assert both >= ROLE_SCOPES["course_coordinator"]

    def test_an_unknown_role_contributes_nothing_and_does_not_raise(self) -> None:
        """A tenant may define its own groups; that is not an error."""
        assert scopes_for_roles(["chess-club"]) == scopes_for_roles([])

    def test_the_scope_string_is_sorted_and_deduplicated(self) -> None:
        scopes = scopes_for_roles(["student", "faculty", "student"]).split()

        assert scopes == sorted(set(scopes))

    def test_all_scopes_covers_every_role(self) -> None:
        """Guards a permission class requiring a scope nothing can issue."""
        for granted in ROLE_SCOPES.values():
            assert granted <= ALL_SCOPES


@pytest.mark.django_db
class TestAccessTokenClaims:
    @pytest.fixture
    def pair(
        self,
        acme: Tenant,
        acme_user: User,
        grant_role: Callable[..., None],
        issue_pair: Callable[..., TokenPair],
    ) -> TokenPair:
        grant_role(acme_user, "faculty", tenant=acme)
        return issue_pair(user=acme_user, tenant=acme, device_id="device-xyz")

    def test_it_carries_the_tenancy_claims(self, pair: TokenPair, acme: Tenant) -> None:
        """Both of them: the two independent comparisons need two sources."""
        payload = decode(pair.access_token)

        assert payload[C.CLAIM_SCHEMA] == "acme"
        assert payload[C.CLAIM_TENANT_ID] == acme.pk
        assert payload[C.CLAIM_ORGANISATION] == acme.slug

    def test_it_carries_the_session_and_device_claims(self, pair: TokenPair) -> None:
        payload = decode(pair.access_token)

        assert payload[C.CLAIM_SESSION_ID]
        assert payload[C.CLAIM_DEVICE_ID] == "device-xyz"

    def test_it_carries_the_roles_and_their_scopes(self, pair: TokenPair) -> None:
        payload = decode(pair.access_token)

        assert payload[C.CLAIM_ROLES] == ["faculty"]
        assert set(payload[C.CLAIM_SCOPES].split()) >= ROLE_SCOPES["faculty"]

    def test_the_token_version_is_read_from_the_user(
        self, acme: Tenant, acme_user: User, issue_pair: Callable[..., TokenPair]
    ) -> None:
        """Never accepted as a parameter.

        A caller passing a value it captured before a revocation is exactly
        how a "log out everywhere" hands back a token that outlives it.
        """
        with tenant_context(acme):
            type(acme_user).all_objects.filter(pk=acme_user.pk).update(token_version=7)
            acme_user.refresh_from_db()

        payload = decode(issue_pair(user=acme_user, tenant=acme).access_token)

        assert payload[C.CLAIM_TOKEN_VERSION] == 7

    def test_the_header_names_the_signing_key(self, pair: TokenPair) -> None:
        """Without a ``kid`` a verifier cannot pick a key during a rotation."""
        header = jwt.get_unverified_header(pair.access_token)

        assert header["kid"] == "test-key"
        assert header["alg"] == "RS256"

    def test_it_carries_no_permission_enumeration(self, pair: TokenPair) -> None:
        """Scopes, not permissions.

        A permission list in a token is a snapshot of authorisation frozen for
        the token's lifetime, and it grows with the model until the token no
        longer fits in a header.
        """
        payload = decode(pair.access_token)

        assert "permissions" not in payload
        assert "perms" not in payload
        assert "groups" not in payload

    def test_it_carries_no_secret(self, pair: TokenPair) -> None:
        """A JWT is signed, not encrypted -- anyone holding it reads it."""
        payload = decode(pair.access_token)

        assert "password" not in payload
        assert "token" not in payload
        assert not any("secret" in key.lower() for key in payload)

    def test_the_expiry_matches_the_configured_lifetime(self, pair: TokenPair) -> None:
        payload = decode(pair.access_token)

        assert payload[C.CLAIM_EXPIRES_AT] - payload[C.CLAIM_ISSUED_AT] == 15 * 60
        assert pair.access_expires_in == 15 * 60


@pytest.mark.django_db
class TestRefreshTokenClaims:
    @pytest.fixture
    def pair(
        self,
        acme: Tenant,
        acme_user: User,
        grant_role: Callable[..., None],
        issue_pair: Callable[..., TokenPair],
    ) -> TokenPair:
        grant_role(acme_user, "faculty", tenant=acme)
        return issue_pair(user=acme_user, tenant=acme)

    def test_it_carries_the_family_and_generation(self, pair: TokenPair) -> None:
        payload = decode(pair.refresh_token)

        assert payload[C.CLAIM_FAMILY]
        assert payload[C.CLAIM_GENERATION] == 1

    def test_it_carries_no_roles_or_profile_data(self, pair: TokenPair) -> None:
        """Re-read on every rotation instead.

        That is what lets a role change take effect within one access-token
        lifetime rather than persisting for the refresh token's seven days.
        """
        payload = decode(pair.refresh_token)

        for claim in (
            C.CLAIM_ROLES,
            C.CLAIM_SCOPES,
            C.CLAIM_EMAIL,
            C.CLAIM_NAME,
            C.CLAIM_IS_STAFF,
        ):
            assert claim not in payload

    def test_its_audience_is_not_the_api(self, pair: TokenPair) -> None:
        payload = decode(pair.refresh_token)

        assert payload[C.CLAIM_AUDIENCE] == [C.AUDIENCE_AUTH]
        assert payload[C.CLAIM_TOKEN_TYPE] == C.TOKEN_TYPE_REFRESH

    def test_the_absolute_deadline_caps_the_sliding_one(self, pair: TokenPair) -> None:
        """A sliding window alone lets a stolen lineage live forever."""
        payload = decode(pair.refresh_token)
        lifetime = payload[C.CLAIM_EXPIRES_AT] - payload[C.CLAIM_ISSUED_AT]

        # Seven-day sliding window, capped at thirty days from the family's
        # creation -- which is a few seconds old here, so the sliding value
        # is the one that wins.
        assert lifetime == 7 * 24 * 3600

    def test_only_the_digest_of_the_refresh_token_is_carried_for_storage(
        self, pair: TokenPair
    ) -> None:
        from apps.authentication.utils.hashing import token_digest

        assert pair.refresh_token_hash == token_digest(pair.refresh_token)
        assert pair.refresh_token not in pair.refresh_token_hash
