"""Attacks the implementation has to resist.

Each test here corresponds to a published attack against JWT deployments
rather than to a line of code, which is why the forgeries are constructed by
hand: asserting that ``jwt.decode`` was called with the right arguments would
pass against an implementation that never rejected anything.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import statistics
import time
from collections.abc import Callable
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from django.conf import settings
from django.test import Client as HttpClient
from django.utils import timezone
from freezegun import freeze_time

from apps.authentication.tokens import claims as C

from .conftest import ACME_HOST, PASSWORD, TEST_KID

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant

ME = "/api/v1/auth/me/"
LOGIN = "/api/v1/auth/login/"


def b64u(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def payload_of(token: str) -> dict[str, Any]:
    return jwt.decode(token, options={"verify_signature": False})


def hs256_forgery(claims: dict[str, Any], *, secret: bytes) -> str:
    """An HS256 token signed with the published RSA public key."""
    header = b64u({"alg": "HS256", "typ": "JWT", "kid": TEST_KID})
    signing_input = f"{header}.{b64u(claims)}"
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{signing_input}.{encoded}"


@pytest.mark.django_db
class TestSignatureForgery:
    def test_alg_none_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """The classic forgery: strip the signature and declare ``alg: none``.

        Defeated by passing a one-element algorithm allow-list from settings,
        which is applied before any key is selected.
        """
        pair = issue_pair(user=acme_user, tenant=acme)
        _header, body, _signature = pair.access_token.split(".")
        forged = f"{b64u({'alg': 'none', 'typ': 'JWT'})}.{body}."

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401

    def test_rs256_to_hs256_confusion_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """The public key is published at the JWKS endpoint by design.

        A verifier that read ``alg`` from the header would HMAC-verify with
        that public value and accept the result -- so the public key must not
        be usable as a shared secret.
        """
        _private_pem, public_pem = rsa_keypair
        pair = issue_pair(user=acme_user, tenant=acme)

        # Assembled by hand: PyJWT refuses to *sign* with a PEM as an HMAC
        # secret, and an attacker is under no such constraint. Using the
        # library here would test PyJWT's guard rail rather than this
        # application's algorithm allow-list.
        forged = hs256_forgery(payload_of(pair.access_token), secret=public_pem)

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401

    def test_a_stripped_signature_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)
        header, body, _signature = pair.access_token.split(".")

        response = api_client.get(
            ME, HTTP_HOST=ACME_HOST, **bearer(f"{header}.{body}.")
        )

        assert response.status_code == 401

    def test_tampered_claims_are_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Privilege escalation by editing the payload."""
        pair = issue_pair(user=acme_user, tenant=acme)
        header, _body, signature = pair.access_token.split(".")

        claims = payload_of(pair.access_token)
        claims[C.CLAIM_ROLES] = ["tenant_admin"]
        claims[C.CLAIM_SCOPES] = "users:admin courses:admin"

        response = api_client.get(
            ME, HTTP_HOST=ACME_HOST, **bearer(f"{header}.{b64u(claims)}.{signature}")
        )

        assert response.status_code == 401

    def test_a_token_signed_by_a_foreign_key_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """A well-formed token from an issuer this deployment does not trust."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = attacker.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pair = issue_pair(user=acme_user, tenant=acme)
        forged = jwt.encode(
            payload_of(pair.access_token),
            pem,
            algorithm="RS256",
            headers={"kid": TEST_KID},
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401

    def test_an_injected_kid_is_a_lookup_failure(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """``kid`` is attacker-chosen and may only select from a closed map."""
        private_pem, _public = rsa_keypair
        pair = issue_pair(user=acme_user, tenant=acme)
        forged = jwt.encode(
            payload_of(pair.access_token),
            private_pem,
            algorithm="RS256",
            headers={"kid": "../../etc/passwd"},
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401
        assert response.json()["error"] == "token_unknown_key"


@pytest.mark.django_db
class TestClaimForgery:
    def test_a_missing_audience_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Audience verification is not optional: without it, any token this
        platform ever signed authenticates against any of its services."""
        private_pem, _public = rsa_keypair
        claims = payload_of(issue_pair(user=acme_user, tenant=acme).access_token)
        del claims[C.CLAIM_AUDIENCE]
        forged = jwt.encode(
            claims, private_pem, algorithm="RS256", headers={"kid": TEST_KID}
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401

    def test_a_foreign_issuer_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        private_pem, _public = rsa_keypair
        claims = payload_of(issue_pair(user=acme_user, tenant=acme).access_token)
        claims[C.CLAIM_ISSUER] = "https://auth.attacker.example"
        forged = jwt.encode(
            claims, private_pem, algorithm="RS256", headers={"kid": TEST_KID}
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401
        assert response.json()["error"] == "token_invalid_issuer"

    def test_an_unsupported_claim_version_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        private_pem, _public = rsa_keypair
        claims = payload_of(issue_pair(user=acme_user, tenant=acme).access_token)
        claims[C.CLAIM_VERSION] = 99
        forged = jwt.encode(
            claims, private_pem, algorithm="RS256", headers={"kid": TEST_KID}
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401
        assert response.json()["error"] == "token_version_unsupported"

    @pytest.mark.parametrize(
        "claim",
        [C.CLAIM_SCHEMA, C.CLAIM_TENANT_ID, C.CLAIM_JWT_ID, C.CLAIM_SESSION_ID],
    )
    def test_a_missing_required_claim_is_rejected(
        self,
        claim: str,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Absence must be a decode failure, never a check that is skipped."""
        private_pem, _public = rsa_keypair
        claims = payload_of(issue_pair(user=acme_user, tenant=acme).access_token)
        del claims[claim]
        forged = jwt.encode(
            claims, private_pem, algorithm="RS256", headers={"kid": TEST_KID}
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401


@pytest.mark.django_db
class TestTemporalHandling:
    def test_an_expired_token_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        with freeze_time(timezone.now()) as frozen:
            pair = issue_pair(user=acme_user, tenant=acme)
            # Past the 15-minute lifetime and the 30-second leeway.
            frozen.tick(timedelta(minutes=16))

            response = api_client.get(
                ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token)
            )

        assert response.status_code == 401
        assert response.json()["error"] == "token_expired"

    def test_a_token_inside_the_leeway_is_still_accepted(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Thirty seconds, which covers ordinary NTP drift and no more.

        A generous leeway is a silent extension of every token's lifetime.
        """
        with freeze_time(timezone.now()) as frozen:
            pair = issue_pair(user=acme_user, tenant=acme)
            frozen.tick(timedelta(minutes=15, seconds=10))

            response = api_client.get(
                ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token)
            )

        assert response.status_code == 200
        assert settings.SIMPLE_JWT["LEEWAY"] == timedelta(seconds=30)

    def test_a_not_yet_valid_token_is_rejected(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        rsa_keypair: tuple[bytes, bytes],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        private_pem, _public = rsa_keypair
        claims = payload_of(issue_pair(user=acme_user, tenant=acme).access_token)
        future = int((timezone.now() + timedelta(hours=1)).timestamp())
        claims[C.CLAIM_NOT_BEFORE] = future
        claims[C.CLAIM_EXPIRES_AT] = future + 900
        forged = jwt.encode(
            claims, private_pem, algorithm="RS256", headers={"kid": TEST_KID}
        )

        response = api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))

        assert response.status_code == 401

    def test_a_captured_token_replays_only_until_it_expires(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
    ) -> None:
        """Replay within the lifetime is inherent to bearer tokens; the short
        lifetime plus the denylist is the whole mitigation."""
        pair = issue_pair(user=acme_user, tenant=acme)

        for _ in range(3):
            assert (
                api_client.get(
                    ME, HTTP_HOST=ACME_HOST, **bearer(pair.access_token)
                ).status_code
                == 200
            )


@pytest.mark.django_db
class TestEnumeration:
    def test_the_verify_endpoint_gives_no_reason(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
    ) -> None:
        """Expired, revoked and wrong-tenant must be one answer.

        The endpoint is unauthenticated, so a differentiated reply would tell
        a caller whether a token is merely stale, is being watched, or belongs
        to another institution.
        """
        pair = issue_pair(user=acme_user, tenant=acme)
        answers = []

        for token in ("not-a-token", pair.refresh_token, "a.b.c"):
            response = api_client.post(
                "/api/v1/auth/verify/",
                data={"token": token},
                content_type="application/json",
                HTTP_HOST=ACME_HOST,
            )
            answers.append(response.json())

        assert all(answer == {"active": False} for answer in answers)

    def test_login_timing_does_not_reveal_whether_an_account_exists(
        self, acme: Tenant, acme_user: User, api_client: HttpClient
    ) -> None:
        """Asserts that the dummy hash exists at all.

        A wall-clock test cannot prove constant time, and pretending otherwise
        would produce a flaky test that gets deleted. Four attempts each: the
        fifth would trip the lockout and measure that instead.
        """

        def timed(email: str) -> float:
            started = time.perf_counter()
            api_client.post(
                LOGIN,
                data={"email": email, "password": "wrong-password"},
                content_type="application/json",
                HTTP_HOST=ACME_HOST,
            )
            return time.perf_counter() - started

        known = statistics.median(timed("priya@acme.edu") for _ in range(4))
        unknown = statistics.median(timed("nobody@acme.edu") for _ in range(4))

        assert abs(known - unknown) < max(known, unknown, 0.05)

    def test_an_unknown_host_and_a_suspended_tenant_answer_alike(
        self, acme: Tenant, api_client: HttpClient
    ) -> None:
        """Subdomain guessing must not confirm that a customer exists."""
        from apps.tenants.utils import public_schema

        unknown = api_client.get(ME, HTTP_HOST="nosuchtenant.testserver")

        with public_schema():
            type(acme).objects.filter(pk=acme.pk).update(is_active=False)
        suspended = api_client.get(ME, HTTP_HOST=ACME_HOST)

        assert unknown.status_code == suspended.status_code == 404


@pytest.mark.django_db
class TestCredentialsNeverEcho:
    def test_the_login_response_does_not_repeat_the_password(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        response = login(api_client)

        assert PASSWORD not in response.content.decode()

    def test_an_error_body_does_not_repeat_the_credential(
        self, acme: Tenant, acme_user: User, api_client: HttpClient, login: Callable
    ) -> None:
        """DRF echoes invalid input by default; the envelope must not."""
        response = login(api_client, password="wrong-but-memorable")

        assert "wrong-but-memorable" not in response.content.decode()

    def test_a_rejected_token_is_not_echoed(
        self, acme: Tenant, api_client: HttpClient, bearer: Callable[[str], dict]
    ) -> None:
        response = api_client.get(
            ME, HTTP_HOST=ACME_HOST, **bearer("eyJhbGciOiJub25lIn0.e30.")
        )

        assert "eyJhbGciOiJub25lIn0" not in response.content.decode()
        assert "eyJhbGciOiJub25lIn0" not in response.get("WWW-Authenticate", "")
