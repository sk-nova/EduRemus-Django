"""Keyring loading, ``kid`` resolution and the JWKS document.

The keyring is the component whose failure mode is "accepts a token it should
not", so these tests build rings directly rather than through the fixture:
what happens with two keys, with an expired one, or with a ``kid`` the ring
has never heard of is the whole subject.
"""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.exceptions import ImproperlyConfigured
from django.test import Client as HttpClient
from django.utils import timezone

from apps.authentication.exceptions import TokenUnknownKey
from apps.authentication.tokens.keys import Keyring, SigningKey

from .conftest import PUBLIC_HOST, TEST_KID


def make_key(
    kid: str,
    keypair: tuple[bytes, bytes],
    *,
    not_before: Any = None,
    not_after: Any = None,
) -> SigningKey:
    private_pem, public_pem = keypair
    now = timezone.now()
    return SigningKey(
        kid=kid,
        private_pem=private_pem,
        public_pem=public_pem,
        not_before=not_before or now - timedelta(days=1),
        not_after=not_after or now + timedelta(days=120),
    )


class TestKeyValidity:
    def test_a_key_inside_its_window_may_sign(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        assert make_key("current", rsa_keypair).is_usable_for_signing is True

    def test_a_key_past_its_window_may_not_sign(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """It stays in the ring: retired from signing is not retired from
        verifying, and that gap is the entire rotation overlap."""
        now = timezone.now()
        retired = make_key(
            "retired",
            rsa_keypair,
            not_before=now - timedelta(days=200),
            not_after=now - timedelta(days=1),
        )

        assert retired.is_usable_for_signing is False

    def test_a_key_not_yet_valid_may_not_sign(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        now = timezone.now()
        staged = make_key(
            "staged",
            rsa_keypair,
            not_before=now + timedelta(days=1),
            not_after=now + timedelta(days=120),
        )

        assert staged.is_usable_for_signing is False


class TestKidResolution:
    def test_the_active_key_is_the_one_that_signs(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        ring = Keyring(
            {"old": make_key("old", rsa_keypair), "new": make_key("new", rsa_keypair)},
            "old",
        )

        assert ring.active().kid == "old"

    def test_every_key_in_the_ring_verifies(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """The outgoing key must keep verifying tokens already in circulation."""
        ring = Keyring(
            {"old": make_key("old", rsa_keypair), "new": make_key("new", rsa_keypair)},
            "new",
        )

        assert ring.public_for("old")
        assert ring.public_for("new")

    def test_an_unknown_kid_is_a_rejection_and_not_a_fetch(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """``kid`` is attacker-controlled: a closed lookup, never a path."""
        ring = Keyring({"only": make_key("only", rsa_keypair)}, "only")

        with pytest.raises(TokenUnknownKey):
            ring.public_for("../../etc/passwd")

    def test_an_empty_kid_is_rejected(self, rsa_keypair: tuple[bytes, bytes]) -> None:
        ring = Keyring({"only": make_key("only", rsa_keypair)}, "only")

        with pytest.raises(TokenUnknownKey):
            ring.public_for("")


class TestJwksDocument:
    def test_it_publishes_every_trusted_key(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        ring = Keyring(
            {"old": make_key("old", rsa_keypair), "new": make_key("new", rsa_keypair)},
            "new",
        )

        published = {key["kid"] for key in ring.jwks()["keys"]}

        assert published == {"old", "new"}

    def test_each_entry_is_a_well_formed_rsa_jwk(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        ring = Keyring({"a": make_key("a", rsa_keypair)}, "a")

        jwk = ring.jwks()["keys"][0]

        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert jwk["n"] and jwk["e"]

    def test_the_modulus_matches_the_public_key(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """A JWKS whose numbers do not match the PEM verifies nothing."""
        _private_pem, public_pem = rsa_keypair
        ring = Keyring({"a": make_key("a", rsa_keypair)}, "a")

        jwk = ring.jwks()["keys"][0]
        public = serialization.load_pem_public_key(public_pem)
        assert isinstance(public, rsa.RSAPublicKey)
        numbers = public.public_numbers()

        assert _b64u_to_int(jwk["n"]) == numbers.n
        assert _b64u_to_int(jwk["e"]) == numbers.e

    def test_it_contains_no_private_material(
        self, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """The one assertion that makes publishing this document safe."""
        ring = Keyring({"a": make_key("a", rsa_keypair)}, "a")

        document = json.dumps(ring.jwks())

        assert "PRIVATE" not in document
        for private_only in ("d", "p", "q", "dp", "dq", "qi"):
            assert private_only not in ring.jwks()["keys"][0]


class TestLoadingFromTheStore:
    def test_it_reads_the_directory_the_settings_name(
        self, jwt_key_directory: Path
    ) -> None:
        ring = Keyring.load(force=True)

        assert ring.kids == (TEST_KID,)
        assert ring.active().kid == TEST_KID

    def test_the_ring_is_cached_between_calls(self, jwt_key_directory: Path) -> None:
        """Re-reading the filesystem per request would be a syscall per token."""
        assert Keyring.load() is Keyring.load()

    def test_force_re_reads_the_store(self, jwt_key_directory: Path) -> None:
        """What makes a rotation propagate without a restart."""
        first = Keyring.load(force=True)
        second = Keyring.load(force=True)

        assert first is not second
        assert first.kids == second.kids

    def test_a_new_key_file_is_picked_up_on_reload(
        self, jwt_key_directory: Path, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, public_pem = rsa_keypair
        now = timezone.now()
        (jwt_key_directory / "incoming.private.pem").write_bytes(private_pem)
        (jwt_key_directory / "incoming.public.pem").write_bytes(public_pem)
        (jwt_key_directory / "incoming.json").write_text(
            json.dumps(
                {
                    "kid": "incoming",
                    "not_before": (now - timedelta(hours=1)).isoformat(),
                    "not_after": (now + timedelta(days=120)).isoformat(),
                }
            ),
            encoding="utf-8",
        )

        try:
            ring = Keyring.load(force=True)
            assert set(ring.kids) == {TEST_KID, "incoming"}
            # Still signing with the configured key: appearing in the ring is
            # not promotion.
            assert ring.active().kid == TEST_KID
        finally:
            for suffix in (".private.pem", ".public.pem", ".json"):
                (jwt_key_directory / f"incoming{suffix}").unlink()
            Keyring.load(force=True)

    def test_a_missing_directory_is_a_configuration_error(self, settings: Any) -> None:
        settings.JWT_AUTH = {**settings.JWT_AUTH, "KEY_DIRECTORY": "/no/such/place"}

        with pytest.raises(ImproperlyConfigured, match="not found"):
            Keyring.load(force=True)

        Keyring.reset()

    def test_an_empty_directory_is_a_configuration_error(
        self, settings: Any, tmp_path: Path
    ) -> None:
        settings.JWT_AUTH = {**settings.JWT_AUTH, "KEY_DIRECTORY": str(tmp_path)}

        with pytest.raises(ImproperlyConfigured, match="No JWT signing keys"):
            Keyring.load(force=True)

        Keyring.reset()

    def test_an_active_kid_that_is_absent_is_a_configuration_error(
        self, settings: Any, jwt_key_directory: Path
    ) -> None:
        """Fails at load rather than at the first signature."""
        settings.JWT_AUTH = {**settings.JWT_AUTH, "ACTIVE_KEY_ID": "not-present"}

        with pytest.raises(ImproperlyConfigured, match="not in the keyring"):
            Keyring.load(force=True)

        Keyring.reset()

    def test_without_an_active_kid_the_newest_signable_key_is_used(
        self, settings: Any, jwt_key_directory: Path, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, public_pem = rsa_keypair
        now = timezone.now()
        (jwt_key_directory / "newer.private.pem").write_bytes(private_pem)
        (jwt_key_directory / "newer.public.pem").write_bytes(public_pem)
        (jwt_key_directory / "newer.json").write_text(
            json.dumps(
                {
                    "kid": "newer",
                    "not_before": (now - timedelta(minutes=1)).isoformat(),
                    "not_after": (now + timedelta(days=120)).isoformat(),
                }
            ),
            encoding="utf-8",
        )
        settings.JWT_AUTH = {**settings.JWT_AUTH, "ACTIVE_KEY_ID": ""}

        try:
            assert Keyring.load(force=True).active().kid == "newer"
        finally:
            for suffix in (".private.pem", ".public.pem", ".json"):
                (jwt_key_directory / f"newer{suffix}").unlink()
            Keyring.reset()

    def test_a_naive_metadata_timestamp_is_read_as_utc(
        self, settings: Any, tmp_path: Path, rsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """A naive value would raise on the first comparison -- at signing
        time, in production. Normalising turns it into a validity window."""
        private_pem, public_pem = rsa_keypair
        (tmp_path / "naive.private.pem").write_bytes(private_pem)
        (tmp_path / "naive.public.pem").write_bytes(public_pem)
        (tmp_path / "naive.json").write_text(
            json.dumps(
                {
                    "kid": "naive",
                    "not_before": "2020-01-01T00:00:00",
                    "not_after": "2099-01-01T00:00:00",
                }
            ),
            encoding="utf-8",
        )
        settings.JWT_AUTH = {
            **settings.JWT_AUTH,
            "KEY_DIRECTORY": str(tmp_path),
            "ACTIVE_KEY_ID": "naive",
        }

        try:
            assert Keyring.load(force=True).active().is_usable_for_signing is True
        finally:
            Keyring.reset()


@pytest.mark.django_db
class TestJwksEndpoint:
    def test_it_serves_the_public_keys_on_the_platform_host(
        self, public_tenant: Any, api_client: HttpClient
    ) -> None:
        response = api_client.get("/.well-known/jwks.json", HTTP_HOST=PUBLIC_HOST)

        assert response.status_code == 200
        assert [key["kid"] for key in response.json()["keys"]] == [TEST_KID]

    def test_it_is_edge_cacheable(
        self, public_tenant: Any, api_client: HttpClient
    ) -> None:
        """An hour, which is far shorter than any rotation overlap."""
        response = api_client.get("/.well-known/jwks.json", HTTP_HOST=PUBLIC_HOST)

        assert response["Cache-Control"] == "public, max-age=3600"

    def test_it_needs_no_credential(
        self, public_tenant: Any, api_client: HttpClient
    ) -> None:
        """Verification keys are public by design; gating them helps nobody."""
        response = api_client.get("/.well-known/jwks.json", HTTP_HOST=PUBLIC_HOST)

        assert response.status_code == 200

    def test_it_is_not_served_from_a_tenant_host(
        self, acme: Any, api_client: HttpClient
    ) -> None:
        """A per-tenant JWKS would imply per-tenant keys, which do not exist."""
        from .conftest import ACME_HOST

        response = api_client.get("/.well-known/jwks.json", HTTP_HOST=ACME_HOST)

        assert response.status_code == 404


def _b64u_to_int(value: str) -> int:
    padded = value + "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")
