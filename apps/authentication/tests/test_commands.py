"""The operational commands.

Every one of these runs outside a request, where there is no ``Host`` header
and therefore no implicit schema. The recurring assertion in this module is
that each command establishes its schema explicitly -- a maintenance job that
silently operates on ``public`` because that is where the connection happened
to be pointing is the failure mode this whole layer exists to prevent.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from django.core.management import CommandError, call_command
from django.utils import timezone

from apps.authentication.models import (
    AuthAuditEvent,
    AuthEventType,
    RefreshToken,
    TokenStatus,
)
from apps.authentication.tokens.keys import Keyring
from apps.tenants.utils import public_schema, tenant_context

from .conftest import TEST_KID

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant


def run(command: str, *args: str, **options: Any) -> str:
    out = io.StringIO()
    call_command(command, *args, stdout=out, stderr=out, **options)
    return out.getvalue()


@pytest.fixture
def key_directory(tmp_path: Path, settings: Any) -> Iterator[Path]:
    """A scratch directory standing in for the secret-store mount."""
    settings.JWT_AUTH = {
        **settings.JWT_AUTH,
        "KEY_DIRECTORY": str(tmp_path),
        "ACTIVE_KEY_ID": "",
    }
    yield tmp_path
    Keyring.reset()


@pytest.mark.django_db
class TestRotateJwtKeys:
    def test_it_writes_the_three_files_of_the_contract(
        self, key_directory: Path
    ) -> None:
        run("rotate_jwt_keys", "--kid", "2026-Q4-a")

        assert (key_directory / "2026-Q4-a.private.pem").exists()
        assert (key_directory / "2026-Q4-a.public.pem").exists()
        metadata = json.loads((key_directory / "2026-Q4-a.json").read_text())
        assert metadata["kid"] == "2026-Q4-a"
        assert metadata["algorithm"] == "RS256"
        assert metadata["key_size"] == 2048

    def test_the_new_key_is_loadable(self, key_directory: Path) -> None:
        run("rotate_jwt_keys", "--kid", "2026-Q4-a")

        assert Keyring.load(force=True).kids == ("2026-Q4-a",)

    def test_it_reports_the_dates_the_later_phases_have_to_respect(
        self, key_directory: Path
    ) -> None:
        output = run("rotate_jwt_keys", "--kid", "2026-Q4-a")

        assert "valid until" in output
        assert "promote by" in output

    def test_activate_prints_instructions_and_promotes_nothing(
        self, key_directory: Path, settings: Any
    ) -> None:
        """Generation and promotion are separate on purpose: a key must be
        visible to every verifier before anything signs with it."""
        output = run("rotate_jwt_keys", "--kid", "2026-Q4-a", "--activate")

        assert "JWT_ACTIVE_KEY_ID=2026-Q4-a" in output
        assert settings.JWT_AUTH["ACTIVE_KEY_ID"] == ""

    def test_a_second_key_with_no_active_kid_warns_loudly(
        self, key_directory: Path
    ) -> None:
        """With no configured active kid the ring signs with the newest valid
        key, which collapses generate, propagate and promote into one step."""
        run("rotate_jwt_keys", "--kid", "first")

        output = run("rotate_jwt_keys", "--kid", "second")

        assert "begins signing within 5 minutes" in output

    @pytest.mark.parametrize(
        "kid", ["../escape", "with/slash", ".hidden", "with space", "a" * 65]
    )
    def test_a_kid_that_is_not_a_safe_filename_is_refused(
        self, kid: str, key_directory: Path
    ) -> None:
        """The kid becomes three paths, so it is validated as a filename."""
        with pytest.raises(CommandError, match="Invalid --kid"):
            run("rotate_jwt_keys", "--kid", kid)

    def test_an_existing_kid_is_never_overwritten(self, key_directory: Path) -> None:
        """Overwriting invalidates every unexpired token it signed, and the
        private key that could re-sign them is gone."""
        run("rotate_jwt_keys", "--kid", "2026-Q4-a")

        with pytest.raises(CommandError, match="already exists"):
            run("rotate_jwt_keys", "--kid", "2026-Q4-a")

    def test_a_weak_key_size_is_refused(self, key_directory: Path) -> None:
        with pytest.raises(CommandError, match="below the 2048-bit minimum"):
            run("rotate_jwt_keys", "--kid", "weak", "--key-size", "1024")

    def test_a_window_shorter_than_the_refresh_lifetime_is_refused(
        self, key_directory: Path
    ) -> None:
        """The overlap has to exceed the maximum refresh lifetime, or retiring
        the key strands credentials that were still redeemable."""
        with pytest.raises(CommandError, match="maximum refresh lifetime"):
            run("rotate_jwt_keys", "--kid", "brief", "--valid-days", "20")

    def test_a_missing_directory_is_refused_rather_than_created(
        self, settings: Any, tmp_path: Path
    ) -> None:
        """A typo in JWT_KEY_DIRECTORY would otherwise write a signing key
        outside the secret store and look like success."""
        settings.JWT_AUTH = {
            **settings.JWT_AUTH,
            "KEY_DIRECTORY": str(tmp_path / "absent"),
        }

        with pytest.raises(CommandError, match="does not exist"):
            run("rotate_jwt_keys", "--kid", "anything")

    def test_it_records_a_key_rotated_event_in_the_public_schema(
        self, key_directory: Path
    ) -> None:
        """Keys are platform-wide, so the record belongs in ``public`` and not
        in whichever tenant happened to be active."""
        run("rotate_jwt_keys", "--kid", "2026-Q4-a")

        with public_schema():
            event = AuthAuditEvent.objects.get(event_type=AuthEventType.KEY_ROTATED)

        assert event.detail["kid"] == "2026-Q4-a"
        assert event.detail["action"] == "staged"

    def test_an_unreachable_database_does_not_fail_the_rotation(
        self, key_directory: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The command legitimately runs where no database is reachable: an
        operator generating a key into a scratch directory to push to the
        secret store. A missing audit row is one line of warning, not a
        traceback on a run that succeeded."""
        from django.db import OperationalError

        def unreachable() -> None:
            raise OperationalError("no server")

        monkeypatch.setattr(
            "apps.authentication.management.commands.rotate_jwt_keys."
            "connection.ensure_connection",
            unreachable,
        )

        output = run("rotate_jwt_keys", "--kid", "offline")

        assert "Staged key 'offline'" in output
        assert "No database reachable" in output


@pytest.mark.django_db
class TestPruneExpiredTokens:
    @pytest.fixture
    def aged_tokens(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """One live token, one rotated-and-expired, one rotated-but-current."""
        issue_pair(user=acme_user, tenant=acme)
        expired = issue_pair(user=acme_user, tenant=acme, device_id="old")
        rotated = issue_pair(user=acme_user, tenant=acme, device_id="recent")

        with tenant_context(acme):
            # issued_at moves with it: a CHECK constraint holds
            # expires_at > issued_at, so backdating only one is rejected.
            RefreshToken.objects.filter(jti=expired.refresh_jti).update(
                status=TokenStatus.ROTATED,
                issued_at=timezone.now() - timedelta(days=8),
                expires_at=timezone.now() - timedelta(days=1),
            )
            RefreshToken.objects.filter(jti=rotated.refresh_jti).update(
                status=TokenStatus.ROTATED
            )

    def test_it_deletes_only_what_is_past_expiry(
        self, acme: Tenant, aged_tokens: None
    ) -> None:
        run("prune_expired_tokens", "--schema", "acme")

        with tenant_context(acme):
            assert RefreshToken.objects.count() == 2

    def test_a_rotated_but_unexpired_row_is_kept(
        self, acme: Tenant, aged_tokens: None
    ) -> None:
        """Deleting these early makes a replayed token indistinguishable from
        an invented one: reuse detection stops working while still appearing
        to be in place."""
        run("prune_expired_tokens", "--schema", "acme")

        with tenant_context(acme):
            assert RefreshToken.objects.filter(status=TokenStatus.ROTATED).count() == 1

    def test_a_dry_run_reports_without_deleting(
        self, acme: Tenant, aged_tokens: None
    ) -> None:
        output = run("prune_expired_tokens", "--schema", "acme", "--dry-run")

        assert "Would delete 1" in output
        with tenant_context(acme):
            assert RefreshToken.objects.count() == 3

    def test_without_a_schema_it_visits_public_and_every_tenant(
        self, acme: Tenant, beta: Tenant, aged_tokens: None
    ) -> None:
        """There is no implicit schema outside a request; the command
        iterates the catalogue rather than assuming one."""
        output = run("prune_expired_tokens", "--dry-run")

        assert "public:" in output
        assert "acme: 1" in output
        assert "beta: 0" in output

    def test_it_does_not_reach_into_another_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
        beta_user: User,
        issue_pair: Callable[..., TokenPair],
        aged_tokens: None,
    ) -> None:
        issue_pair(user=beta_user, tenant=beta)

        run("prune_expired_tokens", "--schema", "acme")

        with tenant_context(beta):
            assert RefreshToken.objects.count() == 1

    def test_an_unknown_schema_is_refused(self, acme: Tenant) -> None:
        with pytest.raises(CommandError, match="does not exist"):
            run("prune_expired_tokens", "--schema", "nosuchtenant")

    def test_a_nonsensical_batch_size_is_refused(self, acme: Tenant) -> None:
        with pytest.raises(CommandError, match="at least 1"):
            run("prune_expired_tokens", "--batch-size", "0")

    def test_it_deletes_in_batches(self, acme: Tenant, aged_tokens: None) -> None:
        run("prune_expired_tokens", "--schema", "acme", "--batch-size", "1")

        with tenant_context(acme):
            assert not RefreshToken.objects.filter(
                expires_at__lt=timezone.now()
            ).exists()


@pytest.mark.django_db
class TestRevokeUserTokens:
    def test_it_revokes_every_credential_the_account_holds(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        issue_pair(user=acme_user, tenant=acme)

        output = run(
            "revoke_user_tokens", "--schema", "acme", "--email", "priya@acme.edu"
        )

        assert "Revoked 1 refresh token(s)" in output
        with tenant_context(acme):
            assert not RefreshToken.objects.active().exists()
            acme_user.refresh_from_db()
        assert acme_user.token_version == 1

    def test_the_address_is_matched_case_insensitively(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        issue_pair(user=acme_user, tenant=acme)

        run("revoke_user_tokens", "--schema", "acme", "--email", "PRIYA@ACME.EDU")

        with tenant_context(acme):
            assert not RefreshToken.objects.active().exists()

    def test_the_reason_is_recorded(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        issue_pair(user=acme_user, tenant=acme)

        run(
            "revoke_user_tokens",
            "--schema",
            "acme",
            "--email",
            "priya@acme.edu",
            "--reason",
            "user_deactivated",
        )

        with tenant_context(acme):
            token = RefreshToken.objects.get()
        assert token.revocation_reason == "user_deactivated"

    def test_a_soft_deleted_account_can_still_be_revoked(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """The default manager hides exactly the account whose credentials
        most need killing."""
        issue_pair(user=acme_user, tenant=acme)
        with tenant_context(acme):
            acme_user.delete()

        run("revoke_user_tokens", "--schema", "acme", "--email", "priya@acme.edu")

        with tenant_context(acme):
            assert not RefreshToken.objects.active().exists()

    def test_an_unknown_account_is_refused(self, acme: Tenant) -> None:
        with pytest.raises(CommandError, match="No account"):
            run("revoke_user_tokens", "--schema", "acme", "--email", "ghost@acme.edu")

    def test_an_unknown_schema_is_refused(self, acme: Tenant) -> None:
        with pytest.raises(CommandError, match="does not exist"):
            run("revoke_user_tokens", "--schema", "nowhere", "--email", "a@b.edu")

    def test_it_does_not_touch_the_same_address_in_another_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
        make_user: Callable[..., User],
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """The same address legitimately exists in several schemas, which is
        why ``--schema`` is mandatory and has no default."""
        with tenant_context(acme):
            here = make_user("shared@example.com")
        with tenant_context(beta):
            there = make_user("shared@example.com")
        issue_pair(user=here, tenant=acme)
        issue_pair(user=there, tenant=beta)

        run("revoke_user_tokens", "--schema", "acme", "--email", "shared@example.com")

        with tenant_context(beta):
            assert RefreshToken.objects.active().count() == 1


@pytest.mark.django_db
class TestJwtInspect:
    def test_it_prints_the_header_and_the_claims(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        output = run("jwt_inspect", "--token", pair.access_token)

        assert TEST_KID in output
        assert "RS256" in output
        assert "acme" in output
        assert "within its lifetime" in output

    def test_it_reads_a_token_from_a_file(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        tmp_path: Path,
    ) -> None:
        """Preferred over ``--token``: an argument lands in the shell history
        and in the process list."""
        pair = issue_pair(user=acme_user, tenant=acme)
        path = tmp_path / "token.txt"
        path.write_text(f'  "Bearer {pair.access_token}"  ', encoding="ascii")

        output = run("jwt_inspect", "--file", str(path))

        assert TEST_KID in output

    def test_it_reports_the_stored_row_and_the_denylist(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        output = run("jwt_inspect", "--token", pair.refresh_token, "--schema", "acme")

        assert "refresh row" in output
        assert "active" in output
        assert "not listed" in output

    def test_it_verifies_against_a_named_schema(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        output = run(
            "jwt_inspect", "--token", pair.access_token, "--schema", "acme", "--verify"
        )

        assert "accepted here as a valid access token" in output

    def test_it_names_the_check_that_rejected_a_foreign_token(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """Support work starts with "why was this rejected", and the answer is
        safe to give an operator even though it is withheld from a caller."""
        pair = issue_pair(user=acme_user, tenant=acme)

        output = run(
            "jwt_inspect", "--token", pair.access_token, "--schema", "beta", "--verify"
        )

        assert "not valid here" in output
        assert "token_wrong_tenant" in output

    def test_an_expired_token_still_inspects(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """A token worth inspecting is usually one that failed."""
        from freezegun import freeze_time

        with freeze_time(timezone.now() - timedelta(hours=1)):
            pair = issue_pair(user=acme_user, tenant=acme)

        output = run("jwt_inspect", "--token", pair.access_token)

        assert "EXPIRED" in output

    def test_it_flags_an_unsigned_token(self, acme: Tenant) -> None:
        import base64

        header = (
            base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}')
            .rstrip(b"=")
            .decode()
        )
        body = base64.urlsafe_b64encode(b'{"sub":"1"}').rstrip(b"=").decode()

        output = run("jwt_inspect", "--token", f"{header}.{body}.")

        assert "alg is 'none'" in output

    def test_verify_without_a_schema_is_refused(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        """The tenancy check compares against the live connection, and there
        is none outside a schema."""
        pair = issue_pair(user=acme_user, tenant=acme)

        with pytest.raises(CommandError, match="--verify needs --schema"):
            run("jwt_inspect", "--token", pair.access_token, "--verify")

    def test_an_unknown_schema_is_refused(self, acme: Tenant) -> None:
        with pytest.raises(CommandError, match="does not exist"):
            run("jwt_inspect", "--token", "a.b.c", "--schema", "nowhere")

    def test_an_undecodable_token_is_reported_plainly(self, acme: Tenant) -> None:
        with pytest.raises(CommandError, match="Not a decodable JWT"):
            run("jwt_inspect", "--token", "not-a-jwt")

    def test_an_unreadable_file_is_reported(self, acme: Tenant, tmp_path: Path) -> None:
        with pytest.raises(CommandError, match="Cannot read"):
            run("jwt_inspect", "--file", str(tmp_path / "absent.txt"))

    def test_a_refresh_digest_with_no_row_is_called_out(
        self,
        acme: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)
        with tenant_context(acme):
            RefreshToken.objects.all().delete()

        output = run("jwt_inspect", "--token", pair.refresh_token, "--schema", "acme")

        assert "no refresh row matches" in output
