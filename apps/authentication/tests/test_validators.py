"""Password policy and the facts derived from a request.

Two modules with one property in common: everything they see is supplied by
the caller. The password validator is the only one of the two that gates
anything, and ``client_ip`` is the one piece of request metadata that feeds a
security decision -- lockout and throttling key on it, so a spoofable address
is a lockout bypass in one direction and a denial-of-service lever in the
other. The rest is for the audit trail and the session list, and is treated
as advisory throughout.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.test import RequestFactory

from apps.authentication.models import PasswordHistory
from apps.authentication.utils.request_meta import (
    client_ip,
    device_identifier,
    request_id,
    user_agent,
)
from apps.authentication.validators import PasswordHistoryValidator
from apps.tenants.utils import tenant_context

from .conftest import PASSWORD

# The breach API returns CRLF-delimited lines.
CRLF = chr(13) + chr(10)

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.tenants.models import Tenant


@pytest.mark.django_db
class TestPasswordHistoryValidator:
    def test_a_fresh_password_is_accepted(self, acme: Tenant, acme_user: User) -> None:
        with tenant_context(acme):
            PasswordHistoryValidator().validate("An0ther-Str0ng-Phrase!", acme_user)

    def test_the_current_password_is_refused(
        self, acme: Tenant, acme_user: User
    ) -> None:
        """Checked directly as well as through the table: the first change
        after this feature ships has nothing recorded yet."""
        with tenant_context(acme), pytest.raises(ValidationError) as failure:
            PasswordHistoryValidator().validate(PASSWORD, acme_user)

        assert failure.value.error_list[0].code == "password_reused"

    def test_a_retained_password_is_refused(
        self, acme: Tenant, acme_user: User
    ) -> None:
        with tenant_context(acme):
            PasswordHistory.objects.create(
                user=acme_user, password_hash=make_password("Previous-Passw0rd!")
            )

            with pytest.raises(ValidationError):
                PasswordHistoryValidator().validate("Previous-Passw0rd!", acme_user)

    def test_only_the_configured_depth_is_consulted(
        self, acme: Tenant, acme_user: User, settings: Any
    ) -> None:
        """Beyond the depth an old password becomes usable again, which is the
        documented policy rather than an oversight."""
        settings.JWT_AUTH = {**settings.JWT_AUTH, "PASSWORD_HISTORY_DEPTH": 1}

        with tenant_context(acme):
            PasswordHistory.objects.create(
                user=acme_user, password_hash=make_password("Ancient-Passw0rd!")
            )
            PasswordHistory.objects.create(
                user=acme_user, password_hash=make_password("Recent-Passw0rd!")
            )

            PasswordHistoryValidator().validate("Ancient-Passw0rd!", acme_user)

    def test_it_is_skipped_when_there_is_no_saved_user(self) -> None:
        """At signup and in ``createsuperuser`` there is no history, and the
        validator must not fail on the absence of one."""
        PasswordHistoryValidator().validate("Anything-At-All!", None)

    def test_it_describes_itself(self) -> None:
        assert "recent" in PasswordHistoryValidator().get_help_text()

    def test_it_is_wired_into_the_configured_policy(
        self, acme: Tenant, acme_user: User
    ) -> None:
        """So the same rule applies to the admin and to ``createsuperuser``,
        not only to the API."""
        with tenant_context(acme), pytest.raises(ValidationError):
            validate_password(PASSWORD, acme_user)


class TestBreachedPasswordValidator:
    """Not registered in AUTH_PASSWORD_VALIDATORS -- an outbound HTTPS call on
    every password set is a deployment decision, not a default. Tested anyway,
    because a validator nobody exercises is one nobody can safely enable."""

    @pytest.fixture
    def fake_requests(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        """Stand in for the optional ``requests`` dependency."""
        import sys
        import types

        module = types.ModuleType("requests")
        monkeypatch.setitem(sys.modules, "requests", module)
        return module

    def _respond(self, module: Any, body: str) -> None:
        class Response:
            text = body

            def raise_for_status(self) -> None:
                return None

        module.get = lambda *_args, **_kwargs: Response()

    def test_a_breached_password_is_refused(self, fake_requests: Any) -> None:
        import hashlib

        from apps.authentication.validators import BreachedPasswordValidator

        suffix = hashlib.sha1(b"hunter2").hexdigest().upper()[5:]
        self._respond(fake_requests, CRLF.join([f"{suffix}:42", "AAAA:1"]))

        with pytest.raises(ValidationError) as failure:
            BreachedPasswordValidator().validate("hunter2")

        assert failure.value.error_list[0].code == "password_breached"

    def test_an_unlisted_password_is_accepted(self, fake_requests: Any) -> None:
        from apps.authentication.validators import BreachedPasswordValidator

        self._respond(fake_requests, "0000000000000000000000000000000000:3")

        BreachedPasswordValidator().validate("An0ther-Str0ng-Phrase!")

    def test_an_unreachable_service_fails_open(self, fake_requests: Any) -> None:
        """The opposite of the denylist policy, deliberately: a breach check
        is advisory, and an outage upstream must not stop people setting a
        password."""
        from apps.authentication.validators import BreachedPasswordValidator

        def unreachable(*_args: Any, **_kwargs: Any) -> None:
            raise OSError("no route to host")

        fake_requests.get = unreachable

        BreachedPasswordValidator().validate("An0ther-Str0ng-Phrase!")

    def test_it_describes_itself(self) -> None:
        from apps.authentication.validators import BreachedPasswordValidator

        assert "breach" in BreachedPasswordValidator().get_help_text()


class TestClientIp:
    def test_the_forwarded_header_is_ignored_by_default(self, settings: Any) -> None:
        """``X-Forwarded-For`` is a request header like any other: with no
        proxy in front, honouring it lets a client choose its own address --
        and its own lockout bucket."""
        settings.JWT_AUTH = {**settings.JWT_AUTH, "TRUSTED_PROXY_HOPS": 0}
        request = RequestFactory().get(
            "/", HTTP_X_FORWARDED_FOR="1.2.3.4", REMOTE_ADDR="203.0.113.7"
        )

        assert client_ip(request) == "203.0.113.7"

    def test_with_one_trusted_hop_the_last_entry_is_used(self, settings: Any) -> None:
        """Each proxy appends what it saw, so the entry written by the
        outermost trusted hop is ``hops`` from the end. Anything to its left
        was supplied by the client."""
        settings.JWT_AUTH = {**settings.JWT_AUTH, "TRUSTED_PROXY_HOPS": 1}
        request = RequestFactory().get(
            "/",
            HTTP_X_FORWARDED_FOR="9.9.9.9, 203.0.113.7",
            REMOTE_ADDR="10.0.0.1",
        )

        assert client_ip(request) == "203.0.113.7"

    def test_a_short_chain_falls_back_to_the_socket_address(
        self, settings: Any
    ) -> None:
        settings.JWT_AUTH = {**settings.JWT_AUTH, "TRUSTED_PROXY_HOPS": 2}
        request = RequestFactory().get(
            "/", HTTP_X_FORWARDED_FOR="203.0.113.7", REMOTE_ADDR="10.0.0.1"
        )

        assert client_ip(request) == "10.0.0.1"

    def test_a_forwarded_value_that_is_not_an_address_is_ignored(
        self, settings: Any
    ) -> None:
        settings.JWT_AUTH = {**settings.JWT_AUTH, "TRUSTED_PROXY_HOPS": 1}
        request = RequestFactory().get(
            "/", HTTP_X_FORWARDED_FOR="not-an-address", REMOTE_ADDR="10.0.0.1"
        )

        assert client_ip(request) == "10.0.0.1"

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("203.0.113.7", "203.0.113.7"),
            ("203.0.113.7:41234", "203.0.113.7"),
            ("2001:db8::1", "2001:db8::1"),
            ("[2001:db8::1]:443", "2001:db8::1"),
        ],
    )
    def test_it_normalises_what_proxies_actually_emit(
        self, raw: str, expected: str
    ) -> None:
        request = RequestFactory().get("/", REMOTE_ADDR=raw)

        assert client_ip(request) == expected

    def test_an_unparseable_address_becomes_none(self) -> None:
        """The audit columns are ``inet`` and reject a non-address, and a
        silent placeholder would merge unrelated clients into one bucket."""
        request = RequestFactory().get("/", REMOTE_ADDR="garbage")

        assert client_ip(request) is None

    def test_a_missing_address_becomes_none(self) -> None:
        request = RequestFactory().get("/")
        request.META.pop("REMOTE_ADDR", None)

        assert client_ip(request) is None


class TestDeviceIdentifier:
    def test_it_is_stable_for_the_same_client(self) -> None:
        factory = RequestFactory()
        first = factory.get("/", HTTP_USER_AGENT="Chrome/1", HTTP_ACCEPT_LANGUAGE="en")
        second = factory.get("/", HTTP_USER_AGENT="Chrome/1", HTTP_ACCEPT_LANGUAGE="en")

        assert device_identifier(first) == device_identifier(second)

    def test_it_differs_for_a_different_client(self) -> None:
        factory = RequestFactory()
        chrome = factory.get("/", HTTP_USER_AGENT="Chrome/1")
        firefox = factory.get("/", HTTP_USER_AGENT="Firefox/2")

        assert device_identifier(chrome) != device_identifier(firefox)

    def test_it_reveals_nothing_about_the_client(self) -> None:
        """A digest, not a fingerprint anyone can read back."""
        request = RequestFactory().get("/", HTTP_USER_AGENT="Chrome/1")

        identifier = device_identifier(request)

        assert len(identifier) == 16
        assert "Chrome" not in identifier

    def test_a_client_supplied_device_header_participates(self) -> None:
        """Advisory only -- it is used to recognise a device in a session
        list, never to authorise anything."""
        factory = RequestFactory()
        plain = factory.get("/", HTTP_USER_AGENT="Chrome/1")
        labelled = factory.get(
            "/", HTTP_USER_AGENT="Chrome/1", headers={"x-device-id": "phone"}
        )

        assert device_identifier(plain) != device_identifier(labelled)


class TestRequestId:
    def test_a_valid_client_value_is_honoured(self) -> None:
        request = RequestFactory().get("/", headers={"x-request-id": "trace-abc_1.2"})

        assert request_id(request) == "trace-abc_1.2"

    @pytest.mark.parametrize(
        "supplied", ["with space", "a" * 65, "semi;colon", "new\nline", ""]
    )
    def test_an_unsafe_client_value_is_replaced(self, supplied: str) -> None:
        """The value is echoed into a response header and into logs, where an
        unvalidated string is header injection and log forging."""
        request = RequestFactory().get("/", headers={"x-request-id": supplied})

        assert request_id(request) != supplied

    def test_a_generated_value_is_stable_for_one_request(self) -> None:
        """The handler, the audit record and the response header all have to
        report the same value."""
        request = RequestFactory().get("/")

        assert request_id(request) == request_id(request)

    def test_two_requests_get_different_values(self) -> None:
        factory = RequestFactory()

        assert request_id(factory.get("/")) != request_id(factory.get("/"))

    def test_it_works_with_no_request_at_all(self) -> None:
        """Called from the exception handler, which may have no request."""
        assert request_id(None)


class TestUserAgent:
    def test_it_is_truncated_to_what_the_column_holds(self) -> None:
        request = RequestFactory().get("/", HTTP_USER_AGENT="x" * 900)

        assert len(user_agent(request)) == 512

    def test_an_absent_header_is_an_empty_string(self) -> None:
        assert user_agent(RequestFactory().get("/")) == ""


@pytest.mark.django_db
class TestSessionTouch:
    def test_it_records_activity_without_loading_the_row(
        self,
        acme: Tenant,
        acme_user: User,
        make_user: Callable[..., User],
    ) -> None:
        from apps.authentication.models import DeviceSession
        from apps.authentication.services.sessions import DeviceSessionService

        with tenant_context(acme):
            session = DeviceSession.objects.create(
                user=acme_user, device_id="laptop", last_seen_at=None
            )

            DeviceSessionService().touch(str(session.pk), ip_address="203.0.113.9")

            session.refresh_from_db()
            assert session.last_seen_at is not None
            assert session.ip_address == "203.0.113.9"

    def test_an_ended_session_is_not_touched(
        self, acme: Tenant, acme_user: User
    ) -> None:
        from django.utils import timezone

        from apps.authentication.models import DeviceSession
        from apps.authentication.services.sessions import DeviceSessionService

        with tenant_context(acme):
            session = DeviceSession.objects.create(
                user=acme_user, device_id="laptop", ended_at=timezone.now()
            )

            DeviceSessionService().touch(session.pk)

            session.refresh_from_db()
            assert session.last_seen_at is None
