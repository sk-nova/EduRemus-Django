"""Structured logging, and the rule that no credential is ever written to it.

The integration test at the bottom is the one that matters. Logs are shipped
to aggregators, retained for months and read by people with no need for
credential access, so a token on a log line is a credential disclosed to all
of them for the whole retention period. The assertion is deliberately blunt:
run the real flows, then search everything that was emitted for the actual
secret values.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest
from django.test import Client as HttpClient

from apps.authentication.logging import (
    REDACTED,
    JsonFormatter,
    RequestIdFilter,
    SensitiveDataFilter,
    TenantContextFilter,
    request_id_var,
)
from apps.tenants.utils import tenant_context

from .conftest import ACME_HOST, PASSWORD, LogCapture

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant

ME = "/api/v1/auth/me/"


def record(message: str = "event", **extra: Any) -> logging.LogRecord:
    """A bare record, plus whatever a caller would have passed as ``extra``."""
    made = logging.LogRecord(
        name="eduremus.auth",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(made, key, value)
    return made


def field(entry: logging.LogRecord, name: str) -> Any:
    """Read an attribute a filter attached.

    Through ``__dict__`` because that is where a filter puts it and because
    ``LogRecord`` declares none of these statically -- the whole point of the
    filters is that they add fields the type does not know about.
    """
    return entry.__dict__.get(name)


@pytest.mark.django_db
class TestTenantContextFilter:
    def test_it_names_the_active_schema(self, acme: Tenant) -> None:
        """Without it a log line cannot be attributed to an institution."""
        entry = record()

        with tenant_context(acme):
            TenantContextFilter().filter(entry)

        assert field(entry, "schema") == "acme"

    def test_outside_a_tenant_it_names_the_public_schema(self) -> None:
        entry = record()

        TenantContextFilter().filter(entry)

        assert field(entry, "schema") == "public"


class TestRequestIdFilter:
    def test_it_attaches_the_bound_identifier(self) -> None:
        entry = record()
        token = request_id_var.set("correlation-1")

        try:
            RequestIdFilter().filter(entry)
        finally:
            request_id_var.reset(token)

        assert field(entry, "request_id") == "correlation-1"

    def test_outside_a_request_the_field_is_present_but_empty(self) -> None:
        """Uniform shape matters more than the value: whatever parses these
        lines should not have to handle a missing key."""
        entry = record()

        RequestIdFilter().filter(entry)

        assert field(entry, "request_id") == ""

    def test_it_falls_back_to_the_request_on_the_record(self) -> None:
        """Django logs 4xx responses after the middleware has unwound, so the
        contextvar is already reset by then -- and those are the lines most
        worth correlating."""
        from django.test import RequestFactory

        request = RequestFactory().get("/", headers={"x-request-id": "from-header"})
        entry = record("Unauthorized: /", request=request)

        RequestIdFilter().filter(entry)

        assert field(entry, "request_id") == "from-header"

    def test_a_record_carrying_something_else_does_not_break_the_handler(
        self,
    ) -> None:
        entry = record("odd", request="not a request")

        RequestIdFilter().filter(entry)

        assert field(entry, "request_id") == ""


class TestSensitiveDataFilter:
    def test_a_jwt_in_the_message_is_redacted(self) -> None:
        entry = record()
        entry.msg = "rejected eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"

        SensitiveDataFilter().filter(entry)

        assert "eyJhbGciOiJSUzI1NiJ9" not in entry.getMessage()
        assert REDACTED in entry.getMessage()

    def test_a_jwt_in_an_extra_field_is_redacted(self) -> None:
        entry = record("event", detail="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln")

        SensitiveDataFilter().filter(entry)

        assert field(entry, "detail") == REDACTED

    @pytest.mark.parametrize(
        "field", ["password", "token", "authorization", "refresh_token", "csrf_token"]
    )
    def test_a_field_whose_value_is_a_credential_is_redacted(self, field: str) -> None:
        """By name, whatever the value looks like: an opaque secret has no
        recognisable shape to match on."""
        entry = record("event", **{field: "not-jwt-shaped-but-still-secret"})

        SensitiveDataFilter().filter(entry)

        assert entry.__dict__[field] == REDACTED

    def test_the_field_name_is_matched_case_insensitively(self) -> None:
        entry = record("event", Authorization="Bearer abc")

        SensitiveDataFilter().filter(entry)

        assert field(entry, "Authorization") == REDACTED

    def test_percent_style_arguments_are_scrubbed(self) -> None:
        entry = logging.LogRecord(
            name="eduremus.auth",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="token %s rejected",
            args=("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",),
            exc_info=None,
        )

        SensitiveDataFilter().filter(entry)

        assert "eyJhbGciOiJSUzI1NiJ9" not in entry.getMessage()

    def test_an_ordinary_field_survives_untouched(self) -> None:
        """A redactor that eats the diagnostics is not worth having."""
        entry = record("event", jti="018f3c6a-8d90-7a11", count=3)

        SensitiveDataFilter().filter(entry)

        assert field(entry, "jti") == "018f3c6a-8d90-7a11"
        assert field(entry, "count") == 3


class TestJsonFormatter:
    def test_it_emits_one_json_object(self) -> None:
        document = json.loads(JsonFormatter().format(record("keyring_loaded")))

        assert document["message"] == "keyring_loaded"
        assert document["level"] == "INFO"
        assert document["logger"] == "eduremus.auth"
        assert document["timestamp"]

    def test_extra_fields_become_top_level_keys(self) -> None:
        """So a log query can filter on them without parsing the message."""
        entry = record("cross_tenant", token_schema="acme", attempts=2)

        document = json.loads(JsonFormatter().format(entry))

        assert document["token_schema"] == "acme"
        assert document["attempts"] == 2

    def test_a_value_that_cannot_be_serialised_does_not_raise(self) -> None:
        """A log record is never worth raising over."""
        entry = record("event", weird=object())

        document = json.loads(JsonFormatter().format(entry))

        assert "weird" in document

    def test_an_exception_is_included_as_text(self) -> None:
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            entry = logging.LogRecord(
                name="eduremus.auth",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="failed",
                args=(),
                exc_info=sys.exc_info(),
            )

        document = json.loads(JsonFormatter().format(entry))

        assert "ValueError: boom" in document["exception"]


@pytest.mark.django_db
class TestEveryRecordIsAttributable:
    def test_records_emitted_during_a_request_carry_the_schema_and_the_id(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        log_capture: LogCapture,
    ) -> None:
        response = login(api_client, password="wrong")

        assert log_capture.documents, "the flow emitted nothing to assert on"
        for document in log_capture.documents:
            assert "schema" in document
            assert "request_id" in document

        assert any(
            document["request_id"] == response["X-Request-Id"]
            for document in log_capture.documents
        )

    def test_a_cross_tenant_rejection_reaches_the_security_stream(
        self,
        acme: Tenant,
        beta: Tenant,
        acme_user: User,
        issue_pair: Callable[..., TokenPair],
        api_client: HttpClient,
        bearer: Callable[[str], dict],
        log_capture: LogCapture,
    ) -> None:
        pair = issue_pair(user=acme_user, tenant=acme)

        api_client.get(ME, HTTP_HOST="beta.testserver", **bearer(pair.access_token))

        security = [
            document
            for document in log_capture.documents
            if document["logger"] == "eduremus.security"
        ]
        assert security
        assert security[0]["message"] == "cross_tenant_token_rejected"
        assert security[0]["schema"] == "beta"


@pytest.mark.django_db
class TestNoCredentialIsEverLogged:
    def test_a_full_login_and_refresh_leaks_nothing(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        log_capture: LogCapture,
    ) -> None:
        """The blunt assertion: run the flows, then look for the secrets."""
        response = login(api_client)
        access = response.json()["access_token"]
        refresh = response.cookies["__Host-eduremus_refresh"].value
        csrf = api_client.cookies["eduremus_csrf"].value

        api_client.post(
            "/api/v1/auth/refresh/",
            HTTP_HOST=ACME_HOST,
            headers={"X-CSRF-Token": csrf},
        )
        api_client.get(ME, HTTP_HOST=ACME_HOST, HTTP_AUTHORIZATION=f"Bearer {access}")

        emitted = log_capture.text
        assert access not in emitted
        assert refresh not in emitted
        assert PASSWORD not in emitted
        assert "Bearer " not in emitted

    def test_a_rejected_credential_is_not_logged_either(
        self,
        acme: Tenant,
        acme_user: User,
        api_client: HttpClient,
        login: Callable,
        bearer: Callable[[str], dict],
        log_capture: LogCapture,
    ) -> None:
        """The failure paths are where a token is most tempting to log."""
        forged = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2UifQ.eyJzdWIiOiJhIn0.c2ln"

        api_client.get(ME, HTTP_HOST=ACME_HOST, **bearer(forged))
        login(api_client, password="hunter2-the-wrong-one")

        emitted = log_capture.text
        assert forged not in emitted
        assert "hunter2-the-wrong-one" not in emitted

    def test_the_configured_handler_applies_the_redaction_filter(self) -> None:
        """The unit tests above prove the filter works; this proves it is
        actually wired into the handler records go through."""
        from django.conf import settings

        configuration: dict[str, Any] = settings.LOGGING
        handler = configuration["handlers"]["json"]
        assert "sensitive" in handler["filters"]
        assert "tenant" in handler["filters"]
        assert "request_id" in handler["filters"]

        for logger in ("eduremus.auth", "eduremus.security", "django.security"):
            assert configuration["loggers"][logger]["handlers"] == ["json"]
