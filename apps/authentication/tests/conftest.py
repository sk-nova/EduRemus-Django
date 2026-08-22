"""Fixtures for the authentication suite.

Built on the project's existing tenancy fixtures: the session-scoped
``tenants`` fixture in the root ``conftest.py`` creates and migrates the
``public``/``acme``/``beta`` schemas and routes ``public.testserver``,
``acme.testserver`` and ``beta.testserver`` to them, and ``_reset_schema``
returns the connection to ``public`` after every test.

Three things here are less obvious than they look:

* **Real keys on disk, not a monkeypatched keyring.** A session-scoped keypair
  is written into the configured key directory in the layout
  :class:`Keyring` expects, so the loader, the ``kid`` resolution and the JWKS
  endpoint are all exercised for real. Patching ``Keyring.load`` would have
  hidden every defect in the one component whose failure mode is "accepts a
  token it should not".
* **Caches are cleared between tests.** Throttle counters, lockout counters and
  the user cache all live in the cache backend, which is process-global and
  survives the per-test transaction rollback. Without this, the eleventh login
  in a module fails as a throttle rather than for the reason it asserts.
* **Tokens are issued through the service layer**, not by hand, so every pair
  a test presents has the ``RefreshToken`` row the refresh path looks for.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.test import Client as HttpClient
from django.utils import timezone

from apps.authentication.logging import (
    JsonFormatter,
    RequestIdFilter,
    SensitiveDataFilter,
    TenantContextFilter,
)
from apps.authentication.models import DeviceSession, TokenFamily
from apps.authentication.services.issuing import issue_and_store
from apps.authentication.tokens.keys import Keyring
from apps.tenants.utils import tenant_context

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.authentication.tokens.generator import TokenPair
    from apps.tenants.models import Tenant
    from conftest import TenantSchemas

PASSWORD = "s3cure-Passw0rd!"

# Matches ACTIVE_KEY_ID in config/settings/test.py, so the ring resolves an
# active key without the "newest signable" fallback being involved.
TEST_KID = "test-key"

ACME_HOST = "acme.testserver"
BETA_HOST = "beta.testserver"
PUBLIC_HOST = "public.testserver"

CSRF_HEADER = "X-CSRF-Token"


# ---------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_keypair() -> tuple[bytes, bytes]:
    """One 2048-bit keypair for the whole session.

    Generated once. Per-test generation costs roughly a second each and would
    dominate the runtime of a suite whose point is that it stays fast enough
    to run before every push.
    """
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


@pytest.fixture(scope="session", autouse=True)
def jwt_key_directory(rsa_keypair: tuple[bytes, bytes]) -> Iterator[Path]:
    """Populate the configured key directory with a throwaway keypair."""
    private_pem, public_pem = rsa_keypair
    directory = Path(settings.JWT_AUTH["KEY_DIRECTORY"])

    _remove_tree(directory)
    directory.mkdir(parents=True, exist_ok=True)

    now = timezone.now()
    (directory / f"{TEST_KID}.private.pem").write_bytes(private_pem)
    (directory / f"{TEST_KID}.public.pem").write_bytes(public_pem)
    (directory / f"{TEST_KID}.json").write_text(
        json.dumps(
            {
                "kid": TEST_KID,
                "algorithm": "RS256",
                "not_before": (now - timedelta(days=1)).isoformat(),
                "not_after": (now + timedelta(days=365)).isoformat(),
            }
        ),
        encoding="utf-8",
    )

    Keyring.reset()
    yield directory
    Keyring.reset()
    _remove_tree(directory)


def _remove_tree(directory: Path) -> None:
    """Delete a directory, clearing the read-only bit Windows honours."""

    def _force(func: Any, path: str, _exc: BaseException) -> None:
        os.chmod(path, stat.S_IWRITE)
        func(path)

    if directory.exists():
        shutil.rmtree(directory, onexc=_force)


@pytest.fixture
def keyring(jwt_key_directory: Path) -> Keyring:
    """The ring the application itself will use."""
    return Keyring.load(force=True)


# ---------------------------------------------------------------------
# Isolation between tests
# ---------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    """Empty every cache alias before and after each test.

    The cache is process-global and is not covered by the transaction that
    rolls a test's database writes back, so throttle buckets, lockout counters
    and cached ``User`` objects would otherwise leak between tests -- and the
    symptom is a 429 or a stale ``token_version`` in a test that asserts
    something else entirely.
    """
    for alias in settings.CACHES:
        caches[alias].clear()
    yield
    for alias in settings.CACHES:
        caches[alias].clear()


# ---------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------


def _fetch(schema_name: str) -> Tenant:
    """Read a tenant row fresh, never sharing an instance between tests."""
    from apps.tenants.models import Tenant

    return Tenant.objects.get(schema_name=schema_name)


@pytest.fixture
def acme(db: None, tenants: TenantSchemas) -> Tenant:
    """First institution. Requesting it does not activate its schema."""
    return _fetch(tenants.acme)


@pytest.fixture
def beta(db: None, tenants: TenantSchemas) -> Tenant:
    """Second institution -- the other side of every isolation assertion."""
    return _fetch(tenants.beta)


@pytest.fixture
def public_tenant(db: None, tenants: TenantSchemas) -> Tenant:
    """The tenant that owns the public schema."""
    return _fetch(tenants.public)


# ---------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------


@pytest.fixture
def make_user(db: None) -> Callable[..., User]:
    """Create a user inside whichever schema is currently active."""

    def _make(email: str = "user@example.com", **fields: Any) -> User:
        return get_user_model().objects.create_user(
            email=email, password=PASSWORD, **fields
        )

    return _make


@pytest.fixture
def acme_user(acme: Tenant, make_user: Callable[..., User]) -> User:
    with tenant_context(acme):
        return make_user("priya@acme.edu", first_name="Priya", last_name="Nair")


@pytest.fixture
def beta_user(beta: Tenant, make_user: Callable[..., User]) -> User:
    with tenant_context(beta):
        return make_user("raj@beta.edu", first_name="Raj", last_name="Menon")


@pytest.fixture
def grant_role() -> Callable[..., None]:
    """Add a user to one of the seeded role groups, inside a tenant."""

    def _grant(user: User, role: str, *, tenant: Tenant) -> None:
        from django.contrib.auth.models import Group

        with tenant_context(tenant):
            group, _ = Group.objects.get_or_create(name=role)
            user.groups.add(group)

    return _grant


# ---------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------


@pytest.fixture
def issue_pair() -> Callable[..., TokenPair]:
    """Mint a pair for a user in a named tenant, with its session and family.

    Goes through the service seam rather than ``TokenService`` directly, so
    the ``RefreshToken`` row exists and the pair can actually be rotated --
    a fixture that mints a refresh token with no row would make every reuse
    test pass for the wrong reason.
    """

    def _issue(
        *,
        user: User,
        tenant: Tenant,
        device_id: str = "test-device",
        **overrides: Any,
    ) -> TokenPair:
        with tenant_context(tenant):
            session = DeviceSession.objects.create(
                user=user, device_id=device_id, ip_address="203.0.113.1"
            )
            family = TokenFamily.objects.create(user=user, session=session)
            return issue_and_store(
                user=user,
                tenant=tenant,
                session=session,
                family=family,
                device_id=device_id,
                **overrides,
            )

    return _issue


# ---------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------


@pytest.fixture
def api_client() -> HttpClient:
    """Django test client. ``HTTP_HOST`` per request selects the tenant."""
    return HttpClient()


@pytest.fixture
def login() -> Callable[..., Any]:
    """Log in over HTTP, leaving the refresh and CSRF cookies on the client."""

    def _login(
        client: HttpClient,
        *,
        host: str = ACME_HOST,
        email: str = "priya@acme.edu",
        password: str = PASSWORD,
        **extra: Any,
    ) -> Any:
        return client.post(
            "/api/v1/auth/login/",
            data={"email": email, "password": password, **extra},
            content_type="application/json",
            HTTP_HOST=host,
        )

    return _login


@pytest.fixture
def csrf_headers() -> Callable[[HttpClient], dict[str, str]]:
    """The double-submit header matching the client's CSRF cookie."""

    def _headers(client: HttpClient) -> dict[str, str]:
        cookie = client.cookies.get(settings.JWT_AUTH["CSRF_COOKIE_NAME"])
        return {CSRF_HEADER: cookie.value if cookie else ""}

    return _headers


@pytest.fixture
def bearer() -> Callable[[str], dict[str, Any]]:
    """Authorization header for a raw access token.

    Typed ``dict[str, Any]`` rather than ``dict[str, str]`` because it is
    splatted into the test client's ``**extra``, whose earlier positional
    parameters are ``bool`` and ``Mapping`` -- a precisely typed value cannot
    satisfy them and mypy rejects the call.
    """

    def _bearer(access_token: str) -> dict[str, Any]:
        return {"HTTP_AUTHORIZATION": f"Bearer {access_token}"}

    return _bearer


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------


class LogCapture(logging.Handler):
    """Collects fully formatted records, filters and all.

    Deliberately not ``caplog``: the authentication loggers are configured
    with ``propagate = False``, so nothing they emit reaches the root handler
    pytest installs. Attaching here also means the assertions run against the
    real formatter and the real redaction filter rather than the raw record.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []
        self.setFormatter(JsonFormatter())
        for log_filter in (
            TenantContextFilter(),
            RequestIdFilter(),
            SensitiveDataFilter(),
        ):
            self.addFilter(log_filter)

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))

    @property
    def documents(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.lines]

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


@pytest.fixture
def log_capture() -> Iterator[LogCapture]:
    """Capture everything the authentication loggers emit during a test."""
    handler = LogCapture()
    names = ("eduremus.auth", "eduremus.security", "django.security", "")
    loggers = [logging.getLogger(name) for name in names]

    previous = [(logger, logger.level) for logger in loggers]
    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    yield handler

    for logger, level in previous:
        logger.removeHandler(handler)
        logger.setLevel(level)
