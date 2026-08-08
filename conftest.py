"""Session-wide fixtures for the multi-tenant suite.

Every test runs against a real Postgres schema, so the tenants the suite needs
are created *once* per session -- creating one runs the whole migration set
against a fresh schema, which is far too slow to do per test.

Consequences worth knowing:

* The catalogue rows and schemas created here are written outside any test's
  transaction, so they survive between tests. Anything a *test* writes still
  rolls back, because pytest-django's ``db`` fixture wraps each test in an
  atomic block and schema switching only moves the ``search_path`` on that same
  connection.
* Only schema *names* are handed out, never model instances. A shared instance
  would carry mutations between tests -- ``Model.delete()`` sets ``pk`` to
  ``None`` on the object it was called with, and no amount of transaction
  rollback undoes that. Per-test fixtures re-read the row instead.
* Creation is idempotent, so ``--reuse-db`` (the default, see
  ``pyproject.toml``) reuses the schemas. After adding a migration, run
  ``make test-fresh`` / ``pytest --create-db``: reused schemas are not
  re-migrated, exactly as the reused public schema is not.
* Tests start in whichever schema the previous one left active, so
  :func:`_reset_schema` returns the connection to ``public`` between tests.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from django.conf import settings
from django_tenants.utils import get_public_schema_name, schema_exists
from pytest_django.plugin import DjangoDbBlocker

from apps.tenants.utils import activate_public_schema

# Hostname Django's test client sends when none is given. Routed to the public
# tenant so that tests written before multi-tenancy -- and any test that does
# not care which tenant it is on -- keep working unchanged.
DEFAULT_TEST_HOST = "testserver"

# Explicit hostname for the public tenant, for tests that need to address it
# unambiguously. Both are covered by ``.testserver`` in ALLOWED_HOSTS.
PUBLIC_TENANT_DOMAIN = "public.testserver"


@dataclass(frozen=True)
class TenantSchemas:
    """Schema names the session fixture guarantees exist and are migrated."""

    public: str
    acme: str
    beta: str


def _ensure_tenant(
    *, schema_name: str, slug: str, name: str, domains: list[str]
) -> None:
    """Create a tenant, its schema and its domains if they are not there yet."""
    from apps.tenants.models import Client, Domain

    client = Client.objects.filter(schema_name=schema_name).first()
    if client is None:
        client = Client(schema_name=schema_name, slug=slug, name=name)
        # verbosity=0: a full migration run per schema is noise in test output.
        client.save(verbosity=0)
    elif not schema_exists(schema_name):
        # Catalogue row survived a manual schema drop; rebuild the schema.
        client.create_schema(check_if_exists=True, verbosity=0)

    for index, domain in enumerate(domains):
        Domain.objects.get_or_create(
            domain=domain,
            defaults={"tenant": client, "is_primary": index == 0},
        )


@pytest.fixture(scope="session", autouse=True)
def tenants(django_db_setup: None, django_db_blocker: DjangoDbBlocker) -> TenantSchemas:
    """Public tenant plus two institutions, with their schemas migrated.

    Autouse because hostname routing is now unconditional: without a tenant
    answering on ``testserver`` every request in the suite would 404 in the
    middleware before reaching a view.
    """
    with django_db_blocker.unblock():
        _ensure_tenant(
            schema_name=get_public_schema_name(),
            slug="public",
            name="EduRemus Platform",
            domains=[PUBLIC_TENANT_DOMAIN, DEFAULT_TEST_HOST],
        )
        _ensure_tenant(
            schema_name="acme",
            slug="acme",
            name="Acme Institute",
            domains=["acme.testserver"],
        )
        _ensure_tenant(
            schema_name="beta",
            slug="beta",
            name="Beta College",
            domains=["beta.testserver"],
        )
        activate_public_schema()

    # No teardown: the schemas are the expensive part and --reuse-db exists
    # precisely so the next run can have them back.
    return TenantSchemas(public=get_public_schema_name(), acme="acme", beta="beta")


@pytest.fixture(autouse=True)
def _reset_schema() -> Iterator[None]:
    """Leave every test on the public schema, whatever it did to get there.

    Schema selection is connection state, not test state, so a test that
    switched schemas and failed part-way would otherwise poison its successors.
    """
    yield
    activate_public_schema()


@pytest.fixture(scope="session", autouse=True)
def _clean_media_root() -> Iterator[None]:
    """Start from an empty MEDIA_ROOT so upload-path assertions are meaningful."""
    shutil.rmtree(settings.MEDIA_ROOT, ignore_errors=True)
    yield
    shutil.rmtree(settings.MEDIA_ROOT, ignore_errors=True)
