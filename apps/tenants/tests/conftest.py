"""Fixtures shared by the tenants suite.

Builds on the session-scoped ``tenants`` catalogue defined in the project-root
``conftest.py``; everything here is per-test and therefore rolled back.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

import pytest
from django.db import connection
from django_tenants.utils import tenant_context

if TYPE_CHECKING:
    from apps.tenants.models import Client
    from conftest import TenantSchemas

PASSWORD = "s3cure-Passw0rd!"


def _fetch(schema_name: str) -> Client:
    """Read a tenant fresh from the catalogue.

    Always a new instance, never one shared with another test: model methods
    mutate the object they are called on (``delete()`` clears ``pk``), and that
    survives the transaction rollback that undoes the row itself.
    """
    from apps.tenants.models import Client

    return Client.objects.get(schema_name=schema_name)


@pytest.fixture
def acme(db: None, tenants: TenantSchemas) -> Client:
    """First institution. Requesting it does *not* activate its schema."""
    return _fetch(tenants.acme)


@pytest.fixture
def beta(db: None, tenants: TenantSchemas) -> Client:
    """Second institution, used as the other side of isolation assertions."""
    return _fetch(tenants.beta)


@pytest.fixture
def public_tenant(db: None, tenants: TenantSchemas) -> Client:
    """The tenant that owns the public schema."""
    return _fetch(tenants.public)


@pytest.fixture
def in_acme(acme: Client) -> Iterator[Client]:
    """Run the test body with the connection switched to ``acme``."""
    with tenant_context(acme):
        yield acme


@pytest.fixture
def in_beta(beta: Client) -> Iterator[Client]:
    """Run the test body with the connection switched to ``beta``."""
    with tenant_context(beta):
        yield beta


@pytest.fixture
def make_tenant(db: None) -> Callable[..., Client]:
    """Create a tenant, and its schema, inside the current test transaction.

    Quiet by default: ``verbosity=0`` suppresses the per-migration output that
    ``TenantMixin.save()`` would otherwise print for every schema it builds.
    """
    from apps.tenants.models import Client

    def _make(slug: str, *, name: str = "", **fields: object) -> Client:
        client = Client(
            name=name or slug.replace("-", " ").title(), slug=slug, **fields
        )
        client.save(verbosity=0)
        return client

    return _make


@pytest.fixture
def flush_deferred_constraints() -> Callable[[], None]:
    """Settle pending FK trigger events so a schema can be dropped.

    Postgres refuses ``DROP SCHEMA ... CASCADE`` while the current transaction
    still has deferred trigger events queued against the tables involved --
    which is the case whenever a test creates a schema and drops it again
    without committing in between. Production never hits this: creating and
    deleting a tenant are separate commands, hence separate transactions.
    """

    def _flush() -> None:
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")

    return _flush


@pytest.fixture
def schema_tables() -> Callable[[str], set[str]]:
    """Callable returning the table names that physically exist in a schema.

    Reads ``information_schema`` directly rather than going through the ORM:
    the point of most of these assertions is what Postgres actually created,
    not what Django believes it created.
    """

    def _tables(schema_name: str) -> set[str]:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = %s",
                [schema_name],
            )
            return {row[0] for row in cursor.fetchall()}

    return _tables
