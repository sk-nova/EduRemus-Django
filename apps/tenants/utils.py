"""Helpers for running code against a specific schema.

``django_tenants`` already ships the two primitives:

``schema_context("acme")``
    Switches the connection's ``search_path`` by *name*. Cheap -- no query is
    needed to enter it -- but inside the block ``connection.tenant`` is only a
    ``FakeTenant`` carrying the schema name, so tenant model fields are not
    available.
``tenant_context(client)``
    Switches using a :class:`~apps.tenants.models.Client` instance, which stays
    reachable as ``connection.tenant``. Use this when the code inside needs
    tenant attributes (name, slug, feature flags...).

Both are re-exported here so callers have one import site, alongside the few
wrappers that keep background jobs, shell scripts and data migrations honest.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from django.db import connection
from django_tenants.utils import (
    get_public_schema_name,
    get_tenant_model,
    schema_context,
    schema_exists,
    tenant_context,
)

if TYPE_CHECKING:
    from apps.tenants.models import Client

__all__ = [
    "activate_public_schema",
    "current_schema_name",
    "current_tenant",
    "each_tenant",
    "get_public_schema_name",
    "public_schema",
    "run_in_every_schema",
    "schema_context",
    "schema_exists",
    "tenant_context",
]


def activate_public_schema() -> None:
    """Point the connection back at the public schema and leave it there.

    Unlike :func:`public_schema` this does not restore anything afterwards --
    it is the "start from a known state" call for test teardown, long-running
    workers and shell sessions.
    """
    # django-tenants ships no type stubs, so the schema-aware methods its
    # backend adds to the connection are invisible to mypy. Narrowed to this
    # one call site rather than ignored at every use.
    connection.set_schema_to_public()  # type: ignore[attr-defined]


def current_schema_name() -> str:
    """Schema the connection is currently pointed at.

    Safe to call anywhere -- outside a request, inside a Celery task, in a
    ``manage.py`` script. Falls back to the public schema before any tenant has
    been activated.
    """
    return getattr(connection, "schema_name", None) or get_public_schema_name()


def current_tenant() -> Client | None:
    """The active :class:`Client`, or ``None`` when none is set.

    Returns ``None`` rather than a ``FakeTenant`` when the schema was entered
    by name via :func:`schema_context`, because a ``FakeTenant`` has no model
    fields and silently returning one invites attribute errors far from here.
    """
    tenant = getattr(connection, "tenant", None)
    if tenant is None or not isinstance(tenant, get_tenant_model()):
        return None
    return tenant


@contextmanager
def public_schema() -> Iterator[None]:
    """Run a block against the public schema, then restore the previous one.

    The tenant catalogue itself lives there, so anything that reads or writes
    :class:`Client` / :class:`Domain` from inside a tenant request must go
    through this.
    """
    with schema_context(get_public_schema_name()):
        yield


def each_tenant(
    *, include_public: bool = False, active_only: bool = True
) -> Iterator[Client]:
    """Yield tenants with the connection already switched to each one.

    The catalogue is read once, up front, in the public schema -- iterating a
    queryset while the search_path moves underneath it would re-issue the query
    against whichever schema happened to be active.

        for client in each_tenant():
            Enrolment.objects.filter(expired=True).delete()
    """
    with public_schema():
        clients = get_tenant_model().objects.all()
        if active_only:
            clients = clients.active()
        if not include_public:
            clients = clients.tenants_only()
        catalogue = list(clients.order_by("schema_name"))

    for client in catalogue:
        with tenant_context(client):
            yield client


def run_in_every_schema[**P, R](
    func: Callable[P, R],
    *args: P.args,
    **kwargs: P.kwargs,
) -> dict[str, R]:
    """Call ``func`` once per active tenant, returning results by schema name.

    Intended for maintenance scripts and periodic jobs::

        run_in_every_schema(rebuild_search_index)
    """
    return {client.schema_name: func(*args, **kwargs) for client in each_tenant()}
