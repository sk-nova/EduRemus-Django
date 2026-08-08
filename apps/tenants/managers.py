"""Managers and querysets for the tenant catalogue."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from django.db import models
from django_tenants.utils import get_public_schema_name

if TYPE_CHECKING:
    # Import-time only: models.py imports this module, so a runtime import
    # back the other way would be circular.
    from apps.tenants.models import Client, Domain  # noqa: F401


class ClientQuerySet(models.QuerySet["Client"]):
    """Selectors over the tenant catalogue.

    Deliberately *not* soft-delete aware: a tenant's real payload is its
    Postgres schema, and hiding a row whose schema is still present would only
    make the two disagree. Suspension is expressed with ``is_active``, removal
    with :meth:`Client.delete`, which drops the schema.
    """

    def active(self) -> Self:
        """Tenants that are allowed to serve requests."""
        return self.filter(is_active=True)

    def suspended(self) -> Self:
        """Tenants whose schema still exists but which may not serve traffic."""
        return self.filter(is_active=False)

    def tenants_only(self) -> Self:
        """Every tenant except the public one."""
        return self.exclude(schema_name=get_public_schema_name())


ClientManager = models.Manager.from_queryset(ClientQuerySet)


class DomainQuerySet(models.QuerySet["Domain"]):
    """Selectors over tenant hostnames."""

    def primary(self) -> Self:
        """Only the canonical hostname of each tenant."""
        return self.filter(is_primary=True)


DomainManager = models.Manager.from_queryset(DomainQuerySet)
