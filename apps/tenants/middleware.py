"""Hostname to schema routing.

``TenantMainMiddleware`` must run before anything that touches the database,
because until it has run the connection still points at the public schema and
every ORM call would read the wrong rows. This subclass adds one rule on top:
a tenant that has been suspended does not serve requests at all.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django_tenants.middleware.main import TenantMainMiddleware as BaseTenantMiddleware

if TYPE_CHECKING:
    from apps.tenants.models import Domain, Tenant


class TenantMainMiddleware(BaseTenantMiddleware):
    """Resolves the request hostname to a tenant, rejecting suspended ones.

    The base class raises ``Http404`` for an unknown hostname; a suspended
    tenant is treated identically and on purpose. Distinguishing "no such
    institution" from "that institution is suspended" would confirm the
    existence of a customer to anyone who can guess a subdomain.
    """

    def get_tenant(self, domain_model: type[Domain], hostname: str) -> Tenant:
        domain: Domain = domain_model.objects.select_related("tenant").get(
            domain=hostname.lower(),
            tenant__is_active=True,
        )
        return domain.tenant
