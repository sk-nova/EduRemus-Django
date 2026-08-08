"""Template context for the active tenant."""

from __future__ import annotations

from django.http import HttpRequest

from apps.tenants.utils import current_schema_name


def tenant(request: HttpRequest) -> dict[str, object]:
    """Expose the active tenant and its schema to every template.

    ``request.tenant`` is attached by
    :class:`apps.tenants.middleware.TenantMainMiddleware`, so templates can
    render ``{{ tenant.name }}`` without every view threading it through. It is
    missing when an earlier middleware short-circuits the request, hence the
    ``getattr``.
    """
    return {
        "tenant": getattr(request, "tenant", None),
        "schema_name": current_schema_name(),
    }
