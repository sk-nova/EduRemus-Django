"""OpenAPI hints for drf-spectacular.

Without this, the generator cannot tell what
``TenantAwareJWTAuthentication`` expects and omits the security requirement
from every endpoint that uses it -- the schema would then describe the
authenticated endpoints as though they were public.

Imported from ``AuthenticationConfig.ready()``: drf-spectacular discovers
extensions by subclass registration, so an extension in a module nothing
imports is silently inert.
"""

from __future__ import annotations

from typing import Any

from drf_spectacular.extensions import OpenApiAuthenticationExtension

__all__ = ["TenantAwareJWTScheme"]


class TenantAwareJWTScheme(OpenApiAuthenticationExtension):
    """Describes the Bearer scheme this API actually implements."""

    target_class = "apps.authentication.authentication.TenantAwareJWTAuthentication"
    name = "BearerAuth"
    match_subclasses = True

    def get_security_definition(self, auto_schema: Any) -> dict[str, Any]:
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "RS256 access token. Must be presented to the same tenant "
                "hostname it was issued for; a token replayed against another "
                "tenant is rejected with token_wrong_tenant."
            ),
        }
