"""Permission classes reading authorisation from verified claims.

Nothing here touches the database. Roles and scopes are embedded in the token
precisely so authorisation costs no query, and a permission class that looks
one up turns every request back into the lookup JWT was adopted to remove.

Anything that genuinely needs live state -- "may this person edit *this*
course" -- belongs in an object-level check, where the query is about the
object rather than about the principal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rest_framework.permissions import BasePermission

from apps.authentication.tokens.claims import CLAIM_ROLES, CLAIM_SCOPES
from apps.tenants.utils import current_schema_name, get_public_schema_name

if TYPE_CHECKING:
    from rest_framework.request import Request
    from rest_framework.views import APIView

__all__ = [
    "HasAnyRole",
    "HasScope",
    "IsPlatformStaff",
    "IsTenantMember",
    "ScopedModelPermission",
    "granted_roles",
    "granted_scopes",
]


def _payload(request: Request) -> dict[str, Any]:
    """Claims attached by the authenticator, or empty for a session login.

    Empty rather than raising: DRF's SessionAuthentication is still configured
    for the browsable API, and a session-authenticated request legitimately
    carries no token. It simply holds no scopes, which every check below
    treats as "not permitted" for anything that requires one.
    """
    return getattr(request, "auth_payload", {}) or {}


def granted_scopes(request: Request) -> set[str]:
    return set(str(_payload(request).get(CLAIM_SCOPES, "")).split())


def granted_roles(request: Request) -> set[str]:
    return set(_payload(request).get(CLAIM_ROLES, ()) or ())


class IsTenantMember(BasePermission):
    """Authenticated, and inside a real tenant schema rather than public.

    The schema half is what separates an institution's API from the
    platform's. It mirrors ``PublicSchemaOnlyAdmin``, which gates the tenant
    catalogue the other way round.
    """

    message = "This endpoint is only available within a tenant."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        if not (user and user.is_authenticated):
            return False
        return current_schema_name() != get_public_schema_name()


class IsPlatformStaff(BasePermission):
    """Staff acting in the public schema -- the platform's own operators."""

    message = "Platform staff access required."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        if not (user and user.is_authenticated and user.is_staff):
            return False
        return current_schema_name() == get_public_schema_name()


class HasScope(BasePermission):
    """Requires every scope named in ``view.required_scopes``."""

    message = "Insufficient scope."

    def has_permission(self, request: Request, view: APIView) -> bool:
        required: set[str] = set(getattr(view, "required_scopes", ()) or ())
        if not required:
            return True

        granted = granted_scopes(request)
        if required <= granted:
            return True

        # `<resource>:admin` implies every action on that resource, so an
        # administrator does not need each verb enumerated in their token.
        implied = {
            scope for scope in required if f"{scope.split(':', 1)[0]}:admin" in granted
        }
        return required <= (granted | implied)


class HasAnyRole(BasePermission):
    """Requires at least one of ``view.required_roles``.

    Prefer :class:`HasScope` for new checks. Roles answer "who is this", which
    is the right question only for genuinely identity-shaped rules -- "only a
    registrar may issue a transcript". Scopes answer "what may this credential
    do", which is narrowable and is usually what a permission check means.
    """

    message = "Insufficient role."

    def has_permission(self, request: Request, view: APIView) -> bool:
        required: set[str] = set(getattr(view, "required_roles", ()) or ())
        if not required:
            return True
        return bool(required & granted_roles(request))


class ScopedModelPermission(BasePermission):
    """Maps HTTP methods onto ``<resource>:<action>`` scopes.

    Set ``scope_resource`` on the view; a view without one is not gated by
    this class. Note that it gates the *endpoint*, not the object -- pair it
    with an object-level permission for anything addressable by id.
    """

    message = "Insufficient scope."

    METHOD_ACTIONS: ClassVar[dict[str, str]] = {
        "GET": "read",
        "HEAD": "read",
        "OPTIONS": "read",
        "POST": "write",
        "PUT": "write",
        "PATCH": "write",
        "DELETE": "delete",
    }

    def has_permission(self, request: Request, view: APIView) -> bool:
        resource: str | None = getattr(view, "scope_resource", None)
        if resource is None:
            return True

        # Unknown methods default to "write" rather than "read": an
        # unrecognised verb must not fall through to the weakest requirement.
        action = self.METHOD_ACTIONS.get(request.method or "", "write")
        granted = granted_scopes(request)
        return f"{resource}:{action}" in granted or f"{resource}:admin" in granted
