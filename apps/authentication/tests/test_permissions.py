"""Authorisation read from verified claims.

Two properties are asserted throughout. Permission classes must reach the
right verdict, and they must reach it **without a query** -- roles and scopes
are embedded in the token precisely so authorisation costs nothing, and a
permission class that looks one up puts back the per-request lookup JWT was
adopted to remove.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest
from django.contrib.auth.models import AnonymousUser
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from apps.authentication.permissions import (
    HasAnyRole,
    HasScope,
    IsPlatformStaff,
    IsTenantMember,
    ScopedModelPermission,
    granted_roles,
    granted_scopes,
)
from apps.tenants.utils import public_schema, tenant_context

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.tenants.models import Tenant


def request_with(
    *,
    user: Any = None,
    scopes: str = "",
    roles: tuple[str, ...] = (),
    method: str = "GET",
    with_payload: bool = True,
) -> Request:
    """A DRF request carrying the claims an authenticator would have attached."""
    factory = APIRequestFactory()
    raw = getattr(factory, method.lower())("/")
    request = Request(raw)
    request.user = user if user is not None else AnonymousUser()
    if with_payload:
        request.auth_payload = {"scp": scopes, "roles": list(roles)}  # type: ignore[attr-defined]
    return request


def view_with(**attributes: Any) -> APIView:
    view = APIView()
    for name, value in attributes.items():
        setattr(view, name, value)
    return view


class TestClaimReaders:
    def test_scopes_are_split_from_the_space_delimited_claim(self) -> None:
        request = request_with(scopes="courses:read courses:write")

        assert granted_scopes(request) == {"courses:read", "courses:write"}

    def test_roles_come_from_the_list_claim(self) -> None:
        request = request_with(roles=("faculty", "registrar"))

        assert granted_roles(request) == {"faculty", "registrar"}

    def test_a_request_with_no_payload_holds_nothing(self) -> None:
        """A session-authenticated request is legitimate and carries no token.

        It holds no scopes, which every check below reads as "not permitted"
        rather than as an error.
        """
        request = request_with(with_payload=False)

        assert granted_scopes(request) == set()
        assert granted_roles(request) == set()


@pytest.mark.django_db
class TestIsTenantMember:
    def test_an_authenticated_user_inside_a_tenant_is_permitted(
        self, acme: Tenant, acme_user: User
    ) -> None:
        request = request_with(user=acme_user)

        with tenant_context(acme):
            assert IsTenantMember().has_permission(request, view_with()) is True

    def test_an_anonymous_caller_is_refused(self, acme: Tenant) -> None:
        request = request_with()

        with tenant_context(acme):
            assert IsTenantMember().has_permission(request, view_with()) is False

    def test_the_public_schema_is_not_a_tenant(
        self, public_tenant: Tenant, make_user: Callable[..., User]
    ) -> None:
        """Mirrors PublicSchemaOnlyAdmin, which gates the catalogue the other
        way round: an institution endpoint is not the platform's."""
        with public_schema():
            staff = make_user("ops@eduremus.com", is_staff=True)
            request = request_with(user=staff)

            assert IsTenantMember().has_permission(request, view_with()) is False


@pytest.mark.django_db
class TestIsPlatformStaff:
    def test_staff_in_the_public_schema_are_permitted(
        self, public_tenant: Tenant, make_user: Callable[..., User]
    ) -> None:
        with public_schema():
            staff = make_user("ops@eduremus.com", is_staff=True)
            request = request_with(user=staff)

            assert IsPlatformStaff().has_permission(request, view_with()) is True

    def test_a_non_staff_user_is_refused(
        self, public_tenant: Tenant, make_user: Callable[..., User]
    ) -> None:
        with public_schema():
            member = make_user("member@eduremus.com")
            request = request_with(user=member)

            assert IsPlatformStaff().has_permission(request, view_with()) is False

    def test_tenant_staff_are_not_platform_staff(
        self, acme: Tenant, make_user: Callable[..., User]
    ) -> None:
        """``is_staff`` inside an institution is an institution's own flag.

        Without the schema half of this check, any tenant administrator could
        promote themselves onto the platform.
        """
        with tenant_context(acme):
            admin = make_user("admin@acme.edu", is_staff=True)
            request = request_with(user=admin)

            assert IsPlatformStaff().has_permission(request, view_with()) is False


class TestHasScope:
    def test_a_view_requiring_nothing_permits_everyone(self) -> None:
        request = request_with(scopes="")

        assert HasScope().has_permission(request, view_with()) is True

    def test_the_required_scope_must_be_held(self) -> None:
        request = request_with(scopes="courses:read")
        view = view_with(required_scopes=["courses:read"])

        assert HasScope().has_permission(request, view) is True

    def test_a_missing_scope_is_refused(self) -> None:
        request = request_with(scopes="courses:read")
        view = view_with(required_scopes=["courses:write"])

        assert HasScope().has_permission(request, view) is False

    def test_every_required_scope_must_be_held(self) -> None:
        """All, not any: a view naming two scopes needs both."""
        request = request_with(scopes="courses:read")
        view = view_with(required_scopes=["courses:read", "grades:write"])

        assert HasScope().has_permission(request, view) is False

    def test_a_resource_admin_scope_implies_the_verbs(self) -> None:
        """So an administrator's token does not have to enumerate every verb."""
        request = request_with(scopes="courses:admin")
        view = view_with(required_scopes=["courses:read", "courses:write"])

        assert HasScope().has_permission(request, view) is True

    def test_admin_on_one_resource_does_not_imply_another(self) -> None:
        request = request_with(scopes="courses:admin")
        view = view_with(required_scopes=["grades:write"])

        assert HasScope().has_permission(request, view) is False


class TestHasAnyRole:
    def test_a_view_requiring_no_role_permits_everyone(self) -> None:
        assert HasAnyRole().has_permission(request_with(), view_with()) is True

    def test_one_matching_role_is_enough(self) -> None:
        request = request_with(roles=("faculty",))
        view = view_with(required_roles=["registrar", "faculty"])

        assert HasAnyRole().has_permission(request, view) is True

    def test_no_matching_role_is_refused(self) -> None:
        request = request_with(roles=("student",))
        view = view_with(required_roles=["registrar"])

        assert HasAnyRole().has_permission(request, view) is False


class TestScopedModelPermission:
    def test_a_view_with_no_resource_is_not_gated_by_this_class(self) -> None:
        request = request_with(scopes="")

        assert ScopedModelPermission().has_permission(request, view_with()) is True

    @pytest.mark.parametrize(
        "method,scope",
        [
            ("GET", "courses:read"),
            ("POST", "courses:write"),
            ("PATCH", "courses:write"),
            ("DELETE", "courses:delete"),
        ],
    )
    def test_the_method_selects_the_scope(self, method: str, scope: str) -> None:
        request = request_with(scopes=scope, method=method)
        view = view_with(scope_resource="courses")

        assert ScopedModelPermission().has_permission(request, view) is True

    def test_a_read_scope_does_not_authorise_a_write(self) -> None:
        request = request_with(scopes="courses:read", method="POST")
        view = view_with(scope_resource="courses")

        assert ScopedModelPermission().has_permission(request, view) is False

    def test_the_resource_admin_scope_authorises_every_method(self) -> None:
        for method in ("GET", "POST", "DELETE"):
            request = request_with(scopes="courses:admin", method=method)
            view = view_with(scope_resource="courses")

            assert ScopedModelPermission().has_permission(request, view) is True

    def test_an_unrecognised_method_falls_through_to_write(self) -> None:
        """Never to the weakest requirement: an unknown verb is not a read."""
        request = request_with(scopes="courses:read", method="PUT")
        request.method = "TRACE"  # type: ignore[misc]
        view = view_with(scope_resource="courses")

        assert ScopedModelPermission().has_permission(request, view) is False


@pytest.mark.django_db
class TestNoQueriesOnTheHotPath:
    def test_scope_checks_touch_no_database(
        self, acme: Tenant, acme_user: User, django_assert_num_queries: Any
    ) -> None:
        """The point of embedding roles in the token.

        A permission class that reads the database gives back the per-request
        lookup the whole design exists to avoid.
        """
        request = request_with(
            user=acme_user, scopes="courses:admin", roles=("tenant_admin",)
        )
        view = view_with(required_scopes=["courses:read"], scope_resource="courses")

        with tenant_context(acme), django_assert_num_queries(0):
            assert HasScope().has_permission(request, view) is True
            assert HasAnyRole().has_permission(request, view_with()) is True
            assert ScopedModelPermission().has_permission(request, view) is True
