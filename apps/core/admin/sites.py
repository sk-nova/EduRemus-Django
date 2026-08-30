"""The two admin registries: a control plane and a tenant admin plane.

One ``AdminSite`` per audience, rather than one registry filtered by a
permission hook. ``control_site`` is mounted only in ``PUBLIC_SCHEMA_URLCONF``
and carries the platform's own records; ``tenant_site`` is mounted only in
``ROOT_URLCONF`` and carries an institution's. A model reaches a plane by being
registered on that plane's site, so "not registered" means "no URL exists" --
structural rather than behavioural.

The plane rule is enforced in two places on purpose:

``has_permission``
    Gates every admin view, including the index. This is what turns a
    wrong-plane staff user's ``GET /control/`` into a redirect to the login
    page.
``login_form``
    ``AdminSite.login()`` consults ``has_permission()`` only on GET; the POST
    path runs ``LoginView`` with ``AdminAuthenticationForm``, which checks
    nothing but ``is_staff``. Without the form half, a wrong-plane staff user
    would authenticate, receive a session cookie, and then bounce forever
    between ``/control/`` and ``/control/login/``.

Each site also checks the active schema. That is defence in depth -- a site is
only reachable through the URLconf that mounts it, so reaching ``control_site``
already implies the public schema -- and it fails closed if that ever stops
being true.

Both forms re-raise Django's stock ``invalid_login`` message rather than a
specific "you are not a platform administrator". A distinct error would confirm
that the credentials themselves were valid, which is the same reasoning behind
the 404 (not 403) a suspended tenant gets from the middleware.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from django.contrib.admin import AdminSite
from django.contrib.admin.forms import AdminAuthenticationForm
from django.utils.translation import gettext_lazy as _

from apps.tenants.utils import (
    current_schema_name,
    current_tenant,
    get_public_schema_name,
)

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.contrib.auth.models import AnonymousUser
    from django.http import HttpRequest
    from django.template.response import TemplateResponse

    from apps.accounts.models import User

__all__ = [
    "CONTROL_PLANE_GROUP",
    "TENANT_PLANE_GROUP",
    "ControlPlaneAdminSite",
    "TenantPlaneAdminSite",
    "control_site",
    "may_administer_institution",
    "may_administer_platform",
    "tenant_site",
]

# Seeded per schema by apps.authentication.migrations.0002_seed_default_roles.
CONTROL_PLANE_GROUP = "platform_admin"
TENANT_PLANE_GROUP = "tenant_admin"


def _is_admitted(user: AbstractBaseUser | AnonymousUser, group_name: str) -> bool:
    """Active staff who is a superuser or a member of ``group_name``."""
    if not (user.is_authenticated and user.is_active):
        return False
    # AUTH_USER_MODEL is accounts.User; the flags below live on
    # PermissionsMixin, which AbstractBaseUser does not declare.
    account = cast("User", user)
    if not account.is_staff:
        return False
    return account.is_superuser or account.groups.filter(name=group_name).exists()


def may_administer_platform(user: AbstractBaseUser | AnonymousUser) -> bool:
    """Whether ``user`` may operate the SaaS itself, from the public schema."""
    return _is_admitted(user, CONTROL_PLANE_GROUP)


def may_administer_institution(user: AbstractBaseUser | AnonymousUser) -> bool:
    """Whether ``user`` may administer the institution whose schema is active."""
    return _is_admitted(user, TENANT_PLANE_GROUP)


class ControlPlaneAuthenticationForm(AdminAuthenticationForm):
    """Admits only platform administrators, on the login POST."""

    def confirm_login_allowed(self, user: User) -> None:
        # super() covers is_active and is_staff.
        super().confirm_login_allowed(user)
        if not may_administer_platform(user):
            raise self.get_invalid_login_error()


class TenantPlaneAuthenticationForm(AdminAuthenticationForm):
    """Admits only institution administrators, on the login POST."""

    def confirm_login_allowed(self, user: User) -> None:
        super().confirm_login_allowed(user)
        if not may_administer_institution(user):
            raise self.get_invalid_login_error()


class ControlPlaneAdminSite(AdminSite):
    """The platform's own admin, mounted at ``/control/`` on the public host."""

    site_title = site_header = _("EduRemus Control Plane")
    index_title = _("Platform administration")
    login_form = ControlPlaneAuthenticationForm

    def has_permission(self, request: HttpRequest) -> bool:
        # The schema half is defence in depth: this site is only mounted in
        # PUBLIC_SCHEMA_URLCONF, so reaching it already implies public. It
        # fails closed if that ever stops being true.
        if current_schema_name() != get_public_schema_name():
            return False
        return may_administer_platform(request.user)


class TenantPlaneAdminSite(AdminSite):
    """An institution's own admin, mounted at ``/admin/`` on its own host.

    Named ``"admin"`` so every existing ``reverse("admin:...")`` is unchanged:
    ``AdminSite.urls`` hard-codes the *application* namespace to ``"admin"``
    and takes only the instance namespace from ``AdminSite(name=...)``.
    """

    site_title = site_header = _("EduRemus")
    index_title = _("Institution administration")
    login_form = TenantPlaneAuthenticationForm

    def has_permission(self, request: HttpRequest) -> bool:
        if current_schema_name() == get_public_schema_name():
            return False
        return may_administer_institution(request.user)

    def each_context(self, request: HttpRequest) -> dict[str, Any]:
        # site_header/site_title are class attributes, so the institution's own
        # name has to be injected per request. current_tenant() returns the
        # instance the middleware already put on the connection -- no query.
        context = super().each_context(request)
        tenant = current_tenant()
        if tenant is not None:
            context["site_header"] = context["site_title"] = tenant.name
        return context

    def index(
        self,
        request: HttpRequest,
        extra_context: dict[str, Any] | None = None,
    ) -> TemplateResponse:
        # index() sets "title" from self.index_title *after* each_context, so
        # the dynamic value has to arrive via extra_context, which wins. The
        # caller's own keys still win over ours.
        tenant = current_tenant()
        if tenant is not None:
            extra_context = {"title": tenant.name, **(extra_context or {})}
        return super().index(request, extra_context)


# Each URLconf mounts exactly one of these. Mounting both in one would break
# LOGIN_URL = "admin:login", which resolves an unknown instance namespace by
# falling back to the first site registered under the "admin" application
# namespace.
control_site = ControlPlaneAdminSite(name="control")
tenant_site = TenantPlaneAdminSite(name="admin")

# has_permission costs one groups query and is called by both admin_view and
# each_context, so two or three per admin page -- noise next to a changelist.
# Deliberately not cached on the request.
