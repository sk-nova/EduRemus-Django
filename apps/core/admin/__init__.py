"""Admin plumbing shared by every app: the two plane-specific admin sites.

``apps.core`` is in both ``SHARED_APPS`` and ``TENANT_APPS`` and owns the
model-free building blocks every business app reuses, which makes it the right
home for these. ``config/`` would be the wrong one -- every app would then
import from the project package, inverting the dependency direction the repo
keeps (no app imports ``config.*``).

Import ``control_site`` / ``tenant_site`` from here rather than from
``.sites``, and register every model explicitly against one or both::

    from apps.core.admin import tenant_site

    @admin.register(Course, site=tenant_site)
    class CourseAdmin(admin.ModelAdmin): ...

``@admin.register(X)`` without ``site=`` targets the default ``admin.site``,
which is mounted nowhere -- the model then vanishes from both planes with no
exception and no system-check failure.
"""

from __future__ import annotations

from apps.core.admin.sites import (
    CONTROL_PLANE_GROUP,
    TENANT_PLANE_GROUP,
    ControlPlaneAdminSite,
    TenantPlaneAdminSite,
    control_site,
    may_administer_institution,
    may_administer_platform,
    tenant_site,
)

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
