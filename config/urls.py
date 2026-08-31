"""Tenant URL configuration -- what an institution's own domain serves.

Selected by ``TenantMainMiddleware`` for every request whose hostname resolves
to a non-public tenant (``acme.example.com``, ``riverdale.example.com``, ...).
The public site is served by :mod:`config.urls_public` instead.

The two files are separate on purpose. Tenant staff reach an admin scoped to
their own schema here; the tenant catalogue that lists *every* institution is
only routable from the public URLconf, where the control plane is mounted.
"""

from django.conf import settings
from django.conf.urls.static import static
from django.urls import URLPattern, URLResolver, include, path

from apps.core.admin import tenant_site

# Annotated because the DEBUG blocks below append plain URLPatterns to
# what would otherwise be inferred as a list of URLResolvers.
urlpatterns: list[URLPattern | URLResolver] = [
    # The institution's own admin, reading and writing its own schema because
    # the connection's search_path was switched before this ran. The tenant
    # catalogue is not merely permission-denied here -- Tenant and Domain are
    # registered on control_site, which this URLconf does not mount, so no URL
    # for them exists.
    #
    # AdminSite.urls snapshots the registry at import time. Autodiscovery runs
    # inside django.setup() and URLconfs are imported afterwards, so this is
    # safe -- but it is why nothing may reverse() or import a URLconf from an
    # AppConfig.ready(), which would freeze a half-built registry in here.
    path("admin/", tenant_site.urls),
    # Mounted unconditionally. A per-tenant feature flag belongs in a view
    # mixin, never in a conditional here: a URLconf is evaluated once per
    # process at import, so a condition would freeze whichever tenant happened
    # to be active at import time for the life of the worker.
    path("api/v1/", include("apps.authentication.urls")),
]

if settings.DEBUG:
    # Uploads live under MEDIA_ROOT/<schema_name>/; TenantFileSystemStorage
    # generates the matching /media/<schema_name>/... URLs, so one static()
    # rule serves every tenant. Development only -- in production this is the
    # web server's or object store's job.
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG and settings.ENABLE_DEBUG_TOOLBAR:
    urlpatterns += [
        path("__debug__/", include("debug_toolbar.urls")),
    ]
