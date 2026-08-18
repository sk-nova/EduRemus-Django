"""Tenant URL configuration -- what an institution's own domain serves.

Selected by ``TenantMainMiddleware`` for every request whose hostname resolves
to a non-public tenant (``acme.example.com``, ``riverdale.example.com``, ...).
The public site is served by :mod:`config.urls_public` instead.

The two files are separate on purpose. Tenant staff reach an admin scoped to
their own schema here; the tenant catalogue that lists *every* institution is
only routable from the public URLconf.
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import URLPattern, URLResolver, include, path

# Annotated because the DEBUG blocks below append plain URLPatterns to
# what would otherwise be inferred as a list of URLResolvers.
urlpatterns: list[URLPattern | URLResolver] = [
    # Reads and writes the tenant's own schema: same admin classes, different
    # tables, because the connection's search_path was switched before this
    # ran. apps.tenants models are excluded by PublicSchemaOnlyAdmin.
    path("admin/", admin.site.urls),
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
