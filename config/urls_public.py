"""Public URL configuration -- what the platform's own domain serves.

Selected by ``TenantMainMiddleware`` when the request's hostname resolves to
the tenant that owns the ``public`` schema (``public.example.com``, or the
apex domain). Everything routed here reads the public schema: the tenant
catalogue, platform staff accounts, marketing pages, sign-up.

Kept apart from :mod:`config.urls` so that adding a route for institutions
never accidentally exposes it on the platform's domain, or the reverse.
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import URLPattern, URLResolver, include, path

# Annotated because the DEBUG blocks below append plain URLPatterns to
# what would otherwise be inferred as a list of URLResolvers.
urlpatterns: list[URLPattern | URLResolver] = [
    # The platform admin. Same ``admin.site`` object as the tenant URLconf --
    # there is only one registry -- but requests arriving here run with the
    # public schema active, which is the only place apps.tenants models are
    # visible (see apps.tenants.admin.PublicSchemaOnlyAdmin).
    path("admin/", admin.site.urls),
    # Platform staff authenticate against the public schema through the same
    # endpoints institutions use.
    path("api/v1/", include("apps.authentication.urls")),
    # Verification keys are platform-wide, so the JWKS document is served from
    # the public hostname only.
    path("", include("apps.authentication.urls_public")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG and settings.ENABLE_DEBUG_TOOLBAR:
    urlpatterns += [
        path("__debug__/", include("debug_toolbar.urls")),
    ]
