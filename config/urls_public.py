"""Public URL configuration -- what the platform's own domain serves.

Selected by ``TenantMainMiddleware`` when the request's hostname resolves to
the tenant that owns the ``public`` schema (``public.example.com``, or the
apex domain). Everything routed here reads the public schema: the tenant
catalogue, platform staff accounts, marketing pages, sign-up.

Kept apart from :mod:`config.urls` so that adding a route for institutions
never accidentally exposes it on the platform's domain, or the reverse. The two
no longer share an admin registry either: this file mounts ``control_site`` and
the tenant URLconf mounts ``tenant_site``, so a model reaches a plane only by
being registered on that plane's site.
"""

from django.conf import settings
from django.conf.urls.static import static
from django.urls import URLPattern, URLResolver, include, path

from apps.core.admin import control_site

# Annotated because the DEBUG blocks below append plain URLPatterns to
# what would otherwise be inferred as a list of URLResolvers.
urlpatterns: list[URLPattern | URLResolver] = [
    # The control plane: the tenant catalogue, platform staff accounts, the
    # platform's own authentication records. Mounted here and nowhere else, so
    # an institution's domain has no URL for any of it.
    #
    # Deliberately no redirect from the old /admin/ -- it 404s. A partial one
    # would be worse than none: a bookmarked /admin/login/ that redirected
    # would have the browser turn a credential POST into a GET against the
    # other plane, and a 404 matches this codebase's stance that a probe should
    # not confirm what exists.
    path("control/", control_site.urls),
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
