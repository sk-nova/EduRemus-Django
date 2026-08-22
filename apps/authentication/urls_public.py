"""Routes served only from the platform's own hostname.

The JWKS document lives here and nowhere else. Verification keys are
platform-wide, so publishing a per-tenant JWKS would imply per-tenant keys and
mislead every verifier that fetched one.

The metrics endpoint is here for the same reason in reverse: the counters are
labelled *by* schema, so a per-tenant copy would hand each institution every
other institution's login rate.
"""

from __future__ import annotations

from django.urls import path

from apps.authentication import views

app_name = "authentication_public"

urlpatterns = [
    path(".well-known/jwks.json", views.JWKSView.as_view(), name="jwks"),
    # Mounted unconditionally and gated per request: a route added behind an
    # `if` in a URLconf is resolved once at import, so the flag could only
    # ever be changed by a redeploy.
    path("metrics", views.MetricsView.as_view(), name="metrics"),
]
