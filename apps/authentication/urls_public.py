"""Routes served only from the platform's own hostname.

The JWKS document lives here and nowhere else. Verification keys are
platform-wide, so publishing a per-tenant JWKS would imply per-tenant keys and
mislead every verifier that fetched one.
"""

from __future__ import annotations

from django.urls import path

from apps.authentication import views

app_name = "authentication_public"

urlpatterns = [
    path(".well-known/jwks.json", views.JWKSView.as_view(), name="jwks"),
]
