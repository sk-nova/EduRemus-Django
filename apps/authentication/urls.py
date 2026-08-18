"""Tenant-facing authentication routes, mounted under ``/api/v1/``.

Included by *both* URLconfs. Institution users authenticate against their own
schema; platform staff authenticate against ``public``. The views are
identical -- what differs is the schema the connection is pointed at, which
the middleware decided before any of this ran.
"""

from __future__ import annotations

from django.urls import path

from apps.authentication import views

app_name = "authentication"

urlpatterns = [
    path("auth/login/", views.LoginView.as_view(), name="login"),
    path("auth/refresh/", views.RefreshView.as_view(), name="refresh"),
    path("auth/logout/", views.LogoutView.as_view(), name="logout"),
    path("auth/logout-all/", views.LogoutAllView.as_view(), name="logout-all"),
    path("auth/verify/", views.VerifyTokenView.as_view(), name="verify"),
    path("auth/me/", views.CurrentUserView.as_view(), name="me"),
    path("auth/sessions/", views.SessionListView.as_view(), name="sessions"),
    path("auth/revoke/", views.RevokeSessionView.as_view(), name="revoke"),
    path(
        "auth/password/change/",
        views.PasswordChangeView.as_view(),
        name="password-change",
    ),
]
