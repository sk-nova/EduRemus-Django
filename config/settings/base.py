"""
Base Django settings for EduRemus-Django project.

The project is multi-tenant by *Postgres schema* (django-tenants). One
database holds a ``public`` schema with the tenant catalogue and the platform's
own records, plus one schema per institution holding that institution's data.
``TenantMainMiddleware`` maps the request's hostname to a schema and sets the
connection's ``search_path`` accordingly, so ordinary ORM code needs no
tenant filtering and cannot reach across the boundary.
"""

from pathlib import Path

import dj_database_url
from decouple import config

# =====================================================================
# CORE SETTINGS
# =====================================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent
APPS_DIR = BASE_DIR / "apps"
DEBUG = False
WSGI_APPLICATION = "config.wsgi.application"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Two URLconfs, selected per request by TenantMainMiddleware: the public one
# for the platform's own hostname, the tenant one for every institution.
ROOT_URLCONF = "config.urls"
PUBLIC_SCHEMA_URLCONF = "config.urls_public"

# =====================================================================
# MULTI-TENANCY SETTINGS
# =====================================================================

# Schema holding the tenant catalogue and everything in SHARED_APPS. It is
# always on the search_path, so shared tables stay readable from a tenant.
PUBLIC_SCHEMA_NAME = "public"

TENANT_MODEL = "tenants.Client"
TENANT_DOMAIN_MODEL = "tenants.Domain"

# An unrecognised hostname is a 404, never a silent fall-through to the public
# site: serving the platform's own pages to an unknown host would let a typo'd
# or spoofed subdomain reach a schema its owner never asked for.
SHOW_PUBLIC_IF_NO_TENANT_FOUND = False

# django-tenants re-issues `SET search_path` on every cursor by default. With
# this on it only does so when the schema actually changed, which is the common
# case under persistent connections. Safe here because nothing in the project
# changes the search_path behind django-tenants' back.
TENANT_LIMIT_SET_CALLS = True

# --- SHARED_APPS ------------------------------------------------------
# Tables created *only* in the public schema. An app belongs here when its
# rows describe the platform rather than an institution.
SHARED_APPS = [
    # Mandatory, and first: it installs the schema-aware database backend
    # checks and the migrate_schemas command.
    "django_tenants",
    # The tenant catalogue must be shared -- it is what the middleware reads
    # *before* it knows which schema to switch to.
    "apps.tenants.apps.TenantsConfig",
    # contenttypes underpins permissions and generic relations, and django-
    # tenants requires it in SHARED_APPS. It is also in TENANT_APPS: each
    # schema needs its own content-type rows for its own permission rows to
    # point at.
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.admin",
    # Ships no models; listed so its checks, template tags and collectstatic
    # are available while running in the public schema.
    "django.contrib.staticfiles",
    # Platform staff sign in to the public admin to manage tenants, so the
    # user model needs a table in the public schema too.
    "apps.core.apps.CoreConfig",
    "apps.accounts.apps.AccountsConfig",
]

# --- TENANT_APPS ------------------------------------------------------
# Tables created in *every* tenant schema. Because a tenant's search_path is
# ("<schema>", "public"), a table listed here shadows the public copy of the
# same name -- that is what isolates institution data.
TENANT_APPS = [
    "django.contrib.contenttypes",
    # Each institution owns its users, groups and permissions. A row in
    # tenant A's accounts_user is invisible from tenant B because the query
    # resolves against tenant B's own table, not because of any filtering.
    "django.contrib.auth",
    # Per-tenant session tables: a session cookie minted on one institution's
    # domain has no matching row in another's schema, so it cannot authenticate
    # there even if the cookie is replayed.
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.admin",
    "django.contrib.staticfiles",
    "apps.core.apps.CoreConfig",
    "apps.accounts.apps.AccountsConfig",
]

THIRD_PARTY_APPS: list[str] = []

# INSTALLED_APPS is the union: Django still needs every app loaded in every
# process. Which of them actually gets *migrated* into a given schema is
# decided by TenantSyncRouter reading the two lists above.
INSTALLED_APPS = SHARED_APPS + [
    app for app in TENANT_APPS + THIRD_PARTY_APPS if app not in SHARED_APPS
]

# =====================================================================
# MIDDLEWARE SETTINGS
# =====================================================================

MIDDLEWARE = [
    # First, without exception. Until this has run the connection still points
    # at the public schema, so any middleware below that touches the ORM --
    # sessions and authentication above all -- would read the wrong schema.
    "apps.tenants.middleware.TenantMainMiddleware",
    "django.middleware.security.SecurityMiddleware",
    # Serves files off disk and never queries the database, so its position
    # relative to the tenant middleware is irrelevant; it stays high to keep
    # static requests cheap.
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# =====================================================================
# TEMPLATES SETTINGS
# =====================================================================

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.tenants.context_processors.tenant",
            ],
        },
    },
]

# =====================================================================
# DATABASE SETTINGS
# =====================================================================

DATABASES = {
    "default": dj_database_url.config(
        default=config("DATABASE_URL", cast=str),
        conn_max_age=600,
        conn_health_checks=True,
    )
}

# dj-database-url hands back the stock Postgres backend; django-tenants needs
# its own wrapper, which adds set_tenant()/set_schema() and rewrites the
# search_path per request. Everything else in the parsed config still applies.
DATABASES["default"]["ENGINE"] = "django_tenants.postgresql_backend"

# Decides which apps get migrated into which schema (SHARED_APPS -> public,
# TENANT_APPS -> every tenant). django-tenants refuses to start without it.
DATABASE_ROUTERS = ["django_tenants.routers.TenantSyncRouter"]

# =====================================================================
# AUTHENTICATION & AUTHORIZATION SETTINGS
# =====================================================================

# Swappable user model. Always reach it via settings.AUTH_USER_MODEL (in
# ForeignKeys) or get_user_model() (at runtime) -- never by direct import.
# The model is unchanged by multi-tenancy: because apps.accounts is in both
# SHARED_APPS and TENANT_APPS, the same table exists in every schema and the
# search_path decides which one a query hits.
AUTH_USER_MODEL = "accounts.User"

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]

LOGIN_URL = "admin:login"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",  # noqa: E501
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Scope the session cookie to the exact host that set it. A cookie shared
# across "*.example.com" would be presented to every tenant's domain; the
# per-tenant session table means it could not authenticate there, but not
# sending it at all is the stronger position.
SESSION_COOKIE_DOMAIN = None

# =====================================================================
# I18N SETTINGS
# =====================================================================

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Asia/Kolkata"

USE_I18N = True

USE_TZ = True

# =====================================================================
# STATIC & MEDIA SETTINGS
# =====================================================================

# Static files are build output, identical for every tenant, so they stay
# shared: one STATIC_ROOT, one collectstatic, one cache entry per file in
# whitenoise. Per-tenant branding would mean TenantStaticFilesStorage and
# `collectstatic_schemas`; see the README before reaching for it.
STATIC_URL = "static/"

# This setting will be applied in local and
# will be overriden in production
STATIC_ROOT = BASE_DIR / "staticfiles"

# Uploads *are* tenant data, so they are namespaced by schema. With
# MULTITENANT_RELATIVE_MEDIA_ROOT = "%s" a file saved as "logo.png" lands in
# media/<schema_name>/logo.png and is served from /media/<schema_name>/logo.png.
# Two tenants uploading the same filename therefore cannot collide.
MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"
MULTITENANT_RELATIVE_MEDIA_ROOT = "%s"

# =====================================================================
# STORAGES SETTINGS
# =====================================================================

STORAGES = {
    "default": {
        "BACKEND": "django_tenants.files.storage.TenantFileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    },
}
