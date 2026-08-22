"""
Base Django settings for EduRemus-Django project.

The project is multi-tenant by *Postgres schema* (django-tenants). One
database holds a ``public`` schema with the tenant catalogue and the platform's
own records, plus one schema per institution holding that institution's data.
``TenantMainMiddleware`` maps the request's hostname to a schema and sets the
connection's ``search_path`` accordingly, so ordinary ORM code needs no
tenant filtering and cannot reach across the boundary.
"""

from datetime import timedelta
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

TENANT_MODEL = "tenants.Tenant"
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

# Common Third party-packages
COMMON_THIRD_PARTY_APPS: list[str] = [
    "rest_framework",
    "corsheaders",
]

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
    # Inserting common 3rd-party packages
    *COMMON_THIRD_PARTY_APPS,
    "apps.core.apps.CoreConfig",
    "apps.accounts.apps.AccountsConfig",
    # Platform staff authenticate against the public schema, so the token,
    # session and audit tables must exist there too.
    "apps.authentication.apps.AuthenticationConfig",
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
    # Inserting common 3rd-party packages
    *COMMON_THIRD_PARTY_APPS,
    "apps.core.apps.CoreConfig",
    "apps.accounts.apps.AccountsConfig",
    # Refresh tokens, device sessions and audit events are institution data.
    # Following the apps.accounts precedent: the same tables in every schema
    # holding different rows, isolated by search_path rather than by a tenant
    # foreign key.
    "apps.authentication.apps.AuthenticationConfig",
]

THIRD_PARTY_APPS = [
    "drf_spectacular",
]


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
    # Directly below the tenant middleware: a preflight has to be answered
    # before CommonMiddleware can redirect it, and the response headers are
    # decided per origin, which is tenant-specific.
    "corsheaders.middleware.CorsMiddleware",
    # Binds the correlation id for the request. Above everything that logs,
    # so no record downstream is emitted without one; it touches no models,
    # so its only ordering constraint is staying below the tenant middleware.
    "apps.authentication.middleware.RequestIdMiddleware",
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
        "OPTIONS": {"min_length": 12},
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
    # Applies to the admin and createsuperuser as well as the API, so a
    # password rejected on one surface is rejected on all of them.
    # BreachedPasswordValidator is deliberately *not* registered: it makes an
    # outbound HTTPS call on every password set, which is a deployment
    # decision rather than a default.
    {
        "NAME": "apps.authentication.validators.PasswordHistoryValidator",
    },
]

# Scope the session cookie to the exact host that set it. A cookie shared
# across "*.example.com" would be presented to every tenant's domain; the
# per-tenant session table means it could not authenticate there, but not
# sending it at all is the stronger position.
SESSION_COOKIE_DOMAIN = None

# =====================================================================
# REST FRAMEWORK SETTINGS
# =====================================================================

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "apps.authentication.authentication.TenantAwareJWTAuthentication",
        # Retained so DRF's browsable API and any session-authenticated
        # internal tooling keep working. Ordered second: a Bearer header
        # always wins over a session cookie.
        "rest_framework.authentication.SessionAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_THROTTLE_CLASSES": (
        "apps.authentication.throttling.TenantScopedUserThrottle",
        "apps.authentication.throttling.TenantScopedAnonThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "anon": "60/hour",
        "user": "1000/hour",
        "login": "10/hour",
        "refresh": "60/hour",
        "password_change": "5/hour",
        # The remaining per-endpoint scopes from the endpoint inventory. A
        # ScopedRateThrottle raises ImproperlyConfigured for a scope with no
        # rate, so every scope a view declares has to be named here.
        "verify": "120/hour",
        "sessions": "120/hour",
        "logout": "60/hour",
        "logout_all": "10/hour",
        "revoke": "60/hour",
    },
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "apps.authentication.exceptions.auth_exception_handler",
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "UNAUTHENTICATED_USER": "django.contrib.auth.models.AnonymousUser",
}

# =====================================================================
# JWT AUTHENTICATION SETTINGS
# =====================================================================

# Consumed by djangorestframework-simplejwt. Anything this project owns rather
# than inherits lives in JWT_AUTH below.
SIMPLE_JWT = {
    # --- lifetimes ---------------------------------------------------
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    # Rotation *is* implemented -- by apps.authentication.services.refresh,
    # which adds the family tracking and reuse detection SimpleJWT's own
    # rotation does not provide. Both flags stay off so the two mechanisms
    # cannot act on the same token and disagree about which lineage is current.
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    # --- cryptography ------------------------------------------------
    # Asymmetric, so a verifier never holds minting capability. The algorithm
    # is fixed here and must never be read back off a token header.
    "ALGORITHM": "RS256",
    # Supplied per call by the keyring: the active key signs, and the
    # verification key is resolved per token by its `kid`.
    "SIGNING_KEY": None,
    "VERIFYING_KEY": None,
    "AUDIENCE": config("JWT_AUDIENCE", default="eduremus-api", cast=str),
    "ISSUER": config("JWT_ISSUER", default="https://auth.eduremus.com", cast=str),
    "LEEWAY": timedelta(seconds=30),
    # --- claim wiring ------------------------------------------------
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",  # uuid7 primary key
    "USER_ID_CLAIM": "sub",
    "USER_AUTHENTICATION_RULE": (
        "apps.authentication.authentication.tenant_user_authentication_rule"
    ),
    "TOKEN_TYPE_CLAIM": "typ",
    "JTI_CLAIM": "jti",
    "AUTH_TOKEN_CLASSES": ("apps.authentication.tokens.types.TenantAccessToken",),
}

# Settings owned by this application rather than by SimpleJWT.
JWT_AUTH = {
    # __Host- forbids a Domain attribute, which pins the cookie to exactly the
    # host that set it -- the only thing that stops one institution's refresh
    # cookie reaching a sibling subdomain, since SameSite treats them as the
    # same site.
    "REFRESH_COOKIE_NAME": "__Host-eduremus_refresh",
    # "/" and not "/api/v1/auth", because the __Host- prefix *requires*
    # Path=/: a browser rejects the cookie outright otherwise, and the refresh
    # endpoint then sees no cookie at all. Path scoping is the attribute
    # traded away to keep host-only scoping, which is worth far more here.
    # utils.cookies enforces this pairing rather than trusting the value.
    "REFRESH_COOKIE_PATH": "/",
    "REFRESH_COOKIE_SAMESITE": "Strict",
    # A refresh lineage may rotate for at most this long before the user has
    # to authenticate again, however recently the last rotation happened.
    "REFRESH_ABSOLUTE_LIFETIME": timedelta(days=30),
    "CSRF_COOKIE_NAME": "eduremus_csrf",
    "CSRF_HEADER_NAME": "X-CSRF-Token",
    # Its own alias, and deliberately not "default": the default cache sets
    # IGNORE_EXCEPTIONS so an outage degrades instead of erroring, which for a
    # denylist would turn "cannot tell" into "not revoked". See CACHES below.
    "DENYLIST_CACHE_ALIAS": "denylist",
    "USER_CACHE_TIMEOUT": 300,
    "MAX_ACTIVE_SESSIONS_PER_USER": 10,
    "LOCKOUT_THRESHOLD": 5,
    "LOCKOUT_WINDOW": timedelta(minutes=15),
    "LOCKOUT_DURATION": timedelta(minutes=30),
    "PASSWORD_HISTORY_DEPTH": 5,
    # How many reverse proxies actually sit in front of the application. Zero
    # means X-Forwarded-For is ignored entirely and REMOTE_ADDR is used, which
    # is the only safe default: the header is client-supplied, and lockout and
    # throttling key on the address it yields.
    "TRUSTED_PROXY_HOPS": config("TRUSTED_PROXY_HOPS", default=0, cast=int),
    # Signing keys are mounted from a secret store, never baked into the image
    # and never committed.
    "KEY_DIRECTORY": config("JWT_KEY_DIRECTORY", default="/run/secrets/jwt", cast=str),
    "ACTIVE_KEY_ID": config("JWT_ACTIVE_KEY_ID", default="", cast=str),
}

# =====================================================================
# CACHE SETTINGS
# =====================================================================

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": config("REDIS_URL", default="redis://127.0.0.1:6379/1", cast=str),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "CONNECTION_POOL_KWARGS": {
                "max_connections": config(
                    "REDIS_MAX_CONNECTIONS", default=50, cast=int
                ),
            },
            "SOCKET_CONNECT_TIMEOUT": 2,
            "SOCKET_TIMEOUT": 2,
            # A Redis outage must not become an application outage for
            # everything that merely *caches*. The denylist deliberately does
            # not rely on this and fails closed instead.
            "IGNORE_EXCEPTIONS": True,
        },
        # No KEY_PREFIX: a static prefix separates this application from
        # others sharing the Redis instance, which is not the same thing as
        # separating one tenant from another. Per-tenant prefixing is applied
        # by apps.authentication.utils.cache_keys.tenant_key().
        "TIMEOUT": 300,
    },
    # Same Redis database, different client policy. Everything above tolerates
    # an outage because a miss only costs a query; a denylist miss silently
    # reinstates a revoked credential, so this alias must *raise* instead of
    # returning None. tokens/denylist.py converts that into a 503.
    "denylist": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": config("REDIS_URL", default="redis://127.0.0.1:6379/1", cast=str),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "CONNECTION_POOL_KWARGS": {
                "max_connections": config(
                    "REDIS_MAX_CONNECTIONS", default=50, cast=int
                ),
            },
            "SOCKET_CONNECT_TIMEOUT": 2,
            "SOCKET_TIMEOUT": 2,
            "IGNORE_EXCEPTIONS": False,
        },
    },
}

DJANGO_REDIS_LOG_IGNORED_EXCEPTIONS = True

# =====================================================================
# CORS SETTINGS
# =====================================================================

# Anchored at both ends, deliberately: an unanchored pattern also matches
# https://acme.eduremus.com.attacker.example. With CORS_ALLOW_CREDENTIALS on,
# a permissive origin policy would let any site drive authenticated requests
# using the victim's refresh cookie.
CORS_ALLOWED_ORIGIN_REGEXES = [
    config(
        "CORS_ALLOWED_ORIGIN_REGEX",
        default=r"^https://[a-z0-9-]+\.eduremus\.com$",
        cast=str,
    ),
]

# Required for the refresh cookie to be sent on cross-origin requests. Never
# combine this with CORS_ALLOW_ALL_ORIGINS.
CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_HEADERS = (
    "authorization",
    "content-type",
    "x-csrf-token",
    "x-device-id",
    "x-request-id",
)

CORS_EXPOSE_HEADERS = ("x-request-id", "retry-after")

CORS_PREFLIGHT_MAX_AGE = 3600

# =====================================================================
# API SCHEMA SETTINGS
# =====================================================================

SPECTACULAR_SETTINGS = {
    "TITLE": "EduRemus API",
    "DESCRIPTION": "Multi-tenant institutional management API.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "SCHEMA_PATH_PREFIX": "/api/v1",
    "SERVERS": [
        {
            "url": "https://{tenant}.eduremus.com/api/v1",
            "description": "Tenant API",
            "variables": {
                "tenant": {"default": "acme", "description": "Tenant subdomain"}
            },
        }
    ],
    "SECURITY": [{"BearerAuth": []}],
    "APPEND_COMPONENTS": {
        "securitySchemes": {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": (
                    "RS256 access token. Must be presented to the same tenant "
                    "hostname it was issued for; a token replayed against "
                    "another tenant is rejected with token_wrong_tenant."
                ),
            }
        }
    },
}

# =====================================================================
# I18N SETTINGS
# =====================================================================

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Asia/Kolkata"

USE_I18N = True

USE_TZ = True

# =====================================================================
# LOGGING SETTINGS
# =====================================================================

# JSON on stdout, for a container that ships its logs to an aggregator. Two
# fields are added to every record by filters rather than by call sites --
# `schema` (which institution) and `request_id` (which request) -- because a
# field each logger has to remember to pass is the field missing from the line
# you actually need.
#
# `SensitiveDataFilter` is a backstop, not a licence: nothing in this codebase
# may log a token, a password or an Authorization header, and a test asserts
# it. See apps/authentication/logging.py.
LOGGING = {
    "version": 1,
    # The third-party loggers configured by libraries at import time keep
    # working; only the ones named below are redirected.
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "apps.authentication.logging.JsonFormatter",
        },
        "console": {
            "format": "{levelname} {asctime} {name} {message}",
            "style": "{",
        },
    },
    "filters": {
        "tenant": {"()": "apps.authentication.logging.TenantContextFilter"},
        "request_id": {"()": "apps.authentication.logging.RequestIdFilter"},
        "sensitive": {"()": "apps.authentication.logging.SensitiveDataFilter"},
    },
    "handlers": {
        "json": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            # Order matters: redaction runs last, so it also covers fields the
            # two context filters attached.
            "filters": ["tenant", "request_id", "sensitive"],
        },
    },
    "loggers": {
        # Everything the authentication path emits.
        "eduremus.auth": {
            "handlers": ["json"],
            "level": config("DJANGO_LOG_LEVEL", default="INFO", cast=str),
            "propagate": False,
        },
        # The SIEM stream: cross-tenant rejections, refresh reuse, lockouts.
        "eduremus.security": {
            "handlers": ["json"],
            "level": "WARNING",
            "propagate": False,
        },
        # Django's own security warnings (host header, CSRF, ...) belong in
        # the same stream as ours rather than in a second format.
        "django.security": {
            "handlers": ["json"],
            "level": "WARNING",
            "propagate": False,
        },
    },
    "root": {"handlers": ["json"], "level": "WARNING"},
}

# =====================================================================
# METRICS SETTINGS
# =====================================================================

# Prometheus exposition at /metrics on the public hostname. Off unless asked
# for: the endpoint is unauthenticated by design -- scrapers do not carry
# credentials -- so enabling it is a statement that the port is reachable only
# from the monitoring network. The route is mounted either way and returns 404
# when disabled, because a conditional URLconf is evaluated once at import and
# cannot be changed without a redeploy.
PROMETHEUS_METRICS_ENABLED = config(
    "PROMETHEUS_METRICS_ENABLED", default=False, cast=bool
)

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
