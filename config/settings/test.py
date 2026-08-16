"""Settings used by pytest.

Deliberately self-sufficient: everything ``base`` needs is resolved and
exported *before* it is imported, so the suite runs on a bare CI box with no
``.env`` file at all.

The connection string is assembled from the ``POSTGRES_*`` variables -- the
same ones Compose feeds the ``db`` service -- rather than reused from
``DATABASE_URL``, because that variable legitimately points at the
container-internal ``db`` host and would be unreachable from a host-side
``pytest``. Set ``TEST_DATABASE_URL`` to override the whole thing, or
``TEST_POSTGRES_HOST`` (``db`` when running inside the stack) to redirect it.
"""

import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

from decouple import config


def _test_database_url() -> str:
    explicit = config("TEST_DATABASE_URL", default="", cast=str)
    if explicit:
        return explicit

    user = config("POSTGRES_USER", default="eduremus", cast=str)
    password = config("POSTGRES_PASSWORD", default="", cast=str)
    host = config("TEST_POSTGRES_HOST", default="127.0.0.1", cast=str)
    port = config("POSTGRES_PORT", default="5432", cast=str)
    name = config("POSTGRES_DB", default="eduremus_db", cast=str)

    credentials = f"{quote(user, safe='')}:{quote(password, safe='')}"
    return f"postgres://{credentials}@{host}:{port}/{name}"


os.environ["DJANGO_SECRET_KEY"] = config(
    "DJANGO_SECRET_KEY",
    default="insecure-key-for-tests-only",
    cast=str,
)
os.environ["DATABASE_URL"] = _test_database_url()

from .base import *  # noqa: E402, F403
from .base import BASE_DIR, JWT_AUTH, TEMPLATES  # noqa: E402

# =====================================================================
# TEST CORE SETTINGS
# =====================================================================

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = False

# Tenant routing is hostname-based, so the suite's tenant domains have to pass
# host validation. The leading dot covers every `<schema>.testserver` the
# fixtures in conftest.py mint.
ALLOWED_HOSTS = [
    "testserver",
    ".testserver",
    "localhost",
    "127.0.0.1",
]

# =====================================================================
# TEST PERFORMANCE SETTINGS
# =====================================================================

# Hashing dominates the runtime of any auth suite; MD5 keeps it honest about
# hashing *something* while being roughly two orders of magnitude faster.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

# =====================================================================
# TEST CACHE SETTINGS
# =====================================================================

# Local memory by default, so the suite needs no Redis service -- the same
# reason the database URL is assembled rather than inherited. Point
# TEST_REDIS_URL at a real instance (use a database of its own; the cache is
# cleared between tests) to exercise django-redis itself.
_test_redis_url = config("TEST_REDIS_URL", default="", cast=str)

if _test_redis_url:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": _test_redis_url,
            "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
        },
        "denylist": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": _test_redis_url,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
                "IGNORE_EXCEPTIONS": False,
            },
        },
    }
else:
    # Two aliases here as well: the denylist reads through its own, and tests
    # that assert fail-closed behaviour patch that alias rather than the one
    # everything else shares.
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "eduremus-test",
        },
        "denylist": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "eduremus-test-denylist",
        },
    }

# =====================================================================
# TEST JWT SETTINGS
# =====================================================================

# The production default is a secret-store mount that does not exist on a
# developer machine. Fixtures generate throwaway keypairs into this directory;
# conftest.py empties it per session, as it does MEDIA_ROOT.
JWT_AUTH = {
    **JWT_AUTH,
    "KEY_DIRECTORY": str(Path(tempfile.gettempdir()) / "eduremus-test-jwt-keys"),
    "ACTIVE_KEY_ID": "test-key",
}

# =====================================================================
# TEST STATIC & MEDIA SETTINGS
# =====================================================================

# The real tenant-aware storage rather than InMemoryStorage, so tests exercise
# the same schema-namespaced paths production uses. MEDIA_ROOT points at a
# throwaway directory outside the repo; conftest.py empties it per session.
MEDIA_ROOT = Path(tempfile.gettempdir()) / "eduremus-test-media"

STORAGES = {
    "default": {
        "BACKEND": "django_tenants.files.storage.TenantFileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

STATIC_ROOT = BASE_DIR / "staticfiles"

# Templates are still compiled, but only once per process.
_django_templates: dict[str, Any] = TEMPLATES[0]
_django_templates["OPTIONS"]["loaders"] = [
    (
        "django.template.loaders.cached.Loader",
        [
            "django.template.loaders.filesystem.Loader",
            "django.template.loaders.app_directories.Loader",
        ],
    ),
]
# APP_DIRS and an explicit loaders list are mutually exclusive.
_django_templates["APP_DIRS"] = False
