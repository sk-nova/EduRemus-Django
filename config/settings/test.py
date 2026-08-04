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
from .base import BASE_DIR, TEMPLATES  # noqa: E402

# =====================================================================
# TEST CORE SETTINGS
# =====================================================================

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = False
ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

# =====================================================================
# TEST PERFORMANCE SETTINGS
# =====================================================================

# Hashing dominates the runtime of any auth suite; MD5 keeps it honest about
# hashing *something* while being roughly two orders of magnitude faster.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.InMemoryStorage",
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
