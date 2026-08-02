from decouple import config

from .base import *  # noqa: F403

# =====================================================================
# LOCAL CORE SETTINGS
# =====================================================================

SECRET_KEY = config("DJANGO_SECRET_KEY", cast=str)
DEBUG = True
ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
]
