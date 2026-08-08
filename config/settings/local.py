import socket

from decouple import Csv, config

from .base import *  # noqa: F403
from .base import INSTALLED_APPS, MIDDLEWARE, SHARED_APPS

# =====================================================================
# LOCAL CORE SETTINGS
# =====================================================================

SECRET_KEY = config("DJANGO_SECRET_KEY", cast=str)
DEBUG = True

# Tenants are addressed by hostname, so every tenant domain used locally has to
# be allowed. A leading dot matches all subdomains, which is what makes
# `acme.localhost` work without editing this list per tenant.
#
# `*.localhost` resolves out of the box on Linux and in Chrome/Firefox; on
# Windows each subdomain still needs a line in
# C:\Windows\System32\drivers\etc\hosts. See the README.
ALLOWED_HOSTS = config(
    "DJANGO_ALLOWED_HOSTS",
    default="localhost,.localhost,127.0.0.1",
    cast=Csv(),
)

# =====================================================================
# DEBUG TOOLBAR SETTINGS
# =====================================================================

# To view debug toolbar will be decided whether a engineer
# wants to enabled it or not as it introduces some
# performance issues

ENABLE_DEBUG_TOOLBAR = config("ENABLE_DEBUG_TOOLBAR", cast=bool, default=False)

INTERNAL_IPS = [
    "127.0.0.1",
    "0.0.0.0",
]

# Debug toolbar config
hostname, _, ips = socket.gethostbyname_ex(socket.gethostname())

INTERNAL_IPS = [ip[:-1] + "1" for ip in ips]

if ENABLE_DEBUG_TOOLBAR:
    INSTALLED_APPS.append("debug_toolbar")
    SHARED_APPS.append("debug_toolbar")

    # Index 1, not 0: TenantMainMiddleware has to stay first so the connection
    # is pointed at the right schema before anything else runs. The toolbar
    # only needs to be early enough to wrap the response, and its SQL panel
    # instruments the connection rather than depending on middleware order.
    MIDDLEWARE.insert(1, "debug_toolbar.middleware.DebugToolbarMiddleware")

    # Debug toolbar panel configurations
    DEBUG_TOOLBAR_PANELS = [
        "debug_toolbar.panels.history.HistoryPanel",
        "debug_toolbar.panels.versions.VersionsPanel",
        "debug_toolbar.panels.timer.TimerPanel",
        "debug_toolbar.panels.settings.SettingsPanel",
        "debug_toolbar.panels.headers.HeadersPanel",
        "debug_toolbar.panels.request.RequestPanel",
        "debug_toolbar.panels.sql.SQLPanel",
        "debug_toolbar.panels.staticfiles.StaticFilesPanel",
        "debug_toolbar.panels.templates.TemplatesPanel",
        "debug_toolbar.panels.alerts.AlertsPanel",
        "debug_toolbar.panels.cache.CachePanel",
        "debug_toolbar.panels.signals.SignalsPanel",
        "debug_toolbar.panels.redirects.RedirectsPanel",
        "debug_toolbar.panels.profiling.ProfilingPanel",
    ]

# =====================================================================
# DJANGO-EXTENSIONS SETTINGS
# =====================================================================

# Registered in SHARED_APPS as well as INSTALLED_APPS: TenantSyncRouter refuses
# to migrate any app that appears in neither list, so a dev-only app added to
# INSTALLED_APPS alone would be silently skipped if it ever grew a migration.
INSTALLED_APPS.append("django_extensions")
SHARED_APPS.append("django_extensions")

SHELL_PLUS = "ipython"
