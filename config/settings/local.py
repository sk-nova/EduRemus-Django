from decouple import config

from .base import INSTALLED_APPS, MIDDLEWARE
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

import socket

# Debug toolbar config
hostname, _, ips = socket.gethostbyname_ex(socket.gethostname())

INTERNAL_IPS = [ip[:-1] + "1" for ip in ips]

if ENABLE_DEBUG_TOOLBAR:

    INSTALLED_APPS.append("debug_toolbar")
    
    MIDDLEWARE.insert(0, "debug_toolbar.middleware.DebugToolbarMiddleware")
    
    # Debug toolbar panel configurations
    DEBUG_TOOLBAR_PANELS = [
    'debug_toolbar.panels.history.HistoryPanel',
    'debug_toolbar.panels.versions.VersionsPanel',
    'debug_toolbar.panels.timer.TimerPanel',
    'debug_toolbar.panels.settings.SettingsPanel',
    'debug_toolbar.panels.headers.HeadersPanel',
    'debug_toolbar.panels.request.RequestPanel',
    'debug_toolbar.panels.sql.SQLPanel',
    'debug_toolbar.panels.staticfiles.StaticFilesPanel',
    'debug_toolbar.panels.templates.TemplatesPanel',
    'debug_toolbar.panels.alerts.AlertsPanel',
    'debug_toolbar.panels.cache.CachePanel',
    'debug_toolbar.panels.signals.SignalsPanel',
    'debug_toolbar.panels.redirects.RedirectsPanel',
    'debug_toolbar.panels.profiling.ProfilingPanel',
]

# =====================================================================
# DJANGO-EXTENSIONS SETTINGS
# =====================================================================

INSTALLED_APPS.append("django_extensions")

SHELL_PLUS = "ipython"