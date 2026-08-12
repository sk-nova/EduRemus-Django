from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class AuthenticationConfig(AppConfig):
    """Token issuance, validation and session records.

    Listed in *both* SHARED_APPS and TENANT_APPS: platform staff authenticate
    against the public schema, institution users against their own. The same
    tables exist in every schema holding different rows, exactly as
    apps.accounts does.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.authentication"
    label = "authentication"
    verbose_name = _("Authentication")
