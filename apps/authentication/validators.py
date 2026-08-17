"""Password policy and related validation.

Plugged into ``AUTH_PASSWORD_VALIDATORS`` so the same rules apply to the
admin, ``createsuperuser`` and the API. Nothing here touches the request or
the token layer.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any, Final

from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

if TYPE_CHECKING:
    from apps.accounts.models import User

logger = logging.getLogger("eduremus.auth")

__all__ = ["PasswordHistoryValidator"]

_DEFAULT_HISTORY_DEPTH: Final = 5


class PasswordHistoryValidator:
    """Rejects a password the account has used recently.

    Compares against retained hashes with ``check_password``; the previous
    plaintexts are never known to the system, so this can only ever answer
    "matches one of the last N" and never reveal what they were.

    Skipped entirely when there is no saved user: at signup or in
    ``createsuperuser`` there is no history to check, and the validator must
    not fail on the absence of one.
    """

    def __init__(self, history_depth: int = _DEFAULT_HISTORY_DEPTH) -> None:
        self.history_depth = history_depth

    def validate(self, password: str, user: User | None = None) -> None:
        if user is None or user.pk is None:
            return

        # Imported here rather than at module scope: this module is loaded
        # from settings while the app registry is still populating, and a
        # model import at that point raises AppRegistryNotReady.
        from apps.authentication.models import PasswordHistory

        recent = PasswordHistory.objects.filter(user=user).order_by("-created_at")[
            : self._depth()
        ]

        for entry in recent:
            if check_password(password, entry.password_hash):
                raise ValidationError(
                    _("This password has been used recently. Choose another."),
                    code="password_reused",
                )

        # The current password is not always in the history table yet -- the
        # first change after this feature ships has nothing recorded -- so it
        # is checked directly as well.
        if user.password and check_password(password, user.password):
            raise ValidationError(
                _("This password has been used recently. Choose another."),
                code="password_reused",
            )

    def get_help_text(self) -> str:
        return _("Your password must differ from your %(count)d most recent ones.") % {
            "count": self._depth()
        }

    def _depth(self) -> int:
        from django.conf import settings

        return int(
            getattr(settings, "JWT_AUTH", {}).get(
                "PASSWORD_HISTORY_DEPTH", self.history_depth
            )
        )


class BreachedPasswordValidator:
    """Rejects passwords appearing in known breach corpora.

    Uses the k-anonymity range API: only the first five characters of the
    SHA-1 digest leave this process, so the password itself is never
    transmitted and the remote service cannot tell which candidate was checked.

    Fails **open**. A breach-corpus lookup is a hardening measure, not an
    authorisation decision, and an outage upstream must not stop people
    setting a password. Disabled unless ``requests`` is installed, so the
    dependency stays optional.
    """

    api_url: Final = "https://api.pwnedpasswords.com/range/{prefix}"
    timeout: Final = 2

    def validate(self, password: str, user: Any = None) -> None:
        try:
            import requests
        except ImportError:  # pragma: no cover - optional dependency
            return

        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]

        try:
            response = requests.get(
                self.api_url.format(prefix=prefix),
                timeout=self.timeout,
                headers={"Add-Padding": "true"},
            )
            response.raise_for_status()
        except Exception:  # pragma: no cover - network dependent
            logger.warning("breach_check_unavailable", exc_info=True)
            return

        for line in response.text.splitlines():
            candidate, _sep, count = line.partition(":")
            if candidate == suffix and int(count or 0) > 0:
                raise ValidationError(
                    _("This password has appeared in a known data breach."),
                    code="password_breached",
                )

    def get_help_text(self) -> str:
        return _("Your password must not appear in any known data breach.")
