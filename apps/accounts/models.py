"""The project's swappable user model.

Referenced everywhere as ``settings.AUTH_USER_MODEL`` / ``get_user_model()`` --
never imported directly by other apps.
"""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.db.models.functions import Lower
from django.utils.translation import gettext_lazy as _

from apps.accounts.managers import UserManager
from apps.core.models import SoftDeleteModel, TimeStampedModel


class User(AbstractBaseUser, PermissionsMixin, TimeStampedModel, SoftDeleteModel):
    """An account identified solely by its email address.

    ``AbstractBaseUser`` contributes ``password`` and ``last_login``;
    ``PermissionsMixin`` contributes ``is_superuser``, ``groups`` and
    ``user_permissions``. There is deliberately no ``username`` field.
    """

    id = models.UUIDField(
        _("ID"),
        primary_key=True,
        # uuid7 is time-ordered, so inserts append to the right-hand edge of
        # the B-tree instead of scattering across it the way uuid4 does. That
        # keeps the primary key index compact under Postgres' page splitting.
        # The trade-off -- the value embeds a creation timestamp -- is
        # immaterial here, since ``created_at`` is public anyway.
        default=uuid.uuid7,
        editable=False,
    )
    email = models.EmailField(
        _("email address"),
        max_length=254,
        unique=True,
        error_messages={
            "unique": _("An account with this email address already exists."),
        },
        help_text=_("Used to sign in. Stored lower-cased."),
    )
    first_name = models.CharField(_("first name"), max_length=150, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)
    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_(
            "Designates whether this account can sign in. Uncheck instead of "
            "deleting to suspend an account."
        ),
    )
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can access the admin site."),
    )

    objects: ClassVar[UserManager] = UserManager()
    all_objects: ClassVar[UserManager] = UserManager(alive_only=False)

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    # Email and password are prompted for separately by ``createsuperuser``.
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
        ordering = ("-created_at",)
        # Related-object traversal must still resolve soft-deleted users.
        base_manager_name = "all_objects"
        indexes = (
            # Partial by design: "not deleted" matches nearly every row, so
            # only the small deleted subset is worth an index. Serves the
            # admin's deleted-accounts filter and any retention/purge job.
            models.Index(
                fields=("deleted_at",),
                name="user_deleted_at_idx",
                condition=models.Q(deleted_at__isnull=False),
            ),
        )
        constraints = (
            models.CheckConstraint(
                condition=models.Q(email=Lower("email")),
                name="user_email_is_lowercase",
                violation_error_message=_(
                    "Email addresses must be stored lower-cased."
                ),
            ),
        )

    def __str__(self) -> str:
        return self.email

    def clean(self) -> None:
        super().clean()
        self.email = UserManager.normalize_email(self.email)

    def save(self, *args: Any, **kwargs: Any) -> None:
        # Normalising in save() -- not only in clean() -- keeps the invariant
        # that backs the case-insensitive unique index true for shell scripts,
        # data migrations and bulk fixtures, none of which call full_clean().
        self.email = UserManager.normalize_email(self.email)
        super().save(*args, **kwargs)

    def get_full_name(self) -> str:
        """First and last name, falling back to the email address."""
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name or self.email
