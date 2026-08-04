"""Manager and queryset for the custom user model."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib.auth.base_user import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _

from apps.core.managers import SoftDeleteManager, SoftDeleteQuerySet

if TYPE_CHECKING:
    from apps.accounts.models import User


class UserQuerySet(SoftDeleteQuerySet["User"]):
    """Adds account-specific bulk helpers on top of soft deletion."""

    def soft_delete_values(self) -> dict[str, Any]:
        # Deactivating alongside the deletion stamp keeps a single UPDATE
        # authoritative for "this account can no longer be used", even for
        # code paths that only ever look at ``is_active``.
        return {**super().soft_delete_values(), "is_active": False}

    def restore_values(self) -> dict[str, Any]:
        return {**super().restore_values(), "is_active": True}

    def active(self) -> UserQuerySet:
        return self.alive().filter(is_active=True)

    def staff(self) -> UserQuerySet:
        return self.filter(is_staff=True)


class UserManager(SoftDeleteManager["User"], BaseUserManager["User"]):
    """Creates users keyed by email, with no username anywhere in sight."""

    def get_queryset(self) -> UserQuerySet:
        queryset = UserQuerySet(self.model, using=self._db)
        return queryset.alive() if self.alive_only else queryset

    def all(self) -> UserQuerySet:
        return self.get_queryset()

    def active(self) -> UserQuerySet:
        return self.get_queryset().active()

    def staff(self) -> UserQuerySet:
        return self.get_queryset().staff()

    @classmethod
    def normalize_email(cls, email: str | None) -> str:
        """Lower-case the whole address, not just the domain.

        Django's implementation only normalises the domain because the local
        part is technically case-sensitive per RFC 5321. Real mail providers
        do not honour that, and treating ``A@x.com`` and ``a@x.com`` as two
        accounts is a well-known account-takeover foot-gun -- so the entire
        address is folded and stored lower-cased. This is what makes the plain
        ``unique=True`` on ``User.email`` behave case-insensitively.
        """
        return super().normalize_email(email).strip().lower()

    def get_by_natural_key(self, username: str | None) -> User:
        """Look users up case-insensitively (used by ``ModelBackend``)."""
        return self.get(**{self.model.USERNAME_FIELD: self.normalize_email(username)})

    def _create_user(
        self,
        email: str,
        password: str | None,
        **extra_fields: Any,
    ) -> User:
        if not email:
            raise ValueError(_("Users must have an email address."))

        email = self.normalize_email(email)
        try:
            validate_email(email)
        except ValidationError as exc:
            raise ValueError(_("Enter a valid email address.")) from exc

        # Checked here rather than left to Model.validate_unique(), which
        # consults the *default* manager and would therefore look straight
        # past a soft-deleted account still holding this address. Surfacing a
        # ValidationError also keeps the caller's transaction usable, unlike
        # the IntegrityError the unique index would otherwise raise. That
        # index remains the authority on the race.
        if self.model.all_objects.filter(email=email).exists():
            raise ValidationError(
                {"email": _("An account with this email address already exists.")}
            )

        user = self.model(email=email, **extra_fields)
        # ``set_password(None)`` marks the password unusable, which is what we
        # want for SSO-provisioned or invite-pending accounts.
        user.set_password(password)
        user.full_clean(exclude=["password"], validate_unique=False)
        user.save(using=self._db)
        return user

    def create_user(
        self,
        email: str,
        password: str | None = None,
        **extra_fields: Any,
    ) -> User:
        """Create a regular, non-privileged account."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(
        self,
        email: str,
        password: str | None = None,
        **extra_fields: Any,
    ) -> User:
        """Create an account with full admin privileges."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))

        return self._create_user(email, password, **extra_fields)
