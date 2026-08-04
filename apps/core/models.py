"""Abstract models shared across the suite.

Nothing in here is concrete, so ``apps.core`` ships no migrations.
"""

from __future__ import annotations

from typing import Any, ClassVar

from django.db import models
from django.utils.translation import gettext_lazy as _

from apps.core.managers import DeleteResult, SoftDeleteManager


class TimeStampedModel(models.Model):
    """Adds self-maintaining ``created_at`` / ``updated_at`` columns."""

    created_at = models.DateTimeField(
        _("created at"),
        auto_now_add=True,
        editable=False,
        db_index=True,
    )
    updated_at = models.DateTimeField(
        _("updated at"),
        auto_now=True,
        editable=False,
    )

    class Meta:
        abstract = True


class SoftDeleteModel(models.Model):
    """Adds reversible deletion via a nullable ``deleted_at`` stamp.

    ``delete()`` is overridden to soft delete; pass ``hard=True`` (or call
    ``hard_delete()``) for a real ``DELETE``. Note that soft deletion is *not*
    a cascade: Django's deletion collector issues raw SQL, so rows removed as
    a side effect of a genuine cascade are still deleted outright.
    """

    # No db_index: the overwhelmingly common predicate is
    # ``deleted_at IS NULL``, which matches nearly every row and would never
    # use a plain index. Concrete models add a *partial* index over the
    # deleted rows instead -- see ``apps.accounts.models.User.Meta.indexes``.
    deleted_at = models.DateTimeField(
        _("deleted at"),
        null=True,
        blank=True,
        default=None,
        editable=False,
        help_text=_("When set, the record is treated as deleted."),
    )

    objects: ClassVar[SoftDeleteManager[Any]] = SoftDeleteManager()
    all_objects: ClassVar[SoftDeleteManager[Any]] = SoftDeleteManager(alive_only=False)

    class Meta:
        abstract = True
        base_manager_name = "all_objects"

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    def soft_delete_values(self) -> dict[str, Any]:
        """Field values applied when this instance is soft deleted."""
        return type(self)._default_manager.get_queryset().soft_delete_values()

    def restore_values(self) -> dict[str, Any]:
        """Field values applied when this instance is restored."""
        return type(self)._default_manager.get_queryset().restore_values()

    def _apply(self, values: dict[str, Any], using: str | None) -> None:
        """Assign ``values`` on the instance and persist just those columns."""
        for field, value in values.items():
            setattr(self, field, value)

        update_fields = list(values)
        if any(f.name == "updated_at" for f in self._meta.fields):
            update_fields.append("updated_at")

        self.save(using=using, update_fields=update_fields)

    def delete(  # type: ignore[override]
        self,
        using: str | None = None,
        keep_parents: bool = False,
        *,
        hard: bool = False,
    ) -> DeleteResult:
        """Soft delete by default; ``hard=True`` performs a real delete."""
        if hard:
            return super().delete(using=using, keep_parents=keep_parents)

        if self.is_deleted:
            # Idempotent: never clobber the original deletion stamp.
            return 0, {}

        self._apply(self.soft_delete_values(), using)
        return 1, {self._meta.label: 1}

    delete.alters_data = True  # type: ignore[attr-defined]

    def hard_delete(
        self,
        using: str | None = None,
        keep_parents: bool = False,
    ) -> DeleteResult:
        """Permanently remove this row."""
        return super().delete(using=using, keep_parents=keep_parents)

    hard_delete.alters_data = True  # type: ignore[attr-defined]

    def restore(self, using: str | None = None) -> None:
        """Reverse a soft deletion. A no-op on rows that are not deleted."""
        if not self.is_deleted:
            return

        self._apply(self.restore_values(), using)

    restore.alters_data = True  # type: ignore[attr-defined]
