"""Managers and querysets backing :mod:`apps.core.models`.

The soft-delete contract implemented here is deliberately explicit:

``Model.objects``
    Hides soft-deleted rows. This is the *default* manager, so it is what
    ``ModelBackend``, generic views and ordinary application code see.
``Model.all_objects``
    Sees every row. It is wired up as ``Meta.base_manager_name`` so that
    related-object traversal (``some_obj.user``) keeps resolving even after
    the target has been soft deleted -- a filtered base manager would raise
    ``RelatedObjectDoesNotExist`` instead, which Django explicitly warns
    against.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Self, TypeVar

from django.db import models
from django.utils import timezone

if TYPE_CHECKING:
    from apps.core.models import SoftDeleteModel

_ModelT = TypeVar("_ModelT", bound="SoftDeleteModel")

# Django's ``delete()`` contract: (total_deleted, {label: count}).
DeleteResult = tuple[int, dict[str, int]]


class SoftDeleteQuerySet(models.QuerySet[_ModelT]):
    """A queryset whose ``delete()`` marks rows instead of removing them."""

    def soft_delete_values(self) -> dict[str, Any]:
        """Column values written when rows in this queryset are deleted.

        Subclasses extend this to flip additional flags atomically with the
        deletion stamp (see ``apps.accounts.managers.UserQuerySet``).
        """
        return {"deleted_at": timezone.now()}

    def restore_values(self) -> dict[str, Any]:
        """Column values written when rows in this queryset are restored."""
        return {"deleted_at": None}

    def alive(self) -> Self:
        """Only rows that have not been soft deleted."""
        return self.filter(deleted_at__isnull=True)

    def dead(self) -> Self:
        """Only rows that have been soft deleted."""
        return self.filter(deleted_at__isnull=False)

    def delete(self) -> DeleteResult:  # type: ignore[override]
        """Soft delete every matched row with a single ``UPDATE``.

        Already-deleted rows are skipped so their original ``deleted_at``
        stamp -- the audit trail -- is never overwritten.
        """
        count = self.alive().update(**self.soft_delete_values())
        return count, {self.model._meta.label: count}

    delete.alters_data = True  # type: ignore[attr-defined]

    def hard_delete(self) -> DeleteResult:
        """Permanently remove every matched row from the database."""
        return super().delete()

    hard_delete.alters_data = True  # type: ignore[attr-defined]

    def restore(self) -> int:
        """Un-delete every matched row; returns the number of rows restored."""
        return self.dead().update(**self.restore_values())

    restore.alters_data = True  # type: ignore[attr-defined]


class SoftDeleteManager(models.Manager[_ModelT]):
    """Manager that can be instantiated in an "alive only" or "all" flavour."""

    # Managers with required __init__ arguments cannot be serialised into
    # migrations; this one is never needed there.
    use_in_migrations = False

    def __init__(self, *, alive_only: bool = True) -> None:
        self.alive_only = alive_only
        super().__init__()

    def get_queryset(self) -> SoftDeleteQuerySet[_ModelT]:
        queryset: SoftDeleteQuerySet[_ModelT] = SoftDeleteQuerySet(
            self.model, using=self._db
        )
        return queryset.alive() if self.alive_only else queryset

    def all(self) -> SoftDeleteQuerySet[_ModelT]:
        # Narrows the inherited return type so the soft-delete helpers stay
        # visible after ``Model.objects.all()``.
        return self.get_queryset()

    def alive(self) -> SoftDeleteQuerySet[_ModelT]:
        return self.get_queryset().alive()

    def dead(self) -> SoftDeleteQuerySet[_ModelT]:
        return self.get_queryset().dead()

    def hard_delete(self) -> DeleteResult:
        return self.get_queryset().hard_delete()

    def restore(self) -> int:
        return self.get_queryset().restore()
