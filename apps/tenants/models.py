"""The tenant catalogue: one row per institution, plus its hostnames.

Both models live in ``SHARED_APPS`` only, so their tables exist exclusively in
the public schema -- that is where ``TenantMainMiddleware`` looks the request's
hostname up before it switches the connection over to the tenant's schema.

Isolation is provided by Postgres schemas, not by a ``tenant`` foreign key: no
other model in the project references :class:`Client`, and none should.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.functions import Lower
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _
from django_tenants.models import DomainMixin, TenantMixin
from django_tenants.utils import get_public_schema_name

from apps.core.managers import DeleteResult
from apps.core.models import TimeStampedModel
from apps.tenants.managers import ClientManager, DomainManager

# django-tenants only rejects names starting with ``pg_`` (anything else is
# legal in Postgres *if quoted*), but schema names are interpolated straight
# into ``CREATE SCHEMA`` / ``SET search_path`` statements. Restricting them to
# bare lower-case SQL identifiers removes that class of problem entirely and
# keeps schema names readable in psql.
SCHEMA_NAME_PATTERN = r"^[a-z][a-z0-9_]{0,62}$"

validate_schema_name = RegexValidator(
    regex=SCHEMA_NAME_PATTERN,
    message=_(
        "Schema names must start with a lower-case letter and contain only "
        "lower-case letters, digits and underscores."
    ),
    code="invalid_schema_name",
)


class Client(TenantMixin, TimeStampedModel):
    """An institution, backed by a dedicated Postgres schema.

    ``TenantMixin`` contributes ``schema_name`` and the schema lifecycle:
    saving a new row runs ``migrate_schemas`` against the new schema, and
    :meth:`delete` optionally drops it.

    The primary key is a plain ``BigAutoField`` rather than the ``uuid7`` used
    by :class:`apps.accounts.models.User`. That choice was about index locality
    under a high insert rate; this table holds one row per customer, so the
    trade-off does not carry over and the simpler key wins.
    """

    #: Created schemas are migrated on save -- see ``TenantMixin.create_schema``.
    auto_create_schema = True
    #: Dropping a schema destroys every row a customer owns, so ``delete()``
    #: leaves it in place unless the caller passes ``force_drop=True``. The
    #: ``tenant_delete`` management command is the supported way to do that.
    auto_drop_schema = False

    if TYPE_CHECKING:
        # django-tenants ships no py.typed marker, so mypy sees TenantMixin as
        # Any and loses every field and method it contributes. These
        # annotations are erased at runtime; the real column is still the one
        # TenantMixin declares.
        schema_name: str

        def create_schema(
            self,
            check_if_exists: bool = False,
            sync_schema: bool = True,
            verbosity: int = 1,
        ) -> None: ...

        def get_primary_domain(self) -> Domain | None: ...

    name = models.CharField(
        _("name"),
        max_length=200,
        help_text=_("Display name of the institution."),
    )
    slug = models.SlugField(
        _("slug"),
        max_length=63,
        unique=True,
        help_text=_(
            "URL-safe identifier, typically the subdomain label. Also seeds "
            "the schema name when one is not given explicitly."
        ),
    )
    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_(
            "Uncheck to suspend the tenant. The schema and its data are kept, "
            "but requests for its domains are refused."
        ),
    )

    objects: ClassVar[ClientManager] = ClientManager()

    class Meta:
        verbose_name = _("client")
        verbose_name_plural = _("clients")
        ordering = (
            "name",
            "created_at",
        )
        constraints = (
            # Mirrors ``validate_schema_name`` at the database level, so bulk
            # writes that skip full_clean() cannot smuggle in a name that would
            # need quoting in a search_path.
            models.CheckConstraint(
                condition=models.Q(schema_name__regex=SCHEMA_NAME_PATTERN),
                name="client_schema_name_is_bare_identifier",
                violation_error_message=_(
                    "Schema names must be bare lower-case SQL identifiers."
                ),
            ),
        )

    def __str__(self) -> str:
        return f"{self.name} ({self.schema_name})"

    @staticmethod
    def schema_name_for(slug: str) -> str:
        """Derive a legal schema name from a slug.

        Slugs may contain hyphens, which are not legal in a bare SQL
        identifier, and may start with a digit; both are fixed up here.
        """
        candidate = slugify(slug).replace("-", "_")
        if candidate and not candidate[0].isalpha():
            candidate = f"t_{candidate}"
        return candidate[:63]

    def clean_fields(self, exclude: Collection[str] | None = None) -> None:
        # Derived here rather than in clean(), because full_clean() validates
        # fields first and would reject the blank schema_name as required
        # before clean() ever ran.
        if not self.schema_name and self.slug:
            self.schema_name = self.schema_name_for(self.slug)
        super().clean_fields(exclude=exclude)

    def clean(self) -> None:
        super().clean()
        if not self.schema_name:
            return
        try:
            validate_schema_name(self.schema_name)
        except ValidationError as exc:
            # Keyed to the field so forms and the admin render it in place;
            # the CheckConstraint below is the backstop for writes that never
            # call full_clean().
            raise ValidationError({"schema_name": exc.messages}) from exc

    def save(self, *args: Any, **kwargs: Any) -> None:
        # Filled in here as well as in clean(), because creating a tenant from
        # a script or data migration never goes through form validation and
        # TenantMixin.save() needs schema_name populated before it runs
        # CREATE SCHEMA.
        if not self.schema_name and self.slug:
            self.schema_name = self.schema_name_for(self.slug)
        super().save(*args, **kwargs)

    def delete(  # type: ignore[override]
        self,
        *args: Any,
        force_drop: bool = False,
        **kwargs: Any,
    ) -> DeleteResult:
        """Delete the catalogue row; ``force_drop=True`` also drops the schema.

        Re-declared rather than inherited so the destructive flag is visible
        (and type-checked) on this model -- ``TenantMixin`` is untyped, which
        would otherwise leave callers looking at ``Model.delete``.
        """
        # force_drop is TenantMixin.delete's first positional parameter.
        return super().delete(force_drop, *args, **kwargs)

    delete.alters_data = True  # type: ignore[attr-defined]

    @property
    def is_public(self) -> bool:
        """True for the tenant that owns the public schema."""
        return self.schema_name == get_public_schema_name()

    def primary_domain_name(self) -> str:
        """Hostname of the canonical domain, or an empty string if unset."""
        domain = self.get_primary_domain()
        return domain.domain if domain is not None else ""


class Domain(DomainMixin, TimeStampedModel):
    """A hostname that routes to a :class:`Client`.

    ``DomainMixin`` contributes ``domain``, ``tenant`` and ``is_primary``, and
    a ``save()`` that keeps at most one primary domain per tenant.
    """

    if TYPE_CHECKING:
        # See the note on Client: DomainMixin is untyped, so its fields have to
        # be re-declared for the type checker only.
        domain: str
        is_primary: bool
        tenant: Client
        tenant_id: int

    objects: ClassVar[DomainManager] = DomainManager()

    class Meta:
        verbose_name = _("domain")
        verbose_name_plural = _("domains")
        ordering = ("domain",)
        constraints = (
            # Hostnames are case-insensitive, but TenantMainMiddleware looks
            # them up with an exact match on whatever the Host header carried.
            # Storing them folded is what makes that lookup reliable.
            models.CheckConstraint(
                condition=models.Q(domain=Lower("domain")),
                name="domain_is_lowercase",
                violation_error_message=_("Domains must be stored lower-cased."),
            ),
        )

    def __str__(self) -> str:
        return self.domain

    @staticmethod
    def normalize(domain: str) -> str:
        """Fold a hostname to the form the middleware will look up."""
        return domain.strip().rstrip(".").lower()

    def clean(self) -> None:
        super().clean()
        self.domain = self.normalize(self.domain)

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.domain = self.normalize(self.domain)
        super().save(*args, **kwargs)
