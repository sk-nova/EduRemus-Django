"""Creation and change forms for the custom user model.

These are written from scratch rather than subclassing
``django.contrib.auth.forms`` so the validation rules -- in particular the
interaction between soft deletion and email uniqueness -- are explicit and
under our control.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from django import forms
from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    # Type-checking only: the runtime reference always goes through
    # get_user_model() so the model stays swappable.
    from apps.accounts.models import User


class EmailUniquenessMixin(forms.ModelForm):
    """Normalises ``email`` and enforces uniqueness across *all* rows.

    Soft-deleted accounts keep their address reserved: their rows still exist
    and still satisfy the unique index, so letting a form "succeed" here would
    only trade a friendly error for an IntegrityError. The distinct message
    tells staff to restore the account instead of guessing.
    """

    def clean_email(self) -> str:
        user_model = get_user_model()
        email = user_model.objects.normalize_email(self.cleaned_data["email"])

        existing = user_model.all_objects.filter(email=email)
        # UUID primary keys are assigned in __init__, so `pk is not None` says
        # nothing about whether this row exists yet -- ask _state instead.
        if not self.instance._state.adding:
            existing = existing.exclude(pk=self.instance.pk)

        conflict = existing.first()
        if conflict is not None:
            if conflict.is_deleted:
                raise forms.ValidationError(
                    _(
                        "A deleted account is already using this email "
                        "address. Restore that account instead."
                    ),
                    code="email_taken_by_deleted",
                )
            raise forms.ValidationError(
                _("An account with this email address already exists."),
                code="email_taken",
            )

        return email


class UserCreationForm(EmailUniquenessMixin):
    """Collects an email and a confirmed password, then hashes it."""

    password1 = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text=password_validation.password_validators_help_text_html,
    )
    password2 = forms.CharField(
        label=_("Password confirmation"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text=_("Enter the same password as above, for verification."),
    )

    class Meta:
        model = get_user_model()
        fields = ("email", "first_name", "last_name")
        widgets: ClassVar[dict[str, forms.Widget]] = {
            "email": forms.EmailInput(attrs={"autocomplete": "email"}),
        }

    def clean_password2(self) -> str:
        # Reached only once the field itself validated, so password2 is set.
        password1: str | None = self.cleaned_data.get("password1")
        password2: str = self.cleaned_data["password2"]

        if password1 and password1 != password2:
            raise forms.ValidationError(
                _("The two password fields didn't match."),
                code="password_mismatch",
            )

        return password2

    def _post_clean(self) -> None:
        super()._post_clean()  # type: ignore[misc]

        # Run AUTH_PASSWORD_VALIDATORS *after* the instance has been populated
        # so UserAttributeSimilarityValidator can compare against the email.
        password = self.cleaned_data.get("password2")
        if not password:
            return

        try:
            password_validation.validate_password(password, self.instance)
        except forms.ValidationError as error:
            self.add_error("password2", error)

    def save(self, commit: bool = True) -> User:
        user: User = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
            self.save_m2m()
        return user


class UserChangeForm(EmailUniquenessMixin):
    """Edits an existing account without ever exposing the password hash."""

    password = ReadOnlyPasswordHashField(
        label=_("Password"),
        help_text=_(
            "Raw passwords are not stored, so there is no way to see this "
            'user\'s password. You can change it using <a href="{}">this '
            "form</a>."
        ),
    )

    class Meta:
        model = get_user_model()
        fields = (
            # "password" is listed so the hash reaches the form's initial data
            # and the read-only widget can render it. The field is disabled,
            # so it round-trips unchanged.
            "password",
            "email",
            "first_name",
            "last_name",
            "is_active",
            "is_staff",
            "is_superuser",
            "groups",
            "user_permissions",
        )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        password = self.fields.get("password")
        if password is not None:
            password.help_text = password.help_text.format("../password/")

        # One query instead of one per permission when rendering the widget.
        permissions = self.fields.get("user_permissions")
        if isinstance(permissions, forms.ModelMultipleChoiceField):
            choices = permissions.queryset
            if choices is not None:
                permissions.queryset = choices.select_related("content_type")

    def clean(self) -> dict[str, Any]:
        super().clean()
        cleaned_data = self.cleaned_data

        # A superuser that cannot reach the admin is a support ticket waiting
        # to happen; keep the two flags coherent.
        if cleaned_data.get("is_superuser") and not cleaned_data.get("is_staff"):
            self.add_error(
                "is_staff",
                forms.ValidationError(
                    _("Superusers must also have staff status."),
                    code="superuser_requires_staff",
                ),
            )

        return cleaned_data
