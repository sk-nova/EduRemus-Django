"""Request and response contracts for the authentication endpoints.

Validation and shaping only. Business rules live in ``services/`` -- a
serializer that decides whether a login succeeds cannot be reused by a
management command or a task, which is exactly the coupling the layering rule
exists to prevent.

Note what no response serializer here contains: the refresh token. It travels
only in the ``__Host-`` HttpOnly cookie, so no JavaScript context ever holds
it. Putting it in a body "for convenience" would defeat the cookie entirely.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from apps.authentication.models import DeviceSession
from apps.authentication.tokens.claims import CLAIM_SCOPES

UserModel = get_user_model()

__all__ = [
    "CurrentUserSerializer",
    "DeviceSessionSerializer",
    "LoginSerializer",
    "PasswordChangeResponseSerializer",
    "PasswordChangeSerializer",
    "RevokeSessionSerializer",
    "TokenPairResponseSerializer",
    "TokenVerifyRequestSerializer",
    "TokenVerifyResponseSerializer",
]


class LoginSerializer(serializers.Serializer[dict[str, Any]]):
    """Login input, with the email normalised exactly as the model does.

    ``UserManager.normalize_email`` lower-cases the *whole* address, not just
    the domain, and a CHECK constraint holds stored addresses to that. -
    Normalising any other way here would make ``Priya@acme.edu`` fail to match
    a row that exists.
    """

    email = serializers.EmailField(max_length=254, trim_whitespace=True)
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        # A trailing space is part of the password, not whitespace to tidy up.
        trim_whitespace=False,
        max_length=128,
    )
    device_name = serializers.CharField(
        max_length=100, required=False, allow_blank=True, default=""
    )

    def validate_email(self, value: str) -> str:
        return UserModel.objects.normalize_email(value)


class TenantSummarySerializer(serializers.Serializer[dict[str, Any]]):
    id = serializers.IntegerField(read_only=True)
    slug = serializers.CharField(read_only=True)
    name = serializers.CharField(read_only=True)


class TokenPairResponseSerializer(serializers.Serializer[dict[str, Any]]):
    """Login and refresh response body."""

    access_token = serializers.CharField(read_only=True)
    token_type = serializers.CharField(read_only=True, default="Bearer")
    expires_in = serializers.IntegerField(read_only=True)
    scope = serializers.CharField(read_only=True)


class CurrentUserSerializer(serializers.ModelSerializer[Any]):
    """Principal and tenant context for ``GET /auth/me/``."""

    name = serializers.CharField(source="get_full_name", read_only=True)
    roles = serializers.SerializerMethodField()
    scopes = serializers.SerializerMethodField()
    tenant = serializers.SerializerMethodField()

    class Meta:
        model = UserModel
        fields = (
            "id",
            "email",
            "name",
            "first_name",
            "last_name",
            "is_staff",
            "roles",
            "scopes",
            "tenant",
            "last_login",
        )
        read_only_fields = fields

    def get_roles(self, obj: Any) -> list[str]:
        # Groups are per-schema, so this returns roles within the active
        # tenant only. There is no cross-schema group to leak.
        return sorted(obj.groups.values_list("name", flat=True))

    def get_scopes(self, obj: Any) -> list[str]:
        """Scopes as carried by the presenting token, not as recomputed.

        A role changed since the token was minted takes effect on the next
        token, and this endpoint should report what the credential in hand can
        actually do rather than what it would be granted if reissued now.
        """
        payload = getattr(self.context.get("request"), "auth_payload", {}) or {}
        return sorted(str(payload.get(CLAIM_SCOPES, "")).split())

    def get_tenant(self, obj: Any) -> dict[str, Any] | None:
        tenant = getattr(self.context.get("request"), "tenant", None)
        if tenant is None:
            return None
        return {"id": tenant.pk, "slug": tenant.slug, "name": tenant.name}


class DeviceSessionSerializer(serializers.ModelSerializer[DeviceSession]):
    """One live session in the session list."""

    current = serializers.SerializerMethodField()

    class Meta:
        model = DeviceSession
        fields = (
            "id",
            "device_name",
            "device_id",
            "user_agent",
            "ip_address",
            "created_at",
            "last_seen_at",
            "current",
        )
        read_only_fields = fields

    def get_current(self, obj: DeviceSession) -> bool:
        """Whether this is the session the request was made from.

        Derived from the verified ``sid`` claim. Informational only -- the
        client uses it to label a row, and nothing is authorised by it.
        """
        return str(obj.pk) == str(self.context.get("current_session_id") or "")


class RevokeSessionSerializer(serializers.Serializer[dict[str, Any]]):
    """Target of ``POST /auth/revoke/``.

    Only an id. Whether the caller may end that session is decided by
    ownership in the service, never by knowing the identifier.
    """

    session_id = serializers.UUIDField()


class TokenVerifyRequestSerializer(serializers.Serializer[dict[str, Any]]):
    token = serializers.CharField(write_only=True, trim_whitespace=True)


class TokenVerifyResponseSerializer(serializers.Serializer[dict[str, Any]]):
    """Introspection result, RFC 7662 shaped.

    Everything but ``active`` is absent when the token is not valid. The
    endpoint is unauthenticated, so a differentiated answer would tell a
    caller whether a token is expired (retry later), revoked (this account is
    being watched) or wrong-tenant (it belongs to another institution).
    """

    active = serializers.BooleanField(read_only=True)
    sub = serializers.CharField(read_only=True, required=False)
    tid = serializers.IntegerField(read_only=True, required=False)
    sch = serializers.CharField(read_only=True, required=False)
    scope = serializers.CharField(read_only=True, required=False)
    exp = serializers.IntegerField(read_only=True, required=False)
    iat = serializers.IntegerField(read_only=True, required=False)
    token_type = serializers.CharField(read_only=True, required=False)


class PasswordChangeSerializer(serializers.Serializer[dict[str, Any]]):
    """Password change input.

    Deliberately does *not* run ``validate_password`` here. The service does,
    because it also owns the history check and the revocation ordering, and
    validating in both places means two code paths that can disagree about
    what the policy is.
    """

    current_password = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password = serializers.CharField(
        write_only=True, trim_whitespace=False, max_length=128
    )

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if attrs["current_password"] == attrs["new_password"]:
            raise serializers.ValidationError(
                {
                    "new_password": _(
                        "The new password must differ from the current one."
                    )
                }
            )
        return attrs


class PasswordChangeResponseSerializer(serializers.Serializer[dict[str, Any]]):
    access_token = serializers.CharField(read_only=True)
    token_type = serializers.CharField(read_only=True, default="Bearer")
    expires_in = serializers.IntegerField(read_only=True)
    sessions_revoked = serializers.IntegerField(read_only=True)
