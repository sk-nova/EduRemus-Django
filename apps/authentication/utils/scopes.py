"""Role-to-scope mapping.

Scopes are derived from roles at issuance rather than stored, so this mapping
is a deployment-wide constant rather than tenant data. Changing it changes what
*newly issued* tokens carry; tokens already in circulation keep the scopes they
were minted with until they expire, which is the documented staleness window.
An immediate effect requires revocation, not an edit here.

Roles themselves are per-schema ``auth.Group`` rows -- "faculty" in *acme* is a
different Group instance from "faculty" in *beta* -- but the capabilities a
role name confers are the same platform-wide.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

__all__ = [
    "ALL_SCOPES",
    "BASE_SCOPES",
    "ROLE_SCOPES",
    "scopes_for_roles",
]

ROLE_SCOPES: Final[dict[str, frozenset[str]]] = {
    "platform_admin": frozenset({"tenants:admin", "platform:admin"}),
    "tenant_admin": frozenset(
        {
            "users:admin",
            "courses:admin",
            "enrolments:admin",
            "reports:read",
            "sessions:revoke",
            "settings:admin",
        }
    ),
    "registrar": frozenset(
        {
            "users:read",
            "users:write",
            "enrolments:admin",
            "courses:read",
            "reports:read",
            "transcripts:admin",
        }
    ),
    "course_coordinator": frozenset(
        {
            "courses:admin",
            "enrolments:read",
            "enrolments:write",
            "users:read",
            "reports:read",
        }
    ),
    "faculty": frozenset(
        {
            "courses:read",
            "courses:write",
            "enrolments:read",
            "grades:write",
            "profile:read",
            "profile:write",
        }
    ),
    "student": frozenset(
        {
            "courses:read",
            "enrolments:read",
            "grades:read",
            "profile:read",
            "profile:write",
            "transcripts:read",
        }
    ),
    "auditor": frozenset(
        {
            "users:read",
            "courses:read",
            "enrolments:read",
            "reports:read",
            "audit:read",
        }
    ),
}

# Granted to every authenticated principal, whatever roles they hold.
BASE_SCOPES: Final[frozenset[str]] = frozenset({"profile:read"})

# Every scope the platform defines. Exists so a permission class can assert at
# import time that it requires a scope that is actually issuable -- a typo in a
# required scope is a check nothing can ever satisfy.
ALL_SCOPES: Final[frozenset[str]] = BASE_SCOPES.union(*ROLE_SCOPES.values())


def scopes_for_roles(roles: Iterable[str]) -> str:
    """Union the scopes of every role held, as a space-delimited string.

    Union rather than intersection: roles are additive, so someone who is both
    ``faculty`` and ``course_coordinator`` holds the capabilities of each. An
    unrecognised role contributes nothing rather than raising -- a group that
    exists in a tenant schema but is not in the mapping is an ordinary
    institution-defined group, not an error.

    Sorted so the claim is deterministic, which keeps token bytes stable and
    test assertions simple.
    """
    granted = set(BASE_SCOPES)
    for role in roles:
        granted |= ROLE_SCOPES.get(role, frozenset())
    return " ".join(sorted(granted))
