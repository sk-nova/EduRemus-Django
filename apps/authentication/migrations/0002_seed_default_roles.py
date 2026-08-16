"""Seed the default role groups.

Runs once per schema. ``auth.Group`` is in TENANT_APPS, so each institution
gets its own set of rows -- "faculty" in *acme* is a different Group instance
from "faculty" in *beta*, and the public schema gets a third set for platform
staff. The names are what ``utils.scopes.ROLE_SCOPES`` maps to scopes, so a
group named here and absent there simply confers no scopes.

Idempotent via get_or_create: a tenant onboarded before this migration and one
created afterwards both end up with exactly one row per role.
"""

from __future__ import annotations

from typing import Any

from django.db import migrations

DEFAULT_ROLES = (
    "platform_admin",
    "tenant_admin",
    "registrar",
    "faculty",
    "course_coordinator",
    "student",
    "auditor",
)


def create_roles(apps: Any, schema_editor: Any) -> None:
    Group = apps.get_model("auth", "Group")
    for name in DEFAULT_ROLES:
        Group.objects.get_or_create(name=name)


def remove_roles(apps: Any, schema_editor: Any) -> None:
    """Drop the seeded groups.

    Deletes by name only. Any permissions or memberships an administrator
    attached to these groups go with them, which is the correct behaviour for
    reversing the migration that created them.
    """
    Group = apps.get_model("auth", "Group")
    Group.objects.filter(name__in=DEFAULT_ROLES).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("authentication", "0001_initial"),
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [migrations.RunPython(create_roles, remove_roles)]
