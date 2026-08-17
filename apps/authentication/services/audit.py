"""The authentication audit trail.

Two rules govern this module. Audit writes never break the flow being audited
-- an audit failure must not stop a legitimate login -- and they are never
swallowed silently, because an audit gap nobody can see is worse than one
nobody has. Hence: catch, log loudly, continue.

Rows here are append-only by convention. Enforce it at the database level in
production, so an application defect cannot rewrite history::

    REVOKE UPDATE, DELETE ON authentication_authauditevent FROM eduremus_app;

Retention then runs as a separate privileged role on a schedule, which is also
the separation of duties a compliance reviewer will ask about.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.db import DatabaseError

from apps.authentication.models import AuthAuditEvent, AuthEventType, EventSeverity
from apps.authentication.utils.request_meta import client_ip, user_agent
from apps.tenants.utils import current_schema_name

if TYPE_CHECKING:
    from django.http import HttpRequest
    from rest_framework.request import Request

    from apps.accounts.models import User

    type AnyRequest = HttpRequest | Request

logger = logging.getLogger("eduremus.auth")
security_logger = logging.getLogger("eduremus.security")

__all__ = ["AuditService", "record", "security_event"]

# Severity is a property of the event type, not of the call site. Keeping the
# mapping here means one event cannot be logged as `info` in one service and
# `warning` in another, which would make any severity-based alert unreliable.
_DEFAULT_SEVERITY: dict[str, EventSeverity] = {
    AuthEventType.LOGIN_SUCCEEDED: EventSeverity.INFO,
    AuthEventType.LOGIN_FAILED: EventSeverity.NOTICE,
    AuthEventType.ACCOUNT_LOCKED: EventSeverity.WARNING,
    AuthEventType.TOKEN_REFRESHED: EventSeverity.INFO,
    AuthEventType.REFRESH_UNKNOWN: EventSeverity.WARNING,
    AuthEventType.REFRESH_REUSE_DETECTED: EventSeverity.CRITICAL,
    AuthEventType.CROSS_TENANT_TOKEN_REJECTED: EventSeverity.CRITICAL,
    AuthEventType.LOGOUT: EventSeverity.INFO,
    AuthEventType.LOGOUT_ALL: EventSeverity.INFO,
    AuthEventType.FORCE_LOGOUT: EventSeverity.WARNING,
    AuthEventType.PASSWORD_CHANGED: EventSeverity.NOTICE,
    AuthEventType.TENANT_SUSPENDED: EventSeverity.WARNING,
    AuthEventType.KEY_ROTATED: EventSeverity.WARNING,
}


class AuditService:
    """Writes ``AuthAuditEvent`` rows and mirrors them to the log stream."""

    def record(
        self,
        event_type: str,
        *,
        user: User | None = None,
        actor: User | None = None,
        request: AnyRequest | None = None,
        severity: EventSeverity | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Write one audit row. Never raises."""
        resolved = severity or _DEFAULT_SEVERITY.get(event_type, EventSeverity.INFO)

        try:
            AuthAuditEvent.objects.create(
                event_type=event_type,
                severity=resolved,
                user=user,
                actor=actor,
                ip_address=client_ip(request) if request is not None else None,
                user_agent=user_agent(request) if request is not None else "",
                detail=detail or {},
            )
        except DatabaseError:
            logger.exception(
                "audit_write_failed",
                extra={"event_type": event_type, "schema": current_schema_name()},
            )

    def security_event(
        self,
        event_type: str,
        *,
        user: User | None = None,
        actor: User | None = None,
        request: AnyRequest | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Record a security-relevant event and mirror it to the SIEM stream."""
        self.record(
            event_type,
            user=user,
            actor=actor,
            request=request,
            severity=_DEFAULT_SEVERITY.get(event_type, EventSeverity.CRITICAL),
            detail=detail,
        )
        security_logger.warning(
            str(event_type),
            extra={"schema": current_schema_name(), **(detail or {})},
        )


_service = AuditService()

# Module-level shorthands: every caller wants the same stateless service, and
# `audit.record(...)` reads better at the call site than instantiating one.
record = _service.record
security_event = _service.security_event
