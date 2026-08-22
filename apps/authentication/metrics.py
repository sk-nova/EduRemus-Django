"""Prometheus instrumentation for the authentication path.

Every metric here is labelled by ``schema``, because a platform-wide failure
rate hides the case that matters: one institution under attack while the other
four hundred are fine.

Two of these should read exactly zero in normal operation --
``cross_tenant_rejections_total`` and ``refresh_reuse_detections_total``. Both
page on any non-zero value (see ``deploy/prometheus/``), which is only
tolerable *because* they are zero: a legitimate client cannot produce either.

Recording helpers rather than bare counters at the call sites. The metric
objects stay private, so a caller cannot invent a label set that splits an
existing series in two, and instrumentation can be removed from a hot path
without touching the code being measured.

**Cardinality.** ``cross_tenant_rejections_total`` carries both the token's
schema and the active one, which is a per-tenant-*pair* product -- 250,000
series at 500 tenants. Acceptable only while the counter stays near zero; if
it ever becomes materially populated, drop the labels here and keep the detail
in the audit trail, which already records it.

**Multiprocess.** Under gunicorn with more than one worker, set
``PROMETHEUS_MULTIPROC_DIR`` to a writable tmpfs directory and have the master
process clean it on start, or each worker will report only its own counters.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from prometheus_client import Counter, Gauge, Histogram

from apps.tenants.utils import current_schema_name

__all__ = [
    "observe_token_validation",
    "record_cross_tenant_rejection",
    "record_denylist_error",
    "record_lockout",
    "record_login",
    "record_refresh",
    "record_reuse_detection",
    "set_signing_key_age",
]

_login_attempts: Final = Counter(
    "eduremus_login_attempts_total",
    "Login attempts, by outcome.",
    ["schema", "result"],
)

_token_validations: Final = Counter(
    "eduremus_token_validations_total",
    "Access token validations, by outcome.",
    ["schema", "result"],
)

_token_refreshes: Final = Counter(
    "eduremus_token_refreshes_total",
    "Refresh token rotations, by outcome.",
    ["schema", "result"],
)

_cross_tenant_rejections: Final = Counter(
    "eduremus_cross_tenant_rejections_total",
    "Tokens rejected because they were minted for a different tenant.",
    ["token_schema", "active_schema"],
)

_refresh_reuse_detections: Final = Counter(
    "eduremus_refresh_reuse_detections_total",
    "Refresh token reuse detections. A non-zero value is an incident.",
    ["schema"],
)

_account_lockouts: Final = Counter(
    "eduremus_account_lockouts_total",
    "Accounts locked after repeated authentication failures.",
    ["schema"],
)

_denylist_errors: Final = Counter(
    "eduremus_denylist_errors_total",
    "Denylist lookups that could not be answered. Each one failed a request closed.",
    ["schema"],
)

_token_validation_seconds: Final = Histogram(
    "eduremus_token_validation_seconds",
    "Wall time spent validating an access token.",
    ["schema"],
    # Tight buckets: the whole operation is a signature verification and a
    # cached user read, so anything past 50 ms means Redis or the database is
    # in the path and the p99 alert should fire.
    buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1),
)

_signing_key_age_days: Final = Gauge(
    "eduremus_signing_key_age_days",
    "Age of the active signing key, in days.",
    ["kid"],
)


def record_login(*, result: str) -> None:
    """Count one login attempt. ``result`` is ``success``/``failure``/``locked``."""
    _login_attempts.labels(schema=current_schema_name(), result=result).inc()


def record_refresh(*, result: str) -> None:
    """Count one rotation attempt, successful or otherwise."""
    _token_refreshes.labels(schema=current_schema_name(), result=result).inc()


def record_reuse_detection() -> None:
    """A rotated refresh token was presented again. Pages on any occurrence."""
    _refresh_reuse_detections.labels(schema=current_schema_name()).inc()


def record_cross_tenant_rejection(*, token_schema: str, active_schema: str) -> None:
    """A token minted for one institution was presented to another."""
    _cross_tenant_rejections.labels(
        token_schema=token_schema or "unknown",
        active_schema=active_schema or "unknown",
    ).inc()


def record_lockout() -> None:
    """An account crossed the failure threshold and was locked."""
    _account_lockouts.labels(schema=current_schema_name()).inc()


def record_denylist_error() -> None:
    """The denylist could not be read, so a request was failed closed."""
    _denylist_errors.labels(schema=current_schema_name()).inc()


def set_signing_key_age(*, kid: str, age_days: float) -> None:
    """Publish the active key's age, which is what the rotation alert reads."""
    _signing_key_age_days.labels(kid=kid).set(age_days)


@contextmanager
def observe_token_validation() -> Iterator[None]:
    """Time one token validation and count its outcome.

    Wraps the whole authenticate() body rather than only the cryptography: the
    question the p99 alert answers is "how long does authenticating cost",
    and the cached user read and the denylist round-trip are part of that.
    """
    schema = current_schema_name()
    started = time.perf_counter()
    result = "failure"
    try:
        yield
        result = "success"
    finally:
        _token_validation_seconds.labels(schema=schema).observe(
            time.perf_counter() - started
        )
        _token_validations.labels(schema=schema, result=result).inc()
