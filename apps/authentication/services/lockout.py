"""Progressive account lockout, on top of the request throttles.

Counters are keyed by **both** email and IP, and a lockout trips only when
both are over threshold. The asymmetry matters:

* email only -- anyone who knows an address can lock its owner out at will,
  which converts a brute-force defence into a denial-of-service tool aimed at
  a named victim.
* IP only -- a distributed campaign against one account never trips it, and a
  single office NAT locks out everyone behind it.

Requiring both keeps each failure mode narrow: an attacker from one network
can lock only themselves out of one account, and the legitimate owner logging
in from anywhere else is unaffected.

Fails **open**. If Redis is unreachable the attempt proceeds -- a counter
outage must not become an authentication outage, and the request throttles and
the WAF remain as outer layers. This is the opposite of the denylist policy,
deliberately: a missed lockout costs an extra guess, a missed denylist
reinstates a revoked credential.
"""

from __future__ import annotations

import logging
from typing import Final

from django.conf import settings
from django.core.cache import cache

from apps.authentication.exceptions import AccountLocked
from apps.authentication.utils.cache_keys import lockout_key

logger = logging.getLogger("eduremus.auth")

__all__ = ["LockoutPolicy"]

_LOCKED_SUFFIX: Final = "locked"


class LockoutPolicy:
    """Failure counting and lockout windows for one schema."""

    @property
    def _threshold(self) -> int:
        return int(settings.JWT_AUTH["LOCKOUT_THRESHOLD"])

    @property
    def _window_seconds(self) -> int:
        return int(settings.JWT_AUTH["LOCKOUT_WINDOW"].total_seconds())

    @property
    def _duration_seconds(self) -> int:
        return int(settings.JWT_AUTH["LOCKOUT_DURATION"].total_seconds())

    def register_failure(self, *, email: str, ip: str | None) -> bool:
        """Count one failed attempt against both discriminators.

        Returns whether *this* attempt is the one that locked the account --
        both counters over threshold, and at least one of them crossing it
        now. The caller uses that to emit the lockout event exactly once per
        lock rather than on every subsequent failure, which is what keeps a
        "lockout storm" alert measuring accounts rather than requests.
        """
        keys = self._counter_keys(email=email, ip=ip)
        counts: list[int] = []

        for key in keys:
            try:
                count = self._increment(key)
            except Exception:
                logger.warning("lockout_counter_unavailable", exc_info=True)
                continue

            counts.append(count)
            if count >= self._threshold:
                cache.set(f"{key}:{_LOCKED_SUFFIX}", True, self._duration_seconds)

        if len(keys) < 2 or len(counts) < len(keys):
            # An email-only counter never locks anything on its own, and a
            # counter that could not be read leaves the state unknown. Neither
            # is a lockout.
            return False

        return all(count >= self._threshold for count in counts) and any(
            count == self._threshold for count in counts
        )

    def assert_not_locked(self, *, email: str, ip: str | None) -> None:
        """Refuse the attempt when both counters are locked."""
        keys = self._counter_keys(email=email, ip=ip)
        if len(keys) < 2:
            # No usable IP, so the "both must trip" rule cannot be satisfied
            # and email-only lockout is exactly the DoS lever described above.
            return

        try:
            locked = [cache.get(f"{key}:{_LOCKED_SUFFIX}") for key in keys]
        except Exception:
            logger.warning("lockout_state_unavailable", exc_info=True)
            return

        if all(locked):
            raise AccountLocked(wait=self._duration_seconds)

    def clear(self, *, email: str, ip: str | None) -> None:
        """Reset the counters after a successful authentication."""
        for key in self._counter_keys(email=email, ip=ip):
            cache.delete_many([key, f"{key}:{_LOCKED_SUFFIX}"])

    def failure_count(self, *, email: str) -> int:
        """Current failure count for an address. Diagnostics and tests."""
        return int(cache.get(lockout_key("email", email.lower())) or 0)

    @staticmethod
    def _counter_keys(*, email: str, ip: str | None) -> list[str]:
        keys = [lockout_key("email", email.lower())]
        if ip:
            keys.append(lockout_key("ip", ip))
        return keys

    def _increment(self, key: str) -> int:
        """Increment a counter, creating it with the window TTL if absent.

        ``cache.incr`` raises ``ValueError`` on a missing key rather than
        starting from zero, which is what makes the seed path explicit. The
        TTL is set only on creation, so the window slides from the first
        failure rather than from the most recent one.
        """
        try:
            return int(cache.incr(key))
        except ValueError:
            cache.set(key, 1, self._window_seconds)
            return 1
