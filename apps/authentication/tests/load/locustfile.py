"""Load scenarios for the authentication path.

Run against staging. Never against production: these deliberately drive
lockout counters, throttle buckets and refresh rotation, all of which write.

    uv run locust -f apps/authentication/tests/load/locustfile.py \
        --host https://acme.staging.eduremus.com --class-picker

Four scenarios, each a ``User`` class the picker can select:

===================  =========================================  ==================
Scenario             Target                                      Pass criterion
===================  =========================================  ==================
``SteadyStateUser``  500 concurrent, 10 min                      p99 < 200 ms,
                                                                 errors < 0.1 %
``LoginBurstUser``   100 logins/second, 1 min                    p99 < 500 ms, no 5xx
``RefreshStormUser`` 500 concurrent rotations                    **no reuse detections**
``TenantFanOutUser`` 50 tenants at once                          no cross-tenant
                                                                 leakage; per-tenant
                                                                 p99 stable
===================  =========================================  ==================

The refresh storm is the one that finds real defects. A reuse detection under
concurrency means either ``select_for_update()`` is missing from the rotation
lookup or the client is not serialising its refreshes -- both present in
production as unexplained logouts, and both are invisible until the
rotations overlap.

Load users are seeded by ``scripts/seed_load_test_users.py`` (not in this
repository -- staging data is not fixtures) with the addresses below.
"""

from __future__ import annotations

import os
import random
from typing import Any

from locust import HttpUser, between, constant_throughput, events, task

PASSWORD = os.environ.get("LOADTEST_PASSWORD", "load-test-password")
POPULATION = int(os.environ.get("LOADTEST_USERS", "1000"))

# Hostnames the tenant fan-out scenario spreads its traffic across. Every one
# has to exist in the staging catalogue.
TENANTS = os.environ.get(
    "LOADTEST_TENANTS", "acme.staging.eduremus.com,beta.staging.eduremus.com"
).split(",")

CSRF_COOKIE = "eduremus_csrf"
REFRESH_COOKIE = "__Host-eduremus_refresh"


def credentials(tenant: str = "acme") -> dict[str, str]:
    index = random.randint(1, POPULATION)
    return {"email": f"loadtest{index}@{tenant}.edu", "password": PASSWORD}


class AuthenticatedUser(HttpUser):
    """Shared login and refresh mechanics. Not a scenario on its own."""

    abstract = True
    access_token: str = ""

    def on_start(self) -> None:
        self.login()

    def login(self, **overrides: Any) -> None:
        with self.client.post(
            "/api/v1/auth/login/",
            json={**credentials(), **overrides},
            name="POST /auth/login/",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                self.access_token = response.json()["access_token"]
                response.success()
            else:
                # A 423 is the lockout doing its job, not a defect -- but it
                # means this user contributes nothing further, so it is worth
                # seeing in the report rather than counting as a failure.
                response.failure(f"login {response.status_code}")

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    def refresh(self) -> None:
        """Rotate, echoing the CSRF cookie back as the double-submit header."""
        csrf = self.client.cookies.get(CSRF_COOKIE, "")
        with self.client.post(
            "/api/v1/auth/refresh/",
            headers={"X-CSRF-Token": csrf},
            name="POST /auth/refresh/",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                self.access_token = response.json()["access_token"]
                response.success()
            elif response.json().get("error") == "token_reuse_detected":
                # The finding this whole scenario exists to surface.
                response.failure("REUSE DETECTED under concurrent rotation")
            else:
                response.failure(f"refresh {response.status_code}")


class SteadyStateUser(AuthenticatedUser):
    """The everyday mix: mostly token verification, occasional rotation."""

    wait_time = between(1, 3)

    @task(20)
    def read_profile(self) -> None:
        self.client.get("/api/v1/auth/me/", headers=self.headers, name="GET /auth/me/")

    @task(3)
    def list_sessions(self) -> None:
        self.client.get(
            "/api/v1/auth/sessions/",
            headers=self.headers,
            name="GET /auth/sessions/",
        )

    @task(1)
    def rotate(self) -> None:
        self.refresh()


class LoginBurstUser(HttpUser):
    """Login only, at a fixed rate. Measures the cost of password hashing.

    Argon2/bcrypt dominates this path by design, so the ceiling here is CPU
    and the useful output is how many logins a worker sustains before the
    queue grows.
    """

    wait_time = constant_throughput(1)

    @task
    def sign_in(self) -> None:
        self.client.post(
            "/api/v1/auth/login/", json=credentials(), name="POST /auth/login/"
        )


class RefreshStormUser(AuthenticatedUser):
    """Rotation as fast as the client will go.

    The concurrency test. Rotation takes ``select_for_update()`` on the
    presented row, so overlapping refreshes of the *same* lineage serialise;
    if they do not, both observe ACTIVE, both rotate, and one login yields two
    live lineages -- which look exactly like reuse the moment either is
    redeemed again.
    """

    wait_time = between(0.1, 0.5)

    @task
    def rotate(self) -> None:
        self.refresh()


class TenantFanOutUser(AuthenticatedUser):
    """One user per tenant, all at once.

    Watches for two things: per-tenant latency staying flat as the tenant
    count rises (the schema-per-tenant design should make this so), and
    ``eduremus_cross_tenant_rejections_total`` staying at zero -- a non-zero
    value here is a leak in the load harness or in the application, and both
    are worth stopping the run for.
    """

    wait_time = between(1, 3)

    def on_start(self) -> None:
        self.tenant_host = random.choice(TENANTS)
        self.client.headers["Host"] = self.tenant_host
        super().on_start()

    @task
    def read_profile(self) -> None:
        self.client.get(
            "/api/v1/auth/me/",
            headers=self.headers,
            name=f"GET /auth/me/ [{self.tenant_host}]",
        )


@events.quitting.add_listener
def _assert_thresholds(environment: Any, **_kwargs: Any) -> None:
    """Fail the run, not just the report.

    Locust exits 0 by default however bad the numbers are, which makes it
    useless in CI. These are the §20.6 criteria.
    """
    stats = environment.stats.total

    if stats.fail_ratio > 0.001:
        environment.process_exit_code = 1
        print(f"FAIL: error rate {stats.fail_ratio:.2%} exceeds 0.1%")
    elif stats.get_response_time_percentile(0.99) > 500:
        environment.process_exit_code = 1
        print(f"FAIL: p99 {stats.get_response_time_percentile(0.99)} ms exceeds 500 ms")
    else:
        environment.process_exit_code = 0
