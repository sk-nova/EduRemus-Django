#!/usr/bin/env bash
#
# Blocks until Postgres accepts connections, then hands control to the
# container command. Compose already gates startup on the database healthcheck;
# this covers the other cases — a database restart, or running the image
# outside Compose.

set -o errexit
set -o pipefail
set -o nounset

python <<'PYCODE'
import os
import sys
import time
from urllib.parse import urlparse

import psycopg2

# Derive the DSN from DATABASE_URL so this check can never drift from what
# Django itself will connect to.
url = urlparse(os.environ["DATABASE_URL"])
dsn = {
    "dbname": url.path.lstrip("/"),
    "user": url.username,
    "password": url.password,
    "host": url.hostname,
    "port": url.port or 5432,
}

timeout = float(os.environ.get("POSTGRES_WAIT_TIMEOUT", "60"))
deadline = time.monotonic() + timeout

while True:
    try:
        psycopg2.connect(**dsn).close()
    except psycopg2.OperationalError as exc:
        if time.monotonic() >= deadline:
            sys.exit(f"Postgres unreachable after {timeout:.0f}s: {exc}")
        print("Waiting for Postgres...", file=sys.stderr, flush=True)
        time.sleep(1)
    else:
        print(f"Postgres is available at {dsn['host']}:{dsn['port']}", file=sys.stderr)
        break
PYCODE

exec "$@"
