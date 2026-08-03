#!/usr/bin/env bash
#
# Default command for the local django service.

set -o errexit
set -o pipefail
set -o nounset

# Perform migrations
python manage.py migrate --no-input

# Perform static file collection
python manage.py collectstatic --no-input

# exec so runserver becomes PID 1's child and receives SIGTERM directly,
# giving Compose a clean, fast shutdown instead of a 10s kill timeout.
exec python manage.py runserver 0.0.0.0:8000 --nostatic
