#!/usr/bin/env bash
#
# Default command for the local django service.

set -o errexit
set -o pipefail
set -o nounset

# django-tenants replaces `migrate` with `migrate_schemas`; the explicit name
# is used here so it is obvious that this walks every schema, not just public.
# One pass applies SHARED_APPS to `public` and TENANT_APPS to each tenant.
python manage.py migrate_schemas --noinput

# Without a tenant answering on the hostname you browse to, every request 404s
# in TenantMainMiddleware. Registering the public tenant makes the stack usable
# the moment it boots; --if-not-exists keeps repeat starts a no-op.
python manage.py tenant_create \
    --name "EduRemus Platform" \
    --slug public \
    --schema public \
    --domain "${PUBLIC_TENANT_DOMAIN:-public.localhost}" \
    --if-not-exists

# Perform static file collection
python manage.py collectstatic --no-input

# exec so runserver becomes PID 1's child and receives SIGTERM directly,
# giving Compose a clean, fast shutdown instead of a 10s kill timeout.
exec python manage.py runserver 0.0.0.0:8000 --nostatic
