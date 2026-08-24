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

# A development signing key, generated once into the mounted key directory.
# Production mounts real keys from a secret store and this block finds them
# already there; locally there is no store, and without a key every token
# operation fails at the first signature. Guarded on the metadata file rather
# than on the command's own error, because `rotate_jwt_keys` refuses to
# overwrite a kid -- correctly, since doing so would invalidate every token it
# had signed.
KEY_DIRECTORY="${JWT_KEY_DIRECTORY:-/run/secrets/jwt}"
KEY_ID="${JWT_ACTIVE_KEY_ID:-dev-local-a}"

if [ ! -f "${KEY_DIRECTORY}/${KEY_ID}.json" ]; then
    if [ ! -w "${KEY_DIRECTORY}" ]; then
        echo "Key directory ${KEY_DIRECTORY} is not writable by this container." >&2
        echo "Create it on the host first: mkdir -p secrets/jwt" >&2
        exit 1
    fi
    python manage.py rotate_jwt_keys --kid "${KEY_ID}"
fi

# Perform static file collection
python manage.py collectstatic --no-input

# exec so runserver becomes PID 1's child and receives SIGTERM directly,
# giving Compose a clean, fast shutdown instead of a 10s kill timeout.
exec python manage.py runserver 0.0.0.0:8000 --nostatic
