# Vault policy for whoever runs `manage.py rotate_jwt_keys`.
#
# Separated from the runtime's read-only policy on purpose: generating and
# promoting a signing key is an operator action with an audit trail, and a
# running pod must not be able to perform it. This is the separation of duties
# a compliance reviewer asks about first.
#
#   vault policy write eduremus-jwt-operator \
#     deploy/vault/eduremus-jwt-operator-policy.hcl
#
# Granted to the operator group, never to a service account:
#
#   vault write auth/oidc/role/eduremus-platform-operator \
#     policies=eduremus-jwt-operator ttl=30m
#
# Note there is no `delete` on the data path. Retiring a key (phase 5 of the
# rotation runbook) destroys a specific version deliberately, through
# `secret/destroy/...`, so an accidental `vault kv delete` cannot silently
# strand every token the key signed.

path "secret/data/eduremus/jwt/*" {
  capabilities = ["create", "read", "update"]
}

path "secret/metadata/eduremus/jwt" {
  capabilities = ["list"]
}

# `delete` on the metadata path is phase 5, retire: it removes the key from the
# store entirely, after which the agent stops projecting it and the keyring
# drops it within its 5-minute TTL.
path "secret/metadata/eduremus/jwt/*" {
  capabilities = ["read", "list", "delete"]
}

# Destroys the stored versions of a retired kid, so the private key is gone
# rather than merely unlisted.
path "secret/destroy/eduremus/jwt/*" {
  capabilities = ["update"]
}
