# Vault policy for the application's JWT signing keys.
#
# Read-only, and scoped to one path. The application never writes key material:
# `manage.py rotate_jwt_keys` is run by an operator holding the separate
# `eduremus-jwt-operator` policy, so a compromised pod cannot mint itself
# a new signing key and promote it.
#
#   vault policy write eduremus-jwt-reader deploy/vault/eduremus-jwt-policy.hcl
#
# Bound to the pod's service account:
#
#   vault write auth/kubernetes/role/eduremus-api \
#     bound_service_account_names=eduremus-django \
#     bound_service_account_namespaces=eduremus \
#     policies=eduremus-jwt-reader \
#     ttl=1h

# --- The runtime: read the keys, learn nothing else --------------------------
path "secret/data/eduremus/jwt/*" {
  capabilities = ["read"]
}

# Listing is what lets the agent template every key currently in the ring
# rather than a hard-coded pair of kids.
path "secret/metadata/eduremus/jwt" {
  capabilities = ["list"]
}

path "secret/metadata/eduremus/jwt/*" {
  capabilities = ["read", "list"]
}
