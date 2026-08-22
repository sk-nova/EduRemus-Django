# Vault wiring for the JWT signing keys

The application reads a *directory*: three files per key, described in
[`docs/jwt-key-management-runbook.md`](../../docs/jwt-key-management-runbook.md)
§1. Vault Agent is what puts them there. Nothing in this directory is secret —
key ids are public, and the policies grant paths rather than values.

| File | Applied to | Purpose |
| :--- | :--- | :--- |
| `eduremus-jwt-policy.hcl` | Vault | Read-only access for the running pods |
| `eduremus-jwt-operator-policy.hcl` | Vault | Write access for whoever rotates keys |
| `deployment.patch.yaml` | Kubernetes | Agent injection, the tmpfs mount, `JWT_ACTIVE_KEY_ID` |

## One-time setup

```bash
vault policy write eduremus-jwt-reader deploy/vault/eduremus-jwt-policy.hcl
```

```bash
vault policy write eduremus-jwt-operator deploy/vault/eduremus-jwt-operator-policy.hcl
```

```bash
vault write auth/kubernetes/role/eduremus-api bound_service_account_names=eduremus-django bound_service_account_namespaces=eduremus policies=eduremus-jwt-reader ttl=1h
```

## Generating a key into the store

`rotate_jwt_keys` writes to a directory, so in production it is run against a
scratch directory on the operator's machine and the result is pushed to Vault.
It is never run against the pod's mount: that mount is agent-owned, and a file
written there by hand is erased on the next render.

```bash
export JWT_KEY_DIRECTORY="$(mktemp -d)" && chmod 700 "$JWT_KEY_DIRECTORY"
```

```bash
uv run manage.py rotate_jwt_keys --kid 2026-Q4-a --valid-days 121
```

```bash
vault kv put secret/eduremus/jwt/2026-Q4-a private_pem=@"$JWT_KEY_DIRECTORY/2026-Q4-a.private.pem" public_pem=@"$JWT_KEY_DIRECTORY/2026-Q4-a.public.pem" metadata_json=@"$JWT_KEY_DIRECTORY/2026-Q4-a.json"
```

```bash
shred -u "$JWT_KEY_DIRECTORY"/* && rmdir "$JWT_KEY_DIRECTORY"
```

Then add the incoming kid's annotations to `deployment.patch.yaml` and apply
it. That is phase 1 of the rotation runbook; **do not** change
`JWT_ACTIVE_KEY_ID` in the same step — promotion is phase 3, 48 hours later.

Use a machine with an ephemeral filesystem, or at minimum `shred` as above. A
private key that touched a laptop's SSD has touched a disk that gets backed up.

## Other stores

The contract is a directory, so any agent that can project files satisfies it:
the AWS Secrets Manager CSI driver, the Azure Key Vault CSI driver, or the GCP
Secret Manager CSI driver, each mounting to `JWT_KEY_DIRECTORY` with the same
filenames and modes. Switching stores is a deployment change with no code
change.
