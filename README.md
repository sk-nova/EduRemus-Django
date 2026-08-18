# EduRemus-Django

A multi-tenant institutional management SaaS suite built on Django 5.2 LTS.

Tenancy is **schema-based**, using [django-tenants]: one Postgres database holds
a `public` schema with the tenant catalogue and the platform's own records, plus
one schema per institution. A request's hostname selects the schema, and the
connection's `search_path` does the rest — application code writes ordinary ORM
queries and cannot reach across the boundary.

[django-tenants]: https://django-tenants.readthedocs.io/

---

## How the tenancy works

```
                       Host: acme.example.com
                                 │
                    TenantMainMiddleware (first)
                                 │
                    tenants_domain ─► tenants_client
                                 │
                    SET search_path = "acme", "public"
                                 │
              ┌──────────────────┴──────────────────┐
              │                                     │
        acme.accounts_user                  public.tenants_client
        acme.auth_group                     public.tenants_domain
        acme.django_session                 public.accounts_user
        …                                   …
```

Three consequences follow from the `search_path` being `("<schema>", "public")`:

1. A table that exists in **both** schemas resolves to the tenant's copy. This
   is what isolates `accounts_user`, `auth_permission`, `django_session` and
   friends — not a filter anyone has to remember to write.
2. A table that exists **only in public** stays readable from a tenant. That is
   how shared models remain usable, and why writes to the catalogue must be
   wrapped in `public_schema()` (see [Tenant context](#tenant-context)).
3. The public schema sees only itself. Tenant rows are invisible from there.

### App split

| App | Shared | Tenant | Why |
|---|:---:|:---:|---|
| `django_tenants` | ✓ | | Mandatory. Installs the schema-aware backend and `migrate_schemas`. |
| `apps.tenants` | ✓ | | The catalogue the middleware reads *before* it knows the schema. Keeping it out of `TENANT_APPS` is what stops one institution enumerating the others. |
| `django.contrib.contenttypes` | ✓ | ✓ | Required shared by django-tenants; required per-tenant so each schema's permission rows point at their own content types. |
| `django.contrib.auth` | ✓ | ✓ | Each institution owns its users, groups and permissions. The public copy holds platform staff. |
| `django.contrib.sessions` | ✓ | ✓ | Per-tenant session tables: a cookie minted on one institution's domain has no row in another's schema, so replaying it authenticates nobody. |
| `django.contrib.admin` | ✓ | ✓ | Tenant staff get an admin scoped to their own schema; platform staff get one over the catalogue. |
| `django.contrib.messages` | ✓ | ✓ | Follows sessions. |
| `django.contrib.staticfiles` | ✓ | ✓ | No models. Static assets are shared (see [Static files](#static-files)). |
| `apps.core` | ✓ | ✓ | Abstract models only, but its label must be migratable wherever its concrete subclasses live. |
| `apps.accounts` | ✓ | ✓ | The swappable user model. Unchanged by tenancy — same model, one table per schema. |

`INSTALLED_APPS` is the de-duplicated union of the two lists; `TenantSyncRouter`
decides which of them is actually migrated into a given schema.

---

## Installation

```bash
uv sync --all-groups
```

Copy `.env.example` to `.env` and fill in `DJANGO_SECRET_KEY` and
`POSTGRES_PASSWORD`. The multi-tenancy keys are `DJANGO_ALLOWED_HOSTS` (must
cover every tenant hostname; a leading dot matches subdomains) and
`PUBLIC_TENANT_DOMAIN`.

Postgres is required — schema-based tenancy has no SQLite equivalent.

```bash
docker compose -f docker-compose.local.yml up --build
```

The local stack migrates every schema and registers the public tenant on
`${PUBLIC_TENANT_DOMAIN}` on first boot, so <http://localhost:8000/admin/> works
immediately.

---

## Running migrations

`django-tenants` replaces `migrate` with `migrate_schemas`. The sequence
matters:

```bash
# 1. SHARED_APPS into the public schema. Creates tenants_client/tenants_domain,
#    so this must come first -- there is nowhere to record a tenant until it has.
uv run manage.py migrate_schemas --shared

# 2. TENANT_APPS into every existing tenant schema.
uv run manage.py migrate_schemas --tenant

# Both at once (public first, then each tenant in turn). This is what the
# container entrypoint runs, and what you want day to day.
uv run manage.py migrate_schemas
```

Notes:

- `manage.py migrate` is an alias for `migrate_schemas`. Use the explicit name;
  it makes "this walks every schema" visible at the call site.
- A schema created after a migration lands is migrated to head automatically —
  `TenantMixin.save()` runs `migrate_schemas` for the new schema.
- `makemigrations` is unchanged. Write migrations normally; the router decides
  where they are applied.
- Data migrations that must run in only one kind of schema can use
  `django_tenants.utils.tenant_migration`.

---

## Creating your first tenant

```bash
# The platform's own tenant. Registers the public schema in the catalogue;
# `migrate_schemas --shared` already built the schema itself.
uv run manage.py tenant_create \
    --name "EduRemus Platform" --slug public --schema public --domain localhost

# An institution. Creates the schema and migrates it.
uv run manage.py tenant_create \
    --name "Acme Institute" --slug acme --domain acme.localhost
```

Then a superuser in each — they are separate accounts in separate tables:

```bash
uv run manage.py createsuperuser                        # public schema
uv run manage.py create_tenant_superuser --schema=acme  # acme's schema
```

<http://localhost:8000/admin/> is the platform admin;
<http://acme.localhost:8000/admin/> is Acme's.

### Tenant commands

| Command | What it does |
|---|---|
| `tenant_create` | Create a tenant, its schema and its primary domain. `--if-not-exists` makes it idempotent. |
| `tenant_domain_add <schema> --domain X` | Route another hostname. `--primary` promotes it. |
| `tenant_list` | Table of schema, slug, name, primary domain, status. `--schemas-only` for piping. |
| `tenant_delete <schema>` | Delete the catalogue row. `--drop-schema` also destroys the data. |
| `migrate_schemas` | Migrate public and/or tenants. |
| `tenant_command <cmd> --schema=X` | Run any management command inside one schema. |
| `all_tenants_command <cmd>` | Run one inside every schema. |
| `clone_tenant`, `rename_schema` | From django-tenants; occasionally useful in ops. |

There are `make` wrappers for the common ones: `make tenants`,
`make tenant-create NAME=… SLUG=… DOMAIN=…`, `make tenant-shell SCHEMA=acme`.

### Authentication commands

Tokens are signed with RS256 keys read from `JWT_KEY_DIRECTORY` — three files
per key, mounted from a secret store, never in git and never in the image. The
contract, the five-phase rotation procedure and the compromise response are in
[docs/jwt-key-management-runbook.md](docs/jwt-key-management-runbook.md).

| Command | What it does |
|---|---|
| `rotate_jwt_keys --kid X` | Generate and *stage* a keypair. Promotion is a separate step: set `JWT_ACTIVE_KEY_ID` 48 hours later. |
| `prune_expired_tokens` | Delete refresh rows past `expires_at`, in every schema. `--dry-run`, `--schema`. Run it daily. |
| `revoke_user_tokens --schema X --email Y` | Log one account out everywhere: bumps `token_version`, revokes the refresh rows, ends the sessions. |
| `jwt_inspect --file token.txt` | Decode a token for support work. `--schema` adds the stored row and the denylist; `--verify` runs the real validator. |

None of them assume a schema: each either takes one explicitly or iterates the
catalogue, because outside a request there is no `Host` header to resolve one
from.

`make jwt-key KID=…`, `make jwt-prune-dry`, `make jwt-revoke SCHEMA=… EMAIL=…`
and `make jwt-inspect FILE=… SCHEMA=…` wrap these for the local stack.

---

## Local development

Tenant hostnames must resolve. `*.localhost` works out of the box on Linux and
in Chrome/Firefox. **On Windows each subdomain needs a line in**
`C:\Windows\System32\drivers\etc\hosts`:

```
127.0.0.1  acme.localhost
127.0.0.1  riverdale.localhost
```

`DJANGO_ALLOWED_HOSTS` already contains `.localhost`, so no settings change is
needed per tenant.

### URLs

Two URLconfs, selected per request by the middleware:

- `config/urls_public.py` — the platform's own domain. Tenant catalogue,
  platform admin, marketing, sign-up.
- `config/urls.py` — an institution's domain. `ROOT_URLCONF`, so it is the
  fallback for anything that is not the public schema.

Adding a route to one does not expose it on the other.

### Tenant context

For anything that is not a request — shell scripts, cron jobs, background
workers — the schema has to be chosen explicitly. `apps.tenants.utils`
re-exports the primitives and adds a few wrappers:

```python
from apps.tenants.utils import (
    each_tenant,
    public_schema,
    run_in_every_schema,
    schema_context,
    tenant_context,
)
from apps.tenants.models import Client

# By instance: connection.tenant stays a real Client, so tenant fields work.
acme = Client.objects.get(slug="acme")
with tenant_context(acme):
    Enrolment.objects.count()

# By name: cheaper (no query to enter), but connection.tenant is a FakeTenant.
with schema_context("acme"):
    Enrolment.objects.count()

# Reach the catalogue from inside a tenant request.
with public_schema():
    Client.objects.filter(is_active=True).count()

# Sweep every active tenant. The catalogue is read once, up front.
for client in each_tenant():
    Enrolment.objects.filter(expired=True).delete()

results = run_in_every_schema(rebuild_search_index)  # {"acme": ..., "beta": ...}
```

`current_schema_name()` and `current_tenant()` report where you are; the latter
returns `None` under `schema_context()`, because a `FakeTenant` has no model
fields and quietly handing one back invites failures far from the cause.

### Media files

Uploads are tenant data, so they are namespaced by schema.
`TenantFileSystemStorage` resolves its location on every access, which means the
one `default_storage` object follows the connection:

```
media/
  public/brochure.pdf
  acme/logo.png
  beta/logo.png      # same filename, no collision
```

Nothing in application code changes — `FileField`/`ImageField` and
`default_storage` already route through it. In `DEBUG`, both URLconfs serve
`MEDIA_URL` from disk; in production that is the web server's or object store's
job, and moving to S3 means a tenant-aware `STORAGES["default"]` (django-tenants
ships `TenantFileSystemStorage`; S3 backends need
`MULTITENANT_RELATIVE_MEDIA_ROOT` honoured by whatever you configure).

### Static files

Deliberately **not** per tenant. Static assets are build output — identical for
every institution — so one `STATIC_ROOT`, one `collectstatic` and one whitenoise
cache entry per file is both correct and cheaper. Per-tenant *branding* is
better served by a tenant-scoped stylesheet or CSS variables driven by
`{{ tenant }}` (added to the template context by
`apps.tenants.context_processors.tenant`) than by duplicating the whole asset
tree.

If genuinely per-tenant static files become necessary, django-tenants provides
`TenantStaticFilesStorage`, `MULTITENANT_RELATIVE_STATIC_ROOT` and
`collectstatic_schemas`. Adopting them means collectstatic runs once per tenant
and whitenoise can no longer serve a single immutable tree — weigh that first.

### Celery

Celery is **not** installed in this project. When it is added, tenant context
must be propagated explicitly: a worker process has no request, so its
connection sits on `public` and every task would silently read the wrong schema.

The pattern is to carry the schema name in the task's arguments and re-enter it
in the worker:

```python
# apps/tenants/celery.py  (when celery is added)
from celery import Task
from apps.tenants.utils import current_schema_name, schema_context


class TenantTask(Task):
    """Re-enters the schema the task was published from."""

    def apply_async(self, args=None, kwargs=None, **options):
        headers = options.setdefault("headers", {})
        headers.setdefault("schema_name", current_schema_name())
        return super().apply_async(args, kwargs, **options)

    def __call__(self, *args, **kwargs):
        schema = self.request.get("schema_name") or "public"
        with schema_context(schema):
            return super().__call__(*args, **kwargs)
```

Register it with `app.Task = TenantTask` (or `@app.task(base=TenantTask)`), and
for periodic jobs that must touch every institution use `each_tenant()` /
`run_in_every_schema()` from inside a task that itself runs on `public`.

---

## Testing

```bash
make test          # inside the container
uv run pytest      # host-side, against a locally reachable Postgres
make test-fresh    # rebuild the test database (needed after a new migration)
```

The suite creates a public tenant plus two institutions (`acme`, `beta`) once
per session — building a schema runs the full migration set, which is far too
slow per test. `testserver`, Django's default test hostname, is routed to the
public tenant so tests that predate multi-tenancy keep working unchanged.

Because `--reuse-db` is on by default, **schemas are not re-migrated on reuse**.
Run `make test-fresh` (`pytest --create-db`) after adding a migration, exactly as
you already had to for the public schema.

Writing tenant-aware tests:

```python
def test_something(acme, beta):  # fixtures from apps/tenants/tests/conftest.py
    with tenant_context(acme):
        ...


def test_over_http(acme):
    response = Client().get("/admin/", headers={"host": "acme.testserver"})
```

Use a plain `django.test.Client` with an explicit `Host` header when the
middleware itself is what you are testing; `django_tenants.test.client.TenantClient`
assigns `request.tenant` directly and bypasses it.

---

## Troubleshooting

**`404` on every request, including `/admin/`.**
No tenant is registered for that hostname. `manage.py tenant_list` to see what
is routed; `SHOW_PUBLIC_IF_NO_TENANT_FOUND` is `False` on purpose, so an
unrecognised host never falls back to the public site.

**`404` on a hostname that *is* in `tenant_list`.**
The tenant is suspended (`is_active=False`). That is deliberately
indistinguishable from an unknown host — telling the two apart would confirm a
customer's existence to anyone guessing subdomains.

**`DisallowedHost` / `Invalid HTTP_HOST header`.**
Add the hostname (or `.parent-domain`) to `DJANGO_ALLOWED_HOSTS`.

**`relation "…" does not exist` inside a tenant.**
That schema is behind. `manage.py migrate_schemas --tenant`. If `tenant_list`
shows `MISSING SCHEMA`, the schema was dropped out from under the catalogue —
`manage.py create_missing_schemas` rebuilds it.

**`Can't create tenant outside the public schema.`**
`Client` rows live in `public`. Wrap the write in `public_schema()`.

**A query returned another tenant's rows.**
Almost always a model in `SHARED_APPS` only. Check the app split table above:
a table that exists solely in `public` is visible from every tenant by design.

**`ImproperlyConfigured: DATABASE_ROUTERS setting must contain …`**
`django_tenants.routers.TenantSyncRouter` was removed from `DATABASE_ROUTERS`.

**Postgres refuses `DROP SCHEMA … CASCADE` ("pending trigger events").**
The schema was created in the same open transaction. In production these are
separate commands; in tests, settle the deferred constraints first (see the
`flush_deferred_constraints` fixture).

**New migration not applied in tests.**
`--reuse-db` skipped it. `make test-fresh`.

---

## Tooling

```bash
uv run manage.py runserver     # dev server (defaults to config.settings.local)
uv run manage.py makemigrations
uv run pytest --cov            # tests with coverage
uv run ruff check . && uv run ruff format .
uv run mypy .
make                           # full target catalogue
```
