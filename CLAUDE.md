# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

EduRemus-Django is a multi-tenant institutional management SaaS suite, built on Django LTS version 5.2.x. Reusable Django core apps live under `apps/`; `templates/`/`docs/` are currently empty.

Tenancy is **schema-based** via `django-tenants`: one database, a `public` schema holding the tenant catalogue and platform records, and one Postgres schema per institution. `TenantMainMiddleware` maps the request hostname to a schema and sets the connection's `search_path`. See "Multi-tenancy" below — it changes what almost every other section here means.

## Tooling & commands

Dependencies are managed with **uv** (`uv.lock` present, requires Python >=3.14). A `Makefile` wraps the common flows — run `make` for the catalogue; the raw equivalents are:

```bash
uv sync --all-groups           # install runtime + dev dependencies
uv run manage.py runserver     # run the dev server
uv run manage.py migrate_schemas          # migrate public + every tenant schema
uv run manage.py migrate_schemas --shared # SHARED_APPS into public only
uv run manage.py migrate_schemas --tenant # TENANT_APPS into every tenant
uv run manage.py makemigrations # create new migrations whenever there is a Model field added/changes.
uv run manage.py createsuperuser          # platform staff, in the public schema
uv run manage.py create_tenant_superuser --schema=acme  # staff inside one tenant
uv run manage.py tenant_list              # what is routed where
uv run pytest                  # run tests
uv run pytest --cov            # ...with a coverage report
uv run ruff check .            # lint
uv run ruff format .           # code format compliant to PEP8
uv run mypy .                  # type check compliant to PEP8
```

`manage.py` defaults `DJANGO_SETTINGS_MODULE` to `config.settings.local`, so local commands don't need the env var set explicitly.

## Multi-tenancy

`django-tenants` 3.14, pinned. The essentials, in the order they bite:

- **`INSTALLED_APPS` is derived**, not authored. `base.py` defines `SHARED_APPS` (public schema only) and `TENANT_APPS` (every tenant schema); `INSTALLED_APPS` is their de-duplicated union. Adding an app to `INSTALLED_APPS` alone means `TenantSyncRouter` never migrates it anywhere — put it in one or both of the real lists. `local.py` appends `django_extensions`/`debug_toolbar` to `SHARED_APPS` for exactly this reason.
- **`apps.accounts`, `apps.core`, `auth`, `contenttypes`, `sessions`, `messages`, `admin` are in *both* lists.** Each institution owns its users, groups, permissions and sessions; the public copies belong to platform staff. The user model itself is completely unchanged by tenancy.
- **`apps.tenants` is shared only.** It is what the middleware reads before it knows the schema, and keeping it out of `TENANT_APPS` is what stops one institution enumerating the others.
- A tenant's `search_path` is `("<schema>", "public")`. A table present in both resolves to the tenant's copy (this is the isolation mechanism); a table present only in `public` stays readable from every tenant (this is how shared models work, and why it is worth checking the app split before assuming a query is isolated).
- **`TenantMainMiddleware` must stay first.** Anything above it queries the database with `public` still selected. `apps.tenants.middleware.TenantMainMiddleware` subclasses it to also refuse suspended tenants (`Client.is_active`), returning the same 404 as an unknown host so subdomain guessing cannot confirm a customer exists.
- **Two URLconfs**: `config/urls.py` (`ROOT_URLCONF`) serves institutions, `config/urls_public.py` (`PUBLIC_SCHEMA_URLCONF`) serves the platform.
- **Never add a `tenant` ForeignKey.** Isolation is the schema. Nothing outside `apps.tenants` references `Client`.
- Writes to `Client`/`Domain` must happen in the public schema — `TenantMixin.save()` raises otherwise. Use `apps.tenants.utils.public_schema()`.
- Outside a request (scripts, jobs, migrations) the schema is never implicit. `apps.tenants.utils` re-exports `tenant_context`/`schema_context` and adds `public_schema()`, `each_tenant()`, `run_in_every_schema()`, `current_schema_name()`, `current_tenant()`, `activate_public_schema()`. `current_tenant()` returns `None` under `schema_context()`, which only knows a name.
- django-tenants ships **no `py.typed`**, so mypy sees `TenantMixin`/`DomainMixin` as `Any`. `apps/tenants/models.py` re-declares the inherited fields under `if TYPE_CHECKING:` and overrides `delete()` explicitly; `activate_public_schema()` is the single narrowed `type: ignore` for the connection's schema methods. `django_tenants.mypy_plugin` (enabled in `pyproject.toml`) supplies `request.tenant`.
- Postgres is mandatory. There is no SQLite path.

## Configuration

- Settings live under `config/settings/` and are split by environment: `base.py` holds shared settings, `local.py` imports `from .base import *` and layers in `DEBUG=True` and dev `ALLOWED_HOSTS`, and `test.py` is what pytest uses. There is no production settings module yet — add one alongside `local.py` following the same import pattern when needed.
- `DATABASES["default"]["ENGINE"]` is overwritten to `django_tenants.postgresql_backend` *after* `dj_database_url` parses `DATABASE_URL`, and `DATABASE_ROUTERS` must keep `django_tenants.routers.TenantSyncRouter` — django-tenants refuses to start without it.
- `ALLOWED_HOSTS` is env-driven (`DJANGO_ALLOWED_HOSTS`) because every tenant hostname has to pass host validation. A leading dot matches subdomains.
- `config/settings/test.py` resolves `DJANGO_SECRET_KEY` and exports a `DATABASE_URL` *before* importing `base`, so the suite runs with no `.env` present. It assembles the connection string from the `POSTGRES_*` vars against `127.0.0.1` rather than reusing `DATABASE_URL`, which legitimately points at the container-internal `db` host. Override with `TEST_DATABASE_URL`, or `TEST_POSTGRES_HOST=db` when running pytest inside the stack (`make docker-test` does this).
- Environment variables are read via `python-decouple` (`config(...)`) and loaded from a `.env` file at the project root (see `.env.example` for required keys: `DJANGO_SECRET_KEY`, `DATABASE_URL`, `DJANGO_ALLOWED_HOSTS`, `PUBLIC_TENANT_DOMAIN`). `DATABASE_URL` is parsed with `dj-database-url`.
- `SECRET_KEY` is only defined in `local.py` (via env var) — `base.py` intentionally has no default secret key.
- `TIME_ZONE` is set to `Asia/Kolkata`.

## Docker (local stack)

`docker-compose.local.yml` runs two services: `django` (built from `docker/local/django/Dockerfile`) and `db` (`postgres:18-trixie`).

```bash
docker compose -f docker-compose.local.yml up --build   # build + start
docker compose -f docker-compose.local.yml exec django python manage.py <cmd>
docker compose -f docker-compose.local.yml logs -f django
docker compose -f docker-compose.local.yml down          # add -v to drop the DB volume
```

Notable constraints when editing the Docker setup:

- The image is multi-stage: a `builder` stage runs `uv sync --locked` into `/opt/venv`, and the `runtime` stage copies only that venv. `uv` itself never reaches the final image.
- **The venv lives at `/opt/venv`, not `/app/.venv`** — Compose bind-mounts the source at `/app`, which would otherwise shadow it with the host's Windows venv.
- Dependency groups are controlled by the `UV_DEPENDENCY_GROUPS` build arg (`--group dev` locally; a production build passes `--no-dev`).
- `uv sync --locked` fails the build if `uv.lock` has drifted from `pyproject.toml` — run `uv lock` after editing dependencies.
- The container runs as the non-root `django` user (uid 1000) and `/opt/venv` is root-owned, so dependency changes require an image rebuild rather than an in-container install.
- `postgres:18` sets `PGDATA=/var/lib/postgresql/18/docker` and declares `/var/lib/postgresql` as its volume — the named volume mounts at `/var/lib/postgresql`, *not* `.../data`.
- Compose builds `DATABASE_URL` for the container from the `POSTGRES_*` vars, overriding the `.env` value (which is for host-side `manage.py` runs). `POSTGRES_PASSWORD` is required and fails fast if unset.
- `.gitattributes` forces LF endings; `docker/local/django/*.sh` are copied into the image with `--chmod=0755` and break if they get CRLF.
- `start.sh` runs `migrate_schemas`, then registers the public tenant on `PUBLIC_TENANT_DOMAIN` with `tenant_create --if-not-exists` (without a tenant answering on the hostname you browse to, every request 404s in the middleware), then `collectstatic`.
- `media/` is bind-mounted; uploads land in `media/<schema_name>/`.

## Architecture notes

- `config/` is the Django project package (settings, root `urls.py`, `wsgi.py`/`asgi.py`) — analogous to the default `django-admin startproject` layout but with settings split into a package.
- `config/urls.py` is the *tenant* URLconf and `config/urls_public.py` the public one; the middleware picks between them per request.
- `INSTALLED_APPS` is composed in `base.py` as the de-duplicated union of `SHARED_APPS` and `TENANT_APPS` (plus `THIRD_PARTY_APPS`); add new project apps to one or both of those by their `AppConfig` path. Editing `INSTALLED_APPS` directly gets an app loaded but never migrated.
- Template resolution: `TEMPLATES[0]['DIRS']` points at the top-level `templates/` directory in addition to each app's own `templates/` dir (`APP_DIRS=True`).
- `apps.tenants.context_processors.tenant` puts `tenant` and `schema_name` in every template context.
- Dev-only dependencies (`django-debug-toolbar`, `django-extensions`, `mypy`, `pre-commit`, `pytest-django`, `pytest-cov`, `ruff`) are declared in the `[dependency-groups.dev]` section of `pyproject.toml`. `psycopg2-binary` is a runtime dependency (Postgres driver), not a dev one.
- Ruff excludes `*/migrations/*` (with `force-exclude` so it holds under pre-commit, which passes filenames explicitly) — generated migrations are not ours to style.

## Apps

### `apps.core`

Abstract building blocks only — **no concrete models, so no migrations**. `TimeStampedModel` (`created_at`/`updated_at`) and `SoftDeleteModel` (`deleted_at`) live here, along with `SoftDeleteQuerySet`/`SoftDeleteManager`.

Soft-delete contract, worth knowing before touching it:

- `Model.objects` hides soft-deleted rows; `Model.all_objects` sees everything and is wired as `Meta.base_manager_name`, so related-object traversal still resolves a deleted target (Django warns against a filtered `_base_manager`).
- `delete()` soft deletes and is idempotent (it never overwrites an existing stamp); `delete(hard=True)` / `hard_delete()` are the escape hatches. Both exist on the model *and* the queryset.
- Subclasses extend `soft_delete_values()` / `restore_values()` to flip extra columns in the same `UPDATE` — that is how `UserQuerySet` also toggles `is_active`.
- Soft deletion does **not** cascade: Django's deletion collector emits raw SQL and bypasses these overrides.

### `apps.accounts`

Holds the swappable user model (`AUTH_USER_MODEL = "accounts.User"`).

- `User(AbstractBaseUser, PermissionsMixin, TimeStampedModel, SoftDeleteModel)` — UUID primary key, `USERNAME_FIELD = "email"`, `REQUIRED_FIELDS = []`, **no username field**.
- The PK default is `uuid.uuid7` (Python 3.14) — time-ordered, so inserts stay at the right edge of the B-tree instead of scattering the way `uuid4` does.
- Emails are folded to lower case *entirely* (not just the domain, as `BaseUserManager` does) in both `clean()` and `save()`. That invariant is what makes the plain `unique=True` behave case-insensitively, and a `CHECK (email = LOWER(email))` constraint enforces it against writes that bypass `save()` (e.g. `queryset.update()`). `get_by_natural_key()` normalises too, so login is case-insensitive.
- A soft-deleted account keeps its email reserved — the row still satisfies the unique index. The forms detect this and return a distinct "restore that account instead" error rather than a generic duplicate message.
- `UserManager.create_user`/`create_superuser` validate before insert and raise `ValidationError` for duplicates (which, unlike `IntegrityError`, leaves the caller's transaction usable). Uniqueness is checked against `all_objects` because `Model.validate_unique()` consults the *default* manager and would look straight past a soft-deleted holder.
- `forms.py` defines `UserCreationForm`/`UserChangeForm` from scratch rather than subclassing `django.contrib.auth.forms`; the admin subclasses `auth.admin.UserAdmin` purely for its password-change view and permission plumbing.
- The admin changelist reads through `all_objects` so staff can see and restore deleted accounts; `DeletionStatusFilter` narrows it back to active users by default, and `delete_model`/`delete_queryset` route the built-in delete controls through soft deletion.

### `apps.tenants`

The tenant catalogue. `SHARED_APPS` only, so `tenants_client`/`tenants_domain` exist in the public schema and nowhere else.

- `Client(TenantMixin, TimeStampedModel)` — `name`, `slug`, `is_active`, plus `schema_name` from the mixin. `BigAutoField` pk, not `uuid7`: that decision was about index locality under load, which one row per customer does not have.
- `schema_name` defaults to the slug with hyphens folded to underscores (`clean_fields()` fills it before field validation runs, so a blank value never trips "required"). It is restricted to bare lower-case SQL identifiers by a validator *and* a `CHECK` constraint — django-tenants only rejects `pg_*`, but the value is interpolated straight into `CREATE SCHEMA` / `SET search_path`.
- `auto_create_schema=True` (saving a new row migrates the new schema), `auto_drop_schema=False`. `Client.delete()` is re-declared with a typed `force_drop` and drops the schema only when asked; the admin's delete never does.
- `Domain(DomainMixin, TimeStampedModel)` — hostnames are folded to lower case in `clean()`/`save()` and held there by a `CHECK` constraint, because the middleware looks them up with an exact match on the `Host` header.
- Commands: `tenant_create`, `tenant_domain_add`, `tenant_list`, `tenant_delete`. Named distinctly from django-tenants' own `create_tenant`/`delete_tenant` (which are interactive) rather than shadowing them.
- Admin: `PublicSchemaOnlyAdmin` denies every permission outside the public schema, so a tenant administrator cannot reach the catalogue at all.

**Never import `django.contrib.auth.models.User`.** Reference the user model as `settings.AUTH_USER_MODEL` in ForeignKeys and `get_user_model()` at runtime; a direct `from apps.accounts.models import User` is acceptable only under `if TYPE_CHECKING:`.
