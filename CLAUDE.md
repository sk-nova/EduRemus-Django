# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

EduRemus-Django is a multi-tenant institutional management SaaS suite, built on Django LTS version 5.2.x. Reusable Django core apps live under `apps/`; `templates/`/`docs/` are currently empty.

## Tooling & commands

Dependencies are managed with **uv** (`uv.lock` present, requires Python >=3.14). A `Makefile` wraps the common flows — run `make` for the catalogue; the raw equivalents are:

```bash
uv sync --all-groups           # install runtime + dev dependencies
uv run manage.py runserver     # run the dev server
uv run manage.py migrate       # apply migrations
uv run manage.py makemigrations # create new migrations whenever there is a Model field added/changes.
uv run manage.py createsuperuser
uv run pytest                  # run tests
uv run pytest --cov            # ...with a coverage report
uv run ruff check .            # lint
uv run ruff format .           # code format compliant to PEP8
uv run mypy .                  # type check compliant to PEP8
```

`manage.py` defaults `DJANGO_SETTINGS_MODULE` to `config.settings.local`, so local commands don't need the env var set explicitly.

## Configuration

- Settings live under `config/settings/` and are split by environment: `base.py` holds shared settings, `local.py` imports `from .base import *` and layers in `DEBUG=True` and dev `ALLOWED_HOSTS`, and `test.py` is what pytest uses. There is no production settings module yet — add one alongside `local.py` following the same import pattern when needed.
- `config/settings/test.py` resolves `DJANGO_SECRET_KEY` and exports a `DATABASE_URL` *before* importing `base`, so the suite runs with no `.env` present. It assembles the connection string from the `POSTGRES_*` vars against `127.0.0.1` rather than reusing `DATABASE_URL`, which legitimately points at the container-internal `db` host. Override with `TEST_DATABASE_URL`, or `TEST_POSTGRES_HOST=db` when running pytest inside the stack (`make docker-test` does this).
- Environment variables are read via `python-decouple` (`config(...)`) and loaded from a `.env` file at the project root (see `.env.example` for required keys: `DJANGO_SECRET_KEY`, `DATABASE_URL`). `DATABASE_URL` is parsed with `dj-database-url`.
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

## Architecture notes

- `config/` is the Django project package (settings, root `urls.py`, `wsgi.py`/`asgi.py`) — analogous to the default `django-admin startproject` layout but with settings split into a package.
- `INSTALLED_APPS` is composed in `base.py` from `DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS`; add new project apps to `LOCAL_APPS` by their `AppConfig` path.
- Template resolution: `TEMPLATES[0]['DIRS']` points at the top-level `templates/` directory in addition to each app's own `templates/` dir (`APP_DIRS=True`).
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

**Never import `django.contrib.auth.models.User`.** Reference the user model as `settings.AUTH_USER_MODEL` in ForeignKeys and `get_user_model()` at runtime; a direct `from apps.accounts.models import User` is acceptable only under `if TYPE_CHECKING:`.
