# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

EduRemus-Django is a multi-tenant institutional management SaaS suite, built on Django 5.2. The project is in early scaffolding: no Django apps have been added to `INSTALLED_APPS` yet beyond Django's built-ins, and `templates/`/`docs/` are currently empty.

## Tooling & commands

Dependencies are managed with **uv** (`uv.lock` present, requires Python >=3.14).

```bash
uv sync                        # install runtime + dev dependencies
uv run manage.py runserver     # run the dev server
uv run manage.py migrate       # apply migrations
uv run manage.py makemigrations
uv run manage.py createsuperuser
uv run pytest                  # run tests (pytest-django is configured as a dev dependency)
uv run ruff check .            # lint
uv run ruff format .           # format
uv run mypy .                  # type check
```

`manage.py` defaults `DJANGO_SETTINGS_MODULE` to `config.settings.local`, so local commands don't need the env var set explicitly.

## Configuration

- Settings live under `config/settings/` and are split by environment: `base.py` holds shared settings, `local.py` imports `from .base import *` and layers in `DEBUG=True` and dev `ALLOWED_HOSTS`. There is no production settings module yet — add one alongside `local.py` following the same import pattern when needed.
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
- Template resolution: `TEMPLATES[0]['DIRS']` points at the top-level `templates/` directory in addition to each app's own `templates/` dir (`APP_DIRS=True`).
- Dev-only dependencies (`django-debug-toolbar`, `django-extensions`, `mypy`, `pre-commit`, `pytest-django`, `ruff`) are declared in the `[dependency-groups.dev]` section of `pyproject.toml` but are not yet wired into `INSTALLED_APPS`/`MIDDLEWARE` — do that when actually using them. `psycopg2-binary` is a runtime dependency (Postgres driver), not a dev one.
