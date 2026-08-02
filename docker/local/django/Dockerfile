# syntax=docker/dockerfile:1.9
#
# EduRemus-Django — local development image.
#
# Two stages: `builder` resolves the locked dependency set with uv into a
# self-contained virtualenv, `runtime` ships only that virtualenv plus the
# application. uv, its cache and any build tooling never reach the final image.

ARG PYTHON_VERSION=3.14.0
ARG DEBIAN_RELEASE=trixie
ARG UV_VERSION=0.12.1


# -----------------------------------------------------------------------------
# uv binary (distroless image, used purely as a file source)
# It's a good practice to include tge uv version to avoid any
# change break in the flow.
# -----------------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv


# -----------------------------------------------------------------------------
# Stage 1 — builder
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS builder

COPY --from=uv /uv /usr/local/bin/uv

# UV_LINK_MODE=copy       : hardlinks don't survive the cache-mount boundary.
# UV_COMPILE_BYTECODE=1   : pay the .pyc cost once at build time, not on boot.
# UV_NO_MANAGED_PYTHON=1  : disable the use of any uv-managed Python versions, 
#                           forcing the tool to rely exclusively on pre-installed 
#                           system or user-managed Python interpreters
# UV_PYTHON_DOWNLOADS=never: use the interpreter this image already ships.
# UV_PROJECT_ENVIRONMENT  : live outside /app so a source bind mount in Compose
#                           cannot shadow the environment.
ENV PYTHONDONTWRITEBYTECODE=0 \  
    PYTHONUNBUFFERED=1 \
    UV_NO_MANAGED_PYTHON=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_CACHE_DIR=/opt/uv-cache

# Which dependency groups end up in the image. Local dev ships the dev group;
# a production build would pass `--build-arg UV_DEPENDENCY_GROUPS=--no-dev`.
ARG UV_DEPENDENCY_GROUPS="--group dev"

# Install System Dependencies with additional build tools

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev

WORKDIR /app

# Only the lockfile and manifest participate in this layer, so dependencies are
# re-resolved solely when they actually change. Both are bind-mounted rather
# than copied — they are build inputs, not image content. `--locked` fails the
# build if uv.lock has drifted from pyproject.toml.
RUN --mount=type=cache,target=/opt/uv-cache,sharing=locked \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project ${UV_DEPENDENCY_GROUPS}


# -----------------------------------------------------------------------------
# Stage 2 — runtime
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS runtime

ARG DJANGO_UID=1000
ARG DJANGO_GID=1000

# PYTHONDONTWRITEBYTECODE keeps __pycache__ out of the bind-mounted source tree
# (bytecode for the dependencies was already compiled in the builder stage).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=config.settings.local


RUN apt-get clean -y && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends \
	# OS dependencies, e.g. bash, db clients, etc.
    bash git bash-completion nano ssh && \
    apt-get autoremove -y && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Unprivileged runtime account. psycopg2-binary vendors libpq, so no additional
# system packages are required.
RUN groupadd --gid ${DJANGO_GID} django \
    && useradd --uid ${DJANGO_UID} --gid ${DJANGO_GID} --create-home --shell /bin/bash django

# The virtualenv stays root-owned: the application must never be able to
# rewrite its own dependencies. `--link` keeps this layer reusable when the
# base image is rebased.
COPY --link --from=builder /opt/venv /opt/venv

# --chmod=0755 sets the executable bit regardless of the host filesystem, which
# Windows checkouts do not preserve.
COPY --chmod=0755 ./docker/local/django/entrypoint.sh /usr/local/bin/entrypoint
COPY --chmod=0755 ./docker/local/django/start.sh      /usr/local/bin/start

WORKDIR /app

# Last layer: application source changes most often. In Compose this is
# overlaid by a bind mount, but baking it in keeps the image runnable alone.
COPY --chown=django:django . /app

USER django

EXPOSE 8000

# will remove this health-check in future
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/admin/login/', timeout=4)"]

ENTRYPOINT ["entrypoint"]
CMD ["start"]
