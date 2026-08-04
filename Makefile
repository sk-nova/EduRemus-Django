# EduRemus-Django developer entry points.
#
# Host-side targets run through `uv`; the docker-* targets drive the local
# Compose stack. Run `make` (or `make help`) for the catalogue.

COMPOSE := docker compose -f docker-compose.local.yml
MANAGE  := uv run manage.py

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------

.PHONY: install
install: ## Install runtime + dev dependencies
	uv sync --all-groups

.PHONY: lock
lock: ## Refresh uv.lock after editing pyproject.toml
	uv lock

# ---------------------------------------------------------------------
# Django (outside Docker container environment)
# ---------------------------------------------------------------------

.PHONY: check
check: ## Run Django system checks
	$(MANAGE) check

.PHONY: check-deploy
check-deploy: ## Run Django's deployment checklist
	$(MANAGE) check --deploy

.PHONY: missing-migrations
missing-migrations: ## Fail if models have drifted from migrations
	$(MANAGE) makemigrations --check --dry-run

# ---------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------

.PHONY: coverage
coverage: ## Run the test suite with a coverage report
	uv run pytest --cov --cov-report=term-missing --cov-report=html

.PHONY: lint
lint: ## Lint with ruff
	uv run ruff check .

.PHONY: format
format: ## Format with ruff
	uv run ruff format .
	uv run ruff check --fix .

.PHONY: typecheck
typecheck: ## Type check with mypy
	uv run mypy .

.PHONY: qa
qa: lint typecheck test ## Lint, type check and test

.PHONY: hooks
hooks: ## Install pre-commit hooks
	uv run pre-commit install

.PHONY: precommit
precommit: ## Run every pre-commit hook against the whole tree
	uv run pre-commit run --all-files

# ---------------------------------------------------------------------
# Docker (local stack)
# ---------------------------------------------------------------------

.PHONY: build
build: ## Build the local images
	$(COMPOSE) --progress plain build

.PHONY: build-nc
build-nc: ## Build local image without using cached layers
	$(COMPOSE) --progress plain build --no-cache

.PHONY: local-up
local-up: ## Start the local stack
	$(COMPOSE) up -d --remove-orphans

.PHONY: local-down
local-down: ## Stop the local stack (keeps the database volume)
	$(COMPOSE) down

.PHONY: local-down-v
local-down-v: ## Stop the local stack and drop the database volume
	$(COMPOSE) down -v

.PHONY: docker-db
docker-db: ## Start only Postgres (enough for host-side pytest)
	$(COMPOSE) up -d db

.PHONY: logs
logs: ## Tail the django service logs
	$(COMPOSE) logs -f django

.PHONY: bash
bash: ## Open a shell inside the django container
	$(COMPOSE) exec django bash

.PHONY: shell-plus
shell-plus: ## Open a shell_plus within Django context
	$(COMPOSE) exec django bash python manage.py shell_plus

.PHONY: migrate
migrate: ## Apply migrations inside the django container
	$(COMPOSE) exec django python manage.py migrate

.PHONY: superuser
superuser: ## Create a superuser inside the django container
	$(COMPOSE) exec django python manage.py createsuperuser

.PHONY: test
test: ## Run the test suite inside the django container
	$(COMPOSE) exec -e TEST_POSTGRES_HOST=db django pytest

.PHONY: test-fresh
test-fresh:  ## Run the test suite against a rebuilt test database
	$(COMPOSE) exec -e TEST_POSTGRES_HOST=db django pytest --create-db

# ---------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------

.PHONY: clean
clean: ## Remove caches and build artefacts
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -not -path "./.venv/*" -exec rm -rf {} +
