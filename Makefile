override SHELL := /bin/bash

COMPOSE_PROD := docker compose -f docker-compose.prod.yml

.PHONY: all
all: clean dev

# Development: local, build from source, hot-reload (UI :3000, API :8000)

.PHONY: dev
dev:
	@echo 'Starting the dev stack with hot-reload (UI :3000, API :8000)...'
	docker compose up -d --build

.PHONY: down
down:
	@echo 'Stopping the dev stack (vault volume is kept)...'
	docker compose down

.PHONY: clean
clean:
	@echo 'Removing the dev stack and its vault volume...'
	-docker compose down --volumes --remove-orphans --rmi local
	@echo 'Removing cache files...'
	-find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete

# Production: the real vault, run from prebuilt GHCR images (needs a sibling .env)

.PHONY: prod-up
prod-up:
	@echo 'Pulling and starting the production stack from GHCR images...'
	$(COMPOSE_PROD) up -d

.PHONY: prod-snapshot
prod-snapshot:
	@echo 'Writing a consistent snapshot of the real vault into its volume...'
	$(COMPOSE_PROD) exec backend ciphermoth-admin snapshot

.PHONY: prod-down
prod-down:
	@echo 'Stopping the production stack (vault volume is kept)...'
	$(COMPOSE_PROD) down

.PHONY: clean-prod
clean-prod:
	@echo 'WARNING: this DESTROYS the production vault volume -> your real vault.'
	@echo 'There is no password recovery. This cannot be undone.'
	@read -r -p 'Type "destroy" to confirm: ' ans; \
	if [ "$$ans" = "destroy" ]; then \
		$(COMPOSE_PROD) down --volumes --remove-orphans; \
		echo 'Production stack and volume removed.'; \
	else \
		echo 'Aborted. Nothing was removed.'; \
	fi

# Release: bump versions, stamp the changelog, tag, push, and publish a GitHub
# release (which triggers the signed image build). Usage: make release VERSION=1.1.0
.PHONY: release release-dry
release:
	@test -n "$(VERSION)" || { echo 'usage: make release VERSION=X.Y.Z'; exit 1; }
	@scripts/release.sh "$(VERSION)"

release-dry:
	@test -n "$(VERSION)" || { echo 'usage: make release-dry VERSION=X.Y.Z'; exit 1; }
	@scripts/release.sh "$(VERSION)" --dry-run

.PHONY: lint
lint:
	cd backend && uv run ruff check . ../docker/smoke
	cd frontend && npm run lint
	cd extension && npm run lint

.PHONY: typecheck
typecheck:
	cd backend && uv run ty check . ../docker/smoke

.PHONY: format
format:
	cd backend && uv run ruff format . ../docker/smoke
	cd frontend && npm run format
	cd extension && npm run format

# Tests use a throwaway SQLite vault in a temporary folder; no services needed.
.PHONY: test
test:
	cd backend && uv run pytest
	cd frontend && npm test
	node --test docker/frontend/runtime-config.test.mjs
	node --test scripts/npm_audit.test.mjs
	cd extension && npm test

# Builds the frontend image and checks its Content-Security-Policy in Chromium.
.PHONY: test-browser
test-browser:
	docker build -f docker/frontend/Dockerfile --build-arg VITE_API_URL=__CIPHERMOTH_API_URL__ -t ciphermoth-frontend:browser-test .
	cd docker/frontend/browser && npm ci && npx playwright install chromium && npm test

# The browser extension in Playwright Chromium against a live backend: user
# flows and the attack lab (extension/tests). Needs uv and Node only.
.PHONY: test-extension
test-extension:
	cd extension && npm ci && npx playwright install chromium && npm run test:e2e

# Fuzzing with many more Hypothesis examples, fault injection and scale tests.
.PHONY: test-stress
test-stress:
	cd backend && HYPOTHESIS_PROFILE=stress uv run pytest -m "stress or not stress"

.PHONY: check
check:
	cd backend && uv run ruff check . ../docker/smoke && uv run ruff format --check . ../docker/smoke && uv run ty check . ../docker/smoke
	cd frontend && npm run lint && npm run format:check
	cd extension && npm run typecheck && npm run lint && npm run format:check

# Desktop uses a private Python process, never the Docker/server installation.
.PHONY: desktop-setup desktop-dev desktop-build desktop-test desktop-check
desktop-setup:
	python3 desktop/dev_setup.py
	cd frontend && npm ci
	cd desktop && npm ci

desktop-dev: desktop-setup
	cd desktop && npm run tauri dev -- --config tauri.dev.json

desktop-build:
	python3 desktop/core/build_core.py --python 3.13.15
	cd frontend && npm ci
	cd desktop && npm ci && npm run tauri build -- --bundles app

desktop-test:
	desktop/core/build/venv/bin/python -m pytest desktop/core/tests
	cd desktop/src-tauri && cargo test --workspace

desktop-check:
	cd desktop/src-tauri && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
	cd backend && uv run ruff check ../desktop --exclude build --exclude dist --exclude target
