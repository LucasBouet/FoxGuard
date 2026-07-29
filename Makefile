.DEFAULT_GOAL := help
BACKEND := backend
AGENT := agent

TEST_DB ?= postgresql+psycopg://foxguard:foxguard@localhost:5433/foxguard_test

# End-to-end API tests get their own database so they never touch dev data.
PG_ADMIN_URL ?= postgresql://foxguard:foxguard@localhost:5432
API_TEST_DBNAME ?= foxguard_apitest
API_TEST_DB ?= postgresql+psycopg://foxguard:foxguard@localhost:5432/$(API_TEST_DBNAME)

# The portal and the enrollment endpoint identify their caller by source
# address, so testing them for real means *sending from* a peer's tunnel IP.
# Allocating the test pool inside 127.0.0.0/8 makes that possible without a
# tunnel: every address in the range is already local, so the client can bind
# to one. A /16 keeps the pool from running out as tests accumulate peers.
API_TEST_POOL ?= 127.30.0.0/16

# The OIDC tests stand up a throwaway identity provider (real RSA keys, real
# discovery document, real signed tokens) inside the pytest process. The API
# has to be told where it lives before it starts, hence a fixed port.
FAKE_IDP_PORT ?= 8766

# Session expiry is tested against the real endpoint rather than a clock stub,
# so the default lifetime is one second and the tests drive
# POST /api/v1/sessions/sweep by hand. The background sweeper's interval is
# pushed out of the way so it cannot fire mid-test and make results depend on
# timing; groups with an explicit session_lifetime_seconds still override the
# one-second default, which is what proves the override works.

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: dev-up
dev-up: ## Start PostgreSQL (dev + test)
	docker compose -f docker-compose.dev.yml up -d

.PHONY: dev-down
dev-down: ## Stop the development stack
	docker compose -f docker-compose.dev.yml down

.PHONY: install
install: ## Install backend + agent in editable mode
	cd $(BACKEND) && pip install -e '.[dev]'
	cd $(AGENT) && pip install -e '.[dev]'

.PHONY: migrate
migrate: ## Apply database migrations
	cd $(BACKEND) && alembic upgrade head

.PHONY: run
run: ## Run the API with hot reload
	# foxguard-serve, not plain uvicorn: it disables proxy headers, without which
	# the portal's source-address identity can be forged. See foxguard/server.py.
	cd $(BACKEND) && foxguard-serve --reload --host 127.0.0.1 --port 8000

.PHONY: test
test: ## Run every test that needs no database
	cd $(BACKEND) && pytest
	cd $(AGENT) && pytest

.PHONY: test-all
test-all: ## Run every test, including the PostgreSQL-backed ones
	cd $(BACKEND) && FOXGUARD_TEST_DATABASE_URL='$(TEST_DB)' pytest
	cd $(AGENT) && pytest

.PHONY: api-test-db
api-test-db: ## Create the database used by `make test-api` (idempotent)
	@psql -w "$(PG_ADMIN_URL)/postgres" -tAc \
	  "SELECT 1 FROM pg_database WHERE datname='$(API_TEST_DBNAME)'" | grep -q 1 || \
	  psql -w "$(PG_ADMIN_URL)/postgres" -c 'CREATE DATABASE $(API_TEST_DBNAME)'

.PHONY: test-api
test-api: api-test-db ## Run end-to-end API tests against a throwaway server
	@cd $(BACKEND) && FOXGUARD_DEV_MODE=true FOXGUARD_DATABASE_URL='$(API_TEST_DB)' \
	  alembic upgrade head >/dev/null
	@cd $(BACKEND) && \
	  FOXGUARD_DEV_MODE=true \
	  FOXGUARD_DATABASE_URL='$(API_TEST_DB)' \
	  FOXGUARD_WAN_INTERFACE=eth0 \
	  FOXGUARD_INTERNAL_CIDRS='10.0.0.0/8,172.16.0.0/12,192.168.0.0/16' \
	  FOXGUARD_WG_POOL_V4='$(API_TEST_POOL)' \
	  FOXGUARD_PORTAL_LOGIN_MAX_ATTEMPTS=5 \
	  FOXGUARD_ENROLL_MAX_ATTEMPTS=5 \
	  FOXGUARD_DEFAULT_SESSION_LIFETIME_SECONDS=1 \
	  FOXGUARD_SESSION_SWEEP_INTERVAL_SECONDS=3600 \
	  FOXGUARD_ADMIN_API_TOKEN=dev \
	  FOXGUARD_ADMIN_LOGIN_MAX_ATTEMPTS=50 \
	  FOXGUARD_OIDC_ISSUER='http://127.0.0.1:$(FAKE_IDP_PORT)' \
	  FOXGUARD_OIDC_CLIENT_ID=foxguard-test \
	  FOXGUARD_OIDC_CLIENT_SECRET=test-client-secret \
	  FOXGUARD_OIDC_REDIRECT_URL='http://127.0.0.1:8765/api/v1/portal/oidc/callback' \
	  sh -c 'foxguard-serve --host 127.0.0.1 --port 8765 & \
	    server=$$!; \
	    trap "kill $$server 2>/dev/null" EXIT; \
	    for i in $$(seq 1 40); do curl -sf http://127.0.0.1:8765/healthz >/dev/null 2>&1 && break; sleep 0.5; done; \
	    FOXGUARD_TEST_API_URL=http://127.0.0.1:8765 pytest tests/test_api_integration.py'

.PHONY: golden
golden: ## Regenerate the nftables golden baseline (review the diff!)
	cd $(BACKEND) && FOXGUARD_UPDATE_GOLDEN=1 pytest tests/test_nft_generator.py -k golden

.PHONY: lint
lint: ## Lint both Python packages
	cd $(BACKEND) && ruff check .
	cd $(AGENT) && ruff check .

.PHONY: ruleset
ruleset: ## Print the ruleset the current database state implies
	cd $(BACKEND) && python -c "from foxguard.config import get_settings; from foxguard.db import SessionLocal; from foxguard.services import ruleset; print(ruleset.render(SessionLocal(), get_settings()))"
