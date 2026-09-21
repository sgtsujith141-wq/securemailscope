# SecureMailScope developer tasks.
#
# Everything here runs locally. No target contacts a network service other
# than the package index during `make install`.

PYTHON  ?= python3.12
VENV    ?= .venv
BIN     := $(VENV)/bin
PY      := $(BIN)/python
PIP     := $(BIN)/pip

.DEFAULT_GOAL := help
.PHONY: help venv install fixtures test lint typecheck check demo clean secrets-check benchmark benchmark-all lock

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtual environment
	$(PYTHON) -m venv $(VENV)

install: venv ## Install the package and development dependencies
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

fixtures: ## Regenerate synthetic captures and expectation manifests
	$(PY) scripts/generate_fixtures.py

test: ## Run the full test suite
	$(PY) -m pytest

test-unit: ## Run everything except the CLI integration tests
	$(PY) -m pytest -m "not integration"

test-integration: ## Run only the CLI integration tests
	$(PY) -m pytest -m integration

lint: ## Check formatting and lint rules
	$(BIN)/ruff check src tests scripts

format: ## Apply safe lint fixes
	$(BIN)/ruff check --fix src tests scripts

typecheck: ## Run mypy
	$(BIN)/mypy

check: lint typecheck test ## Lint, type-check and test

demo: fixtures ## Analyse a generated fixture and print the report path
	$(BIN)/securemailscope analyze tests/fixtures/generated/a_complete_connection.pcap \
	  --output out/demo-report.json

benchmark: ## Measure performance (small, medium, large) and judge the result
	$(BIN)/python scripts/run_benchmarks.py
	$(BIN)/python scripts/check_benchmarks.py

benchmark-all: ## Measure performance including the stress profile
	$(BIN)/python scripts/run_benchmarks.py --profile all
	$(BIN)/python scripts/check_benchmarks.py

lock: ## Regenerate requirements-lock.txt from the current environment
	@{ head -9 requirements-lock.txt; \
	   $(BIN)/pip list --format=freeze | grep -v "^securemailscope" | grep -v "^-e" | sort; \
	 } > requirements-lock.txt.new && mv requirements-lock.txt.new requirements-lock.txt
	@echo "requirements-lock.txt regenerated"

secrets-check: ## Refuse to proceed if capture data or secrets are staged
	@./scripts/check_staged.sh

clean: ## Remove caches, build output and generated captures
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info out
	rm -rf src/*.egg-info tests/fixtures/generated
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
