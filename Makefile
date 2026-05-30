.PHONY: help install install-dev lint format test test-unit test-integration \
        scan clean build docker-build docker-run coverage

PYTHON     ?= python3
PIP        ?= pip
IMAGE      ?= nginx:latest
FAIL_ON    ?= CRITICAL
REPORT_DIR ?= ./reports

# Default target
.DEFAULT_GOAL := help

# Colour codes
BOLD   := $(shell tput bold 2>/dev/null || echo "")
RESET  := $(shell tput sgr0 2>/dev/null || echo "")
GREEN  := $(shell tput setaf 2 2>/dev/null || echo "")
YELLOW := $(shell tput setaf 3 2>/dev/null || echo "")
CYAN   := $(shell tput setaf 6 2>/dev/null || echo "")

##@ General

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\n$(BOLD)container-security-scanner$(RESET)\n\nUsage:\n  make $(CYAN)<target>$(RESET)\n"} \
	/^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(CYAN)%-20s$(RESET) %s\n", $$1, $$2 } \
	/^##@/ { printf "\n$(BOLD)%s$(RESET)\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Development

install: ## Install the package in editable mode (production deps only)
	$(PIP) install -e .

install-dev: ## Install with all development dependencies
	$(PIP) install -e ".[dev]"
	pre-commit install

##@ Code Quality

lint: ## Run ruff linter and mypy type checker
	@echo "$(YELLOW)Running ruff...$(RESET)"
	ruff check scanner/ tests/
	@echo "$(YELLOW)Running mypy...$(RESET)"
	mypy scanner/ --ignore-missing-imports
	@echo "$(GREEN)Lint passed.$(RESET)"

format: ## Auto-format code with ruff
	ruff format scanner/ tests/
	ruff check --fix scanner/ tests/

##@ Testing

test: ## Run all tests (unit + integration markers skipped by default)
	pytest tests/ -v --tb=short

test-unit: ## Run only unit tests (no external tools required)
	pytest tests/ -v --tb=short -m "not integration"

test-integration: ## Run integration tests (requires Trivy installed)
	pytest tests/ -v --tb=short -m integration

coverage: ## Run tests with coverage report
	pytest tests/ \
	  --cov=scanner \
	  --cov-report=term-missing \
	  --cov-report=html:htmlcov \
	  --cov-fail-under=80
	@echo "$(CYAN)HTML report: htmlcov/index.html$(RESET)"

##@ Scanning

scan: ## Scan IMAGE against policy (IMAGE=nginx:latest FAIL_ON=CRITICAL)
	@echo "$(YELLOW)Scanning $(IMAGE) (fail-on: $(FAIL_ON))...$(RESET)"
	@mkdir -p $(REPORT_DIR)
	$(PYTHON) -m scanner.main scan $(IMAGE) \
	  --fail-on $(FAIL_ON) \
	  --output $(REPORT_DIR) \
	  --format json,sarif

scan-demo: ## Run demo scan against nginx:latest (always exits 0 for demo purposes)
	@mkdir -p $(REPORT_DIR)
	$(PYTHON) -m scanner.main scan nginx:latest \
	  --fail-on NONE \
	  --output $(REPORT_DIR) \
	  --format json,html,sarif

scan-strict: ## Scan IMAGE with strict policy — fail on HIGH+
	@mkdir -p $(REPORT_DIR)
	$(PYTHON) -m scanner.main scan $(IMAGE) \
	  --fail-on CRITICAL,HIGH \
	  --ignore-unfixed \
	  --output $(REPORT_DIR) \
	  --format json,sarif

##@ Docker

docker-build: ## Build the Docker image
	docker build -t container-security-scanner:dev .

docker-run: ## Run the scanner via Docker against IMAGE
	docker run --rm \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  -v $(PWD)/$(REPORT_DIR):/reports \
	  container-security-scanner:dev \
	  scan $(IMAGE) --output /reports

##@ Cleanup

clean: ## Remove build artifacts, reports, and cache
	rm -rf build/ dist/ *.egg-info .mypy_cache .ruff_cache htmlcov .coverage
	rm -rf $(REPORT_DIR)/*.json $(REPORT_DIR)/*.html $(REPORT_DIR)/*.sarif
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "$(GREEN)Clean.$(RESET)"
