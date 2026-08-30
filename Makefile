COMPOSE_FILE := examples/dependency-track/docker-compose.yml
DT_BACKEND_URL ?= http://localhost:8080
GCP_POC_DIR := infra/gcp/poc
DT_LAB_DIR ?= var/dt-lab
DT_LAB_ROOT := lab/dependency_track
DT_LAB_PYTHONPATH := src:$(DT_LAB_ROOT)/src
DT_LAB_MANIFEST := $(DT_LAB_ROOT)/scenarios/scenarios.yaml
DT_LAB_CORPUS_CATALOG := $(DT_LAB_ROOT)/corpus/corpus.yaml
DT_LAB_CORPUS_DIR := $(DT_LAB_DIR)/corpus
DT_LAB_EXECUTE_FLAG = $(if $(filter 1 true yes,$(EXECUTE)),--execute,)
DT_LAB_PROCESSING_TIMEOUT ?= 600
PYTHON ?= python3.12

.PHONY: dt-up dt-down dt-logs dt-ps dt-openapi-check dt-lab-validate dt-lab-openapi dt-lab-run dt-lab-triage-analysis dt-lab-corpus-validate dt-lab-corpus-run dt-lab-cleanup dt-lab-test dt-bom-upload dt-demo-upload dt-demo-update-upload infra-gcp-poc-fmt-check infra-gcp-poc-validate test lint

dt-up:
	docker compose -f $(COMPOSE_FILE) up -d

dt-down:
	docker compose -f $(COMPOSE_FILE) down

dt-logs:
	docker compose -f $(COMPOSE_FILE) logs -f

dt-ps:
	docker compose -f $(COMPOSE_FILE) ps

dt-openapi-check:
	./scripts/check_dt_openapi.sh "$(DT_BACKEND_URL)"

dt-lab-validate:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli validate-manifest --manifest "$(DT_LAB_MANIFEST)"

dt-lab-openapi:
	mkdir -p "$(DT_LAB_DIR)"
	./scripts/check_dt_openapi.sh "$(DT_BACKEND_URL)" "$(DT_LAB_DIR)/openapi.json"
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli openapi-inventory "$(DT_LAB_DIR)/openapi.json" --output "$(DT_LAB_DIR)/openapi-inventory.json"

dt-lab-run:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json"

dt-lab-triage-analysis:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --scenario triage-analysis-states --allow-analysis-mutation

dt-lab-corpus-validate:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli validate-corpus --catalog "$(DT_LAB_CORPUS_CATALOG)" --artifact-dir "$(DT_LAB_CORPUS_DIR)" --require-local

dt-lab-corpus-run:
	$(if $(strip $(CORPUS_ID)),,$(error CORPUS_ID is required, for example: make dt-lab-corpus-run CORPUS_ID=go-otel-obi-0-12-2))
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-corpus --catalog "$(DT_LAB_CORPUS_CATALOG)" --artifact-dir "$(DT_LAB_CORPUS_DIR)" --artifact "$(CORPUS_ID)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --processing-timeout "$(DT_LAB_PROCESSING_TIMEOUT)"

dt-lab-cleanup:
	$(if $(strip $(RUN_ID)),,$(error RUN_ID is required, for example: make dt-lab-cleanup RUN_ID=<uuid>))
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli cleanup-run --output-dir "$(DT_LAB_DIR)/runs" --run-id "$(RUN_ID)" $(DT_LAB_EXECUTE_FLAG)

dt-lab-test:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m pytest -q $(DT_LAB_ROOT)/tests

dt-bom-upload:
	./scripts/upload_bom.sh

dt-demo-upload:
	SBOM_OPS_DT_PROJECT_NAME=sbom-ops-vulnerable-demo \
	SBOM_OPS_DT_PROJECT_VERSION=0.1.0 \
	./scripts/upload_bom.sh examples/sboms/vulnerable-demo.cdx.json

dt-demo-update-upload:
	SBOM_OPS_DT_PROJECT_NAME=sbom-ops-vulnerable-demo \
	SBOM_OPS_DT_PROJECT_VERSION=0.1.0 \
	./scripts/upload_bom.sh examples/sboms/vulnerable-demo-updated.cdx.json

infra-gcp-poc-fmt-check:
	terraform -chdir=$(GCP_POC_DIR) fmt -check

infra-gcp-poc-validate:
	terraform -chdir=$(GCP_POC_DIR) validate

test:
	pytest

lint:
	ruff check .
