COMPOSE_FILE := examples/dependency-track/docker-compose.yml
DT_BACKEND_URL ?= http://localhost:8080
GCP_POC_DIR := infra/gcp/poc
DT_LAB_DIR ?= var/dt-lab
DT_LAB_MANIFEST := examples/sboms/scenarios.yaml
PYTHON ?= python3.12

.PHONY: dt-up dt-down dt-logs dt-ps dt-openapi-check dt-lab-validate dt-lab-openapi dt-lab-run dt-bom-upload dt-demo-upload dt-demo-update-upload infra-gcp-poc-fmt-check infra-gcp-poc-validate test lint

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
	PYTHONPATH=src $(PYTHON) -m sbom_ops.dt_lab_cli validate-manifest --manifest "$(DT_LAB_MANIFEST)"

dt-lab-openapi:
	mkdir -p "$(DT_LAB_DIR)"
	./scripts/check_dt_openapi.sh "$(DT_BACKEND_URL)" "$(DT_LAB_DIR)/openapi.json"
	PYTHONPATH=src $(PYTHON) -m sbom_ops.dt_lab_cli openapi-inventory "$(DT_LAB_DIR)/openapi.json" --output "$(DT_LAB_DIR)/openapi-inventory.json"

dt-lab-run:
	PYTHONPATH=src $(PYTHON) -m sbom_ops.dt_lab_cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json"

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
