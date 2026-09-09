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
EXPLOIT_LAB_ROOT := lab/exploit_intelligence
EXPLOIT_LAB_PYTHONPATH := src:$(EXPLOIT_LAB_ROOT)/src
EXPLOIT_LAB_MANIFEST := $(EXPLOIT_LAB_ROOT)/scenarios/scenarios.yaml
EXPLOIT_LAB_DIR ?= var/exploit-intelligence-lab
VULS_DB_CLI ?= $(EXPLOIT_LAB_DIR)/tools/vuls2-nightly/bin/vuls
VULS_DB_PATH ?= $(EXPLOIT_LAB_DIR)/vuls-db/vuls.db
VULS_DB_SAMPLE_CVES ?=
VULNERABILITY_LOOKUP_BASE_URL ?= https://vulnerability.circl.lu
VULNERABILITY_LOOKUP_SAMPLE_CVES ?= 25
VULNERABILITY_LOOKUP_MAX_CVES ?= 25
VULNERABILITY_LOOKUP_RECORD_LIMIT ?= 1
VULNERABILITY_LOOKUP_MAX_RETRIES ?= 1
VULNERABILITY_LOOKUP_CHECKPOINT ?= $(EXPLOIT_LAB_DIR)/vulnerability-lookup-checkpoint.json
VULNERABILITY_LOOKUP_CHECKPOINT_MAX_AGE ?= 86400
VULNERABILITY_LOOKUP_CHECKPOINT_LOCK_TIMEOUT ?= 10
VULNERABILITY_LOOKUP_REQUEST_INTERVAL ?= 0.25
PYTHON ?= python3.12

.PHONY: dt-up dt-down dt-logs dt-ps dt-openapi-check dt-lab-validate dt-lab-openapi dt-lab-run dt-lab-parent-child dt-lab-routing-metadata dt-lab-triage-analysis dt-lab-triage-delegation dt-lab-triage-vex dt-lab-triage-vex-targeting dt-lab-invalid-cyclonedx dt-lab-json-xml-equivalence dt-lab-corpus-validate dt-lab-corpus-run dt-lab-cleanup dt-lab-test exploit-lab-validate exploit-lab-run exploit-lab-vuls-db-run exploit-lab-dt-sample exploit-lab-vulnerability-lookup-run exploit-lab-vulnerability-lookup-dt-sample exploit-lab-vulnerability-lookup-compare exploit-lab-evidence-review-queue exploit-lab-evidence-review-template exploit-lab-evidence-review-apply exploit-lab-evidence-review-agreement exploit-lab-evidence-adjudication-queue exploit-lab-evidence-adjudication-template exploit-lab-evidence-adjudication-apply exploit-lab-test dt-bom-upload dt-demo-upload dt-demo-update-upload infra-gcp-poc-fmt-check infra-gcp-poc-validate test lint

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

dt-lab-parent-child:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --scenario portfolio-parent-child

dt-lab-routing-metadata:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --scenario portfolio-tags-properties

dt-lab-triage-analysis:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --scenario triage-analysis-states --allow-analysis-mutation

dt-lab-triage-delegation:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --scenario triage-delegation-boundary --allow-analysis-mutation

dt-lab-triage-vex:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --scenario triage-vex-round-trip --allow-analysis-mutation

dt-lab-triage-vex-targeting:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --scenario triage-vex-targeting --allow-analysis-mutation

dt-lab-invalid-cyclonedx:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --scenario robustness-invalid-cyclonedx

dt-lab-json-xml-equivalence:
	PYTHONPATH=$(DT_LAB_PYTHONPATH) $(PYTHON) -m dt_lab.cli run-scenarios --manifest "$(DT_LAB_MANIFEST)" --output-dir "$(DT_LAB_DIR)/runs" --openapi-inventory "$(DT_LAB_DIR)/openapi-inventory.json" --scenario robustness-json-xml-equivalence

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

exploit-lab-validate:
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli validate-manifest --manifest "$(EXPLOIT_LAB_MANIFEST)"

exploit-lab-run:
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli run --manifest "$(EXPLOIT_LAB_MANIFEST)" --output-dir "$(EXPLOIT_LAB_DIR)/runs"

exploit-lab-vuls-db-run:
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli run-vuls-db --manifest "$(EXPLOIT_LAB_MANIFEST)" --binary "$(VULS_DB_CLI)" --db-path "$(VULS_DB_PATH)" --output-dir "$(EXPLOIT_LAB_DIR)/runs"

exploit-lab-dt-sample:
	$(if $(strip $(DT_FINDINGS)),,$(error DT_FINDINGS is required and may contain multiple findings.json paths))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli sample-dt-findings --manifest "$(EXPLOIT_LAB_MANIFEST)" --binary "$(VULS_DB_CLI)" --db-path "$(VULS_DB_PATH)" --output-dir "$(EXPLOIT_LAB_DIR)/runs" $(if $(strip $(VULS_DB_SAMPLE_CVES)),--sample-cves "$(VULS_DB_SAMPLE_CVES)",) $(foreach path,$(DT_FINDINGS),--findings "$(path)")

exploit-lab-vulnerability-lookup-run:
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli run-vulnerability-lookup --manifest "$(EXPLOIT_LAB_MANIFEST)" --base-url "$(VULNERABILITY_LOOKUP_BASE_URL)" --max-retries "$(VULNERABILITY_LOOKUP_MAX_RETRIES)" --record-limit-per-signal "$(VULNERABILITY_LOOKUP_RECORD_LIMIT)" --output-dir "$(EXPLOIT_LAB_DIR)/runs"

exploit-lab-vulnerability-lookup-dt-sample:
	$(if $(strip $(DT_FINDINGS)),,$(error DT_FINDINGS is required and may contain multiple findings.json paths))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli sample-dt-findings-vulnerability-lookup --manifest "$(EXPLOIT_LAB_MANIFEST)" --base-url "$(VULNERABILITY_LOOKUP_BASE_URL)" --max-retries "$(VULNERABILITY_LOOKUP_MAX_RETRIES)" --record-limit-per-signal "$(VULNERABILITY_LOOKUP_RECORD_LIMIT)" --sample-cves "$(VULNERABILITY_LOOKUP_SAMPLE_CVES)" --max-cves "$(VULNERABILITY_LOOKUP_MAX_CVES)" --checkpoint "$(VULNERABILITY_LOOKUP_CHECKPOINT)" --checkpoint-max-age-seconds "$(VULNERABILITY_LOOKUP_CHECKPOINT_MAX_AGE)" --checkpoint-lock-timeout-seconds "$(VULNERABILITY_LOOKUP_CHECKPOINT_LOCK_TIMEOUT)" --request-interval-seconds "$(VULNERABILITY_LOOKUP_REQUEST_INTERVAL)" --output-dir "$(EXPLOIT_LAB_DIR)/runs" $(foreach path,$(DT_FINDINGS),--findings "$(path)")

exploit-lab-vulnerability-lookup-compare:
	$(if $(strip $(VULS_RESULT)),,$(error VULS_RESULT is required))
	$(if $(strip $(VULNERABILITY_LOOKUP_RESULT)),,$(error VULNERABILITY_LOOKUP_RESULT is required))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli compare-vulnerability-lookup --manifest "$(EXPLOIT_LAB_MANIFEST)" --vuls-result "$(VULS_RESULT)" --vulnerability-lookup-result "$(VULNERABILITY_LOOKUP_RESULT)" --output-dir "$(EXPLOIT_LAB_DIR)/runs"

exploit-lab-evidence-review-queue:
	$(if $(strip $(VULS_RESULT)),,$(error VULS_RESULT is required))
	$(if $(strip $(COMPARISON_RESULT)),,$(error COMPARISON_RESULT is required))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli build-evidence-review-queue --manifest "$(EXPLOIT_LAB_MANIFEST)" --vuls-result "$(VULS_RESULT)" --comparison-result "$(COMPARISON_RESULT)" --cohort "$(or $(REVIEW_COHORT),vuls-db-only)" --output-dir "$(EXPLOIT_LAB_DIR)/runs"

exploit-lab-evidence-review-template:
	$(if $(strip $(REVIEW_QUEUE)),,$(error REVIEW_QUEUE is required))
	$(if $(strip $(REVIEW_FILE)),,$(error REVIEW_FILE is required))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli create-evidence-review-template --manifest "$(EXPLOIT_LAB_MANIFEST)" --queue "$(REVIEW_QUEUE)" --output "$(REVIEW_FILE)"

exploit-lab-evidence-review-apply:
	$(if $(strip $(REVIEW_QUEUE)),,$(error REVIEW_QUEUE is required))
	$(if $(strip $(REVIEW_FILE)),,$(error REVIEW_FILE is required))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli apply-evidence-reviews --manifest "$(EXPLOIT_LAB_MANIFEST)" --queue "$(REVIEW_QUEUE)" --reviews "$(REVIEW_FILE)" --output-dir "$(EXPLOIT_LAB_DIR)/runs"

exploit-lab-evidence-review-agreement:
	$(if $(strip $(REVIEWED_RESULT_A)),,$(error REVIEWED_RESULT_A is required))
	$(if $(strip $(REVIEWED_RESULT_B)),,$(error REVIEWED_RESULT_B is required))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli compare-evidence-reviews --manifest "$(EXPLOIT_LAB_MANIFEST)" --reviewer-a-result "$(REVIEWED_RESULT_A)" --reviewer-b-result "$(REVIEWED_RESULT_B)" --output-dir "$(EXPLOIT_LAB_DIR)/runs"

exploit-lab-evidence-adjudication-queue:
	$(if $(strip $(AGREEMENT_RESULT)),,$(error AGREEMENT_RESULT is required))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli build-evidence-adjudication-queue --manifest "$(EXPLOIT_LAB_MANIFEST)" --agreement-result "$(AGREEMENT_RESULT)" --output-dir "$(EXPLOIT_LAB_DIR)/runs"

exploit-lab-evidence-adjudication-template:
	$(if $(strip $(ADJUDICATION_QUEUE)),,$(error ADJUDICATION_QUEUE is required))
	$(if $(strip $(ADJUDICATION_FILE)),,$(error ADJUDICATION_FILE is required))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli create-evidence-adjudication-template --manifest "$(EXPLOIT_LAB_MANIFEST)" --queue "$(ADJUDICATION_QUEUE)" --output "$(ADJUDICATION_FILE)"

exploit-lab-evidence-adjudication-apply:
	$(if $(strip $(ADJUDICATION_QUEUE)),,$(error ADJUDICATION_QUEUE is required))
	$(if $(strip $(ADJUDICATION_FILE)),,$(error ADJUDICATION_FILE is required))
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m exploit_lab.cli apply-evidence-adjudications --manifest "$(EXPLOIT_LAB_MANIFEST)" --queue "$(ADJUDICATION_QUEUE)" --adjudications "$(ADJUDICATION_FILE)" --output-dir "$(EXPLOIT_LAB_DIR)/runs"

exploit-lab-test:
	PYTHONPATH=$(EXPLOIT_LAB_PYTHONPATH) $(PYTHON) -m pytest -q $(EXPLOIT_LAB_ROOT)/tests

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
