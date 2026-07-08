COMPOSE_FILE := examples/dependency-track/docker-compose.yml
DT_BACKEND_URL ?= http://localhost:8080

.PHONY: dt-up dt-down dt-logs dt-ps dt-openapi-check dt-bom-upload test lint

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

dt-bom-upload:
	./scripts/upload_bom.sh

test:
	pytest

lint:
	ruff check .
