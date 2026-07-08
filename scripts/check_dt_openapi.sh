#!/usr/bin/env bash

set -euo pipefail

base_url="${1:-http://localhost:8080}"

echo "Checking Dependency-Track OpenAPI endpoint: ${base_url}/api/openapi.json"
curl -fsS -o /dev/null "${base_url}/api/openapi.json"
echo "OpenAPI endpoint reachable."
