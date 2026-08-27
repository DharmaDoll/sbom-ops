#!/usr/bin/env bash

set -euo pipefail

base_url="${1:-http://localhost:8080}"
output_path="${2:-}"

echo "Checking Dependency-Track OpenAPI endpoint: ${base_url}/api/openapi.json"
if [[ -n "${output_path}" ]]; then
  curl -fsS -o "${output_path}" "${base_url}/api/openapi.json"
  echo "OpenAPI document saved to ${output_path}."
else
  curl -fsS -o /dev/null "${base_url}/api/openapi.json"
fi
echo "OpenAPI endpoint reachable."
