#!/usr/bin/env bash

set -euo pipefail

base_url="${SBOM_OPS_DT_BASE_URL:-http://localhost:8080}"
api_key="${SBOM_OPS_SBOM_UPLOAD_API_KEY:-}"
project_uuid="${SBOM_OPS_DT_PROJECT_UUID:-}"
bom_path="${1:-}"

if [[ -z "${api_key}" ]]; then
  echo "Missing SBOM_OPS_SBOM_UPLOAD_API_KEY" >&2
  exit 1
fi

if [[ -z "${project_uuid}" ]]; then
  echo "Missing SBOM_OPS_DT_PROJECT_UUID" >&2
  exit 1
fi

if [[ -z "${bom_path}" ]]; then
  echo "Usage: scripts/upload_bom.sh path/to/bom.xml" >&2
  exit 1
fi

if [[ ! -f "${bom_path}" ]]; then
  echo "BOM file not found: ${bom_path}" >&2
  exit 1
fi

echo "Uploading BOM '${bom_path}' to project '${project_uuid}' via ${base_url}"

curl -fsS -X POST "${base_url}/api/v1/bom" \
  -H "X-Api-Key: ${api_key}" \
  -F "project=${project_uuid}" \
  -F "bom=@${bom_path}"

echo
echo "Upload request completed."
