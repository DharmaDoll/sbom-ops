#!/usr/bin/env bash
# Run from the repository root. Only stdout is the SBOM; no DT credentials needed.
set -euo pipefail
source examples/sbom-producers/tools.env
case "${1:-}" in
  npm)
    docker run --rm --platform "$PLATFORM" --user "$(id -u):$(id -g)" \
      -e HOME=/tmp -e NODE_ENV=development \
      -v "$PWD/examples/sbom-producers/npm:/src:ro" "$NODE_IMAGE" sh -ec '
        mkdir /tmp/project
        cp /src/package.json /src/package-lock.json /tmp/project/
        cd /tmp/project
        npm ci --ignore-scripts --include=dev --include=optional --include=peer \
          --no-audit --no-fund >&2
        npm sbom --sbom-format cyclonedx --package-lock-only \
          --include=dev --include=optional --include=peer
      '
    ;;
  uv)
    uv_runtime=$(docker build -q --platform "$PLATFORM" \
      -f examples/sbom-producers/Source.Dockerfile examples/sbom-producers/uv)
    docker run --rm --platform "$PLATFORM" --user "$(id -u):$(id -g)" \
      --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
      -e UV_CACHE_DIR=/tmp/cache -e UV_PYTHON_DOWNLOADS=never \
      -v "$PWD/examples/sbom-producers/uv:/src:ro" "$uv_runtime" \
      export --directory /src --locked --all-groups --all-extras \
      --format cyclonedx1.5
    ;;
  *) echo 'Usage: bash examples/sbom-producers/source.sh npm|uv' >&2; exit 2 ;;
esac
