# Dependency-Track SBOM Operations

Security-as-a-Task orchestration for OWASP Dependency-Track SBOM workflows.

Dependency-Track owns inventory, vulnerability correlation, EPSS, and
VEX-derived analysis state. GitHub Issues own remediation workflow. `sbom-ops`
connects the two: it reads Dependency-Track findings, enriches them with CISA
KEV, calculates an operational priority, and optionally creates or updates
remediation issues.

The important boundary is intentional: sbom-ops can recommend and synchronize
work, but it must not approve exceptions, suppress findings, or overwrite
Dependency-Track analysis state automatically.

## What It Does Today

- Reads projects, findings, EPSS, suppression, and analysis state from Dependency-Track
- Uploads CycloneDX SBOMs to an existing Dependency-Track project as a CI helper
- Enriches findings with the CISA KEV catalog
- Calculates deterministic `P0` to `P3` priorities from configurable thresholds
- Produces action-neutral finding assessments before any GitHub write
- Can run with GitHub Issue operations disabled via `--no-github`
- Supports YAML config, environment overrides, project-to-repository routing, JSON output, and optional JSONL sync logs
- Uses safe, opt-in issue closure after verified consecutive absence observations

## Quick Start

Prerequisites:

- Python 3.12 or newer
- Docker Engine and the Docker Compose plugin
- GitHub CLI only if you want to exercise GitHub Issue synchronization

Install locally:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run the local test suite:

```bash
ruff check .
pytest
```

Start the local Dependency-Track evaluation stack:

```bash
docker compose -f examples/dependency-track/docker-compose.yml up -d
curl -fsS -o /dev/null http://localhost:8080/api/openapi.json
```

Open `http://localhost:8080`, sign in with the initial local credentials, and
change the password immediately:

```text
admin / admin
```

Create two local API keys in Dependency-Track:

- SBOM upload key: `BOM_UPLOAD`, plus `PROJECT_CREATION_UPLOAD` if you use demo auto-create
- Orchestrator read key: `VIEW_PORTFOLIO` and `VIEW_VULNERABILITY`

Keep the keys in your shell or a local uncommitted `.env` file:

```bash
export SBOM_OPS_DT_BASE_URL=http://localhost:8080
export SBOM_OPS_DT_API_KEY=replace-with-orchestrator-read-key
export SBOM_OPS_SBOM_UPLOAD_API_KEY=replace-with-upload-key
```

Upload the demo SBOM:

```bash
SBOM_OPS_DT_PROJECT_NAME=sbom-ops-vulnerable-demo \
SBOM_OPS_DT_PROJECT_VERSION=0.1.0 \
scripts/upload_bom.sh examples/sboms/vulnerable-demo.cdx.json
```

Copy the created project UUID from the Dependency-Track UI, then preview the
runtime plan without enabling GitHub writes:

```bash
export SBOM_OPS_DT_PROJECT_UUID=replace-with-project-uuid
sbom-ops plan --config examples/config.yaml --project "$SBOM_OPS_DT_PROJECT_UUID" --no-github
```

Run the first synchronization as a safe local preview:

```bash
sbom-ops sync \
  --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" \
  --wait-for-analysis \
  --dry-run \
  --no-github
```

For machine-readable output:

```bash
sbom-ops sync \
  --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" \
  --wait-for-analysis \
  --dry-run \
  --no-github \
  --output json
```

At this point you should be able to see the core idea without granting GitHub
write access: Dependency-Track provides the inventory and analysis facts,
sbom-ops calculates the operational priority, and the Issue step remains an
explicit final action.

## Enabling GitHub Issue Sync

After reviewing dry-run output, provide GitHub repository settings and a token.
For local use, the GitHub CLI credential store is convenient:

```bash
export SBOM_OPS_GITHUB_OWNER=your-org
export SBOM_OPS_GITHUB_REPO=your-repo
export GH_TOKEN="$(gh auth token)"
```

Then remove `--no-github`. Keep `--dry-run` until labels, issue body, and
routing behavior are confirmed:

```bash
sbom-ops sync \
  --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" \
  --wait-for-analysis \
  --dry-run
```

`SBOM_OPS_GITHUB_TOKEN` is also supported. Do not commit tokens or place real
secrets in documentation.

## Configuration

`sync` and `plan` accept `--config PATH`. If omitted, `SBOM_OPS_CONFIG_FILE` is
used. Precedence is:

1. CLI flags
2. Environment variables
3. YAML config file
4. Code defaults

Use `env:VARIABLE_NAME` in YAML for secrets:

```yaml
dependency_track:
  base_url: http://localhost:8080
  api_key: env:SBOM_OPS_DT_API_KEY

github:
  enabled: false
  # token: env:SBOM_OPS_GITHUB_TOKEN
  # owner: acme
  # repo: service-a
```

See [`examples/config.yaml`](examples/config.yaml) for a complete example and
[`SPEC.md`](SPEC.md) for the full configuration contract.

## Core Commands

```bash
sbom-ops plan --config examples/config.yaml --no-github
sbom-ops sync --config examples/config.yaml --dry-run --no-github
sbom-ops sync --config examples/config.yaml --dry-run --no-github --output json
sbom-ops upload path/to/bom.cdx.json --project "$SBOM_OPS_DT_PROJECT_UUID"
make infra-gcp-poc-fmt-check
make infra-gcp-poc-validate
```

## Documentation

The active documentation has four primary entry points:

- [`README.md`](README.md): local quick start and command overview
- [`SPEC.md`](SPEC.md): normative product and Google Cloud deployment contract
- [`ARCHITECTURE.md`](ARCHITECTURE.md): stable boundaries and repository layout
- [`ROADMAP.md`](ROADMAP.md): current status, backlog, and delivery order

Supporting guides are grouped by purpose:

- Operations: [`use cases`](docs/use-cases.md), [`data sources`](docs/data-sources.md),
  [`runbook`](docs/operations.md), and
  [`Dependency-Track setup`](docs/dependency-track/setup.md)
- Policies: [`priority`](docs/priority-policy.md) and
  [`VEX`](docs/vex.md)
- Decisions and infrastructure: [`ADRs`](docs/adr/README.md) and the
  [`GCP PoC`](infra/gcp/poc/README.md)

## Design Principles

1. SBOM is the source of truth for software composition.
2. Dependency-Track is the source of truth for inventory and vulnerability analysis state.
3. GitHub Issues are the source of truth for remediation workflow.
4. Threat intelligence drives operational prioritization.
5. AI can assist triage, but must not replace security decisions.
