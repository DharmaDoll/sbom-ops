# Implementation Specification

## Scope

This document defines the MVP contract for the SBOM operations orchestrator.
It is intentionally narrower than the full roadmap.

MVP includes:

- Dependency-Track findings ingestion
- KEV enrichment
- EPSS retrieval from Dependency-Track findings
- Priority calculation
- GitHub Issue creation and update
- CLI execution
- Config-driven thresholds
- Unit tests and mock-based integration fixtures

MVP excludes:

- VEX write operations from sbom-ops
- Jira
- Slack / Teams
- Reachability
- Automatic risk acceptance
- Automatic analysis-state mutation in Dependency-Track

## Design Constraints

- Python 3.12+
- Type hints required
- Business logic lives in `src/sbom_ops/domain/`
- Orchestration lives in `src/sbom_ops/services/`
- External API communication lives in `src/sbom_ops/clients/`
- Configuration values and thresholds must not be hardcoded in domain logic
- Dependency-Track remains the source of truth for inventory and finding state
- Dependency-Track is the preferred source of truth for EPSS and VEX-derived analysis state
- GitHub Issues remain the source of truth for remediation workflow state

## Repository Layout

```text
src/sbom_ops/
  cli.py
  config.py
  domain/
    models.py
    priority.py
  services/
    orchestrator.py
  clients/
    dependency_track.py
    epss.py
    kev.py
    github.py
  utils/
    logging.py

tests/
  unit/
  fixtures/
```

## Execution Model

The orchestrator runs as a stateless CLI job.
Typical execution modes:

- scheduled poll from CI or cron
- project-scoped ad hoc run
- dry-run for validation

The process flow is:

1. Load configuration
2. Pull findings from Dependency-Track
3. Normalize findings into domain models
4. Read Dependency-Track EPSS and analysis state; enrich findings with KEV
5. Calculate operational priority
6. Decide whether an issue should be created or updated
7. Write issue changes to GitHub
8. Emit summary to stdout and logs

## Configuration Contract

Configuration source order:

1. CLI options
2. Environment variables
3. Optional YAML config file
4. Code defaults

The initial implementation may support environment variables first, with YAML added in a compatible shape.

### Required environment variables

```text
SBOM_OPS_DT_BASE_URL
SBOM_OPS_DT_API_KEY
SBOM_OPS_GITHUB_TOKEN
SBOM_OPS_GITHUB_OWNER
SBOM_OPS_GITHUB_REPO
```

### Optional environment variables

```text
SBOM_OPS_CONFIG_FILE
SBOM_OPS_LOG_LEVEL
SBOM_OPS_EPSS_API_URL
SBOM_OPS_KEV_FEED_URL
SBOM_OPS_PRIORITY_P1_EPSS_THRESHOLD
SBOM_OPS_PRIORITY_P2_CVSS_THRESHOLD
SBOM_OPS_ISSUE_LABEL_PREFIX
SBOM_OPS_DRY_RUN
SBOM_OPS_PROJECT_UUIDS
```

### Config schema

```yaml
dependency_track:
  base_url: https://dtrack.example.com
  api_key: env:SBOM_OPS_DT_API_KEY
  page_size: 100

github:
  token: env:SBOM_OPS_GITHUB_TOKEN
  owner: acme
  repo: service-a
  issue_label_prefix: sbom

intelligence:
  kev_feed_url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  # Optional fallback/verification source. Dependency-Track EPSS is preferred.
  epss_api_url: https://api.first.org/data/v1/epss

priority:
  p1_epss_threshold: 0.7
  p2_cvss_threshold: 7.0
  create_issues_for:
    - P0
    - P1

runtime:
  dry_run: false
  project_uuids: []
  log_level: INFO
```

Notes:

- P0 remains rule-based from KEV or explicit active exploitation input.
- `p1_epss_threshold` and `p2_cvss_threshold` must be configurable.
- Project filtering is optional and defaults to all accessible projects.

## Domain Model

### Severity

Allowed values:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`
- `UNKNOWN`

### Priority

Allowed values:

- `P0`
- `P1`
- `P2`
- `P3`

### Finding

Required fields:

- `project_uuid: str`
- `project_name: str`
- `component_name: str`
- `component_version: str | None`
- `vulnerability_id: str`
- `severity: Severity`
- `cvss_score: float | None`
- `cwes: tuple[int, ...]`
- `description: str | None`
- `dependency_track_finding_id: str | None`
- `dependency_track_vulnerability_uuid: str | None`

### Enrichment

Required fields:

- `in_kev: bool`
- `epss_score: float | None`
- `has_known_active_exploitation: bool`
- `analysis_state: str | None`
- `is_suppressed: bool`

`epss_score` should be populated from the Dependency-Track finding when
available. The external EPSS client is optional and may only be used as a
fallback or for verification when explicitly configured.

VEX-derived analysis information is read from Dependency-Track. sbom-ops must
not independently decide that a finding is not affected or a false positive.
For MVP, `has_known_active_exploitation` may map to `in_kev`.
The field exists now to avoid rewriting the domain model later.

### Prioritized Finding

Required fields:

- `finding: Finding`
- `enrichment: Enrichment`
- `priority: Priority`
- `rationale: tuple[str, ...]`

## Priority Rules

The priority engine must be deterministic and side-effect free.

Rules in order:

1. `P0` if `in_kev` is true
2. `P0` if `has_known_active_exploitation` is true
3. `P1` if severity is `CRITICAL`
4. `P1` if `epss_score >= p1_epss_threshold`
5. `P2` if `cvss_score >= p2_cvss_threshold`
6. `P3` otherwise

Notes:

- Rule order matters.
- The engine must return rationale strings for auditability.
- Missing scores must not crash evaluation.

## Workflow Rules

### Dependency-Track analysis and VEX

Dependency-Track owns vulnerability analysis state and VEX ingestion. sbom-ops
may read analysis state and suppression information when deciding whether to
create or update a GitHub Issue, but must not overwrite those values
automatically in the MVP.

Supplier or CI-generated CycloneDX VEX should be uploaded to Dependency-Track
through the Dependency-Track integration boundary. The orchestrator consumes
the resulting state; it does not implement an independent VEX decision engine.

Findings marked `NOT_AFFECTED`, `FALSE_POSITIVE`, or suppressed are excluded
from new remediation issues unless an explicit future policy says otherwise.

### Issue creation

Create GitHub Issues only for priorities configured in `priority.create_issues_for`.
Default is `P0` and `P1`.

### Idempotency

Each finding must map to a stable external key:

```text
{project_uuid}:{component_name}:{component_version}:{vulnerability_id}
```

This key must be stored in the issue body or machine-readable metadata block.

### Duplicate handling

- If an open issue exists for the external key, update it instead of creating a new issue
- If a closed issue exists and the finding still exists, reopen or create a new issue based on config later
- MVP behavior: create a new issue only when no open issue matches

### Issue closure

MVP closure rule:

- close the GitHub Issue when the finding is no longer returned by Dependency-Track for that project and vulnerability key

### Analysis state

MVP must not mutate Dependency-Track analysis state automatically.
The orchestrator reads analysis data and suppression state for workflow
decisions, but Dependency-Track remains authoritative.

## Client Contracts

Clients expose intent-based methods only.

### `DependencyTrackClient`

Required methods:

- `list_projects()`
- `get_project_findings(project_uuid: str)`

Deferred methods:

- `upload_bom(...)`
- `get_project(...)`
- `update_analysis_state(...)`

### `KevClient`

Required methods:

- `get_known_exploited_vulnerabilities()`

### `EpssClient`

Required methods:

- `get_scores(cve_ids: list[str])` (optional fallback/verification only)

The primary EPSS value must come from Dependency-Track findings. Direct calls
to the external EPSS service must not override a value supplied by
Dependency-Track unless explicitly configured.

### `GitHubIssuesClient`

Required methods:

- `find_open_issue_by_finding_key(finding_key: str)`
- `create_issue(...)`
- `update_issue(...)`
- `close_issue(...)`

## CLI Contract

Entry point:

```text
sbom-ops
```

Subcommands for MVP:

- `sync`
- `plan`

### `sync`

Runs the full orchestration flow.

Supported options:

```text
--config PATH
--project UUID           # repeatable later, single value acceptable for now
--dry-run
--log-level LEVEL
```

### `plan`

Validates configuration and prints the effective runtime plan without writing to external systems.

## Logging

Structured logging is preferred, but MVP may start with standard logging.

Each run should log:

- start and end of run
- projects processed
- findings count
- issues created / updated / closed
- failed API operations

Secrets must never be logged.

## Testing Strategy

### Unit tests

Mandatory for:

- config parsing
- priority engine
- issue key generation
- orchestration decisions with fake clients

### Integration tests

For Dependency-Track and GitHub client layers, MVP can use documented mock fixtures instead of live services.

Fixtures should cover:

- project list response
- findings response
- GitHub issue search response
- GitHub issue create/update payloads

## Open Items

These are intentionally deferred, not blockers for the first implementation:

- YAML config file loader
- issue reopen policy
- analysis-state read mapping
- VEX upload and ingestion workflow
- multi-repo routing
- Jira adapter
