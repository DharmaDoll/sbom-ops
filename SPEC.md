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
- Safe, opt-in GitHub Issue closure after confirmed absence
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
- The orchestrator produces an action-neutral Finding assessment first; GitHub
  Issue synchronization is an optional final action and may be disabled.
- `sync --output json` exposes the same assessment and action summary for
  downstream adapters without requiring GitHub access.
- Every sync result includes a unique `run_id` and `duration_seconds` for
  correlation with audit and structured-log records.

## Repository Layout

```text
src/sbom_ops/
  cli.py
  config.py
  domain/
    models.py
    priority.py
    routing.py
  services/
    orchestrator.py
    sync_log.py
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
2. Pull findings from Dependency-Track after the CI upload/analysis stage
3. Normalize findings into domain models
4. Read Dependency-Track EPSS and analysis state; enrich findings with KEV
5. Calculate operational priority
6. Decide whether an issue should be created, updated, marked missing, or closed
7. Write issue changes to GitHub
8. Emit summary and planned actions to stdout and logs

SBOM generation and upload are CI/CD responsibilities. The separate `upload`
command is an integration helper for CI; `sync` never uploads an SBOM.

## Configuration Contract

Configuration source order:

1. CLI options
2. Environment variables
3. Optional YAML config file
4. Code defaults

The implementation supports environment variables and the compatible YAML shape.

### Required settings (environment variables or YAML)

```text
SBOM_OPS_DT_BASE_URL
SBOM_OPS_DT_API_KEY
SBOM_OPS_GITHUB_OWNER
SBOM_OPS_GITHUB_REPO
```

`SBOM_OPS_GITHUB_TOKEN` or `GH_TOKEN` is required when `github.token` is not
provided in YAML. The Dependency-Track URL and API key may likewise be supplied
by YAML instead of environment variables.

### Optional environment variables

```text
SBOM_OPS_CONFIG_FILE
SBOM_OPS_LOG_LEVEL
SBOM_OPS_EPSS_API_URL
SBOM_OPS_KEV_FEED_URL
SBOM_OPS_KEV_CACHE_FILE
SBOM_OPS_KEV_CACHE_TTL_SECONDS
SBOM_OPS_KEV_CACHE_ALLOW_STALE
SBOM_OPS_PRIORITY_P1_EPSS_THRESHOLD
SBOM_OPS_PRIORITY_P2_CVSS_THRESHOLD
SBOM_OPS_CREATE_ISSUES_FOR
SBOM_OPS_ISSUE_LABEL_PREFIX
SBOM_OPS_DRY_RUN
SBOM_OPS_PROJECT_UUIDS
SBOM_OPS_DT_PAGE_SIZE
SBOM_OPS_DT_TIMEOUT_SECONDS
SBOM_OPS_DT_MAX_RETRIES
SBOM_OPS_DT_ANALYSIS_WAIT_TIMEOUT_SECONDS
SBOM_OPS_DT_ANALYSIS_POLL_INTERVAL_SECONDS
SBOM_OPS_WAIT_FOR_ANALYSIS
SBOM_OPS_SYNC_LOG_FILE
SBOM_OPS_CLOSE_MISSING_FINDINGS
SBOM_OPS_MISSING_CONFIRMATION_RUNS
SBOM_OPS_GITHUB_TIMEOUT_SECONDS
SBOM_OPS_GITHUB_MAX_RETRIES
SBOM_OPS_GITHUB_ENABLED
SBOM_OPS_INTEL_TIMEOUT_SECONDS
SBOM_OPS_INTEL_MAX_RETRIES
```

### Config schema

```yaml
dependency_track:
  base_url: https://dtrack.example.com
  api_key: env:SBOM_OPS_DT_API_KEY
  page_size: 100

github:
  # Set false to run collection and prioritization without Issue operations.
  enabled: true
  token: env:SBOM_OPS_GITHUB_TOKEN
  owner: acme
  repo: service-a
  issue_label_prefix: sbom

intelligence:
  kev_feed_url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  # Optional fallback/verification source. Dependency-Track EPSS is preferred.
  epss_api_url: https://api.first.org/data/v1/epss
  # Optional local KEV cache.
  # kev_cache_file: var/kev.json
  kev_cache_ttl_seconds: 18000
  kev_cache_allow_stale: false

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
  wait_for_analysis: false
  # Optional JSONL output for completed sync results.
  # sync_log_file: var/sbom-ops-sync.jsonl

workflow:
  close_missing_findings: false
  missing_confirmation_runs: 2

routing:
  projects:
    - project_uuid: project-uuid
      owner: acme
      repo: service-a
      issue_label_prefix: sbom
```

Notes:

- P0 remains rule-based from KEV or explicit active exploitation input.
- `p1_epss_threshold` and `p2_cvss_threshold` must be configurable.
- Project filtering is optional and defaults to all accessible projects.
- `routing.projects` is optional. When it is configured, every processed
  Dependency-Track Project must have exactly one route; an unknown Project is
  rejected rather than sent to the default repository.
- `api_key` and `token` may use `env:VARIABLE_NAME` references. Environment
  variables override file values, and CLI flags override both.
- `SBOM_OPS_CONFIG_FILE` selects the YAML file when `--config` is not provided.
- Unknown sections and keys are rejected to prevent silent configuration typos.

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
- `vulnerability_source: str | None`
- `dependency_track_component_uuid: str | None`
- `component_purl: str | None`

Finding lifecycle, Dependency-Track analysis, and remediation workflow are
separate concepts. `FindingState` represents observations such as `ACTIVE`,
`MISSING`, `RESOLVED`, and `UNKNOWN`. Dependency-Track analysis values such as
`NOT_AFFECTED` are not GitHub workflow states.

The domain workflow keeps these transitions independent:

- Finding absence becomes `MISSING` and then `RESOLVED` only after the configured
  consecutive, verified absence confirmations.
- Analysis is an observation read from Dependency-Track; sbom-ops does not
  transition or write it as part of remediation.
- Remediation remains `OPEN` for `ACTIVE`, `MISSING`, and `UNKNOWN` findings and
  becomes `CLOSED` only for an explicitly confirmed `RESOLVED` finding. A
  reappeared finding therefore returns to `OPEN` regardless of its analysis
  observation.

### Enrichment

Required fields:

- `in_kev: bool`
- `epss_score: float | None`
- `has_known_active_exploitation: bool`
- `analysis_state: AnalysisState`
- `is_suppressed: bool`
- `analysis_detail: str | None`

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
v2:{project_uuid}:sha256(machine_identity)
```

`machine_identity` prefers `project_uuid + component_uuid + vulnerability_uuid`.
When those Dependency-Track identifiers are unavailable, it uses
`project_uuid + purl + vulnerability_source + vulnerability_id`, then falls
back to display coordinates. The key is opaque; component name/version remain
separate human-readable fields. The v1 display-derived key is searched during
migration so an existing issue is updated instead of duplicated.

The key, Finding observation state, and consecutive-missing counter must be
stored in machine-readable metadata blocks in the issue body.

### Duplicate handling

- If an open issue exists for the external key, update it instead of creating a new issue
- If a closed issue exists and the finding still exists, reopen or create a new issue based on config later
- MVP behavior: create a new issue only when no open issue matches

### Issue closure

Absence is not resolution. Automatic closure is disabled by default. When it
is explicitly enabled, the orchestrator may close an issue only when:

- the complete synchronization run succeeds
- the target project used the analysis-wait path (unless an explicit future
  verified completion signal replaces it)
- the finding is absent for at least `missing_confirmation_runs` consecutive
  successful observations (minimum 2)

The first verified absence records `MISSING` in issue metadata and keeps the
issue open. An unverified or failed read is `UNKNOWN`, not `RESOLVED`.

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

- `get_project(...)`
- `update_analysis_state(...)`

`upload_bom(...)` is available only to the separate CI upload helper and is
not called by synchronization orchestration.

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
- `list_open_issues(label: str)`
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
- `upload`

### `sync`

Runs the full orchestration flow.

Supported options:

```text
--config PATH
--project UUID           # repeatable later, single value acceptable for now
--dry-run
--log-level LEVEL
--wait-for-analysis
--no-github
--output text|json
--sync-log-file PATH
```

### `plan`

Validates configuration and prints the effective runtime plan without writing to external systems.

Supported options:

```text
--config PATH
--project UUID
--dry-run
--log-level LEVEL
--no-github
--sync-log-file PATH
```

### `upload`

Uploads a CycloneDX BOM to an existing Dependency-Track project and optionally
waits for the upload processing token to complete. This command is a CI helper;
`sync` does not upload SBOMs.

Supported options:

```text
bom_path
--project UUID
--no-wait
```

## Logging

The CLI prints a run summary and can optionally append completed sync results
to a JSONL file through `runtime.sync_log_file` or `--sync-log-file`.

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

- issue reopen policy
- analysis-state read mapping
- VEX upload and ingestion workflow
- multi-repo routing
- Jira adapter
