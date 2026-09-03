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

## Google Cloud Deployment Contract

The core orchestrator remains deployable as a stateless CLI job and does not
require Google Cloud. When the project is deployed on Google Cloud, the
following requirements are part of the supported deployment profile.

- The Dependency-Track API server, browser frontend, and persistent PostgreSQL
  database must be modeled as separate runtime concerns.
- The final runtime must be selected through the proof of concept recorded in
  [`ADR 0001`](docs/adr/0001-gcp-secure-delivery-runtime.md). Cloud Run and GKE
  remain candidates until that ADR is accepted.
- GitHub Actions must authenticate to Google Cloud with OIDC and Workload
  Identity Federation. Long-lived Google Cloud service-account keys must not be
  stored in GitHub.
- Workload Identity trust must be restricted with immutable organization and
  repository IDs, protected refs or environments, and the approved reusable
  workflow identity.
- Dependency-Track API keys must be held in Secret Manager or an equivalent
  managed secret store and must not be exposed to calling repositories or logs.
- CI uploads must pass through a least-privilege boundary that only permits the
  documented BOM upload operation. It must not become a general
  Dependency-Track reverse proxy.
- The upload target must be resolved from an authoritative
  repository-to-Dependency-Track-project mapping. A caller-provided
  `project_uuid` alone is not authorization.
- Service-to-service authentication and browser authentication are separate
  controls and must be validated independently.
- Production readiness requires structured logs, authentication and upload
  audit events, failure alerts, backup and restore validation, and a documented
  rollback path.

The ADR owns the runtime decision and its rationale. The
[`infra/gcp/poc`](infra/gcp/poc/README.md) directory owns executable evaluation
artifacts. This specification owns the security and behavior requirements that
must remain true regardless of the selected runtime.

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
Before any future production upload, it must resolve every `affects.ref` within
the VEX document, classify the target as Component- or Project-scoped, reject
unresolved references, and require explicit approval for the complete expected
Finding set. After DT's event token completes, it must reconcile that exact set
and fail closed on missing or additional changes. Schema validity and an
accepted upload are not evidence that the intended Finding was updated.

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
decisions, but Dependency-Track remains authoritative. Project Finding reads
must request `suppressed=true`; omission from DT's default unsuppressed view is
not Finding absence. Reconciliation compares a normalized semantic projection
of stable Finding identity, state, justification, response, detail, and
suppression. It must not depend on Project metrics, `ETag`, `Last-Modified`, or
an Analysis update cursor that DT 4.14.3 does not expose.

The minimum orchestrator state is the stable Finding key, last observed
semantic digest, observation outcome and time, and external work-item
correlation. DT remains authoritative for Analysis comments and audit history.
A future Analysis writer must not blindly retry a request containing a comment,
because an identical PUT can append a duplicate comment while leaving semantic
state unchanged.

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

Dependency-Track behavior exploration is a repository-only subsystem under
`lab/dependency_track/`; it is excluded from the product wheel and runtime CLI.
Its versioned scenario manifest is
`lab/dependency_track/scenarios/scenarios.yaml`. Every repository scenario must
state hypotheses and decision questions in addition to its purpose and
observations. A planned status is an experiment backlog entry, not a requirement
to implement the scenario for coverage.

Each completed experiment must turn observations into one of four reviewed
decisions:

1. use an existing Dependency-Track capability and keep sbom-ops thin
2. encode a verified Dependency-Track constraint in product fixtures, contracts,
   tests, and documentation
3. implement only the orchestration gap that Dependency-Track does not provide
4. reject or defer the hypothesis with the supporting evidence recorded

Every attempted live experiment, including a failed, partial, or inconclusive
run, must update the single durable ledger at
`lab/dependency_track/EXPERIMENTS.md`. Each entry records the purpose, performed
work, observed facts, interpretation or product decision, unresolved questions,
target versions, and ignored local evidence path. Facts must be separated from
inference. Scenario status `implemented` means runnable and does not by itself
claim that live behavior has been verified.

Product code must not import lab modules, and lab code is not mechanically moved
into `src/sbom_ops/`. Raw OpenAPI and API observations remain ignored under
`var/dt-lab/`; only minimal, reviewed contract examples belong in product test
fixtures. Live vulnerability counts, EPSS values, and datasource timing must not
be treated as deterministic assertions.

The lab must explicitly test how far human security triage can remain in
Dependency-Track—including Analysis decisions and history, comments,
suppression, and VEX—and which state is still required in sbom-ops or the work
management system. Until that boundary is supported by evidence, experiments
must not create a second authoritative triage state machine.

Experiments use short-lived branches. Branch separation alone is not a security
boundary; mutating experiments require a disposable Project, least-privilege
credentials, and an explicit CLI opt-in.

The Analysis-state experiment has three independent gates: it must be selected
by scenario ID, `--allow-analysis-mutation` must be present, and the selected API
key must have `VULNERABILITY_ANALYSIS`. The lab prefers
`SBOM_OPS_DT_ANALYSIS_API_KEY` when supplied and otherwise reuses
`SBOM_OPS_DT_API_KEY`. Before any Project creation, `GET /api/v1/team/self` must
report `VULNERABILITY_ANALYSIS` and no permission outside
`VIEW_BADGES`, `VIEW_POLICY_VIOLATION`, `VIEW_PORTFOLIO`,
`VIEW_VULNERABILITY`, and `VULNERABILITY_ANALYSIS`.
The normal all-implemented-scenarios run excludes mutation actions. Analysis
targets must be resolved from the newly created run-scoped Project by stable
Component and vulnerability identifiers; global Analysis mutation is forbidden.
Every action must retain its request and response, Analysis trail, applicable
default and include-suppressed Finding views, metrics, semantic and audit
digests, and expected-versus-observed projection under ignored `var/dt-lab/`
evidence. Every action sequence must end each target at unsuppressed `NOT_SET`
and attempt a verified emergency reset on failure.

The VEX round-trip lab experiment uses the same three gates. It must export a
decision from the run-scoped Project, reset that exact Finding before import,
upload the captured VEX only to the same Project, compare Finding state and VEX
Analysis semantics after ingestion, and restore `NOT_SET` after success or
failure. Dependency-Track suppression is evaluated separately because it is not
a CycloneDX VEX field. An explicitly declared replay must compare both state and
audit-comment changes so retry safety is not inferred from an unchanged final
state. This lab behavior does not authorize product VEX writes.

A VEX targeting experiment must use at least two run-scoped Findings for the
same vulnerability. It compares unresolved DT-exported and source Component
`bom-ref` values, a `components[]`-declared Component reference, and the
Project-level `affects.ref`. It records both target and control projections
after each import and restores both Findings between probes and on every exit
path. Product code must not infer Component isolation from a bare reference or
a Project-scoped export.

An invalid-BOM experiment must be explicitly selected and declare its expected
HTTP client-error status, base response media type, and Project-creation side
effect. It must retain safe RFC 9457 problem details and input integrity
metadata without credentials or the multipart body. A synchronous rejection is
a completed negative experiment only when all declared expectations match.
HTTP 400 is non-retryable. Coordinate upload with `autoCreate` must write the
Project ledger before the request because DT 4.14.3 can create an empty Project
before schema rejection. Production upload continues to resolve and use an
existing Project UUID rather than relying on this side effect.

A format-equivalence experiment must ingest equivalent JSON and XML into the
same run-scoped Project version and compare more than acceptance status or item
counts. It must retain normalized inventory and Finding semantics, stable API
identity mappings, dependency-graph projections, and normalized DT re-export.
The comparison is evidence only for the exercised CycloneDX version and fields.
The reviewed 1.5 result permits the production upload boundary to remain
format-neutral; it does not permit either schema validation or identifier
quality checks to be skipped.

A portfolio-hierarchy experiment may give a step a distinct Project name and
link it to an earlier step as its parent. It must retain the upload response,
verify the child's nested parent identity, retrieve the parent's complete
paginated children collection, and capture Project and metrics risk projections
for both sides. Component deltas apply only to consecutive uploads to the same
Project coordinates; comparing a parent inventory with a child inventory is not
a lifecycle delta. The reviewed DT 4.14.3 result permits sbom-ops to delegate
hierarchy storage and enumeration to DT, but the default
`collectionLogic=NONE` does not permit inferred parent-level risk aggregation.
Changing collection logic is a separate `PORTFOLIO_MANAGEMENT` mutation and is
not authorized by the read-only experiment or by the product MVP.

A routing-metadata experiment must upload the same SBOM and Project coordinates
with an initial and then changed `projectTags` set, retain the upload team's
permissions, compare requested and observed tags after each completed token,
and verify membership through paginated tag-filter queries. It may probe the
Project properties read endpoint, but it must not grant or use management
permission to make the probe succeed. On reviewed DT 4.14.3 behavior, an upload
key with `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD` set initial tags but a later
changed request returned success without replacing them; the read key received
HTTP 403 for Project properties.

Therefore the configured Dependency-Track Project-to-work-repository mapping is
the MVP routing source of truth. DT tags are optional selectors and consistency
signals, not silently mutable routing authority. Project properties are excluded
from the least-privilege read path. A future DT-authoritative routing design
would require explicit `PORTFOLIO_MANAGEMENT`, exact replacement semantics,
post-write reconciliation, and a reviewed migration from YAML.

Every lab run must persist a run-scoped Project ledger before upload and update
it with the observed Project UUID. Lab cleanup must be a local dry-run by
default. Executed cleanup must:

- use a dedicated key with `VIEW_PORTFOLIO` and `PORTFOLIO_MANAGEMENT`
- accept one canonical run UUID rather than an arbitrary Project selector
- require the `dt-lab-` Project-name prefix and matching
  `-lab-<first-eight-run-id-characters>` version
- re-read the live Project and verify name, version, and recorded UUID before
  calling `DELETE /api/v1/project/{uuid}`
- treat an already absent Project as an idempotent success
- fail closed on every identity mismatch and preserve an immutable local audit
- retain local observations and failed-run Projects unless explicitly cleaned

Immediate automatic cleanup is prohibited. Dependency-Track 4.14.3 may still
run asynchronous repository metadata work after BOM event-token completion;
deleting the Project at that point can race the worker. After evidence review
and target quiescence, cleanup requires a separate explicit run-scoped command.
Failed runs remain available for diagnosis until explicitly cleaned.

## Open Items

These are intentionally deferred, not blockers for the first implementation:

- issue reopen policy
- production VEX upload and ingestion workflow
- Jira adapter
- live Dependency-Track and GitHub contract validation
- provider-backed Google Cloud runtime proof of concept
