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
This describes the process, not a guarantee that all future workflows can be
implemented without durable shared state. The optional asset registry is a
single-host SQLite DB for manually registered services and deployables plus
reviewed DT Project links. Schema v2 also stores append-only human deployment
and exposure declarations by service, deployable, environment, and artifact ID,
with reviewer, evidence, observation time, and expiry. These declarations are
not verified runtime facts, are not joined to individual Findings, and do not
resolve conflicting claims. The DB still does not store verified
build/SBOM/deployment identity or a resolved correction history. Those
remain in [`ROADMAP.md`](ROADMAP.md#phase-0-production-validation-p0). No
external organizational asset register is assumed; platform discovery is
optional evidence and must not silently override reviewed declarations.
With `sync --asset-db PATH`, an existing registry is checked and read-only
loaded before orchestration. The sync result reports one association status per
selected DT Project: `matched`, `unlinked`, `identity_changed`, or `ambiguous`.
Owner and criticality appear only for a `matched` reviewed UUID/name/version;
they do not affect priority or Issue operations. The separate
`registry_deployments` output joins a human declaration only when the reviewed
UUID/name/version still match DT and the declaration's artifact ID equals the
reviewed Project version exactly. It reports `unverified_link`, `unreported`,
`other_artifact`, `expired`, `future_observation`, `conflict`, or `reported`
per Project/environment. Multiple live claims with incompatible deployment or
exposure states remain `conflict`, without an effective verdict. An active
claim is still not an independent runtime observation. This is distinct from
the legacy optional deployment-context JSON (`--asset-inventory`) and does not
establish CI provenance or change priority or Issue operations.
An existing schema-v1 DB remains readable. Adding declaration storage requires
an explicit `assets migrate --backup PATH`, which creates a checked,
non-overwriting v1 backup before the v2 migration; it is never automatic on
`sync` or read. A deployment declaration is append-only and expiry is checked
when listed. No report is treated as confirmed deployment merely because its
artifact ID resembles a DT Project version.
Typical execution modes:

- scheduled poll from CI or cron
- project-scoped ad hoc run
- dry-run for validation

When `runtime.wait_for_analysis` is enabled, the Dependency-Track client waits
for two consecutive project Finding snapshots with identical assessment- and
workflow-relevant inputs, including Finding/Component identity, vulnerability
source and ID, severity and scores, description, Analysis state/detail, and
suppression. This is a stability heuristic, not a server-provided job completion
token. A timeout fails the run and must not be interpreted as verified absence.
The sync result reports `analysis_snapshot_status` as `not_requested`, `stable`,
or `no_projects`; `stable` means only that the configured snapshot heuristic
completed for every processed Project.
DT read failures, malformed Project/Finding responses, and incomplete Project
pagination fail the run rather than representing an empty inventory. The Project
list requires the documented `X-Total-Count` response header on each page and
checks it against the accumulated page count. Transient HTTP failures use the
configured bounded retry policy; authentication and permission failures are
terminal. These checks cannot prove that a syntactically valid Finding array is
complete or that DT's background analysis has finished. Do not enable automatic
Issue closure solely on the strength of a stable snapshot without an operational
review of this remaining uncertainty.

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
- CI uploads CycloneDX BOMs directly to Dependency-Track with a minimally
  scoped API key held in a CI secret store, never in repository files or logs.
  Use a controlled Project name (`service_id/deployable_id`) and immutable
  Project version. Grant `BOM_UPLOAD`; `autoCreate=true` additionally requires
  `PROJECT_CREATION_UPLOAD` (or broader `PORTFOLIO_MANAGEMENT`, which should be
  avoided for this flow). Do not grant analysis or administrative permissions.
- A CI-supplied Project name/UUID is not proof of repository identity or
  artifact provenance. sbom-ops reads DT Projects as candidates and requires
  human review before recording a Project-to-asset link. The risk of a
  compromised CI writing an incorrect Project is accepted for this initial
  design; no SBOM upload gateway is required.
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
- CVSS/EPSS observations and configured thresholds must be finite numbers;
  booleans, NaN, and positive/negative infinity are invalid and must not enter
  priority evaluation or machine-readable results.
- CVSS scores and their threshold must be within 0–10; EPSS scores and their
  threshold must be within 0–1. Out-of-range observations are unavailable, not
  stronger evidence.
- Project filtering is optional and defaults to all accessible projects.
- Every explicitly selected project UUID must appear in the accessible
  Dependency-Track project list. If any selected UUID is absent, the run fails
  before enrichment or GitHub workflow actions rather than succeeding with an
  empty or partial selection.
- `routing.projects` is optional. When it is configured, every processed
  Dependency-Track Project must have exactly one route; an unknown Project is
  rejected rather than sent to the default repository.
- `api_key` and `token` may use `env:VARIABLE_NAME` references. Environment
  variables override file values, and CLI flags override both.
- `SBOM_OPS_CONFIG_FILE` selects the YAML file when `--config` is not provided.
- Unknown sections and keys are rejected to prevent silent configuration typos.
- `sync --refresh-kev` must contact the configured KEV feed even when the local
  cache is within its TTL. Existing ETag/Last-Modified validators may confirm
  that cached content is unchanged. If refresh fails, stale-cache use remains
  opt-in and must be disclosed by `kev_used_stale_cache` in the result.
- New KEV cache records use schema version 1 and a SHA-256 checksum over the
  timestamp, sorted CVE identifiers, and HTTP validators. Invalid checksums or
  malformed versioned records are cache misses and must never be used as stale
  fallback. Structurally valid legacy records without a version/checksum remain
  readable for compatibility and are replaced by the versioned format after a
  successful refresh. This checksum detects accidental corruption; it is not an
  authenticity mechanism against an actor able to rewrite the cache.
- Cache reads and refreshes sharing a cache path are serialized across processes
  with a local SQLite lock file. The lock is released by the operating system if
  the process exits; lock acquisition is bounded based on configured request
  timeout/retry limits. Lock errors fail the sync rather than permit concurrent
  access to a potentially partial cache. Use a local filesystem for this cache.

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
- `cvss_version: str | None`, identifying the selected CVSS field (`CVSSv3`,
  `CVSSv4`, or `CVSSv2`)
- `cwes: tuple[int, ...]`
- `description: str | None`
- `dependency_track_finding_id: str | None`
- `dependency_track_vulnerability_uuid: str | None`
- `vulnerability_source: str | None`
- `vulnerability_aliases: tuple[str, ...]`, containing CVE/GHSA identifiers
  explicitly returned in Dependency-Track alias records
- `dependency_track_component_uuid: str | None`
- `component_purl: str | None`

The primary `vulnerability_id` must come from Dependency-Track's primary
identifier fields. If those are absent, reject the malformed Finding; do not
promote an alias into the primary identifier or stable Finding identity.

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

KEV membership is checked against the primary identifier when it is a CVE and
against explicit CVE identifiers returned in Dependency-Track alias records.
Matching trims surrounding whitespace and is case-insensitive; malformed IDs
and non-CVE aliases do not match. This does not replace the primary identifier,
change the Finding key, or establish equivalence for other intelligence sources.

### Prioritized Finding

Required fields:

- `finding: Finding`
- `enrichment: Enrichment`
- `priority: Priority`
- `rationale: tuple[str, ...]`

### Finding Assessment

The action-neutral sync projection must retain the inputs needed to interpret a
priority without consulting an Issue body:

- `project_uuid` and stable `finding_key`
- `vulnerability_id` and `vulnerability_source`
- `vulnerability_aliases`, preserved as review context and used for KEV matching
  only when Dependency-Track explicitly supplies a syntactically valid CVE alias
- nullable `component_uuid` and `component_purl`, plus `component_name` and
  nullable `component_version`, so vulnerability-level enrichment remains
  traceable to the affected inventory item
- textual `severity`
- nullable numeric `cvss_score` and `epss_score`
- nullable `cvss_version`, so consumers can identify which CVSS scale supplied
  the score used by the configured threshold
- `priority`
- `in_kev`, as an explicit per-Finding boolean rather than a value consumers
  must parse from the rationale text
- nullable `analysis_detail`, passed through from Dependency-Track unchanged as
  the human analyst note; it is context, not a machine decision input
- Dependency-Track `analysis_state` and `is_suppressed`
- `rationale`

A missing numeric score remains `null`; it must not be represented as zero or as
evidence that the Finding is low risk.
An explicit numeric score of `0.0` is a present value and must not be replaced
by another score field or treated as missing during fallback selection.

## Priority Rules

The priority engine must be deterministic and side-effect free.

When Dependency-Track provides multiple valid CVSS scores, the MVP selects
`cvssV3BaseScore`, then `cvssV4Score`, then `cvssV2BaseScore`. It must preserve
the selected version in the assessment and rationale. Invalid or out-of-range
values are skipped, allowing the next valid version to be used.

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
- When the result is `P3`, the rationale must show unavailable or below-threshold
  EPSS/CVSS inputs. If CVSS is unavailable, state that the severity label is not
  substituted for a numeric score. This explains the configured rule result; it
  must not describe `P3` as evidence of low risk or alter the priority policy.

## Asset Inventory Context

`sync --asset-inventory PATH` accepts a reviewed, precomputed JSON file. DT
remains authoritative for SBOM inventory; the file supplies organizational
deployment facts that DT cannot infer from packages. The product does not
contact a CMDB or deployment platform for this input.

The v1 file has integer `schema_version: 1`, `snapshot_id`, timezone-aware
`generated_at`, and a `deployments` array. It is limited to 1 MiB and 2,000
deployments. Each deployment has:

- exact DT `project_uuid`, `service_id`, and `environment`
- nullable `owner` and `deployed_version`; required `deployment_status`
  (`deployed`, `not_deployed`, `unknown`), `exposure_status` (`confirmed`,
  `rejected`, `unknown`, `conflict`), and `criticality` (`critical`, `high`,
  `standard`, `unknown`)
- `source`, timezone-aware `observed_at` and `expires_at`, and optional
  `reviewer`; expiry must be after observation

The same Project may have multiple services or environments. A duplicate
Project/service/environment entry and unknown fields are rejected. The run
result reports the file's declared timestamp and SHA-256 digest, selected
Project deployments, selected DT Projects without a mapping, and inventory
Project UUIDs not returned by DT. The digest identifies the input bytes, not
their trustworthiness. An invalid optional file emits a warning and the core
sync continues with `asset_inventory_status=invalid`.

Expired entries retain their reported values for audit but have effective
owner and deployed version `null`, and effective deployment, exposure, and
criticality `unknown`. A `not_deployed` record cannot claim a deployed version.
The declared version is not yet checked against DT Project version or CI
deployment evidence; the Project UUID join only checks that DT returned it.
Therefore a loaded asset record is review context, not proof that a particular
SBOM or Component is currently deployed. No consumer may label a Finding as
confirmed deployed solely from this v1 Project UUID join.
These facts are scoped to Project/service/environment, not to a particular
Component or Finding. They do not automatically change priority, DT Analysis,
Issue routing, or Issue state. If an advisory snapshot also supplies Project
exposure, both observations remain separate; the product does not silently
choose one. Real asset mappings and owner assignments need review before any
policy or workflow change.

## Advisory Evidence and Deployment Context

The accepted boundary is recorded in
[`ADR 0002`](docs/adr/0002-advisory-evidence-boundaries.md). Product sync now
accepts a bounded, precomputed v1 JSON snapshot via `--advisory-snapshot`; it
does not acquire provider data itself. See
[`examples/advisory-snapshot.example.json`](examples/advisory-snapshot.example.json)
for the full shape.

- Exploit/public-reference observations remain source-attributed and preserve
  `available`, `not_observed`, and `unknown`, source time/revision/freshness,
  total and retained counts, completeness, and upstream record metadata.
- Published PoC references, exploitation reports, scanner templates, Component
  applicability, vulnerable-code reachability, and internet exposure are
  separate dimensions. No source-native flag becomes an sbom-ops verdict.
- Internet exposure is scoped to a Project/deployment environment and requires
  provenance, observation time, and expiry. Missing or stale context is
  `unknown`; contradictory current observations are `conflict`.
- A CVE-level record may be shown beside a Finding only through its primary CVE
  ID or an explicit Dependency-Track alias. It does not prove that the Component
  is affected or deployed in the exposed environment.
- Evidence remains advisory: it cannot alter priority, Dependency-Track
  Analysis/VEX, suppression, Issue state, or remediation workflow.
- The exact signal `published_poc` means a provider reports public-PoC records
  for a syntactically valid CVE; it does not claim that sbom-ops executed or
  validated them. A source-attributed `poc_reports` summary exposes
  `reported`, `not_observed`, or `unknown` and each source's count. Generic
  `exploit-record` and other advisory signals do not count as PoCs. Counts are
  never summed across providers. Only a `fresh` `available` report is
  `reported`; `published_poc` requires an `expires_at` later than `observed_at`,
  and expiry is checked again at review time. All queried sources must be
  effectively fresh and `not_observed` to report `not_observed` within those
  sources. Otherwise the status is `unknown`.
- JSON and text assessment output places a `reported` PoC first only among
  Findings equal in Project, P0–P3, KEV, severity, numeric CVSS, EPSS, Analysis,
  and suppression. It preserves unrelated output positions and does not
  reorder internal Findings or GitHub actions. PoC count is context, not a
  linear weight, and PoC presence is not BOD 26-04 exploit automation.
- Optional acquisition failure must not block the core Dependency-Track sync.
  Product code must not import or execute the lab package.
- `schema_version` must be integer `1`; the document has `snapshot_id`,
  timezone-aware `generated_at`, `vulnerability_observations`, and
  `project_exposure` arrays. The file is limited to 5 MiB, each top-level
  observation array to 10,000 records, and each vulnerability record retains
  at most 20 references. Each vulnerability observation identifies a
  vulnerability, source, signal, outcome (`available`, `not_observed`, or
  `unknown`), timezone-aware observation time, freshness, nullable total count,
  completeness, and at most 20 HTTP(S) references. `not_observed` is valid only
  for complete observations with zero records and no references; partial or
  failed lookups must remain `unknown`. Duplicate source/signal observations
  for one vulnerability are rejected.
- Exposure records require Project UUID, environment, status, source,
  timezone-aware observation and expiry times; expiry must follow observation.
  Expired records retain reported status but have effective status `unknown`.
- Invalid or unreadable optional snapshots emit a warning and sync continues;
  the result reports `advisory_snapshot_status=invalid`. The loader never
  dereferences reference URLs. Evidence is attached only by exact,
  case-insensitive primary ID/explicit alias matching. Project exposure is
  displayed separately and is not inferred to apply to individual Components.
- When a snapshot loads, the run result records its declared `generated_at` and
  SHA-256 of the exact input bytes, alongside `snapshot_id`, for later review.
  The digest identifies bytes; it does not prove who created or approved them.

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
Approval is bound to the resolved target scope: a Component-scoped review must
not be widened to Project scope. Project-scoped VEX requires explicit review of
the complete matching Finding set, including Findings on other Components in
the Project. DT 4.14.3 lab evidence showed that Project scope applies the
decision to matching Findings beyond the reviewed Component.

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
Only a prior issue observation with exactly one `MISSING` state marker and one
valid missing counter below the configured threshold can advance the counter.
A counter without that state, conflicting markers, or an out-of-range counter
starts a new confirmation sequence. When a Finding reappears, the issue's
observation returns to `ACTIVE` and its missing counter is removed.

### Analysis state

MVP must not mutate Dependency-Track analysis state automatically.
The orchestrator reads analysis data and suppression state for workflow
decisions, but Dependency-Track remains authoritative. Project Finding reads
must request `suppressed=true`; omission from DT's default unsuppressed view is
not Finding absence. On the tested DT 4.14.3 target, the Project Finding
projection provides Analysis state, detail, and suppression, but not
justification or response. Those fields are available from a per-Finding
Analysis trail read; the current product client does not make those additional
requests. Do not treat their absence from a Project Finding response as
`NOT_SET` or as empty values. Any future semantic reconciliation that includes
them must combine the Project snapshot and per-Finding trail reads, and validate
the request cost before adoption. Reconciliation must not depend on Project
metrics, `ETag`, `Last-Modified`, or an Analysis update cursor that DT 4.14.3
does not expose.

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
Failure of this optional sink must not replace the primary sync result, but must
be reported on stderr without corrupting machine-readable stdout.

The JSON result and optional JSONL sync log include Dependency-Track
`analysis_detail` values and supplied asset owners verbatim. Treat these
human-authored and organizational details as operationally sensitive and apply
appropriate access and retention controls.

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
path. It also imports the same synthetic SBOM into a second run-scoped Project
and verifies that VEX applied to the target Project does not change the
comparison Project's matching Findings. Product code must not infer Component
isolation from a bare reference or a Project-scoped export.

An invalid-BOM experiment must be explicitly selected and declare its expected
HTTP client-error status, base response media type, and Project-creation side
effect. It must retain safe RFC 9457 problem details and input integrity
metadata without credentials or the multipart body. A synchronous rejection is
a completed negative experiment only when all declared expectations match.
HTTP 400 is non-retryable. Coordinate upload with `autoCreate` must write the
Project ledger before the request because DT 4.14.3 can create an empty Project
before schema rejection. The existing `sbom-ops upload --project` helper uses
an existing UUID; direct CI uploads may use `autoCreate`, but operators must
not treat upload acceptance as a reviewed asset link.

A format-equivalence experiment must ingest equivalent JSON and XML into the
same run-scoped Project version and compare more than acceptance status or item
counts. It must retain normalized inventory and Finding semantics, stable API
identity mappings, dependency-graph projections, and normalized DT re-export.
The comparison is evidence only for the exercised CycloneDX version and fields.
The reviewed 1.5 result permits the direct CI upload flow to remain
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
