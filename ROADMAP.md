# Roadmap

This is the single source of truth for implementation status and planned work.
Behavioral requirements belong in [`SPEC.md`](SPEC.md); architecture decisions
belong in [`docs/adr/`](docs/adr/README.md).

Priority labels mean:

- P0: required before production use
- P1: operational reliability and Security team workflow
- P2: advanced analysis and efficiency
- P3: ecosystem expansion

## Current State

The repository has a working MVP with:

- Dependency-Track project, Finding, EPSS, Analysis state, and SBOM upload clients
- deterministic KEV/EPSS/CVSS priority calculation
- `sync --refresh-kev` bypasses a fresh local KEV cache and conditionally checks
  CISA; stale fallback remains opt-in and visible in the result
- KEV cache reads/refreshes are serialized across processes by a bounded local
  SQLite lock; lock contention fails closed after a timeout
- action-neutral assessments before optional GitHub Issue synchronization
- assessments and priority rationale identify which CVSS version supplied the
  selected score; the DT 4.14.3 `cvssV4Score` response field is now consumed
- action-neutral assessment JSON retains Dependency-Track Component UUID,
  PURL, name, and version where available; text output shows package name,
  version, and PURL alongside priority and evidence inputs for review; JSON and
  text also expose the per-Finding KEV match explicitly; JSON retains the
  Dependency-Track analysis detail as human-authored context and aliases as
  review context; only an explicit, syntactically valid CVE alias may match KEV,
  without changing the primary ID or stable Finding identity
- On the tested DT 4.14.3 target, the Project Finding projection omits Analysis
  justification and response; those require per-Finding Analysis trail reads.
  Keep them out of the MVP assessment until the extra request cost and intended
  consumer are justified.
- `--no-github`, dry-run, JSON output, and optional JSONL sync records
- safe, opt-in closure after consecutive verified absence observations
- UUID/PURL-based Finding identity with legacy-key migration
- YAML configuration and Dependency-Track Project to GitHub repository routing
- retry, timeout, pagination, contract fixtures, and failure-path tests
- `wait_for_analysis` now rechecks all current assessment-relevant Finding
  fields, including Component identity and Analysis detail, before accepting
  two consecutive stable snapshots; the sync result reports `not_requested`,
  `stable`, or `no_projects`. This remains a heuristic, not a DT job token
- explicit project filters fail closed when any requested UUID is absent from
  the accessible Dependency-Track project list
- a hardened repository-local GitHub Actions sync example
- a versioned DT lab scenario manifest, OpenAPI contract inventory, and isolated
  scenario runner with raw observations and Component delta reports
- physical separation of the repository-only DT lab from the product wheel,
  runtime CLI, adapter, and test suite
- run-scoped DT lab Project cleanup with a durable ledger, local dry-run,
  live identity verification, explicit deletion, and immutable audits
- DT lab coverage for Component identity, add/remove lifecycle, Project version
  boundaries, direct/transitive dependency graphs, CycloneDX Services, and
  source/alias/EPSS Finding projections
- hypothesis and product-decision questions attached to every DT lab scenario
- an opt-in, least-privilege Analysis-state experiment that records decisions,
  comments, suppression, audit trails, Finding projections, and metrics without
  entering the default lab run
- a reconciliation-boundary experiment proving comment replay behavior,
  suppression visibility, the lack of API validators, safe final-state
  enforcement, and the minimum state retained outside DT
- an opt-in VEX round-trip experiment that exports a reviewed Analysis decision,
  resets it, re-imports the exported CycloneDX VEX, compares semantic and
  suppression behavior, measures replay idempotency, and safely restores the
  disposable Finding
- an isolated VEX targeting probe that compares unresolved, explicitly declared
  Component, and Project references across two Findings for the same vulnerability,
  plus cross-Project isolation using the same synthetic SBOM
- an explicit invalid-CycloneDX probe that records RFC 9457 rejection details,
  verifies non-retryable HTTP 400 behavior, and tracks the auto-created empty
  Project for cleanup
- a JSON/XML equivalence probe showing stable inventory, dependency graph,
  non-empty Findings, API identities, and normalized re-export for equivalent
  CycloneDX 1.5 inputs
- a parent/child portfolio probe verifying DT-owned hierarchy and paginated
  child enumeration while showing that default `collectionLogic=NONE` does not
  aggregate child risk into the parent
- a routing-metadata probe showing that creation-only upload credentials can set
  initial tags but cannot reconcile changes, and that Project properties are
  unavailable to the least-privilege read key; YAML remains routing authority
- a provenance- and hash-pinned real-world Go, TypeScript, Rails, and Python
  SBOM corpus, with explicit selection and schema-rejection comparison cases
- complete paginated Component observations checked against `X-Total-Count`,
  plus repeatable triage-field coverage summaries
- a lab-only, raw-log-free datasource task-window summarizer that distinguishes
  completed, failed, incomplete, and not-observed evidence without asserting
  datasource freshness
- an append-only-style experiment ledger that separates observed facts from
  interpretation and records failed or partial live runs
- a physically separate exploit-intelligence lab with a pinned Vuls
  `go-exploitdb` baseline, digest-pinned `vuls.db` comparison/offline path, and
  a bounded Vulnerability-Lookup online candidate; source-attributed evidence,
  three-state observation semantics, and CVE association remain distinct from
  Component applicability
- a DT Finding sampler that preserves purl identity, queries each unique CVE
  once, caps retained examples without losing counts, and measured 55 of 151
  CVEs with public references while leaving applicability explicitly unreviewed
- a proposed GCP runtime ADR and static Terraform evaluation harness
- an accepted, source-neutral advisory-evidence boundary in
  [`ADR 0002`](docs/adr/0002-advisory-evidence-boundaries.md); the production
  sync handoff now accepts bounded precomputed v1 JSON with explicit-ID
  joining, separately scoped expiring Project/environment exposure, and
  snapshot timestamp/digest in results; live source acquisition,
  schema-version evolution, and deployment-inventory integration remain
  deferred

## Work tracking and decision records

`ROADMAP.md` is the canonical plan: it records outcomes, priorities, phase
order, and what is intentionally deferred. GitHub Issues track executable work
or explicit decisions, each with scope and acceptance criteria; they are not a
second roadmap. Use `type:decision`, `type:implementation`, and `type:lab` for
project work, reserving `type:remediation` for vulnerability Issues generated
by sbom-ops.

`lab/dependency_track/EXPERIMENTS.md` is the factual ledger for live
Dependency-Track observations. `SPEC.md` and ADRs hold decisions that have
become normative. Link Issues to the relevant ledger entry instead of copying
raw observations into Issue descriptions. Close or update the Issue when the
decision is reflected in the roadmap or a normative document.

## Next work from recorded lab evidence

The following decisions use recorded observations, not scenario completion.
They apply to the tested DT environment; upgrades require revalidation.

| Recorded evidence | Decision and current product status | Next useful work |
| --- | --- | --- |
| DT ledger, 2026-09-01: suppression hides a Finding only from the default view; include-suppressed retains it | Adopt DT Analysis and suppression. The client already includes suppressed Findings; the orchestrator keeps them in inventory before task filtering. A product regression now verifies that suppression cancels pending absence closure. | Exercise a representative read-only dry-run and inspect task transitions before enabling closure. |
| DT ledger, 2026-08-27: NVD Findings exposed EPSS; GitHub/OSV records were absent | Reuse DT EPSS. Missing Findings do not establish source coverage or absence of vulnerabilities. | Verify enabled datasource coverage before comparing ecosystems. |
| DT ledger, 2026-09-03: creation-only upload did not update existing tags; properties returned 403 to the read key | Retain YAML routing; defer migration to DT metadata. | Validate real Project-to-repository mappings without expanding upload permissions. |
| DT ledger, 2026-09-25/26: Component-scoped VEX affected one Component; Project scope affected matching Findings within that Project, while identical Findings in a second Project stayed unchanged | Keep DT as VEX/Analysis authority; bind approval to target Project and scope. Never widen a Component review to Project scope. | Phase 2 must present the complete target-Project Finding diff and require explicit approval when VEX scope is Project-wide. |
| Exploit ledger, 2026-09-06 and 2026-09-27/28: CVE-level public references are noisy, source-specific, sometimes stale, and often unrelated to an executable PoC; provider flags are assertions, not sbom-ops verdicts. | Keep source provenance, reference kind, freshness, applicability, exploitation, and exposure separate. No `has_poc` or source-confidence score; no automatic priority or Analysis change. | [ADR 0002](docs/adr/0002-advisory-evidence-boundaries.md), the product's optional snapshot input, and a lab-only offline exporter implement the bounded handoff. A 25-CVE/149-record retained real-SBOM sample passed product snapshot loading with 19 `available`, 6 `not_observed`, and explicit `unknown` freshness because no source-age rule is established. The product dry-run below verified the Finding join; live acquisition and deployment-inventory integration remain deferred. |

Current execution focus (2026-10-04): exploratory lab work is paused. A
read-only product dry-run against the current local DT inventory processed 27
Projects and 1,750 Findings both with and without the retained advisory
snapshot. The snapshot attached to 49 Findings (25 vulnerability IDs across
three Projects); all 1,750 non-advisory assessments, priorities, and action
counts were identical. Both runs used `--dry-run --no-github` and produced zero
Issue actions. A separate `--wait-for-analysis` run reached `stable` for one
Project with 644 Findings and 21 advisory matches. The original sample's
Project UUIDs are no longer accessible, so this validates the current product
join, not a rerun of those exact Project snapshots. Local output remains under
ignored `var/product-validation-20261004/`. The product closure rule now
requires a consistent prior `MISSING` state and count; a counter alone or
conflicting markers restart confirmation, and reappearing Findings clear stale
missing state. Issue-enabled dry-run and live GitHub closure remain the final integration
validation. Resume a targeted lab experiment only when a concrete product
decision cannot be made from recorded evidence.

Asset context is now the first product workstream (user direction,
2026-10-04). The optional v1 `--asset-inventory` input and offline fictional
scenario show Project/service/environment, owner, deployment, exposure,
deployed version, criticality, expiry, and mapping gaps without changing
priority or Issues.
An additional read-only product run attached a clearly fictional asset record
to one existing DT Project with 644 Findings; the record matched, all 644
non-advisory Finding assessments matched the earlier run, and Issue actions
remained zero. The synthetic input and result are ignored under
`var/product-validation-20261004/`; they establish join behavior, not real
ownership or exposure.
Next validate one real build-to-SBOM-to-DT-Project-to-deployment chain, including
the immutable artifact identity, Project UUID resolution, deployed version,
environment, and ownership. A manual UUID entry is only a learning exercise:
the current Project/version join cannot prove the deployed artifact matches the
SBOM.
The 2026-10-07 local probe found only the Dependency-Track service container
running, not a representative application deployment. Its fixed image ID was
read from Docker and an OS-package-only CycloneDX SBOM with 103 Components was
generated locally; no BOM was uploaded to DT and no deployment was registered.
This checks only that a running image can be tied to a generated SBOM, not the
CI build, application dependency inventory, DT Project, or production runtime
chain. Use a representative application artifact for that gate rather than
counting the DT infrastructure image as product validation.
On 2026-10-08 a purpose-built, dependency-free Go HTTP container completed a
local end-to-end identity exercise. The running container's image ID matched
the ID used for a CycloneDX 1.6 SBOM, the DT Project version, and a human
deployment report in SQLite. DT ingested all three SBOM Components, and a
GitHub-disabled dry-run joined the reviewed Project and report while leaving
Issue actions at zero. Its 47 Findings were all for the Go standard library
and all P3 under current score rules; this is not a production risk verdict.
After the disposable container was stopped, a second report produced
`conflict`, not an automatic transition to `not_deployed`; Finding priorities
remained unchanged. Schema v3 now supports an explicit, audited successor
report for this transition; the 2026-10-08 live run predates that change.
On 2026-10-09 a fresh DB and the same DT Project showed the successor excludes
the old claim, but the post-stop live sync occurred after its two-hour TTL and
returned `expired`, not an in-window `reported/not_deployed`. Fixed-time
read-only evaluation showed the expected before/after transition. An in-window
live check remains open. The DBs and raw sync outputs remain ignored under
`var/product-validation-20261007-identity-demo/` and
`var/product-validation-20261009-supersession/`. These exercises validate
identity plumbing, not CI provenance, SBOM completeness, deployment discovery,
or internet exposure. Next repeat the chain with a real CI-built application
artifact before asset context can influence prioritization.
The CI workflow now packages the representative image, its immutable image ID,
and a checksum list without DT credentials or registry publishing. On
2026-10-10, a successful main run was downloaded: checksums, source commit,
archive image-config digest, and the image ID embedded in a Docker-free Trivy
CycloneDX SBOM matched the artifact metadata. Runtime inspection, SBOM import,
DT readback, deployment join, and in-window stop/supersession still require a
reachable Docker daemon and DT before this gate can be marked complete. This
artifact is not signed build provenance, and the offline license-only SBOM
check does not establish vulnerability or dependency completeness.
The [target operating flow](docs/operations.md#sbomと稼働資産を結ぶ運用フロー一部実装)
now assumes no external organizational asset register. A small, manual-first
SQLite asset DB exists for one host with local persistent storage; it now
accepts append-only human deployment reports. A read-only, ambiguity-aware
join to reviewed DT Project name/version and an exact declared artifact ID
is implemented, but does not prove that the artifact is running or that the
SBOM came from that build. The next product gate is an operator-verified real
build-to-SBOM-to-DT-to-deployment chain. AWS or other platform discovery is
optional later evidence,
not a prerequisite for registration. A human-reported deployment is not
verified runtime evidence. Only after the identity evidence should asset-based
priority or routing policy be considered with human review.
Missing datasource visibility follows this work.

Prioritize asset mapping and datasource coverage over additional lab workflow
machinery. Human-review tooling is sufficient for an initial
sample; escalation, additional adjudication machinery, NFS testing, and power
loss experiments are deferred until an actual deployment or review need exists.
Do not require those storage experiments before a bounded local enrichment run.
A larger public sample needs a stated coverage/freshness question and request
budget, rather than a goal of completing all 151 CVEs.

GitHub synchronization is the final, low-priority validation step (user direction,
2026-09-11). First complete reviewed asset mapping, datasource visibility,
representative real-SBOM assessment, inventory/closure boundary tests, and
bounded enrichment evaluation.
Keep GitHub disabled during these runs. Validate Issue routing, GitHub-enabled
dry-run, and live create/update/closure only after those product decisions are
reviewed; GitHub integration is not a prerequisite for lab progress.
Vulnerability-Lookup results currently establish public, unauthenticated read
behavior only. API-key support is optional; authenticated coverage, access policy,
rate limits, and suitability for frequent polling remain unverified. Treat
authentication or transport failures as unknown, never as absent evidence.

The 2026-09-11 read-only product run evaluated 191 Findings across 22 accessible
lab Projects with GitHub disabled. All Findings were NVD-sourced and had EPSS;
ten Projects had no Findings and none had suppressed Findings. This validates
the current read/assessment path, not real repository routing, Issue transitions,
or datasource completeness. Next, obtain a redacted administrator observation of
enabled analyzers, mirrors, and last successful synchronization; then select
representative real-SBOM Projects. Defer the GitHub dry-run target to the final
integration step. After the user added `SYSTEM_CONFIGURATION`, a read-only
configuration check confirmed GitHub Advisories disabled, no configured OSV
ecosystems, and NVD plus EPSS enabled. Mirror cadence settings were 24 hours;
these are not evidence of successful synchronization. Next, review the desired
OSV ecosystems/GHSA configuration before changing it and rerunning real SBOMs.
The corpus readiness check passed all six pinned artifacts. Start with OSV Go,
npm, PyPI, and RubyGems after a verified datastore backup and explicit approval
of the instance-wide change; keep OSV alias sync disabled. Measure one source
change at a time and compare per ecosystem/package identity. OSV disablement
retains mirrored data and is not a rollback. Evaluate GHSA separately with a
dedicated appropriate credential; do not reuse the GitHub CLI token implicitly.
See the ledger's OSV/GHSA readiness entry for counts and execution gates.
The local H2 instance now has a cold full-data backup under ignored
`var/dt-lab/backups/`; the original instance restarted and exposed 22 Projects.
An isolated restore now starts healthy on the exact original image with network
disabled and no published ports. Existing-key authentication works; 22 Projects,
191 portfolio vulnerabilities, and the five selected source settings match the
baseline observations. This is a bounded recovery check, not a full row-level
comparison or verification of every encrypted integration secret. The restored
container is stopped and retained. The explicit, audited `configure-osv` command
has now enabled the four ecosystems and verified the exact set through readback;
DT reordered its serialization. GHSA and OSV alias sync remain disabled. The
initial mirror completed in about 12 minutes 38 seconds. Reimported pinned Go,
n8n, and Airflow inputs retained Component counts and produced 22, 42, and 19
Findings respectively (earlier: 7, 0, 0). Product dry-runs completed. All n8n and
Airflow Findings became P3, including HIGH labels with missing numeric scores:
retain missing-score visibility as a requirement, but defer triage rule changes
until PoC and asset-context evidence can be acquired and linked. Do not interpret
P3 as low risk or change policy implicitly. Source
GITHUB appeared despite GHSA mirroring being disabled; source labels do not
identify enabled acquisition mechanisms. Rails/OpenProject now also completed:
16,742 Components and 619 Findings (earlier: 285), all with PURL/Component UUID,
but only 307 primary CVE IDs and no aliases. The 17,831-to-16,742 component-count
difference is accounted for by repeated PURL identities plus two no-PURL
GitHub-action occurrences (same name/version/CPE, distinct source references
and locations) represented once each by DT. No unique name/version identity was
missing in the no-PURL comparison; the API did not establish that occurrence
location metadata survives. Compare normalized inventory identity separately
from raw SBOM occurrence counts. Next assess CVE/alias correlation gaps and
deployment-context joins; measure incremental synchronization separately.
The experiment also exposed silent optional sync-log failure when its parent
directory is absent. The CLI now makes that failure visible on stderr without
losing the primary sync result or corrupting JSON stdout. Current validation
runs must still create and verify the evidence directory before execution.
The 2026-09-13 read-only rerun processed 1,066 Findings across 26 accessible lab
Projects with GitHub disabled and emitted the expanded assessment contract for
every Finding. Numeric CVSS and EPSS were absent on 561 records; all 135 HIGH
records without numeric CVSS remained P3 under the unchanged numeric-score rule.
The P3 rationale now distinguishes unavailable from below-threshold EPSS/CVSS
and explicitly says severity is not substituted for missing numeric CVSS. Keep
the existing rule unchanged; do not add a severity fallback until PoC and
deployment context can be reviewed. Keep source, severity, null scores,
Analysis, and suppression visible, and do not interpret P3 as low risk.
The 2026-09-14 datasource log-window check recognized the initial OSV, NIST, and
EPSS completions, but found no lifecycle event for those tasks in two later
30-hour samples despite a healthy, restart-free container and non-empty general
logs. This does not prove the mirrors did not run or that data is stale. Treat
freshness as unknown when a stable last-success signal is unavailable; do not
infer it from enabled settings or configured intervals. Next identify supported
task telemetry or stable synchronization timestamps before adding configurable
stale thresholds or product alerts. Do not restart DT merely to manufacture a
freshness result.
The follow-up internal-marker diagnostic found all four OSV success markers still
at the initial mirror start times about 73 hours later. This establishes no newer
successful OSV update was recorded on the tested 4.14.3 datastore, but does not
separate a missing scheduler run from an early failure. Scheduler controls showed
19 hourly-task executions and three six-hour-task executions over about 78.5
wall-clock hours. Combined with Alpine's separate fixed-delay timers, this is
consistent with an intermittently suspended lab host that has not yet accrued
the first 24-hour repeat interval; it is not evidence of a global scheduler stop.
Keep these version-coupled filesystem markers out of production code. Next keep
the target active through the first effective recurrence, then inspect
notification/error telemetry only if the mirror remains absent. In deployment
design, monitor runtime availability separately from datasource age.
The 2026-09-15 bounded follow-up observed approximately 22 hourly control
executions in total and unchanged OSV success markers. Wait for at least three
additional non-overlapping hourly starts before evaluating the first mirror
recurrence; use task count rather than a wall-clock deadline on this lab host.
The 2026-09-20 read-only `configProperty` check confirmed OSV is enabled for
RubyGems, PyPI, Go, and npm and that `task-scheduler.osv.mirror.cadence` is 24
hours. After the 2026-09-15 restart, OSV still recorded only its successful
startup incremental run while control tasks continued. Treat this as an
unresolved DT timer-lifecycle or task-failure investigation; do not change
product freshness logic or force a mirror. The next useful lab action is
supported telemetry or a reviewed DT-version-specific diagnostic.
On 2026-09-21, after the API path recovered, the OSV task completed a full
fallback mirror: 4,778 RubyGems, 25,645 PyPI, 9,295 Go, and 229,117 npm
advisories. This confirms the datastore can refresh, but does not explain the
preceding gap or provide a supported freshness API. Preserve the lab-only
marker/log diagnostic and keep product freshness unknown until a stable DT
telemetry contract exists.

## Phase 0: Production Validation (P0)

- Establish a reproducible, immutable artifact identity linking the generated
  SBOM and verified DT Project UUID; distinguish a human-reported deployment
  from an independently observed runtime deployment. Cover
  multiple containers, overlapping old/new rollouts, missing/ambiguous matches,
  stale observations, and corrections. Reject silent reuse of one DT Project
  UUID for a different artifact; record reviewed SBOM corrections. Do not assert
  deployment from Project UUID or a mutable version tag alone.
- Implement a minimal manual-first sbom-ops asset DB because no external
  organizational asset register is assumed. Use SQLite on one host with local
  persistent storage for the initial deployment; do not share its file across
  hosts or over network storage. Persist artifact/SBOM/Project links, reviewed
  service and deployment declarations, provenance, corrections, and audit
  history; do not copy DT's Findings or GitHub's remediation workflow. Define
  schema migrations, retention, integrity checks, online backup/restore, and
  bounded write contention before production use. Revisit a server DB if
  multi-host writers become necessary. Ephemeral CI jobs must not keep the
  SQLite file; design a durable registration endpoint or server DB before
  enabling CI writes to this registry.
  The registry rejects missing DB paths on read/approval, exposes SQLite
  integrity/foreign-key checks, and creates non-overwriting online backups.
  Schema v2 added append-only human deployment declarations. Schema v3 adds
  one-to-one, same-subject report supersession with a backup-first migration
  from v1/v2. Retention policy, broader conflict resolution, and production
  restore drills remain open.
- Define the manual registration contract and CLI first. Register a stable
  service ID, owner, business criticality and rationale, and planned
  environments before any build or DT Project exists. A system grouping is
  optional; each independently built deployable unit gets its own artifact,
  SBOM, and DT Project mapping. The CLI now records human deployment and
  exposure declarations with artifact ID, reviewer, evidence, and expiry as
  append-only claims, not verified running state. The read-only sync now joins
  exact version-matching declarations to reviewed DT Project links while
  showing stale, missing, future, other-artifact, and conflicting claims.
  Explicit one-to-one human-report correction is implemented. Next verify one
  real immutable artifact chain; support reviewed JSON import through
  the same validation path. Preserve `unknown` for missing declarations and
  show conflicts; never silently replace a human declaration with collected
  data.
- Prove a real build-to-SBOM-to-DT-Project chain and an operator-entered
  deployment for one representative service, then test what can and cannot be
  independently verified. Keep the current JSON input as an evaluation bridge,
  not proof of deployed coverage. Add read-only ECS/EKS or other-platform
  discovery only when it closes a specific evidence gap; keep observations
  source-attributed and handle untagged/unmapped workloads, stale/partial
  scans, and overlapping versions. Discovery is not a prerequisite for the
  manual-first registry.
- Use direct CI-to-DT BOM upload with registered
  `service_id/deployable_id` Project names and immutable versions. The SQLite
  registry, candidate discovery, and explicit Project-link approval are the
  first implemented slice. Read-only auditing now flags reviewed links that
  are not visible, changed, or ambiguous in DT. An explicit `sync --asset-db`
  now reports reviewed links for selected Projects without altering priority or
  Issues. A local Quick Start trial used a disposable DT Project and separate
  SQLite DB: BOM upload, candidate approval, link audit, backup check, and
  read-only sync succeeded; DT API and sync each returned 77 Findings. The
  DT UI login worked, but Finding inspection in the UI was not completed.
  A subsequent `sync --asset-db` dry-run reported the reviewed link as
  `matched` with its registered owner and criticality; all 77 Findings were
  still processed and no Issue action occurred.
  Next, test real CI run/artifact evidence, re-uploads, corrections,
  permissions, and deployment joins. Do not treat
  Project name, tags, or CycloneDX properties as verified identity alone.
- Validate Dependency-Track Project, Finding, EPSS, Analysis, pagination, and
  processing-token behavior against a representative environment.
- Run the highest-value planned Identity, Lifecycle, Portfolio, Triage, and
  Robustness scenarios in `lab/dependency_track/scenarios/scenarios.yaml` until
  each product decision has sufficient evidence. The planned list is an
  uncertainty backlog, not a coverage target.
- Apply the verified triage boundary: DT owns Analysis decisions, comments,
  suppression, and VEX; sbom-ops uses complete include-suppressed snapshots and
  retains only semantic reconciliation and work-item correlation state.
- For each reviewed lab result, explicitly choose DT capability adoption,
  verified constraint encoding, minimal gap implementation, or evidence-backed
  rejection/deferment.
- Validate GitHub Issue create, update, migration, and safe closure after a
  reviewed dry-run.
- Exercise timeout, `429`, `5xx`, partial reads, analysis-in-progress, and
  project-filter failure paths without incorrectly closing Issues. The client
  now rejects malformed Finding and Project responses, inconsistent or
  incomplete Project pagination, and malformed BOM processing status; unit
  tests cover terminal 401/403, transient retries, and no-close on failed
  Finding reads. A valid-looking but incomplete Finding array and the absence
  of a server-side analysis-completion signal remain unresolved closure risks.
- Validate YAML overrides, secret references, and multi-project routing in
  representative environments.
- Confirm minimum permissions for separate Dependency-Track read/upload keys and
  GitHub Issue access.
- Run the hardened sync workflow in GitHub Actions and document its required
  permissions and secrets.

## Phase 0.5: Secure GCP Delivery (P0/P1)

The normative controls are in the
[`Google Cloud Deployment Contract`](SPEC.md#google-cloud-deployment-contract).
The runtime decision and PoC gates are in
[`ADR 0001`](docs/adr/0001-gcp-secure-delivery-runtime.md).

- Expand [`infra/gcp/poc`](infra/gcp/poc/README.md) into a provider-backed PoC
  comparing GKE Autopilot and Cloud Run against Dependency-Track's runtime needs.
- Validate separate Dependency-Track API, frontend, and external PostgreSQL
  deployment, including migrations, backup, restore, upgrade, and rollback.
- Implement tightly scoped GitHub OIDC and Workload Identity Federation trust.
- Validate direct CI-to-DT upload with `BOM_UPLOAD` and, only if auto-creating
  Projects, `PROJECT_CREATION_UPLOAD`, protected CI
  secrets, immutable Project coordinates, and operator-reviewed asset links.
  Reconsider a gateway only if operational evidence justifies its complexity.
- Validate service-to-service authentication and human browser access separately.
- Publish a pinned, reusable GitHub Actions upload workflow that fails closed by
  default and exposes actionable failures.
- Add Terraform plan/policy checks, negative authorization tests, structured
  audit events, metrics, alerts, and cost estimates before production exposure.

## Phase 1: Operations Foundation (P1)

- Extend the Phase 0 verified artifact/deployment join to a small reviewed
  set of services in the sbom-ops asset DB. Establish source update cadence,
  expiry monitoring,
  correction handling, and review ownership. The optional v1 asset input and
  fictional offline scenario are implemented, but do not verify artifact
  identity. Keep criticality and exposure visible without changing priority or
  Issues until a separate policy decision is reviewed.
- Move local JSONL sync records to a queryable operational store.
- Record an audit history for Finding, priority, Analysis, and Issue changes.
- Add freshness monitoring and synchronization failure alerts. Explicit
  `--refresh-kev`, schema-v1 SHA-256 cache integrity, and bounded cross-process
  refresh locking are implemented; valid legacy caches remain readable and are
  upgraded on the next successful refresh.
- Add a remediation policy model that keeps priority separate from SLA dates.
- Extend `PriorityContext` with asset criticality, exposure, reachability, and
  compensating controls without allowing them to mutate priority implicitly.
- Prioritize evidence acquisition and identity joins before triage-policy design
  (user agreement, 2026-09-11). Preserve Project UUID, Component UUID/PURL,
  vulnerability source/ID, and separately evidenced CVE mappings. The first
  post-OSV three-corpus sample had 83 Findings with PURLs/Component UUIDs but only
  seven primary CVE IDs and no aliases. The existing CVE-only exploit sampler
  rejects all three mixed-ID captures. A new evidence-only resolver now preserves
  mixed IDs and samples by prefix and sorted-family range. In a 25-ID live run,
  Vulnerability-Lookup resolved eight of nine GHSA and all eight PYSEC IDs, but
  none of eight GO IDs. Direct OSV reads confirmed the 16 candidates, supplied
  CVE aliases for seven GO IDs, and confirmed one GO and one GHSA record had no
  CVE alias. Do not use Vulnerability-Lookup correlation as the sole resolver;
  merge source-attributed candidates and expose disagreement or absence for
  review before any PoC join. Only explicit aliases are identity candidates;
  never promote `related`, `upstream`, or free-text references to equivalence.
  Do not drop non-CVE Findings or treat them as PoC absence. Validate future
  mappings with source, timestamp, and freshness policy. The product now checks
  KEV against a primary CVE or a syntactically valid, explicit Dependency-Track
  CVE alias while retaining the original ID and Finding key; this bounded join
  is not reused for other intelligence sources. A snapshot-bound lab
  review queue now makes every candidate `unreviewed`, requires an identified
  human, rationale, and timezone-aware decision, and emits confirmed aliases
  without authorizing downstream actions. Use reviewed mappings—not source
  agreement alone—for the next bounded PoC comparison. The handoff adapter now
  revalidates both snapshots and all review projections, preserves original IDs
  and human provenance, accepts only confirmed aliases, caps mappings at 25, and
  performs no implicit network request. A separate mapped-ID PoC runner now
  validates and displays the five-signal request plan in dry-run mode, requires
  explicit execution, enforces 25-CVE/125-request limits, and reuses checkpoint
  and pacing controls. No live mapped-ID PoC run may occur until a human completes
  at least one real review.
- Evaluate internet-facing evidence per deployment environment and Project or
  service, with authoritative source, observation time, expiry, and explicit
  unknown/conflict states. Use a deployment inventory or reviewed operator input;
  package PURLs, public repositories, and SBOM service URLs do not establish
  actual exposure. Public exposure and reachability of a vulnerable function are
  separate observations. Do not infer exposure for the imported public corpus.
- Keep published PoC, actual exploitation, component applicability, and exposure
  as distinct evidence. Assess available/not-observed/unknown and freshness before
  proposing any configurable priority policy. Lab runs must not assign a final
  security decision or silently change current prioritization.
- Adopt the 2026-10-07 PoC ordering decision: for otherwise equivalent Findings
  in the same P0–P3 category, a source-reported public PoC should be reviewed
  first. A source-attributed, CVE-scoped presence/count projection and
  deterministic review-output tie-break are implemented for the explicit
  `published_poc` snapshot signal. The current Vuls exporter emits general
  `exploit-record` observations and therefore does not trigger the tie-break.
  The isolated lab now exports recorded Vulnerability-Lookup PoC Sighting
  counts with a configured expiry window; product-runtime acquisition remains
  future work. Do not assess
  whether PoC code works, treat generic public-reference counts as PoC counts,
  demote `unknown` as if it meant none, or equate PoC with BOD 26-04 exploit
  automation. Category/SLA changes remain a later policy decision with asset
  context and EPSS double-counting considered; see `docs/priority-policy.md`.
- Continue the bounded Vulnerability-Lookup evaluation as a complementary
  online source. In a 2026-09-26 refresh of the same 25-CVE cohort, five CVEs
  still had Sightings in both sources, `vuls.db` alone covered thirteen, and
  Vulnerability-Lookup alone covered one new Telegram-associated Sighting.
  That label does not establish a usable PoC. All 25 EPSS observations had
  changed since the 2026-09-05 query and carried a 2026-09-25 data date. Keep
  `vuls.db` as the broader comparison/offline candidate; evaluate
  Vulnerability-Lookup for independently attributed exploitation, KEV, EPSS,
  and VEX signals rather than as a PoC replacement. The public CIRCL policy
  currently exposes neither a Sighting `since` filter nor a stream; use
  targeted CVE refreshes with checkpointing and the 3-second default pacing,
  verifying the instance policy before live runs. A one-CVE check over a mixed
  Go capture completed five public reads in 14.38 seconds; the sampler reported
  15 non-CVE Findings separately instead of failing CVE enrichment. Request pacing,
  checkpoint/resume, expiry refresh, bounded transient retry, and both
  Retry-After forms now have deterministic contracts. A controlled mid-run
  interruption also resumes only missing signals, and locked timestamp merge
  prevents local concurrent writers from losing distinct or newer entries.
  Two barrier-synchronized local processes preserve both writes. A writer
  killed with `SIGKILL` immediately before replace leaves the old checkpoint
  intact, and the next locked write removes its UUID-named orphan temporary
  file before merging. Temporary-file and parent-directory `fsync` now bound the
  atomic replace, and a pre-replace sync failure preserves the old file.
  Local controlled-endpoint tests now exercise `429 → 200`, `503 → 200`,
  connection-close → retry, and a delayed-response timeout through the real
  adapter and HTTP transport.
  Host/storage failure and non-local filesystem
  experiments are deployment-specific follow-ups, not prerequisites for
  bounded local runs.
  Lock waits use a configurable fail-closed timeout.
  Preserve source, upstream type, timestamps, API policy/version, OCI provenance,
  and `available` / `not_observed` / `unknown` outcomes. Neither source may map
  record presence directly to P0 or DT `EXPLOITABLE`.
- Continue the manifest-backed evidence quality review. The first
  `vuls-db-only` queue reduced 37 retained records to 27 URLs and exposed three
  cross-CVE reused URLs plus two cross-datasource duplicate pairs. The review
  template and validator now require reviewer, timestamp, rationale, exact queue
  run, snapshot digest, and immutable record identity. An agreement tool now
  compares the overlapping work of two independent reviewers using exact
  agreement, Cohen's kappa, a confusion matrix, and explicit disagreements,
  without applying a pass/fail threshold. A provenance-validated adjudication
  queue now carries only disagreements, both rationales, and immutable snapshot
  bindings to a required new human reviewer. A non-overwriting template and
  fail-closed partial application now reject either original reviewer as
  adjudicator and retain unresolved records as `unreviewed`.
  Conduct a real human review sample, use that artifact to refine label guidance,
  then define escalation for unresolved adjudications and explicit re-review
  rules across source snapshots. Mechanical URL hints must remain
  `unreviewed` and must not become confidence, priority, applicability, or
  Analysis decisions.

## Phase 2: Human-reviewed VEX (P1)

- Add a Security team candidate queue and cross-project context view.
- Add mandatory rationale/evidence templates and Draft / Review / Approve /
  Publish states.
- Validate CycloneDX schema, resolve Component versus Project target scope,
  reject unresolved references, show the complete Finding diff, and require
  explicit approval before Dependency-Track ingestion.
- Add VEX versioning, expiry, re-evaluation triggers, and reviewer audit history.

## Phase 3: Reachability Evidence (P2)

- Integrate `govulncheck`, `pip-audit`, and `osv-scanner` through independent
  adapters with mock fixtures and explicit failure behavior.
- Store tool version, inputs, output, timestamp, and confidence as advisory
  evidence for human VEX review.
- Never use reachability alone to suppress a Finding or publish a VEX decision.

## Phase 4: LLM Triage Assistance (P2)

- Generate structured summaries, impact explanations, remediation proposals,
  evidence references, confidence, and follow-up questions.
- Keep model output separate from authoritative Dependency-Track Analysis state.
- Require human review before publishing suggestions to work-management systems.
- Prevent the LLM from changing priority, accepting risk, suppressing Findings,
  changing VEX state, or closing Issues.

## Phase 5: Integrations and Visibility (P3)

- Jira adapter
- Slack and Teams notifications
- Security team dashboard and operational metrics
- SARIF and Dependency Graph integrations
- Multi-tenancy

## Delivery Order

```text
Phase 0: production validation
    ↓
Phase 0.5: GCP runtime PoC and secure SBOM delivery
    ↓
Phase 1: durable operations and audit
    ↓
Phase 2: human-reviewed VEX
    ↓
Phase 3: reachability evidence
    ↓
Phase 4: LLM assistance
    ↓
Phase 5: integrations and visibility
```
