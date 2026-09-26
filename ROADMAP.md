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
- action-neutral assessments before optional GitHub Issue synchronization
- `--no-github`, dry-run, JSON output, and optional JSONL sync records
- safe, opt-in closure after consecutive verified absence observations
- UUID/PURL-based Finding identity with legacy-key migration
- YAML configuration and Dependency-Track Project to GitHub repository routing
- retry, timeout, pagination, contract fixtures, and failure-path tests
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
| Exploit ledger, 2026-09-06: 25-CVE comparison had no unique Sighting-covered CVE; thirteen vuls.db-only matches included broad references | Defer a production PoC flag. Keep source-attributed public references distinct from applicability and exploitation. | Review a bounded retained URL sample with recorded human rationale before choosing product presentation. |

Prioritize the closure/inventory boundary and datasource coverage over additional
lab workflow machinery. Human-review tooling is sufficient for an initial
sample; escalation, additional adjudication machinery, NFS testing, and power
loss experiments are deferred until an actual deployment or review need exists.
Do not require those storage experiments before a bounded local enrichment run.
A larger public sample needs a stated coverage/freshness question and request
budget, rather than a goal of completing all 151 CVEs.

GitHub synchronization is the final, low-priority validation step (user direction,
2026-09-11). First complete datasource visibility, representative real-SBOM
assessment, inventory/closure boundary tests, and bounded enrichment evaluation.
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
Keep source, severity, null scores, Analysis, and suppression visible, but do not
add a severity fallback until PoC and deployment context can be reviewed.
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
  project-filter failure paths without incorrectly closing Issues.
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
- Implement a least-privilege SBOM upload gateway with server-side
  repository-to-project authorization and Secret Manager integration.
- Validate service-to-service authentication and human browser access separately.
- Publish a pinned, reusable GitHub Actions upload workflow that fails closed by
  default and exposes actionable failures.
- Add Terraform plan/policy checks, negative authorization tests, structured
  audit events, metrics, alerts, and cost estimates before production exposure.

## Phase 1: Operations Foundation (P1)

- Move local JSONL sync records to a queryable operational store.
- Record an audit history for Finding, priority, Analysis, and Issue changes.
- Add KEV forced refresh, cache integrity metadata, concurrent refresh locking,
  freshness monitoring, and synchronization failure alerts.
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
  mappings with source, timestamp, and freshness policy. A snapshot-bound lab
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
  verifying the instance policy before live runs. Request pacing,
  checkpoint/resume, expiry refresh, bounded transient retry, and both
  Retry-After forms now have deterministic contracts. A controlled mid-run
  interruption also resumes only missing signals, and locked timestamp merge
  prevents local concurrent writers from losing distinct or newer entries.
  Two barrier-synchronized local processes preserve both writes. A writer
  killed with `SIGKILL` immediately before replace leaves the old checkpoint
  intact, and the next locked write removes its UUID-named orphan temporary
  file before merging. Temporary-file and parent-directory `fsync` now bound the
  atomic replace, and a pre-replace sync failure preserves the old file.
  Exercise transient HTTP failures on a controlled endpoint when validating the
  acquisition path. Host/storage failure and non-local filesystem experiments
  are deployment-specific follow-ups, not prerequisites for bounded local runs.
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
