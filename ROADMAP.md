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
  Component, and Project references across two Findings for the same vulnerability
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

## Next work from recorded lab evidence

The following decisions use recorded observations, not scenario completion.
They apply to the tested DT environment; upgrades require revalidation.

| Recorded evidence | Decision and current product status | Next useful work |
| --- | --- | --- |
| DT ledger, 2026-09-01: suppression hides a Finding only from the default view; include-suppressed retains it | Adopt DT Analysis and suppression. The client already includes suppressed Findings; the orchestrator keeps them in inventory before task filtering. A product regression now verifies that suppression cancels pending absence closure. | Exercise a representative read-only dry-run and inspect task transitions before enabling closure. |
| DT ledger, 2026-08-27: NVD Findings exposed EPSS; GitHub/OSV records were absent | Reuse DT EPSS. Missing Findings do not establish source coverage or absence of vulnerabilities. | Verify enabled datasource coverage before comparing ecosystems. |
| DT ledger, 2026-09-03: creation-only upload did not update existing tags; properties returned 403 to the read key | Retain YAML routing; defer migration to DT metadata. | Validate real Project-to-repository mappings without expanding upload permissions. |
| Exploit ledger, 2026-09-06: 25-CVE comparison had no unique Sighting-covered CVE; thirteen vuls.db-only matches included broad references | Defer a production PoC flag. Keep source-attributed public references distinct from applicability and exploitation. | Review a bounded retained URL sample with recorded human rationale before choosing product presentation. |

Prioritize the closure/inventory boundary and datasource coverage over additional
lab workflow machinery. Human-review tooling is sufficient for an initial
sample; escalation, additional adjudication machinery, NFS testing, and power
loss experiments are deferred until an actual deployment or review need exists.
Do not require those storage experiments before a bounded local enrichment run.
A larger public sample needs a stated coverage/freshness question and request
budget, rather than a goal of completing all 151 CVEs.

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
- Continue the bounded Vulnerability-Lookup evaluation as a complementary
  online source. A deterministic 25-CVE DT sample found Sighting coverage for
  five CVEs, all already covered by `vuls.db`, while `vuls.db` alone covered
  thirteen more. Keep `vuls.db` as the broader comparison/offline candidate;
  evaluate Vulnerability-Lookup for independently attributed exploitation,
  KEV, EPSS, and VEX signals rather than as a PoC replacement. Request pacing,
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
