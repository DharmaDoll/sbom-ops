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
  KEV, EPSS, and VEX signals rather than as a PoC replacement. Add request
  pacing, checkpoint/resume, cache freshness, 429/5xx recovery, and source URL
  quality sampling before a 151-CVE public run. Preserve source, upstream type,
  timestamps, API policy/version, OCI provenance, and `available` /
  `not_observed` / `unknown` outcomes. Neither source may map record presence
  directly to P0 or DT `EXPLOITABLE`.
- Continue the manifest-backed evidence quality review. The first
  `vuls-db-only` queue reduced 37 retained records to 27 URLs and exposed three
  cross-CVE reused URLs plus two cross-datasource duplicate pairs. The review
  template and validator now require reviewer, timestamp, rationale, exact queue
  run, snapshot digest, and immutable record identity. An agreement tool now
  compares the overlapping work of two independent reviewers using exact
  agreement, Cohen's kappa, a confusion matrix, and explicit disagreements,
  without applying a pass/fail threshold. Conduct a real human review sample,
  use that artifact to refine label guidance, and define explicit re-review and
  adjudication rules across source snapshots. Mechanical URL hints must remain
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
