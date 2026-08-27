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
- a proposed GCP runtime ADR and static Terraform evaluation harness

## Phase 0: Production Validation (P0)

- Validate Dependency-Track Project, Finding, EPSS, Analysis, pagination, and
  processing-token behavior against a representative environment.
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

## Phase 2: Human-reviewed VEX (P1)

- Add a Security team candidate queue and cross-project context view.
- Add mandatory rationale/evidence templates and Draft / Review / Approve /
  Publish states.
- Validate CycloneDX schema and SBOM/VEX identity, show a publication diff, and
  require explicit approval before Dependency-Track ingestion.
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
