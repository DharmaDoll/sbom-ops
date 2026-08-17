# Roadmap

## MVP

- Dependency-Track API
- KEV lookup
- Dependency-Track EPSS retrieval
- Priority Engine
- GitHub Issues
- Basic GitHub Actions sync example

---

## v0.2

- Duplicate detection
- Safe, opt-in closure after consecutive verified absence
- UUID/PURL-based Finding identity and legacy-key migration
- Separate Finding / Analysis / Remediation states
- Dependency-Track project to GitHub repository routing
- Config file
- Docker

---

## v0.2.x Operations Foundation

- Persistent structured synchronization logs
- Audit history for Finding, priority, Analysis state, and GitHub Issue changes
- KEV cache with configurable five-hour default TTL
- ETag/Last-Modified conditional refresh
- Stale-cache fallback and forced KEV refresh command
- Cache freshness and sync failure alerts

---

## v0.2.x Secure GCP Delivery Foundation

- Architecture decision record and proof of concept comparing Cloud Run with a
  supported, operable alternative such as GKE
- Separate Dependency-Track API server, frontend, and external PostgreSQL
- Keyless GitHub Actions authentication with OIDC and Workload Identity Federation
- Immutable organization/repository and reusable-workflow claim restrictions
- Least-privilege SBOM upload gateway with repository-to-project authorization
- Dependency-Track API key storage and rotation through Secret Manager
- Human access through an independently validated IAP / Microsoft Entra ID design
- Reusable SBOM upload workflow that fails closed by default and reports failures
- Minimum production-gate logs, audit events, failure alerts, and upload metrics
- Terraform, integration tests, observability, backup, restore, and rollback guidance

The upload gateway is limited to the documented BOM upload operation. It must not
become a general Dependency-Track reverse proxy, and caller-provided project UUIDs
must be checked against an authoritative repository-to-project mapping.

---

## v0.3

- VEX candidate queue
- Human-reviewed Draft / Review / Approve / Publish workflow
- CycloneDX validation, diff preview, expiry, and re-evaluation
- Dependency-Track VEX ingestion after explicit approval

VEX ingestion remains owned by Dependency-Track. sbom-ops reads the resulting
analysis state and uses it for workflow decisions; it does not independently
approve, suppress, or mark findings as not affected. VEX publication requires
explicit Security team approval.

---

## v0.4

- Reachability
- govulncheck
- pip-audit
- osv-scanner

Reachability is advisory evidence for human review. It must not suppress findings,
change priority, or publish VEX decisions automatically.

---

## v0.5

- LLM Triage
- OpenAI
- Claude

LLM output remains advisory. It may summarize findings, explain impact, propose
remediation, and identify missing information. It must not change priority,
approve exceptions, suppress findings, change VEX/Analysis state, or close
GitHub Issues automatically. Reachability and approved VEX context should be
available as evidence before LLM triage is introduced.

---

## v1.0

- Jira
- Slack
- Teams
- Dashboard
- Metrics
