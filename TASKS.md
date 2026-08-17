# Tasks

## Implemented Foundation

- API retry and timeout controls are implemented; production failure behavior still needs validation
- Dependency-Track project pagination is implemented; portfolio-scale validation is pending
- BOM processing wait and safe, opt-in closure are implemented; real analysis timing and partial-failure validation is pending
- Finding, Analysis, and Remediation state types are implemented; broader transition rules remain planned
- A basic repository-local GitHub Actions sync example exists; it is not the reusable WIF upload workflow

## Near Term

- Implement YAML config loader compatible with `SPEC.md`
- Add Dependency-Track project to GitHub repository routing
- Validate safe closure against real Dependency-Track timeout, analysis-in-progress,
  pagination failure, and project-filter scenarios
- Validate component UUID/PURL and vulnerability UUID/source against the target
  Dependency-Track OpenAPI response
- Validate GitHub Issue creation, update, duplicate migration, and closure after a dry-run
- Complete Finding, Analysis, and Remediation transition rules independently
- Keep external EPSS client as an explicit fallback/verification path only
- Harden the existing sync workflow with commit-SHA-pinned actions, timeouts,
  concurrency control, and an explicit distinction from SBOM upload

## Secure GCP Delivery

- Write an ADR and run a production-shaped proof of concept before selecting
  Cloud Run; compare it with the supported GKE/Helm deployment path
- Model Dependency-Track as separate API server and frontend services backed by
  external PostgreSQL, including migrations, sizing, background processing,
  backup/restore, upgrades, and rollback
- Define GitHub OIDC/WIF trust with immutable organization and repository IDs,
  protected refs/environments, and the approved reusable workflow identity
- Implement repository-to-Dependency-Track-project authorization at an upload
  gateway; do not trust a caller-supplied `project_uuid` by itself
- Restrict the gateway to the documented BOM upload method/path/content types and
  validate request size, token audience, issuer, and mapped caller identity
- Store and rotate the least-privilege Dependency-Track upload API key in Secret
  Manager without exposing it to GitHub Actions or logs
- Validate human access separately using IAP and Microsoft Entra ID, including
  frontend-to-API browser requests, CORS, logout, group authorization, and break-glass access
- Publish a reusable GitHub Actions workflow using OIDC/WIF, pinned actions,
  explicit minimal permissions, timeouts, retries, and fail-closed default behavior
- Add minimum production-gate structured logs, audit events, upload metrics, and
  failure alerts before exposing the upload path to development teams
- Add Terraform validation, policy checks, integration tests, disaster recovery
  tests, and cost estimates

## Future Operations

- Add persistent structured sync logs (`run_id`, counts, failures, duration)
- Add an audit store for observed Finding, priority, Analysis state, and Issue changes
- Add a persistent KEV cache with configurable TTL, ETag/Last-Modified support, stale fallback, and forced refresh
- Add cache locking to prevent concurrent KEV refreshes
- Add KEV cache freshness and synchronization failure alerts
- Add a remediation policy model that keeps priority separate from SLA dates
- Add `PriorityContext` inputs for asset criticality, exposure, reachability,
  and compensating controls without changing priority automatically

## Future VEX Operations

- Add Security team VEX candidate queue across projects
- Add Finding, EPSS, KEV, Analysis, SBOM and Issue context view for VEX authors
- Add structured VEX rationale templates and mandatory evidence fields
- Add VEX draft/review/approval/publish lifecycle
- Add CycloneDX schema validation and SBOM/VEX version consistency checks
- Add VEX diff preview before Dependency-Track import
- Add VEX expiry and re-evaluation triggers
- Add VEX artifact versioning and reviewer audit trail

## Future Reachability

- Add reachability as advisory evidence without allowing it to suppress findings automatically
- Integrate `govulncheck`, `pip-audit`, and `osv-scanner` through independent adapters
- Record tool version, inputs, outputs, timestamps, and confidence for auditability
- Feed reachability results into VEX review and later LLM triage as evidence

## Future LLM Triage

- Add optional LLM triage adapter after VEX and reachability evidence are available
- Generate summaries, impact explanations, remediation proposals, and follow-up questions
- Require structured LLM output with evidence references and confidence
- Store LLM suggestions separately from authoritative Dependency-Track analysis decisions
- Add human review workflow before publishing LLM suggestions to GitHub Issues
- Ensure LLM cannot change priority, suppress findings, approve exceptions, change VEX state, or close Issues
