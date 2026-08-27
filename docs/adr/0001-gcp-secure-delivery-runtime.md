# ADR 0001: GCP Secure Delivery Runtime Selection

Status: Proposed

Date: 2026-08-26

## Context

sbom-ops needs a secure delivery path for SBOM ingestion and Dependency-Track
operations on Google Cloud.

The platform has three different workload shapes:

- Dependency-Track API server and frontend
- PostgreSQL-backed inventory data
- sbom-ops automation, including scheduled sync and a future SBOM upload gateway

Dependency-Track remains the inventory and analysis source of truth. GitHub
Issues remain the remediation workflow source of truth. The GCP design must not
turn sbom-ops into a general Dependency-Track proxy or allow callers to choose
arbitrary Dependency-Track project UUIDs.

Google skills reviewed for this ADR:

- `google-cloud-solution-architecture`: keep requirements, product selection,
  validation, and packaging as separate phases; avoid premature product lock-in.
- `cloud-run-basics`: Cloud Run services, jobs, and worker pools fit different
  HTTP, run-to-completion, and background workload shapes.
- `gke-basics`: default to GKE Autopilot unless Standard-only constraints are
  proven; never mount raw Google service account JSON keys in pods.
- `google-cloud-waf-security`: use security by design, zero trust, least
  privilege, centralized logging, and IaC validation.

## Decision

Do not select Cloud Run as the final Dependency-Track hosting architecture yet.

Adopt a two-track production-shaped PoC before writing production Terraform:

1. Evaluate Dependency-Track API server, frontend, and PostgreSQL on GKE
   Autopilot with an external managed PostgreSQL option.
2. Evaluate Cloud Run only for stateless or bounded sbom-ops components, such
   as the SBOM upload gateway and scheduled sync jobs, unless the PoC proves
   that Dependency-Track runtime behavior is a good fit.

The first production candidate is:

- GKE Autopilot for Dependency-Track API server and frontend
- managed PostgreSQL for Dependency-Track persistence
- Workload Identity Federation for GitHub Actions to Google Cloud
- Secret Manager for Dependency-Track API keys and gateway secrets
- a narrow SBOM upload gateway that accepts only the documented BOM upload flow
- Cloud Run service or job for sbom-ops components where stateless execution is
  a better fit than Kubernetes

This is not yet an accepted production architecture. It is the evaluation target
for the next PoC.

## Required Invariants

- GitHub Actions must not store long-lived Google Cloud service account keys.
- OIDC/WIF trust must restrict immutable organization/repository identity,
  protected refs or environments, and approved reusable workflow identity.
- Caller-provided `project_uuid` must not be trusted as authorization.
- Repository-to-Dependency-Track-project mapping must be resolved server side.
- The upload gateway must allow only the BOM upload operation and required
  content types.
- Dependency-Track API keys must remain in Secret Manager or an equivalent
  managed secret store, not in repository or workflow secrets.
- Human browser access must be validated separately from machine upload access.
- Analysis state, VEX decisions, suppression, exceptions, and risk acceptance
  must remain human or explicitly governed workflows.

## Options Considered

### Option A: Cloud Run for all services

Pros:

- Low operational overhead for stateless HTTP services and scheduled jobs.
- Good fit for an SBOM upload gateway and `sbom-ops sync` job.
- Native service identity and private invocation controls.

Cons:

- Dependency-Track API server has persistent state, background processing,
  JVM sizing, and frontend/API separation requirements that must be validated.
- A browser-facing frontend plus API, CORS, OIDC, and service-to-service paths
  need an explicit end-to-end proof.
- Prematurely forcing the full platform into Cloud Run risks hiding operational
  complexity in ad hoc glue.

Use only if the PoC proves startup, background analysis, memory sizing,
frontend/API routing, authentication, and database behavior are acceptable.

### Option B: GKE Autopilot for Dependency-Track, Cloud Run for sbom-ops edge jobs

Pros:

- Better fit for long-running containers and Kubernetes-native Dependency-Track
  deployment patterns.
- Autopilot reduces node management while preserving Kubernetes primitives for
  services, ingress, secrets integration, probes, and rollout control.
- Keeps the upload gateway and scheduled sync free to use Cloud Run when their
  workload shape is stateless or run-to-completion.

Cons:

- Higher operational surface than pure Cloud Run.
- Requires Kubernetes deployment, network, identity, and upgrade validation.
- Still needs a clear GKE versus Cloud Run cost and operations comparison.

This is the preferred PoC baseline.

### Option C: GKE Standard for Dependency-Track

Pros:

- Maximum control over node pools and low-level Kubernetes behavior.

Cons:

- More operational burden.
- Should only be used if Autopilot blockers are proven, such as required
  DaemonSets, host mounts, custom node pools, or unsupported kernel settings.

Do not choose Standard unless the PoC documents a concrete Autopilot blocker.

## PoC Scope

The PoC must validate:

- Dependency-Track API server and frontend deployment as separate services.
- PostgreSQL persistence, backup, restore, migration, and rollback behavior.
- API server memory and CPU sizing against at least the documented recommended
  local requirements.
- Dependency-Track OpenAPI reachability from the orchestrator path.
- SBOM upload through the gateway without exposing the Dependency-Track upload
  key to GitHub Actions.
- WIF token exchange from GitHub Actions with deny tests for wrong repository,
  wrong ref/environment, and wrong reusable workflow.
- Secret Manager access only from the gateway or approved automation identity.
- Cloud Logging and Monitoring coverage for auth failures, gateway 4xx/5xx,
  upload token, Dependency-Track analysis delay, and sync failure.
- Human frontend access through IAP, Identity Platform, or Dependency-Track
  native OIDC before choosing one.
- Rollback from a failed deployment without losing Dependency-Track inventory.

## Validation Commands

The first implementation for this ADR adds static validation only:

```bash
terraform -chdir=infra/gcp/poc fmt -check
terraform -chdir=infra/gcp/poc validate
```

`terraform plan` becomes required when provider-backed resources are added.
Live deployment commands must not be run automatically by agents. They require
explicit human approval because they can create cloud resources and cost.

## Consequences

- Terraform work must start as an evaluation harness, not a production promise.
- The repository needs a small `infra/gcp/poc` boundary before reusable modules.
- The upload gateway authorization model must be designed before accepting any
  caller-selected project UUID.
- Documentation must record threat model impact, rollback, and validation
  evidence with each infrastructure change.
- GKE and Cloud Run remain candidates until the PoC result is accepted or this
  ADR is superseded.

## References

- Google skills: https://github.com/google/skills
- Google skill `google-cloud-solution-architecture`: https://github.com/google/skills/tree/main/skills/cloud/google-cloud-solution-architecture
- Google skill `cloud-run-basics`: https://github.com/google/skills/tree/main/skills/cloud/cloud-run-basics
- Google skill `gke-basics`: https://github.com/google/skills/tree/main/skills/cloud/gke-basics
- Google skill `google-cloud-waf-security`: https://github.com/google/skills/tree/main/skills/cloud/google-cloud-waf-security
- Dependency-Track Docker deployment: https://docs.dependencytrack.org/getting-started/deploy-docker/
- Dependency-Track REST API: https://docs.dependencytrack.org/integrations/rest-api/
- Google Cloud Workload Identity Federation for deployment pipelines: https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines
- Cloud Run service-to-service authentication: https://cloud.google.com/run/docs/authenticating/service-to-service
- Cloud Run with Identity-Aware Proxy: https://cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run
- Secret Manager best practices: https://cloud.google.com/secret-manager/docs/best-practices
- GitHub OIDC for Google Cloud: https://docs.github.com/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-google-cloud-platform
- GitHub OIDC reference: https://docs.github.com/actions/reference/security/oidc
