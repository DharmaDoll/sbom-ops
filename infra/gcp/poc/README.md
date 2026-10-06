# GCP Secure Delivery PoC

This directory is the static evaluation harness for
[`ADR 0001`](../../../docs/adr/0001-gcp-secure-delivery-runtime.md).

It intentionally does not provision live Google Cloud resources yet. The first
goal is to make the proposed security boundaries reviewable before writing
production Terraform modules.

The static Terraform inputs below still model an earlier upload-gateway
proposal. That proposal was superseded by direct CI-to-DT upload with a
protected minimally scoped key and reviewed asset links. Do not use the gateway
outputs as a deployment requirement; update this harness before any live plan.

## Scope

The harness captures:

- candidate runtime boundaries for Dependency-Track and sbom-ops components
- GitHub Actions OIDC/WIF trust inputs
- legacy repository-to-Dependency-Track-project authorization inputs
- the obsolete narrow SBOM upload gateway contract (for removal, not adoption)
- validation gates required before any production architecture is accepted

## Static Validation

Run:

```bash
terraform -chdir=infra/gcp/poc fmt -check
terraform -chdir=infra/gcp/poc validate
```

If the configuration has not been initialized:

```bash
terraform -chdir=infra/gcp/poc init -backend=false
terraform -chdir=infra/gcp/poc validate
```

`terraform plan` is intentionally deferred until provider-backed resources are
added. Live apply commands must not be run by agents without explicit approval.

## Next Steps

1. Add provider-backed resources behind this boundary.
2. Add deny tests for wrong repository, ref, environment, and reusable workflow.
3. Remove the obsolete gateway contract from the static harness and model the
   direct-upload key, network boundary, and asset-review flow.
4. Add either GKE Autopilot or Cloud Run resources only after the PoC decision is documented.
