locals {
  runtime_candidates = {
    dependency_track_platform = {
      baseline = "gke-autopilot"
      alternatives = [
        "cloud-run",
        "gke-standard",
      ]
      decision_state = "poc-required"
      reason         = "Dependency-Track has API/frontend separation, JVM sizing, persistent inventory data, and background processing that must be validated before selecting a final runtime."
    }

    sbom_upload_gateway = {
      baseline       = "cloud-run-service"
      alternatives   = ["gke-service"]
      decision_state = "poc-required"
      reason         = "The gateway is a narrow stateless HTTP boundary when it only accepts authorized BOM upload requests."
    }

    sbom_ops_sync = {
      baseline       = "cloud-run-job"
      alternatives   = ["gke-cronjob"]
      decision_state = "poc-required"
      reason         = "The sync process is a bounded run-to-completion workload."
    }
  }

  github_oidc_attribute_condition = join(" && ", [
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.repository_owner_id == '${var.github_repository_owner_id}'",
    "assertion.ref == '${var.github_ref}'",
    "assertion.job_workflow_ref == '${var.github_reusable_workflow_ref}'",
  ])

  upload_gateway_contract = {
    allowed_methods = ["POST"]
    allowed_paths   = ["/api/v1/bom"]
    allowed_content_types = [
      "multipart/form-data",
    ]
    rejects_caller_project_uuid = true
    maps_repository_server_side = true
  }

  validation_gates = [
    "dependency-track-api-frontend-separated",
    "postgres-backup-restore-tested",
    "github-wif-positive-and-negative-tests",
    "secret-manager-access-tested",
    "gateway-method-path-content-type-tests",
    "repository-project-mapping-deny-tests",
    "human-access-authn-authz-poc",
    "structured-logs-and-alerts-present",
    "rollback-tested",
  ]
}
