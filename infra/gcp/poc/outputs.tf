output "runtime_candidates" {
  description = "Runtime candidates that must be validated before an architecture is accepted."
  value       = local.runtime_candidates
}

output "github_oidc_attribute_condition" {
  description = "Baseline WIF attribute condition for the approved repository, ref, and reusable workflow."
  value       = local.github_oidc_attribute_condition
}

output "upload_gateway_contract" {
  description = "Non-negotiable request boundary for the SBOM upload gateway."
  value       = local.upload_gateway_contract
}

output "repository_project_map" {
  description = "Server-side repository to Dependency-Track project mapping input."
  value       = var.repository_project_map
}

output "validation_gates" {
  description = "Validation gates required before production selection."
  value       = local.validation_gates
}
