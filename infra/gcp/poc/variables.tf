variable "project_id" {
  description = "Google Cloud project ID used by the PoC."
  type        = string

  validation {
    condition     = length(trimspace(var.project_id)) > 0
    error_message = "project_id must not be empty."
  }
}

variable "region" {
  description = "Primary Google Cloud region for regional PoC resources."
  type        = string
  default     = "asia-northeast1"

  validation {
    condition     = length(trimspace(var.region)) > 0
    error_message = "region must not be empty."
  }
}

variable "environment" {
  description = "Environment name used in resource names and OIDC policies."
  type        = string
  default     = "poc"

  validation {
    condition     = contains(["poc", "dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of poc, dev, staging, or prod."
  }
}

variable "github_repository_id" {
  description = "Immutable GitHub repository ID allowed to exchange OIDC tokens."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.github_repository_id))
    error_message = "github_repository_id must be a numeric immutable GitHub repository ID."
  }
}

variable "github_repository_owner_id" {
  description = "Immutable GitHub organization or owner ID allowed to exchange OIDC tokens."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.github_repository_owner_id))
    error_message = "github_repository_owner_id must be a numeric immutable GitHub owner ID."
  }
}

variable "github_ref" {
  description = "Git ref allowed to exchange OIDC tokens."
  type        = string
  default     = "refs/heads/main"

  validation {
    condition     = startswith(var.github_ref, "refs/")
    error_message = "github_ref must start with refs/."
  }
}

variable "github_reusable_workflow_ref" {
  description = "Approved reusable workflow ref allowed by the WIF condition."
  type        = string

  validation {
    condition     = can(regex("^.+/.+/.github/workflows/.+\\.ya?ml@refs/.+$", var.github_reusable_workflow_ref))
    error_message = "github_reusable_workflow_ref must look like org/repo/.github/workflows/file.yml@refs/heads/main."
  }
}

variable "repository_project_map" {
  description = "Server-side mapping from immutable GitHub repository ID to Dependency-Track project UUID."
  type        = map(string)

  validation {
    condition     = length(var.repository_project_map) > 0
    error_message = "repository_project_map must contain at least one repository to project mapping."
  }
}
