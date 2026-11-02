# Dependency-Track Guide

This directory documents how this project uses OWASP Dependency-Track.

Dependency-Track is the most important external dependency of this system.

Official documentation must be treated as the source of truth:

- https://docs.dependencytrack.org/
- https://docs.dependencytrack.org/integrations/rest-api/
- https://docs.dependencytrack.org/usage/cicd/
- https://docs.dependencytrack.org/usage/vex/
- https://docs.dependencytrack.org/triage/auditing-basics/
- https://docs.dependencytrack.org/triage/analysis-states/

Local repository guides:

- [setup.md](setup.md) for bootstrap, API validation and ongoing administration
- [api.md](api.md) for production client implementation rules
- [operator guide](../operations.md#日常の流れ) for the day-to-day application workflow
- [`../getting-started.md`](../getting-started.md#運用担当者向けの初回演習)
  for the guided first operator exercise (with an optional isolated SBOM upload)
- [`../../lab/dependency_track/README.md`](../../lab/dependency_track/README.md)
  for repository-only behavior exploration and product-decision rules

Dependency-Track is used for:

- SBOM ingestion
- Project inventory
- Component inventory
- Vulnerability correlation
- Analysis state
- Policy violations
- VEX handling

This orchestrator is used for:

- Prioritization
- Threat intelligence enrichment
- GitHub Issue creation
- SLA tracking
- Workflow automation
