# Dependency-Track Guide

This directory documents how this project uses OWASP Dependency-Track.

Dependency-Track is the most important external dependency of this system.

Official documentation must be treated as the source of truth:

- https://docs.dependencytrack.org/
- https://docs.dependencytrack.org/integrations/rest-api/
- https://docs.dependencytrack.org/usage/cicd/
- https://docs.dependencytrack.org/usage/vex/
- https://docs.dependencytrack.org/usage/analysis/

Local repository guides:

- `setup.md` for local bootstrap and API validation
- `api.md` for client implementation rules
- `operations.md` for day-2 operating flow

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
