# AGENTS.md

## Project

Dependency-Track SBOM Operations  
This repository implements a Security-as-a-Task orchestrator on top of OWASP Dependency-Track.  
Dependency-Track is the inventory system.  
GitHub Issues (or Jira) is the work management system.

This project bridges the two.

---

# Design Principles

1. SBOM is the source of truth.
2. Dependency-Track owns inventory.
3. GitHub Issues own remediation workflow.
4. Everything should be automatable.
5. AI assists humans but never makes final security decisions.
6. Components should be loosely coupled.
7. Every module should be independently testable.

---

# Architecture

Input

CI/CD
 ↓
CycloneDX SBOM
 ↓
Dependency-Track

↓

Orchestrator

↓

Threat Intelligence

- CISA KEV
- EPSS
- GitHub Advisory
- NVD

↓

Priority Engine

↓

LLM Triage (optional)

↓

GitHub Issues

↓

Developer

↓

CI

↓

Dependency-Track

---

# Coding Guidelines

- Python 3.12+
- Type hints required
- Ruff
- Black
- pytest
- No business logic inside API clients.
- Separate adapters from domain logic.

Example

```
dependency_track.py
    only API communication

priority.py
    only priority calculation

github.py
    only GitHub communication

main.py
    orchestration only
```
---

# Priority Rules

P0

- KEV
- Active exploitation

P1

- EPSS >= threshold
- Critical CVSS

P2

- High CVSS

P3

Everything else

Never hardcode thresholds.
Thresholds belong in config.

---

# AI Usage

LLM must only

- summarize findings
- explain impact
- propose remediation

LLM must never

- suppress vulnerabilities
- approve exceptions
- change priority automatically

---

## Dependency-Track Development Rule

Dependency-Track is an external system and the most important integration point in this project.

Before implementing or modifying any Dependency-Track integration, agents must read:

- https://docs.dependencytrack.org/
- https://docs.dependencytrack.org/integrations/rest-api/
- https://docs.dependencytrack.org/usage/cicd/
- https://docs.dependencytrack.org/usage/vex/
- https://docs.dependencytrack.org/usage/analysis/
- https://docs.dependencytrack.org/getting-started/deploy-docker/

Rules:

1. Do not assume API behavior.
2. Confirm endpoint, method, request body, response body, and required permission from official documentation.
3. Keep Dependency-Track API code isolated in `src/sbom_ops/clients/dependency_track.py`.
4. Do not put priority logic, GitHub logic, or SLA logic in the Dependency-Track client.
5. Treat Dependency-Track as the source of truth for SBOM inventory.
6. Treat GitHub Issues as the source of truth for remediation workflow.
7. Never overwrite Dependency-Track analysis state without explicit workflow logic.
8. All Dependency-Track API changes require integration tests or documented mock fixtures.


# Future Features

- VEX
- Reachability
- Jira
- Slack
- Teams
- SARIF
- Dependency Graph
- Multi-tenancy



# Repository Rules

When adding new functionality:

1. Define domain models first.
2. Implement business rules.
3. Add service orchestration.
4. Implement external clients.
5. Add CLI entrypoint.
6. Add tests.
7. Update documentation.

Never bypass the architecture.
