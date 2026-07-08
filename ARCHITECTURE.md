# Architecture

## Goal
Transform SBOM vulnerabilities into actionable engineering tasks.

Dependency-Track is intentionally kept as an inventory platform.
Workflow management belongs outside Dependency-Track.

---

## Components

### Input Layer
Generate SBOM

Examples
- Syft
- cyclonedx-py
- cyclonedx-node
- cargo-cyclonedx

Upload
- Dependency-Track API

---

### Inventory Layer
Dependency-Track

Stores
- Projects
- Components
- Vulnerabilities
- Analysis
- Policies

---

### Intelligence Layer
Collect
- KEV
- EPSS
- NVD
- GitHub Advisory

Normalize
- Enrich findings

---

### Decision Layer
Priority Engine

Inputs
- CVSS
- EPSS
- KEV
- Reachability (future)

Outputs
- P0
- P1
- P2
- P3

---

### Collaboration Layer
- GitHub Issues

Future
- Jira
- Slack
- Teams

---

### Verification Layer
CI
- Re-upload SBOM
- Close issues automatically

# Repository Structure
The project follows a layered architecture.

```text
dependency-track-sbom-ops/
├── README.md
├── LICENSE
├── AGENTS.md
├── ARCHITECTURE.md
├── ROADMAP.md
├── SPEC.md
├── TASKS.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── pyproject.toml
├── .env.example
├── docs/
│   ├── architecture/
│   │   ├── overview.md
│   │   ├── sequence.md
│   │   └── decisions/
│   ├── operations.md
│   ├── workflow.md
│   ├── priority-policy.md
│   ├── vex.md
│   └── api.md
├── src/
│   └── sbom_ops/
│       ├── main.py
│       ├── config.py
│       ├── models.py
│       ├── clients/
│       ├── services/
│       ├── domain/
│       └── utils/
├── tests/
├── scripts/
├── examples/
└── .github/
```

## Layer Responsibilities

### docs/
Project documentation.
No executable code.

---

### src/sbom_ops/clients/
Responsible for communication with external systems.

Examples:
- Dependency-Track
- GitHub
- EPSS
- KEV
- OpenAI

No business logic is allowed here.

---

### src/sbom_ops/services/
Implements application use cases.
Coordinates multiple clients and domain objects.
Contains orchestration logic only.

---

### src/sbom_ops/domain/
Contains core business logic.

Examples
- Vulnerability model
- Priority Engine
- Workflow state
- SLA rules

No API calls.

---

### src/sbom_ops/utils/
Reusable helper functions.

Examples
- logging
- retry
- cache
- datetime

---

### tests/
- Unit tests
- Integration tests
- Fixtures

---

### scripts/
Developer utilities.
- Bootstrap
- Local execution
- SBOM upload

---

### examples/
Reference implementations.
- GitHub Actions
- Docker Compose
- Example SBOMs

## Dependency-Track Boundary
Dependency-Track is not embedded in this repository.
It is an external platform used as the SBOM inventory and vulnerability analysis hub.
This project must not reimplement Dependency-Track features.

Responsibilities owned by Dependency-Track:
- Project inventory
- Component inventory
- SBOM ingestion
- Vulnerability correlation
- Policy violation tracking
- Analysis state storage
- VEX-related exploitability information

Responsibilities owned by this repository:
- Polling findings
- Enriching findings with KEV and EPSS
- Calculating operational priority
- Creating remediation tasks
- Synchronizing workflow state with GitHub Issues
- Producing operational reports

Dependency-Track remains the inventory system.
GitHub Issues remains the task system.
The orchestrator only connects them.
