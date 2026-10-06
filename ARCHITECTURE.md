# Architecture

## Goal
Transform SBOM vulnerabilities into actionable engineering tasks.

Concrete operational flows and acceptance conditions are defined in
`docs/use-cases.md`.

Dependency-Track is intentionally kept as an inventory platform.
Workflow management belongs outside Dependency-Track.

## Runtime Inputs and Connections

```text
sbom-ops CLI
     │
     ├─ Dependency-Track API
     │    ├─ Project
     │    ├─ Finding
     │    ├─ EPSS
     │    └─ VEX / Analysis state
     │
     ├─ CISA KEV feed
     │
     ├─ reviewed asset inventory JSON (optional)
     │    └─ Project → service / environment / owner / deployed version
     │
     ├─ local SQLite asset registry (optional)
     │    └─ registered service / deployable / reviewed DT Project link
     │
     ├─ advisory evidence JSON (optional)
     │
     └─ GitHub REST API
          └─ Issue作成・更新・クローズ
```

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
- CI → Dependency-Track BOM API directly; sbom-ops is not an upload gateway

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

### Asset Context Layer

A reviewed local snapshot connects a DT Project to its service, environment,
owner, deployed version, exposure, and business criticality. It reports
unmapped Projects and expired observations. These facts are scoped to a
deployment and remain separate from per-Component Findings. The current
priority engine and Issue routing do not consume them automatically.
The current join checks only the Project UUID; it does not prove that the
deployed artifact is the one represented by that Project's SBOM. The local
JSON file is an evaluation input, not a production asset system of record.

No external organizational asset register is assumed. The first SQLite asset
registry now stores manually registered services and deployables and explicit
human-approved DT Project links. Project names and versions read from DT are
candidates, not proof of CI origin, SBOM provenance, or deployment.
`sync --asset-db` projects matching reviewed links into read-only run output;
it does not feed priority or Issue workflow. A later stage must connect an
immutable built artifact and its SBOM to the reviewed
DT Project and retain time-bounded deployment declarations.
ECS/EKS collectors would later add separate machine observations where useful,
without silently replacing human records. It must retain provenance and
unmatched/conflicting observations, plus reviewed owner and business metadata
that cannot be derived from infrastructure alone. It
must not copy DT's Finding inventory or GitHub's remediation workflow. The
first single-host implementation uses SQLite on local persistent storage;
ephemeral CI jobs only upload to DT and do not write this DB. Shared-file or
multi-host deployment requires a server DB. See the
[target operating flow](docs/operations.md#sbomと稼働資産を結ぶ運用フロー一部実装).

---

### Intelligence Layer
Collect
- KEV
- EPSS (prefer Dependency-Track-provided value)
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
- Wait for Dependency-Track processing

Orchestrator
- Observe consecutive absence
- Close issues only under the explicit safe-closure policy

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
├── CONTRIBUTING.md
├── CHANGELOG.md
├── pyproject.toml
├── docs/
│   ├── operations.md
│   ├── priority-policy.md
│   ├── vex.md
│   ├── use-cases.md
│   ├── data-sources.md
│   ├── dependency-track/
│   └── adr/
├── src/
│   └── sbom_ops/
│       ├── cli.py
│       ├── config.py
│       ├── clients/
│       ├── services/
│       ├── domain/
│       └── utils/
├── tests/
├── lab/
│   └── dependency_track/
│       ├── fixtures/
│       ├── scenarios/
│       ├── src/dt_lab/
│       └── tests/
├── scripts/
├── examples/
└── .github/
```

## Layer Responsibilities

### docs/
Focused operating guides, policy explanations, external-integration notes, and
architecture decision records. Project status and backlog belong only in
`ROADMAP.md`; normative behavior belongs only in `SPEC.md`.
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
- datetime

---

### tests/
- Unit tests
- Integration tests
- Fixtures

---

### lab/dependency_track/

Repository-only Dependency-Track behavior exploration. It owns its own adapter,
domain models, orchestration, CLI, synthetic scenario fixtures, real-world
corpus catalog, and tests. It is excluded from the product wheel and may depend
on generic product infrastructure, but `src/sbom_ops/` must never depend on it.

Lab observations feed an explicit product decision: use an existing DT
capability, encode a verified DT constraint in fixtures and contracts,
implement only the missing orchestration gap, or reject/defer the hypothesis.
Lab code is not a staging area for product code. Experiments use short-lived
branches; the stable lab harness remains on `main`.

The lab owns a run-scoped Project ledger and cleanup service. Cleanup depends on
the ledger plus a live name/version/UUID lookup, is dry-run by default, and uses
a dedicated least-privilege key when explicitly executed. It removes verified
DT Projects but retains ignored local observations and immutable cleanup audits.
Cleanup is never coupled to run completion because BOM event-token completion
does not cover every asynchronous repository metadata task.

Synthetic scenario BOMs are committed deterministic fixtures. The separate
real-world corpus commits only provenance, expected hashes, hypotheses, and
Project coordinates; upstream payloads, attestations, tools, and run evidence
stay in ignored `var/dt-lab/`. Large Component collections are observed through
the target's documented pagination and must match `X-Total-Count`.

Mutating Analysis experiments use a `VULNERABILITY_ANALYSIS` client, an explicit
CLI gate, an exact Finding selector, and only the newly created run-scoped
Project. The client prefers the optional lab-only Analysis key and otherwise
reuses the orchestrator read key after checking that its team has the required
Analysis permission and no write permission outside the lab allowlist. These
scenarios are excluded from the default lab run and cannot add write behavior
to the production Dependency-Track client by implication.

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
- Quick Start SBOMs

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
- EPSS data and risk information
- VEX ingestion and VEX-derived exploitability information

Responsibilities owned by this repository:
- Polling findings
- Enriching findings with KEV
- Using Dependency-Track-provided EPSS in priority calculation
- Calculating operational priority
- Creating remediation tasks
- Synchronizing workflow state with GitHub Issues
- Producing operational reports

The reconciliation model keeps three state dimensions separate:

- Finding state: active, missing, resolved, or unknown observation
- Dependency-Track analysis state: exploitable, in triage, not affected, and so on
- GitHub remediation state: open or closed workflow task

An absent Finding is not automatically a resolved Finding. Automatic closure
is opt-in and requires verified reads plus consecutive absence observations.

An external EPSS adapter may be retained as an explicitly configured fallback
or verification source. It must not silently replace Dependency-Track values.
This repository reads Dependency-Track analysis/VEX state but does not make
independent VEX decisions or mutate analysis state automatically.

Dependency-Track remains the inventory system.
GitHub Issues remains the task system.
The orchestrator only connects them.
