# Workflow

SBOM

↓

Dependency-Track
  ├─ EPSS
  └─ VEX / analysis state

↓

KEV enrichment

↓

Priority Engine
(EPSS and VEX state from Dependency-Track)

↓

GitHub Issue

↓

Developer

↓

Merge

↓

CI

↓

Dependency-Track

↓

Finding ACTIVE / MISSING / RESOLVED / UNKNOWN

↓

Issue remains open until the safe-closure policy confirms resolution

Dependency-Track analysis state and GitHub remediation state are intentionally
separate. A single missing observation or an unverified read never closes an
Issue.
