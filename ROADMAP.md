# Roadmap

## MVP

- Dependency-Track API
- KEV lookup
- Dependency-Track EPSS retrieval
- Priority Engine
- GitHub Issues
- GitHub Actions

---

## v0.2

- Duplicate detection
- Auto close
- Config file
- Docker

---

## v0.3

- LLM Triage
- OpenAI
- Claude

## v0.3.x Operations Foundation

- Persistent structured synchronization logs
- Audit history for Finding, priority, Analysis state, and GitHub Issue changes
- KEV cache with configurable five-hour default TTL
- ETag/Last-Modified conditional refresh
- Stale-cache fallback and forced KEV refresh command
- Cache freshness and sync failure alerts

LLM output remains advisory. It may summarize findings, explain impact, propose
remediation, and identify missing information. It must not change priority,
approve exceptions, suppress findings, change VEX/Analysis state, or close
GitHub Issues automatically.

---

## v0.4

- Reachability
- govulncheck
- pip-audit
- osv-scanner

---

## v0.5

- VEX
- Suppression Sync

VEX ingestion remains owned by Dependency-Track. sbom-ops reads the resulting
analysis state and uses it for workflow decisions; it does not independently
approve, suppress, or mark findings as not affected.

Future VEX operations will support Security team candidate queues, evidence
collection, structured rationale, draft/review/approval/publish workflow,
validation, diff preview, expiry, and re-evaluation. LLM assistance remains
advisory and cannot approve VEX decisions or mutate Dependency-Track state.

---

## v1.0

- Jira
- Slack
- Teams
- Dashboard
- Metrics
