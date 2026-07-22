# Tasks

## Near Term

- Implement YAML config loader compatible with `SPEC.md`
- Add real HTTP clients for Dependency-Track, KEV, and GitHub
- Map Dependency-Track EPSS and analysis/VEX state into domain findings
- Keep external EPSS client as an explicit fallback/verification path only
- Add orchestrator decision tests with fake clients
- Add mock fixtures for Dependency-Track findings and GitHub Issues
- Add GitHub Actions example workflow

## Future Operations

- Add persistent structured sync logs (`run_id`, counts, failures, duration)
- Add an audit store for observed Finding, priority, Analysis state, and Issue changes
- Add a persistent KEV cache with configurable TTL, ETag/Last-Modified support, stale fallback, and forced refresh
- Add cache locking to prevent concurrent KEV refreshes
- Add KEV cache freshness and synchronization failure alerts

## Future LLM Triage

- Add optional LLM triage adapter for summaries, impact explanations, remediation proposals, and follow-up questions
- Require structured LLM output with evidence references and confidence
- Store LLM suggestions separately from authoritative Dependency-Track analysis decisions
- Add human review workflow before publishing LLM suggestions to GitHub Issues
- Ensure LLM cannot change priority, suppress findings, approve exceptions, change VEX state, or close Issues

## Future VEX Operations

- Add Security team VEX candidate queue across projects
- Add Finding, EPSS, KEV, Analysis, SBOM and Issue context view for VEX authors
- Add structured VEX rationale templates and mandatory evidence fields
- Add VEX draft/review/approval/publish lifecycle
- Add CycloneDX schema validation and SBOM/VEX version consistency checks
- Add VEX diff preview before Dependency-Track import
- Add VEX expiry and re-evaluation triggers
- Add VEX artifact versioning and reviewer audit trail
