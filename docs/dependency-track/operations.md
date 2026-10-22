# Dependency-Track Operations

## Daily Flow

1. CI generates CycloneDX SBOM.
2. CI uploads SBOM to Dependency-Track.
3. Dependency-Track analyzes components and vulnerabilities.
4. Orchestrator polls Dependency-Track findings.
5. Orchestrator enriches findings with KEV and EPSS.
6. Orchestrator creates GitHub Issues for P0/P1 findings.
7. Developers remediate issues.
8. CI uploads updated SBOM.
9. Orchestrator verifies analysis readiness and observes whether findings are absent.
10. Absence remains unverified; it does not authorize closing an Issue.
11. Automatic closure is not supported and its enablement setting is rejected.

Reviewed assets allow findings from multiple builds to share one repair Issue
per repository. Finding identities and DT analysis decisions remain separate.
See the [current workflow contract](../../SPEC.md#workflow-rules) and
[operator guide](../operations.md#github同期の確認) for matching, migration and write opt-in.

## Operational Ownership

Security team owns:

- Dependency-Track configuration
- API keys
- vulnerability intelligence sources
- priority policy
- exception approval

Development teams own:

- remediation
- dependency updates
- code changes
- risk acceptance requests

Platform team owns:

- Dependency-Track hosting
- backup
- monitoring
- upgrade
- availability

## Local Lab Cleanup

DT lab cleanup is a development operation, not part of the production daily
flow. It is scoped to one recorded run, previews locally by default, and needs a
separate `VIEW_PORTFOLIO` plus `PORTFOLIO_MANAGEMENT` key for explicit deletion.
Use `make dt-lab-cleanup RUN_ID=<uuid>` before adding `EXECUTE=1`. Wait until
repository metadata and other target background work is quiet; BOM event-token
completion alone is not sufficient for immediate deletion on DT 4.14.3. Failed
runs remain intact unless a human deliberately cleans them. See the
[behavior lab runbook](../../lab/dependency_track/README.md#cleaning-a-run).

## Minimum Production Checklist

- Dependency-Track deployed with persistent database
- Admin account secured
- API access restricted by team permissions
- Separate API key for SBOM upload
- Separate API key for orchestrator read operations
- Separate future key for analysis-write operations, only if explicit workflow support is implemented
- Vulnerability data sources configured
- Backup policy defined
- Upgrade policy defined
- Project naming convention defined
- SBOM upload convention defined
- Analysis state workflow defined
