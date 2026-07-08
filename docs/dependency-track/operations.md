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
9. Orchestrator verifies that findings disappeared or changed state.
10. GitHub Issues are updated or closed.

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

## Minimum Production Checklist

- Dependency-Track deployed with persistent database
- Admin account secured
- API access restricted by team permissions
- Separate API key for SBOM upload
- Separate API key for orchestrator read/write operations
- Vulnerability data sources configured
- Backup policy defined
- Upgrade policy defined
- Project naming convention defined
- SBOM upload convention defined
- Analysis state workflow defined
