# Dependency-Track Setup

## Purpose

This document defines the local evaluation setup for Dependency-Track used by this project.

Goal:

- start Dependency-Track locally
- complete first login safely
- create API keys with the correct responsibilities
- upload a CycloneDX SBOM
- confirm API access before implementing the client

This setup is for development and evaluation.
It is not a production deployment guide.

## Official References

Use these official documents as the source of truth:

- https://docs.dependencytrack.org/getting-started/deploy-docker/
- https://docs.dependencytrack.org/getting-started/initial-startup/
- https://docs.dependencytrack.org/getting-started/configuration/
- https://docs.dependencytrack.org/getting-started/recurring-tasks/
- https://docs.dependencytrack.org/integrations/rest-api/
- https://docs.dependencytrack.org/usage/cicd/
- https://docs.dependencytrack.org/datasources/private-vuln-repo/
- https://docs.dependencytrack.org/administration/users-and-permissions/

## Local Topology

This repository uses the following local ports:

- Frontend UI: `http://localhost:8080`
- Backend API: `http://localhost:8080/api`

Important:

- The bundled local container publishes a single HTTP port, `8080`
- The frontend and API are both served from `http://localhost:8080`
- The OpenAPI document is served at `http://localhost:8080/api/openapi.json`

## Prerequisites

- Docker Engine
- Docker Compose plugin
- At least 8 GB RAM available for the API server

The official quickstart notes that Docker is the easiest way to start.
For local evaluation, the bundled container is acceptable.
For production, move to an external database.

## Start Dependency-Track

Use the repository-local compose example:

```bash
docker compose -f examples/dependency-track/docker-compose.yml up -d
```

Equivalent helper:

```bash
make dt-up
```

Check container status:

```bash
docker compose -f examples/dependency-track/docker-compose.yml ps
```

Follow logs during first startup:

```bash
docker compose -f examples/dependency-track/docker-compose.yml logs -f
```

Equivalent helpers:

```bash
make dt-ps
make dt-logs
```

## First Startup Expectations

The first startup performs initialization tasks including:

- default user and team creation
- secret key generation
- SPDX and CWE data population
- initial vulnerability datasource mirroring

The official documentation states that initial mirroring may take 10 to 30 minutes or more.
Do not interrupt the process during this phase.

Wait until the UI is reachable and background initialization has settled before testing the API.

## First Login

Open:

```text
http://localhost:8080
```

Default initial credentials:

- username: `admin`
- password: `admin`

On first login, change the password immediately.

Recommended local convention:

- keep the built-in `admin` account for bootstrap only
- create a separate local team and API keys for automation

## API Key Model

This project requires separate API keys for separate responsibilities.

### 1. SBOM upload key

Purpose:

- CI uploads CycloneDX SBOMs

Required permissions:

- `BOM_UPLOAD`
- `PROJECT_CREATION_UPLOAD` only if CI is allowed to auto-create projects

### 2. Orchestrator read key

Purpose:

- read projects
- read findings
- read vulnerabilities

Required permissions:

- `VIEW_PORTFOLIO`
- `VIEW_VULNERABILITY`

### 3. Future analysis-write key

Not required for MVP.

If analysis state is ever updated intentionally, that key will also need:

- `VULNERABILITY_ANALYSIS`

## Create Team and API Keys

From the UI:

1. Create a dedicated team for SBOM upload automation
2. Assign only the permissions needed for upload
3. Create a second team for the orchestrator
4. Assign only read permissions for MVP
5. Generate an API key for each team
6. Save each key immediately

Dependency-Track stores API keys in hashed form and only shows the key at creation time.

## Verify the Backend API

The backend should expose OpenAPI on:

```text
http://localhost:8080/api/openapi.json
http://localhost:8080/api/openapi.yaml
```

Verification:

```bash
curl -fsS -o /dev/null http://localhost:8080/api/openapi.json
```

Equivalent helper:

```bash
make dt-openapi-check
```

If this fails but the UI is reachable on `8080`, check that the container is healthy and still using the bundled local compose file.

## Create or Select a Project

For local evaluation, either:

- create a project manually in the UI and use its UUID, or
- allow auto-create during BOM upload

Recommended for this project:

- create the project manually for predictable naming and UUID handling

Suggested naming convention:

- project name: repository or deployable service name
- version: build version, release version, or snapshot identifier

## Upload a CycloneDX SBOM

The official CI/CD guide supports both JSON `PUT` and multipart `POST`.
For local validation, use multipart `POST`.

Example:

```bash
curl -X POST "http://localhost:8080/api/v1/bom" \
  -H "X-Api-Key: REPLACE_WITH_SBOM_UPLOAD_KEY" \
  -F "project=REPLACE_WITH_PROJECT_UUID" \
  -F "bom=@path/to/bom.xml"
```

Repository helper:

```bash
export SBOM_OPS_SBOM_UPLOAD_API_KEY=replace-with-upload-key
export SBOM_OPS_DT_PROJECT_UUID=replace-with-project-uuid
scripts/upload_bom.sh path/to/bom.xml
```

Repository demo SBOM with project auto-create:

```bash
export SBOM_OPS_SBOM_UPLOAD_API_KEY=replace-with-upload-key
make dt-demo-upload
```

This uploads:

```text
examples/sboms/vulnerable-demo.cdx.json
```

to project:

```text
sbom-ops-vulnerable-demo / 0.1.0
```

Alternative auto-create flow:

```bash
curl -X POST "http://localhost:8080/api/v1/bom" \
  -H "X-Api-Key: REPLACE_WITH_SBOM_UPLOAD_KEY" \
  -F "autoCreate=true" \
  -F "projectName=example-service" \
  -F "projectVersion=0.1.0" \
  -F "bom=@path/to/bom.xml"
```

## Confirm Analysis Results

After upload:

1. Open the project in the UI
2. Confirm components appear
3. Confirm vulnerabilities are analyzed
4. Allow time for datasource processing if results are incomplete

Dependency-Track analyzes on ingestion and also re-analyzes components daily.

## Verify the Orchestrator Read Path

Before writing any client code, confirm these inputs exist:

1. Dependency-Track base URL
2. orchestrator read API key
3. at least one project UUID
4. at least one uploaded SBOM
5. at least one project with findings or at minimum component inventory

Only after these are available should implementation start in `src/sbom_ops/clients/dependency_track.py`.

## Local Environment Variables

Suggested local values:

```bash
export SBOM_OPS_DT_BASE_URL=http://localhost:8080
export SBOM_OPS_DT_API_KEY=replace-with-orchestrator-read-key
export SBOM_OPS_SBOM_UPLOAD_API_KEY=replace-with-upload-key
export SBOM_OPS_DT_PROJECT_UUID=replace-with-project-uuid
```

The upload key should be kept separate from the orchestrator key.

For local development, store real secrets in `.env`.
Do not put real API keys in `.env.example` or committed documentation.

This repository ignores `.env` via `.gitignore`.
Load it into the current shell before running upload helpers:

```bash
set -a
source .env
set +a
```

For the repository demo SBOM, project auto-create uses:

```bash
SBOM_OPS_DT_PROJECT_NAME=sbom-ops-vulnerable-demo
SBOM_OPS_DT_PROJECT_VERSION=0.1.0
```

When project auto-create is used, the upload API key needs both:

- `BOM_UPLOAD`
- `PROJECT_CREATION_UPLOAD`

## Reference Notes

### API keys

Dependency-Track UI credentials and REST API keys are separate.
Scripts, CI jobs, and this repository's upload helper authenticate with the
`X-Api-Key` HTTP header.

API keys are created for teams.
Creating a team does not automatically create an API key.
New API keys are shown once when created and are stored hashed afterward, so save
the key immediately in a local secret store such as `.env`.

Use separate keys for separate responsibilities:

- SBOM upload automation
- orchestrator read access
- future analysis-write workflows, if explicitly implemented

### Vulnerability database count

The global vulnerability count shown in the Dependency-Track UI is not the count
of findings in the demo project.
It is the local vulnerability intelligence catalog mirrored from configured
datasources such as NVD, GitHub Advisories, OSV, and other enabled sources.

For project validation, inspect the project-specific views instead:

```text
Projects
-> sbom-ops-vulnerable-demo / 0.1.0
-> Components
-> Vulnerabilities or Audit Vulnerabilities
```

### Update cadence

Dependency-Track uses asynchronous recurring tasks for mirroring, analysis, and
metrics.
Default intervals include:

- GitHub Advisories mirror: every 24 hours
- NVD mirror: every 24 hours
- EPSS mirror: immediately after the NVD mirror task
- OSV mirror: every 24 hours
- VulnDB sync: every 24 hours, when enabled and configured
- full portfolio vulnerability analysis: every 24 hours
- portfolio metrics update: every 1 hour
- vulnerability database metrics update: every 1 hour

Dependency-Track also analyzes components during BOM ingestion and when
components are changed through the REST API or UI.

Task intervals can be configured in the administration panel.
Changing task intervals should be rare because short intervals can add
significant system load.
Interval changes require an application restart to take effect.

### Private vulnerability data

Dependency-Track can maintain internally managed vulnerabilities in its private
vulnerability repository.
These vulnerabilities use the `INTERNAL` source and require a unique
vulnerability ID.

Creating internal vulnerabilities requires:

- `VULNERABILITY_MANAGEMENT`

Internal vulnerabilities can include severity, CVSS or OWASP risk rating,
description, details, recommendation, references, and affected components.

Affected components must be configured for the vulnerability to be picked up by
Dependency-Track's scanner.
Use identifiers that match ingested SBOM component identities, usually Package
URL for modern BOM generators.

Examples:

```text
pkg:pypi/django@2.2.0
pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
```

Dependency-Track does not automatically convert between Package URL and CPE.
If the SBOM contains Package URLs, define affected components with Package URLs.
If exact versions are used, include the version in the identifier.
If version ranges are used, provide the package identifier and range bounds.

## Troubleshooting

### UI works but API calls fail

- verify you are using `http://localhost:8080` as the local Dependency-Track base URL
- verify the API key is valid
- verify the team has the required permissions

### No vulnerabilities appear after upload

- wait for initial datasource mirroring to finish
- verify the BOM is valid CycloneDX
- verify the uploaded components map to known ecosystems

### First startup takes a long time

- this is expected during initial mirroring
- avoid restarting the stack during datasource bootstrap

### Local stack is too heavy

- ensure enough RAM is available
- stop unrelated containers
- use the bundled local setup only for development, not shared production use

## Exit Criteria

Dependency-Track is considered ready for this repository when all of the following are true:

- frontend reachable on `http://localhost:8080`
- backend OpenAPI reachable on `http://localhost:8080/api/openapi.json`
- admin password changed
- upload API key created
- orchestrator read API key created
- test CycloneDX BOM uploaded successfully
- project and findings visible in the UI
