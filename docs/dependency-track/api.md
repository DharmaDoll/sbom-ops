# Dependency-Track API Usage

Official API documentation is the source of truth.

Before changing API code, check:

- endpoint path
- HTTP method
- required permission
- request format
- response format
- pagination behavior
- async processing behavior
- error response behavior

## Used API Areas

The orchestrator is expected to use API areas related to:

- Projects
- BOM upload
- Findings
- Vulnerabilities
- Analysis
- VEX
- EPSS and finding risk metadata
- Teams/API keys

## Implementation Rule

All production Dependency-Track API calls must be implemented in:

`src/sbom_ops/clients/dependency_track.py`

The client must expose intent-based methods, not raw endpoint names.

Exploratory calls belong only in the repository lab adapter at
[`lab/dependency_track/src/dt_lab/client.py`](../../lab/dependency_track/src/dt_lab/client.py).
Product modules must not import the lab. A lab observation becomes production
behavior only after official documentation review and promotion into a minimal
fixture, client contract, and product test.

Dependency-Track is the preferred source for EPSS values and VEX-derived
analysis state. The client should expose normalized finding fields for these
values, including component UUID/PURL and vulnerability UUID/source for stable
machine identity. VEX upload and analysis-state mutation require explicit workflow
support and permissions; they are not part of the MVP.

The MVP read path uses the following intent-level operations:

- `GET /api/v1/project` to enumerate accessible projects
- `GET /api/v1/project/{uuid}` to resolve project metadata
- `GET /api/v1/finding/project/{uuid}` to retrieve findings and analysis state
- `GET /api/v1/vulnerability/project/{uuid}` as the EPSS fallback source when a
  finding response does not include an EPSS value

The upload-and-wait path uses:

- `POST /api/v1/bom` with multipart `project` and `bom` fields; the response
  contains an asynchronous processing `token`
- `GET /api/v1/event/token/{token}` until `processing=false`
- then the project Finding and vulnerability endpoints above

The event token is the authoritative signal for the tasks created by that BOM
upload. Finding stability is retained only as a defensive read-side check when
the sync is started without a token. A stable read is not, on its own, proof
that a missing Finding is resolved; safe closure therefore also requires
consecutive successful absence observations and explicit opt-in.

The findings API requires the `VIEW_VULNERABILITY` permission. Endpoint details
must be validated against the target instance's OpenAPI document before
production deployment.

The v4.14 OpenAPI document exposes `offset`/`limit` pagination for project
listing. Finding and project-vulnerability endpoints return their documented
collections without pagination parameters in that version, so the client only
sends pagination parameters where the target contract supports them. This
avoids silently relying on an undocumented query parameter.

Good:

```python
list_projects()
get_project_findings(project_uuid)
upload_bom(project_uuid, bom_path)
update_analysis_state(...)
```

Bad:

```python
get_api_v1_finding_project_uuid(...)
post_api_v1_bom(...)
```

## Behavior Lab Promotion Boundary

The repository-only [Dependency-Track behavior lab](../../lab/dependency_track/README.md)
owns exploratory endpoints, scenario execution, raw observations, and current
behavior notes. This product API guide owns only reviewed production contracts.
