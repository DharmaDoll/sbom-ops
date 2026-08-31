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
behavior only through an explicit reviewed decision: use the existing DT
capability, encode a verified constraint in a minimal fixture and product test,
implement a missing orchestration gap, or reject/defer the hypothesis.

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

The event token is the authoritative completion signal for the token-tracked
BOM processing and vulnerability-analysis workflow. It is not a global
quiescence signal: on v4.14.3, repository metadata analysis can continue after
`processing=false`. Finding stability is retained only as a defensive read-side
check when the sync is started without a token. A stable read is not, on its
own, proof that a missing Finding is resolved; safe closure therefore also
requires consecutive successful absence observations and explicit opt-in.

The findings API requires the `VIEW_VULNERABILITY` permission. Endpoint details
must be validated against the target instance's OpenAPI document before
production deployment.

The v4.14 OpenAPI document exposes `offset`/`limit` pagination for project
listing. Finding and project-vulnerability endpoints return their documented
collections without pagination parameters in that version, so the client only
sends pagination parameters where the target contract supports them. This
avoids silently relying on an undocumented query parameter.

The lab's `GET /api/v1/component/project/{uuid}` observation is a separate
documented collection contract. On v4.14.3 it uses one-based `pageNumber`,
`pageSize` defaulting to 100, and the `X-Total-Count` response header. The lab
retrieves every page and rejects an observation when the combined item count
does not match the header. This behavior remains lab-only until a production
use case explicitly requires full Component enumeration.

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

The lab-only cleanup adapter uses `GET /api/v1/project/lookup` for live identity
verification followed by `DELETE /api/v1/project/{uuid}`. The captured v4.14.3
OpenAPI contract documents `204` on successful deletion and requires
`PORTFOLIO_MANAGEMENT`; the lookup also requires `VIEW_PORTFOLIO`. These methods
must not be exposed by the production client merely because the lab uses them.

The opt-in lab Analysis experiment uses `PUT /api/v1/analysis` with the target
Project, Component, and vulnerability UUIDs and reads the trail with
`GET /api/v1/analysis`. The captured v4.14.3 contract requires
`VULNERABILITY_ANALYSIS` for the write and `VIEW_VULNERABILITY` for the read.
These methods remain lab-only while the triage delegation boundary is under
evaluation; their presence is not authorization to mutate product Analysis
state. Before the experiment creates a Project, `GET /api/v1/team/self` must
show that the selected key has `VULNERABILITY_ANALYSIS`. The lab accepts the
read-only permissions `VIEW_BADGES`, `VIEW_POLICY_VIOLATION`, `VIEW_PORTFOLIO`,
and `VIEW_VULNERABILITY`, but rejects any other permission.

The lab adapter also exposes the read-only CycloneDX VEX export observation at
`GET /api/v1/vex/cyclonedx/project/{uuid}`. The v4.14.3 contract requires
`VULNERABILITY_ANALYSIS` and returns `application/vnd.cyclonedx+json`; the
adapter requests the 1.5 variant. VEX upload and round-trip mutation remain in
the explicit `triage-vex-round-trip` lab scenario. The lab-only adapter sends
the documented multipart `POST /api/v1/vex` request for an existing Project and
waits on its asynchronous processing token. The scenario is excluded from the
default lab run and is available only through scenario selection plus the
Analysis-mutation opt-in. This does not enable VEX writes in the product client.
In the completed one-Component v4.14.3 round trip, DT exported the Project UUID
as `vulnerabilities[].affects[].ref`, not the vulnerable Component PURL. Treat
that as a version-bounded Project-scoped observation; Component-scoped matching
remains unverified and must not be inferred from this sample.

## Behavior Lab Decision Boundary

The repository-only [Dependency-Track behavior lab](../../lab/dependency_track/README.md)
owns exploratory endpoints, scenario execution, raw observations, and current
behavior notes. It also tests how much triage can remain authoritative in DT
without duplicating state in sbom-ops. This product API guide owns only reviewed
production contracts and explicitly justified adapter behavior.
