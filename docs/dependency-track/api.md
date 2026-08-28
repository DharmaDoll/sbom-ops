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

All Dependency-Track API calls must be implemented in:

`src/sbom_ops/clients/dependency_track.py`

The client must expose intent-based methods, not raw endpoint names.

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

The behavior lab also reads the following v4.14 portfolio surfaces with a
`VIEW_PORTFOLIO` key:

- `GET /api/v1/component/project/{uuid}` for all Components
- `GET /api/v1/component/project/{uuid}?onlyDirect=true` for direct Components
- `GET /api/v1/service/project/{uuid}` for CycloneDX Services
- `GET /api/v1/dependencyGraph/project/{uuid}/directDependencies` for the
  dependency graph

These methods only preserve raw observations and stable counts. Interpreting a
Component as reachable, affected, or safe belongs in reviewed domain workflow,
not in the API client.

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

## Behavior Lab

The DT behavior lab turns assumptions about Dependency-Track into repeatable
observations before they become product-client contracts.

The scenario source of truth is
[`examples/sboms/scenarios.yaml`](../../examples/sboms/scenarios.yaml). Each
scenario has a purpose, isolated Project identity, implementation status, ordered
BOM steps, and the API areas that must be observed. Planned scenarios may omit
steps; implemented scenarios must reference existing BOM files.

The manifest validator checks repository-level invariants, including unique
CycloneDX references and valid dependency references. New or changed valid SBOM
samples must also pass the official CycloneDX schema for their declared version;
this corpus currently targets CycloneDX 1.5.

Validate the corpus without contacting Dependency-Track:

```bash
make dt-lab-validate
```

Capture the target instance's OpenAPI document and produce a normalized
inventory:

```bash
make dt-lab-openapi
```

The generated files are deliberately ignored by Git:

```text
var/dt-lab/openapi.json
var/dt-lab/openapi-inventory.json
```

The inventory records the OpenAPI contract hash, path and operation counts,
operation IDs, permissions mentioned by the operation description, query
parameters, response statuses, response headers, response media types, and
deprecation state. By default it selects the API tags relevant to sbom-ops:

- BOM and processing events
- Projects, Components, Services, and Dependency Graph
- Findings, Vulnerabilities, Metrics, and Search
- Analysis, VEX, policy violations, and violation analysis

Use the lab CLI directly when an all-tag inventory is needed:

```bash
sbom-ops-dt-lab openapi-inventory \
  var/dt-lab/openapi.json \
  --all-tags \
  --output var/dt-lab/openapi-inventory-all.json
```

Raw OpenAPI documents and API observations are environment-specific and must
remain under `var/dt-lab/`. Only a minimal, reviewed response that supports a
client contract may be promoted into `tests/fixtures/`. Do not turn live
vulnerability counts or EPSS values into fixed assertions because intelligence
feeds change over time.

Run all implemented scenarios against an isolated local Dependency-Track
instance after exporting separate upload and read keys:

```bash
export SBOM_OPS_DT_BASE_URL=http://localhost:8080
export SBOM_OPS_SBOM_UPLOAD_API_KEY=replace-with-upload-key
export SBOM_OPS_DT_API_KEY=replace-with-read-key
make dt-lab-run
```

Use `--scenario` with the lab CLI to limit an execution:

```bash
sbom-ops-dt-lab run-scenarios \
  --scenario identity-same-name-different-purl \
  --scenario lifecycle-add-remove-components
```

Every run adds a unique suffix to the declared Project version. A step may
override the scenario's declared version so the same scenario can compare
separate releases of one named Project. This prevents prior Analysis or
suppression decisions from contaminating a structural test and avoids deleting
existing Projects. The generated run directory contains the raw observation
envelopes, a stable-field summary, and a Component delta for each step after the
first. Summaries distinguish all Components, direct Components, and Services;
raw dependency-graph responses remain available for contract discovery.

A failed run rewrites `run.json` with `status=failed`, the failure timestamp,
the number of completed steps, and a sanitized exception type and message. A
consumer must not treat an old `status=running` file as a successful or complete
observation.

For each implemented SBOM scenario, the runner follows this observation loop:

1. Upload one declared step to its isolated lab Project.
2. Wait for the returned event token to report `processing=false`.
3. Capture only the API areas listed in `observe`.
4. Record the DT version, OpenAPI contract hash, timestamp, HTTP status, response
   headers, duration, and datasource freshness with the response.
5. Compare the result with the preceding step and classify stable contract fields
   separately from volatile intelligence fields.
6. Promote only reviewed stable examples into fixtures or implementation rules.

The lab does not write Analysis, VEX, suppression, policy, or administrative
state until a scenario explicitly requires the operation and uses a disposable
lab key with the documented permission.

### Observed v4.14.3 behavior

The following results were reproduced against the repository's local v4.14.3
container on 2026-08-27. They are behavior observations, not substitutes for the
OpenAPI contract, and must be rechecked during an upgrade:

- CycloneDX Project export returns `406` for a generic `Accept: application/json`.
  `Accept: application/vnd.cyclonedx+json` is required for the JSON export used
  by the lab.
- A retained Component with the same PURL receives a different Component UUID
  in different Project versions. Cross-Project remediation identity therefore
  cannot rely on Component UUID alone.
- `onlyDirect=true` returned only the two root dependencies from a four-Component
  graph. The unfiltered Component endpoint returned all four.
- Component-to-Service edges appeared in Component `directDependencies` and the
  dependency-graph response. The Project CycloneDX re-export preserved Service
  objects but omitted those Service edges from `dependencies`.
- With the current datasource configuration, PURL-only samples produced no NVD
  Findings. Adding matching CPEs to the same Components produced NVD Findings,
  demonstrating that match results depend on both datasource and supplied
  identity types.
- NVD Findings included EPSS score and percentile plus CVSS fields. GitHub and
  OSV records were not present in this local instance, so alias and cross-source
  behavior remains intentionally unasserted until those datasources are ready.

Live Finding counts and scores are volatile. Tests assert the projection shape,
not the values observed in one run.
