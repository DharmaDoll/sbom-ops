# Dependency-Track Lab Experiment Ledger

## 2026-09-26 — VEX targeting isolation across Projects

- Status: live two-Project run completed; Analysis state restored; both Projects cleaned
- Target: Dependency-Track 4.14.3 bundled container
- Scenario: `triage-vex-targeting`
- Input: same repository-owned synthetic CycloneDX SBOM uploaded to two disposable Projects

### Purpose and Performed Work

Extend the Component-versus-Project VEX test to check whether an import into one
Project changes matching Findings in another Project that contains the same
Component versions and vulnerability. The run imported identical synthetic
SBOMs into two run-scoped Projects, exercised exported-reference, input-reference,
declared-Component, and Project-scoped VEX paths in the target Project, captured
both matching Findings in the comparison Project after every import, and
restored the target Project's two Findings to `NOT_SET`. The comparison Project
was never mutated. After reviewing the output and allowing a short quiescence
period, run-scoped cleanup deleted both Projects.

### Observed Facts

- Both Projects ingested 2 Components and returned 19 Findings across 10 unique
  vulnerabilities.
- The target Project's Component-scoped declared reference changed only the
  selected Component's Finding; its Project-scoped reference changed both
  matching Findings in the target Project.
- In the comparison Project, both matching Findings remained unsuppressed and
  had no Analysis state projection after every tested VEX import, including
  Project-scoped import to the target Project.
- The target Project's final verification reported `NOT_SET` and unsuppressed
  for both Findings.
- Cleanup completed for exactly two recorded Projects with zero failures; a
  subsequent lookup for each run-scoped name/version returned HTTP 404.

### Interpretation and Product Decision

For DT 4.14.3, CycloneDX VEX ingestion through a Project-specific endpoint
confines its resulting Analysis decisions to matching Findings in that Project.
Within the target Project, Project scope is broader than Component scope; across
Projects, the observed decision did not leak to matching inventory. Product
approval must still bind to the full target Project Finding set and preserve
Project identity. This does not authorize sbom-ops to upload VEX in the MVP.

### Unverified and Evidence

Concurrent analyst changes during VEX import, cross-Project references encoded
with an external supplier's identifiers, and behavior after a DT upgrade remain
unverified. Raw observations, UUIDs, and cleanup audits remain under ignored
`var/dt-lab/runs/<run-id>/`; no credentials or target-specific IDs were copied
to this ledger.

## 2026-09-26 — OSV marker recheck; no newer run

- Status: read-only marker and sanitized log check completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: four enabled OSV ecosystems since the prior 2026-09-25 observation

At 2026-09-25T21:52:54Z, Go, npm, PyPI, and RubyGems still pointed to the
2026-09-21 full-mirror window and exceeded the 30-hour threshold. The bounded
log query found no later `OsvDownloadTask` events through the observation
window. This is a repeated no-change observation about 70 minutes after the
prior check, not new evidence about why the scheduler has not produced a later
marker. The normalized artifact is under the ignored
`var/dt-lab/runs/<run-id>/osv-internal-markers.json`; raw markers and logs were
not retained.

## 2026-09-26 — OpenProject no-PURL count reconciliation

- Status: read-only live inventory check completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: the retained schema-valid OpenProject SBOM and its existing disposable Project

### Purpose and Performed Work

Resolve the two-row difference among PURL-less components without changing
Analysis or Project state. Verified the local input against its pinned SHA-256,
then fetched the full paginated Component inventory again and compared only the
four source records for the two suspected name/version identities.

### Observed Facts

- The input hash still matches the corpus catalog. Its 14,141 no-PURL records
  include two records each for `./.github/actions/install-openssl` and
  `./.github/actions/install-ruby`, both at version `UNKNOWN`.
- For each name, the two CycloneDX records have distinct `bom-ref` values and
  distinct `syft:location:0:path` properties. Their name, version, type, and
  CPE match; both have no PURL.
- The live DT API returned 16,742 Components, including one no-PURL row for
  each of these names. Both rows have version `UNKNOWN`, classifier `LIBRARY`,
  the corresponding CPE, and no returned properties. Total no-PURL rows were
  14,139. The request was read-only; no Project or Analysis state was changed.

### Interpretation and Product Decision

The two-row count difference is explained by DT representing each pair of
same-name/version/CPE records as one inventory row. This is consistent with
DT deduplicating on its component identity rather than preserving each source
occurrence. It is not evidence that location metadata from both source records
survives: the Component API response returned no properties. No unique
PURL-less name/version identity from this comparison is missing. For product
reconciliation, compare normalized inventory identities separately from raw
SBOM occurrences, and do not claim occurrence-level metadata preservation.

### Unverified and Evidence

The exact DT deduplication key and whether either source location remains
available through another endpoint are unverified. The full prior paginated
response is in the ignored run evidence under
`var/dt-lab/runs/<run-id>/rails-openproject-17-7-2-schema-valid/01-import/`;
the current check retained only the summary above. No credentials, raw payloads,
or environment-specific UUIDs were added to the ledger.

## 2026-09-26 — Large-collection pagination and full-list endpoints

- Status: read-only live contract and pagination checks completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: OpenProject Component inventory, Project Findings/Vulnerabilities, and portfolio Project listing

### Purpose and Performed Work

Measure how page size affects complete reads for the 16,742-Component
OpenProject Project and verify the collection semantics used by the production
adapter. Reviewed the pinned 4.14.3 OpenAPI description, fetched the Component
collection with several `pageSize` values, read Project Findings and
Vulnerabilities without pagination parameters, and walked the portfolio
Project endpoint using the production adapter's `offset`/`limit` pattern.
Only counts and timings were retained.

### Observed Facts

- Component reads with `pageSize` 100, 500, 1,000, 2,000, and 5,000 all
  returned HTTP 200 and exactly 16,742 rows, matching `X-Total-Count`. The
  corresponding page counts were 168, 34, 17, 9, and 4.
- The sequential measurements were 40.960 seconds at 100 (repeat), 25.381 at
  500, 6.910 then 6.233 at 1,000, 5.478 at 2,000, and 4.071 then 3.477 at
  5,000. Compact JSON serialization of the combined Component payload was
  26,521,391 bytes. The API schema sets a default page size of 100 and does not
  declare a maximum; the tested values through 5,000 were accepted.
- `GET /v1/finding/project/{uuid}` and
  `GET /v1/vulnerability/project/{uuid}` have no pagination parameters in the
  OpenAPI definition. Each returned all 630 rows for this Project with
  `X-Total-Count: 630`.
- The production adapter's Project-list pattern (`offset`/`limit`) returned
  page counts 7, 7, 7, and 6 at a limit of 7. The 27 returned Project IDs were
  unique and matched `X-Total-Count: 27`.
- All requests were reads; no Project, Finding, or Analysis state changed.

### Interpretation and Product Decision

The production Project-list pagination contract worked against the target, and
the Finding/Vulnerability operations return complete unpaginated lists as
described. Component inventory reads can reduce round trips substantially with
larger page sizes, but the timing run was sequential, cache state was not
controlled, and its 26.5 MB aggregate payload makes memory cost material. The
current production adapter does not read the Component collection, and its
page-size setting applies to Project listing; these measurements do not justify
changing the product default. Keep page size configurable and establish
representative portfolio size, payload, and latency before tuning a deployment.

### Unverified and Evidence

No server-side maximum above 5,000, concurrent load impact, cold-cache latency,
or memory pressure under production concurrency was measured. The target
OpenAPI document and raw responses remain in ignored `var/dt-lab/`; the current
run retained only the summarized facts above. No credentials or
environment-specific UUIDs were copied to the ledger.

## 2026-09-25 — VEX Component versus Project targeting live run

- Status: live disposable run completed; state restored; run-scoped cleanup completed
- Target: Dependency-Track 4.14.3 bundled container
- Scenario: `triage-vex-targeting`

### Purpose and Performed Work

On a run-scoped disposable Project, imported the synthetic VEX-targeting SBOM,
applied the declared Component-scoped VEX decision, then applied the
Project-scoped comparison. The runner captured Finding projections, Analysis
trails, suppression changes, VEX export/restore checkpoints, and final reset to
unsuppressed `NOT_SET`. A separate run-scoped cleanup dry-run verified one
Project target; deletion was intentionally not executed.

### Observed Facts

- The run completed with one Project and 45 recorded observations.
- Baseline: 2 Components and 19 Findings from NVD across 10 unique
  vulnerabilities.
- Component-scoped VEX (`NOT_AFFECTED`, `CODE_NOT_REACHABLE`) changed the
  reviewed primary Component/Finding and suppressed that Finding; the control
  Component remained unaffected.
- Project-scoped VEX changed both the reviewed primary Finding and the control
  Finding to the same `NOT_AFFECTED`/suppressed projection, demonstrating
  broader Project scope.
- CycloneDX VEX export and re-import checkpoints were observed; the runner
  restored the final primary and control targets to `NOT_SET` and unsuppressed.
- The run-scoped cleanup dry-run contained exactly one target.

The evidence was reviewed, the target had remained quiescent after the
experiment, and the separate run-scoped cleanup command then deleted exactly
the recorded disposable Project. Its execution audit reports one deletion and
zero failures; a subsequent name/version lookup returned HTTP 404. The audit is
retained under the ignored run directory.

### Interpretation and Product Decision

DT applies a Component-scoped VEX decision narrowly to the referenced Component,
while a Project-scoped reference propagates the decision to matching Findings
throughout the Project. sbom-ops must preserve the reviewed target scope and
reject or escalate Project-scoped VEX when the human review covered only one
Component. The VEX document and DT Analysis trail are authoritative evidence;
the orchestrator should retain correlation and restoration/reconciliation state,
not duplicate the decision history.

### Unverified and Evidence

Cross-Project reuse, multiple vulnerabilities sharing a Component, and
concurrent analyst edits remain unverified. Raw responses and UUIDs remain under
ignored `var/dt-lab/runs/<run-id>/`; no credentials or target-specific IDs were
added to the ledger. Cleanup plan and execution audits are retained under that
ignored run directory.

## 2026-09-25 — VEX targeting preflight rejected excessive key permission

- Status: live attempt failed closed during permission preflight; no Project or VEX mutation
- Target: Dependency-Track 4.14.3 bundled container
- Scenario: `triage-vex-targeting`

### Purpose and Performed Work

Attempted the explicitly gated VEX targeting scenario to compare Component- and
Project-scoped VEX behavior on a disposable Project. The runner was invoked
with `--allow-analysis-mutation` and performed its team-permission preflight
before creating a Project.

### Observed Facts

- The analysis key's team permissions included `VULNERABILITY_ANALYSIS` and
  `SYSTEM_CONFIGURATION`.
- The lab allowlist permits only `VULNERABILITY_ANALYSIS` plus the documented
  read permissions, so the preflight rejected the key.
- A retry after adding `VULNERABILITY_ANALYSIS` produced the same rejection;
  `SYSTEM_CONFIGURATION` is still present on the team.
- No Project was created, no VEX or Analysis state was changed, and no cleanup
  target was generated.

### Interpretation and Product Decision

The fail-closed least-privilege guard works as intended and prevents a VEX
experiment from using an over-privileged key. The scenario remains unverified;
it requires a dedicated analysis key whose team permissions satisfy the lab
allowlist. Do not weaken the allowlist or reuse administrative permissions just
to complete the experiment.

### Unverified and Evidence

Component-versus-Project VEX targeting semantics remain unverified. The
attempt produced no durable raw response; only this normalized failure fact is
recorded.

## 2026-09-25 — DT runtime continuity check for OSV gap

- Status: read-only runtime metadata observation completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: container start, restart, status, and health metadata

### Purpose and Performed Work

Check whether a container restart after the last OSV mirror could explain the
absence of newer internal markers. Only Docker runtime metadata was read; no
container, database, scheduler, or datasource state was changed.

### Observed Facts

- Container start time: 2026-09-15T21:59:46Z.
- Docker restart count: 1.
- Current status: running; health status: healthy.
- The container started before the 2026-09-21 OSV task window and has not
  restarted since that start according to the runtime metadata.

### Interpretation and Product Decision

The missing OSV recurrence is not explained by a post-mirror container restart
in this runtime. Health status also does not prove that the scheduler executed
or completed its task. Keep the datasource health state stale/unknown and avoid
using container health as a proxy for mirror freshness.

### Unverified and Evidence

Scheduler trigger history, executor queue state, and task-specific failure
diagnostics remain unavailable from the current supported API surface. Only
normalized runtime facts were retained; no raw Docker metadata was persisted.

## 2026-09-25 — OSV task-log recurrence check

- Status: read-only log metadata observation completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: sanitized `OsvDownloadTask` log metadata since 2026-09-21

### Purpose and Performed Work

Inspect bounded container logs after the stale-marker observation to distinguish
an absent recurrence from an explicit task failure. The command retained only
task name, UTC date, count, first/last timestamps, and a simple error-token
count. Log bodies were not persisted.

### Observed Facts

- 69 `OsvDownloadTask` log events were present after 2026-09-21T00:00:00Z.
- All 69 events occurred on 2026-09-21, from approximately 00:13:55Z through
  00:32:06Z.
- No task-log event was observed on later dates through the observation window.
- No failure/exception/error tokens were present in the bounded event metadata.
- Current configuration readback still reports `osv.mirror.cadence=24`,
  `google.osv.enabled=RubyGems;PyPI;Go;npm`, and alias synchronization disabled.
- The configuration surface does not expose a task-run history or per-run
  failure state.

### Interpretation and Product Decision

The logs corroborate one successful-looking OSV task window on September 21
and no later recurrence, but they do not prove that the scheduler did not run
silently or that all four ecosystem operations succeeded independently. The
stale/unknown product health state remains appropriate. Do not increase cadence
or infer datasource failure solely from this absence; investigate supported
scheduler telemetry or task configuration next.

### Unverified and Evidence

Per-ecosystem completion semantics, scheduler trigger history, and log retention
limits remain unverified. Only sanitized counts were retained; no raw logs or
credentials were written. Evidence path pattern remains
`var/dt-lab/runs/<run-id>/`.

## 2026-09-25 — OSV recurrence marker check

- Status: read-only marker observation completed; no new recurrence observed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: internal OSV success markers for Go, npm, PyPI, and RubyGems

### Purpose and Performed Work

Re-read the internal OSV marker files after the previous successful full mirror
to determine whether a later incremental or full cycle had been recorded. The
existing lab-only marker summarizer was run with a 30-hour threshold. No DT
configuration, scheduler, datasource, or product state was changed.

### Observed Facts

- All four ecosystems still report their latest successful operation at
  2026-09-21T00:13:55Z–00:16:29Z.
- At observation time 2026-09-24T20:42:52Z, all four were classified
  `older-than-threshold` (approximately 92.4 hours old).
- No newer marker was present for either full or modified OSV files.
- The normalized diagnostic was written under the ignored
  `var/dt-lab/runs/<run-id>/` path; raw marker input was not persisted.

### Interpretation and Product Decision

No post-mirror OSV recurrence is evidenced by this datastore's internal
markers. This does not distinguish a task that never ran from a failed task and
does not prove upstream data is incomplete. Product code must not claim OSV
freshness from these files; an operator-facing health state should remain
unknown/stale until a supported telemetry contract or explicit task evidence is
available. Investigate scheduler/API diagnostics before changing cadence.

### Unverified and Evidence

The effective scheduler timer, task failure path, and cause of the missing
recurrence remain unverified. Evidence path pattern:
`var/dt-lab/runs/<run-id>/osv-internal-markers.json`.

## 2026-09-24 — Project 30-day metrics retention probe

- Status: read-only observation completed
- Target: Dependency-Track 4.14.3 bundled container, same disposable OpenProject corpus Project
- Scope: `/v1/metrics/project/{uuid}/days/30`

### Purpose and Performed Work

Check whether the Project metrics endpoint provides a useful multi-day trend.
The request was read-only and retained only the array size and min/max values
for component and Finding totals.

### Observed Facts

- HTTP 200; response time was approximately 0.007 seconds.
- The 30-day request returned one metrics object, not a 30-point time series.
- `findingsTotal` remained 630 and `components` remained 16,742 for the
  returned object.

### Interpretation and Product Decision

This DT instance does not expose a usable multi-day Project metric trend from
this endpoint. The endpoint may represent only an available snapshot for the
requested period. sbom-ops must not infer daily history or freshness from the
array length; if trend visibility is required, it must record timestamped
observations externally or use a supported DT history contract after upgrade
validation.

### Unverified and Evidence

Retention behavior with multiple metric refreshes remains unverified. No raw
response, credentials, or persistent environment-specific identifiers were
retained.

## 2026-09-24 — Project historical metrics contract probe

- Status: read-only observation completed
- Target: Dependency-Track 4.14.3 bundled container, same disposable OpenProject corpus Project
- Scope: `/v1/metrics/project/{uuid}/days/1`

### Purpose and Performed Work

Read the one-day historical metrics endpoint to determine whether it supplies a
usable time series or an explicit timestamp/freshness field. The request was
read-only; only response shape and selected scalar values were retained.

### Observed Facts

- HTTP 200; response time was approximately 0.05 seconds.
- The response contained one metrics object.
- Its `findingsTotal` was 630 and `components` was 16,742, matching current
  metrics.
- The object exposes `firstOccurrence` and `lastOccurrence`, but no explicit
  sample-date, recorded-at, or synchronization timestamp field.

### Interpretation and Product Decision

The historical endpoint is available but does not by itself provide a clear
freshness contract for operator or product use. Treat its values as DT metric
history, not datasource synchronization evidence. Product freshness must remain
unknown unless a timestamp is supplied by a supported contract or an external
observation records when the query was made.

### Unverified and Evidence

Multiple-day retention and behavior after a metric refresh remain unverified.
No raw response, credentials, or persistent environment-specific identifiers
were retained.

## 2026-09-24 — Large-project current metrics readback

- Status: read-only observation completed
- Target: Dependency-Track 4.14.3 bundled container, same disposable OpenProject corpus Project
- Scope: `/v1/metrics/project/{uuid}/current`

### Purpose and Performed Work

Read the current Project metrics after the Component and Finding collection
checks to determine whether DT's aggregate metrics are available and how they
relate to collection counts. No refresh endpoint or other mutation was called.
Only scalar metric fields were retained.

### Observed Facts

- HTTP 200; response time was approximately 0.02 seconds.
- `components=16742`, `vulnerabilities=630`, `findingsTotal=630`.
- Severity counts were critical 15, high 150, medium 214, low 251,
  unassigned 0; these sum to 630.
- `vulnerableComponents=88`, `suppressed=0`, and all 630 Findings were
  unaudited.
- `collectionLogic=NONE`; policy-violation totals were all zero.
- `inheritedRiskScore=1793.0`.

### Interpretation and Product Decision

The metrics endpoint is a fast, stable aggregate suitable for progress and
operator display, while the Finding collection remains the authoritative detail
set. `vulnerabilities` counts Finding instances rather than unique vulnerability
identifiers (the collection-level sample had one unique identifier), and
`vulnerableComponents` is an aggregate identity count (88 versus 87 distinct
PURLs in the sampled payload). Product code must label these metrics precisely
and must not treat them as interchangeable counts.

### Unverified and Evidence

Metric refresh timing and historical metric semantics remain unverified. No raw
response, credentials, or persistent environment-specific identifiers were
added to the ledger.

## 2026-09-24 — Large-project aggregate/read consistency check

- Status: read-only observation completed
- Target: Dependency-Track 4.14.3 bundled container, same disposable OpenProject corpus Project
- Scope: Project identity, component collection header, and Finding collection

### Purpose and Performed Work

Compare the stable Project identity with the two collections most relevant to
the product inventory boundary. The Project resource and lookup projection were
read without mutation; the Component endpoint was sampled with a single-item
page to read its total header, and the Finding endpoint was read in full.

### Observed Facts

- The Project remained active with the expected lab name and run-scoped version.
- The Component endpoint reported `X-Total-Count: 16742`.
- The Finding endpoint returned 630 items.
- No suppressed Findings were present in the returned collection.

### Interpretation and Product Decision

The large-project inventory and Finding readbacks are internally consistent
with the prior live-run baseline (16,742 Components and 630 Findings). Product
reconciliation should use the complete Component collection total and the
Finding collection, rather than relying on optional aggregate fields in the
Project representation or lookup projection.

### Unverified and Evidence

This does not establish asynchronous metric refresh behavior or explain prior
historical Finding-count changes between SBOM imports. No raw payloads,
credentials, or new persistent artifacts were retained.

## 2026-09-24 — Large-project Finding collection readback

- Status: read-only observation completed
- Target: Dependency-Track 4.14.3 bundled container, disposable large OpenProject corpus Project
- Scope: bounded Finding collection response and repeatability check

### Purpose and Performed Work

Retried the large-project Finding request using the configured DT base URL from
the approved external network path after the sandbox-only probe failed. Three
bounded GET requests were made with the existing read key; no upload, analysis,
policy, VEX, or cleanup mutation was attempted. Only status, response size,
latency, and array counts were retained.

### Observed Facts

- All three requests returned HTTP 200.
- Each response contained exactly 630 Findings and 1,864,951 downloaded bytes.
- Request times were 0.396s, 0.211s, and 0.126s.
- The response contained 1 unique vulnerability identifier and 87 unique
  component PURLs in the returned Finding collection.

### Interpretation and Product Decision

The large-project Finding collection is repeatably readable at this snapshot,
with a roughly 1.8 MB response and sub-second request time. The current DT
Finding endpoint returns the complete project collection in one response rather
than requiring the lab client's paginated list helper; production adapters must
still retain bounded timeouts and response-size safeguards. The low unique
vulnerability count is a property of this imported snapshot and is not a
general DT coverage claim.

### Unverified and Evidence

This did not measure asynchronous processing latency or behavior at larger
Finding counts. No raw response or credential was persisted. The earlier
sandbox-only connection failure remains recorded as a separate inconclusive
attempt.

## 2026-09-24 — Large-project Finding pagination probe unavailable

- Status: inconclusive; read-only request did not reach the DT API
- Target: Dependency-Track 4.14.3 bundled container, existing disposable large-SBOM Project
- Scope: bounded Finding collection read for page/response-size validation

### Purpose and Performed Work

Attempted a read-only request for the existing large OpenProject corpus Project to
measure the Finding collection response size, item count, unique vulnerability
count, and request latency. No upload, analysis, policy, VEX, or cleanup action
was attempted. The request failed immediately because the published host port
was not accepting connections. A Docker health/status check was also attempted,
but the current shell cannot access the Docker daemon socket.

### Observed Facts

- `127.0.0.1:8080` returned connection failure before an HTTP response.
- No response body, Finding payload, credential, or new evidence artifact was
  retained.
- Container health and restart state could not be observed from this shell due
  to Docker socket permission denial.

### Interpretation and Product Decision

The pagination and response-size behavior remain unverified by this attempt.
Connection failure is transport/availability evidence only; it must not be
interpreted as an empty Project or missing Findings. Retry after the DT service
is reachable, using the same read-only request and bounded timeout.

### Unverified and Evidence

No durable raw evidence was created. This failed attempt is recorded here so the
lab does not treat the planned measurement as completed.

## 2026-09-24 — Large OpenProject SBOM live run

- Status: live upload and readback completed; cleanup plan written, deletion not executed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: disposable corpus Project using the schema-valid OpenProject SBOM

### Purpose and Performed Work

Execute the largest pinned corpus artifact with the explicit `--execute` gate,
then measure DT inventory counts and prepare the separate run-scoped cleanup.
The upload used the dedicated lab upload/read keys; no analysis mutation was
enabled. The CLI process lost its final summary output, so the run artifact
remained marked `running`; the Project and paginated count headers were then
verified independently with bounded read-only requests. Cleanup was planned but
not executed.

### Observed Facts

- Input baseline: 14,113,899 bytes, 17,831 Components, 869 dependencies.
- DT readback reported 16,742 Components, 630 Findings, and 630 Vulnerabilities.
- The disposable Project is active and isolated by a run-specific version.
- A run-scoped cleanup plan and local audit were created; no Project deletion
  occurred.

### Interpretation and Product Decision

The large real-world SBOM is ingestible and queryable at approximately 16.7k
Components. The discrepancy between input component count and DT inventory is a
product-relevant fact requiring explanation before assuming one-to-one counts.
The 630 Finding/Vulnerability counts provide a baseline for pagination and
assessment performance. The interrupted final CLI output exposes a robustness
gap: run completion must be durably finalized even when post-upload observation
or output handling is interrupted.

### Follow-up Count Reconciliation

A bounded paginated read compared the complete DT Component collection with
the local input PURLs without retaining raw payloads. The input had 17,831
component entries, 3,690 PURL-bearing entries, 2,385 unique PURLs, and 14,141
entries without a PURL. DT returned 16,742 rows, 2,603 PURL-bearing rows, the
same 2,385 unique PURLs, 218 duplicate PURL entries, and 14,139 rows without a
PURL. No input PURL was missing and DT introduced no new PURL.

This explains the 1,089-row difference as DT normalization/deduplication of
PURL-bearing entries plus two collapsed PURL-less occurrences. A follow-up
read-only live comparison (2026-09-26 entry) found that the two names and
versions are present once each in DT: each source pair shared name/version/CPE
but had distinct `bom-ref` values and location properties. Thus no unique
name/version identity was absent, although the API response did not establish
whether occurrence-level location metadata survived import.

The product should compare normalized semantic identity sets, not raw SBOM
component-entry counts, while preserving raw SBOM counts as audit metrics.

### Unverified and Evidence

Upload and processing latency and full paginated response sizes remain to be
analyzed from the ignored run artifacts. The no-PURL row-count difference is
explained at the observed identity level; DT's exact deduplication key and
occurrence-level property preservation remain unverified.
Cleanup execution remains pending explicit review. Evidence paths use
`var/dt-lab/runs/<run>/` patterns; no raw credentials or UUIDs were added to
the ledger.

## 2026-09-23 — Policy-violation endpoint contract probe

- Status: read-only probe completed; no policy or analysis mutation
- Target: Dependency-Track 4.14.3 bundled container
- Scope: OpenAPI contract and portfolio policy-violation endpoint

### Purpose and Performed Work

Prepare the planned `triage-policy-violations` scenario using the supported
REST surface. OpenAPI inspection identified portfolio, Project, and Component
violation reads requiring `VIEW_POLICY_VIOLATION`, plus a separate violation
analysis mutation endpoint. A bounded authenticated request to the portfolio
endpoint with `limit=1` returned HTTP 200 and `X-Total-Count: 0`; only status
metadata was retained.

### Interpretation and Product Decision

Policy violations are a distinct DT resource and permission boundary from
vulnerability Findings. The scenario should compare separate read snapshots and
avoid mixing policy violations into vulnerability priority until an explicit
product rule exists. The mutation endpoint requires a separately authorized,
disposable experiment and remains out of this read-only preparation.

### Unverified and Evidence

No live policy violation exists in the current portfolio, so state transitions,
analysis semantics, and audit behavior remain unverified. No response payload,
UUID, or credential was persisted.

## 2026-09-22 — Normalized evidence for OSV full mirror

- Status: read-only evidence capture completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: marker and datasource-log summarizers for the 2026-09-21 full mirror

### Purpose and Performed Work

Run the repository's strict marker and bounded log summarizers against the
successful full-mirror window. The marker summarizer used a caller-supplied
30-hour threshold and persisted only normalized timestamps, counts, and a
digest; the log summarizer retained sanitized event classifications only.

### Observed Facts

- All four ecosystems are `within-threshold` at the observation time
  2026-09-21 22:09:17 UTC.
- Full mirror start markers are recorded at 00:13:55–00:16:29 UTC on
  2026-09-21, matching the successful task log window.
- Evidence artifacts were written under ignored `var/dt-lab/runs/<run>/` paths;
  raw marker input and raw Docker logs were not persisted.

### Interpretation and Product Decision

The lab diagnostic is reproducible for a successful OSV full mirror and can
support operator investigation. It remains version-coupled and is not a
production freshness API; no product code should consume these internal files.

### Unverified and Evidence

The cause of the earlier cadence gap and a supported DT freshness contract
remain unresolved. The two sanitized run artifacts are the local evidence for
this observation.

## 2026-09-22 — OSV full fallback mirror completed

- Status: read-only observation completed; OSV mirror success confirmed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: OSV markers and bounded 2026-09-21 task logs

### Purpose and Observed Facts

After API connectivity recovered, re-read the four OSV marker pairs and
inspected the 2026-09-21 00:13:55–00:32:07 UTC OSV log window. All four full
and modified markers advanced. The task performed a full mirror for each
ecosystem, processing 4,778 RubyGems, 25,645 PyPI, 9,295 Go, and 229,117 npm
advisories, and logged successful completion. Total logged task time was about
18 minutes 11 seconds. No state or configuration was changed by the lab.

### Interpretation and Product Decision

The earlier absence of OSV runs is now followed by a successful full fallback
mirror, proving that the task can execute and refresh the datastore after the
observed timer gap. The marker timestamp represents the operation start, while
completion occurs later; freshness tooling must preserve both semantics when
available. Keep internal markers lab-only and continue treating product
freshness as unknown without a supported telemetry contract.

### Unverified and Evidence

The reason for the long gap before this full fallback remains unverified; the
24-hour cadence and five-day full-mirror fallback are both configured. No raw
logs or API payloads were persisted; sanitized evidence uses ignored
`var/dt-lab/runs/<run>/` paths.

## 2026-09-22 — Host API recovered; OpenAPI telemetry inventory

- Status: read-only connectivity recovery and OpenAPI inspection completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: published port/container-IP probes and local OpenAPI paths

### Purpose and Observed Facts

Retry the host-to-container path after the 2026-09-21 timeout. Health requests
to both the container IP (`172.18.0.2:8080`) and published loopback
(`127.0.0.1:8080`) returned HTTP 200. The OpenAPI document then loaded
successfully. It exposes configuration and metrics endpoints, but no task
status, scheduler, datasource freshness, or mirror-history endpoint; the
metrics paths are component/project/portfolio refresh and current/history
views. No state or configuration was changed.

### Interpretation and Product Decision

The prior timeout was transient host/API-path unavailability, not a permanent
port mapping failure. Docker health and host reachability can diverge
temporarily, so lab readiness must include an explicit host API probe. Since
the supported OpenAPI surface has no task telemetry contract, retain the
version-coupled marker/log diagnostic and freshness-unknown product policy.

### Unverified and Evidence

The cause and duration of the transient timeout remain unknown. No OpenAPI
payload or environment-specific network identifiers were persisted.

## 2026-09-21 — Host/API path versus container health divergence

- Status: read-only connectivity diagnosis completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: host loopback probes and Docker healthcheck metadata

### Purpose and Observed Facts

Recheck API availability after a full day and compare host-visible routes with
the container's own health signal. Host requests to `/health`, `/api/version`,
and `/api/openapi.json` all timed out within five seconds on both
`localhost:8080` and `127.0.0.1:8080`. Docker still reports `healthy`; its
healthcheck is an in-container request to `http://127.0.0.1:8080/health`, and
recent checks are succeeding. No restart or network/configuration mutation was
performed.

### Interpretation and Product Decision

The current failure boundary is host-to-container port reachability or Docker
forwarding, not proven application health: the in-container healthcheck can
pass while the lab client cannot reach the API. Do not treat the container as
lab-ready, and do not run mutating scenarios until host API connectivity is
restored and independently verified.

### Unverified and Evidence

The external forwarding failure mechanism remains unverified. No response
payloads, credentials, or network dumps were persisted.

## 2026-09-20 — API timeout resource and port check

- Status: read-only runtime diagnosis completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: port mapping, JVM process state, and container resource usage

### Purpose and Observed Facts

Investigate whether the persistent API timeout is explained by a stopped
process, missing port publication, or obvious resource exhaustion. Docker shows
port 8080 published on IPv4 and IPv6; the Java process is running for the full
post-restart interval. At observation time it used about 3.1 GiB of 8 GiB
memory, 0.26% CPU, and 100 PIDs. No restart or mutation occurred.

### Interpretation and Product Decision

The timeout is not explained by a stopped JVM, absent port mapping, OOM state,
or high instantaneous resource usage. The application/DB request path remains
the leading unknown. Do not run mutating lab scenarios until the API responds.

### Unverified and Evidence

Thread-level and database diagnostics were not available through the bundled
image tooling and remain unverified. No process output or credentials were
persisted.

## 2026-09-20 — API timeout persists

- Status: read-only follow-up completed; API remains unresponsive
- Target: Dependency-Track 4.14.3 bundled container
- Scope: bounded HTTP probes and recent error-log inspection

### Purpose and Observed Facts

Retried `/api/version`, `/api/openapi.json`, and `/metrics` at
2026-09-20 11:03:45 UTC after the earlier timeout. All three again exceeded
five seconds. The bounded log search found only the previously recorded
09:02:21 UTC Jetty/Jersey broken-pipe error and no OOM or shutdown signal.
No restart or state change was performed.

### Interpretation and Product Decision

The API responsiveness issue is persistent across independent probes, while
the container had previously reported healthy. Treat the Docker health result
as insufficient for lab readiness and do not run mutating scenarios or further
configuration reads until the supported API responds again. Product freshness
remains unknown.

### Unverified and Evidence

The cause of the application-level timeout remains unverified. No raw response,
credentials, or environment-specific identifiers were persisted.

## 2026-09-20 — Supported API telemetry probe inconclusive

- Status: read-only probe completed; API responsiveness degraded
- Target: Dependency-Track 4.14.3 bundled container
- Scope: local OpenAPI/version/metrics HTTP probes and container health metadata

### Purpose and Performed Work

Check whether supported HTTP telemetry can replace the internal marker
diagnostic. Bounded requests to `/`, `/api/version`, `/api/openapi.json`, and
`/metrics` all timed out. The container was then inspected without restarting
it, and recent logs were searched for runtime errors.

### Observed Facts

- Docker reports the container `running`, `healthy`, `oom=false`, and exit code
  zero; no restart was performed.
- All four HTTP probes timed out at five seconds, so no OpenAPI or task-status
  endpoint could be evaluated.
- Recent logs contained a Jetty/Jersey broken-pipe response-write error, which
  is compatible with a client disconnect but does not explain the timeouts.

### Interpretation and Product Decision

Supported API telemetry is currently inconclusive because the application did
not respond within the bounded probe window. Docker health alone cannot prove
API responsiveness or OSV task health. Preserve the freshness-unknown policy;
do not restart or alter configuration merely to recover the probe.

### Unverified and Evidence

The cause of API unresponsiveness and availability of a supported task-status
endpoint remain unverified. No response payloads or credentials were stored.

## 2026-09-20 — Persisted datasource and cadence configuration read

- Status: read-only API observation completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: selected `configProperty` values; no POST or configuration mutation

### Purpose and Performed Work

Use the existing lab read key with the documented configuration endpoint to
resolve whether OSV is enabled and which cadence the scheduler has persisted.
The query printed only an allowlisted set of datasource and cadence fields;
credentials and encrypted values were not recorded.

### Observed Facts

- `google.osv.enabled` is `RubyGems;PyPI;Go;npm`.
- `google.osv.alias.sync.enabled` and `github.advisories.enabled` are `false`.
- `task-scheduler.osv.mirror.cadence` is `24` hours; NIST, GHSA, and VulnDB
  cadence values are also `24`.
- NVD and EPSS source settings are enabled, while NVD feed download is false.

### Interpretation and Product Decision

The missing post-restart OSV recurrence is not explained by OSV being disabled
or by an unexpected persisted cadence. With control tasks active and a 24-hour
OSV cadence confirmed, the remaining uncertainty is timer lifecycle or an
internal task failure after the successful startup run. Keep the API read in
the lab; do not expose cadence as product freshness or alter configuration.

### Unverified and Evidence

The scheduler's effective timer execution and failure path remain unverified.
Only sanitized facts are retained in this ledger; no API response or key was
persisted.

## 2026-09-20 — OSV startup-path and runtime-config check

- Status: read-only diagnosis completed; no configuration mutation
- Target: Dependency-Track 4.14.3 bundled container
- Scope: container command/environment metadata and startup OSV logs

### Purpose and Performed Work

Investigate whether the absent post-restart OSV recurrence is caused by an
obvious container-level schedule override. Listed configuration paths, reviewed
the image command and selected non-secret environment values, and inspected the
bounded startup log for the OSV task.

### Observed Facts

- The bundled image starts the Dependency-Track JAR with Java options and no
  visible task-specific OSV/NIST/EPSS environment variables.
- The only OSV task execution after the restart began at 22:00 UTC and was a
  successful incremental mirror: RubyGems had no changes; PyPI processed 1;
  Go processed 45; npm processed 29 advisories. The task logged completion.
- No second OSV task execution is present in the retained post-restart logs,
  while other scheduled controls continue.

### Interpretation and Product Decision

The first post-restart run is a valid successful incremental update, not a full
mirror. The absence of a task-specific environment override shifts the open
question toward persisted/system configuration, timer lifecycle, or an
internal scheduling failure. Do not change product logic or force a mirror;
investigate through supported DT configuration/telemetry on the next planned
lab run.

### Unverified and Evidence

The persisted cadence value and the exact reason for the missing second task
remain unverified. Only sanitized ledger facts are retained; no credentials or
raw environment/configuration payloads were saved.

## 2026-09-20 — Post-restart OSV recurrence remains absent

- Status: read-only interval review completed; recurrence not observed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: runtime metadata, OSV markers, scheduler controls, and non-secret env inspection

### Purpose and Performed Work

Revisit the post-restart baseline after roughly four days of runtime. Read the
container state and OSV markers, summarized logs from the restart through
2026-09-19 21:04 UTC, and checked for non-secret scheduling environment
variables. No state, configuration, or credentials were changed.

### Observed Facts

- The container remains running with start time 2026-09-15 21:59:46 UTC and
  `restart_count=1`.
- The four OSV modified markers remain at approximately 2026-09-15 22:00 UTC;
  no later OSV marker exists. Full markers remain at their initial values.
- Post-restart logs contain only the initial 32 OSV task lines, while control
  tasks continue: 20 Portfolio Metrics pairs and four Internal Component
  Identification pairs were observed through 2026-09-19.
- No matching non-secret task scheduling environment variables were present.

### Interpretation and Product Decision

This is now strong evidence that the tested 4.14.3 process did not record a
second OSV task execution while other scheduled controls continued. It still
does not identify whether the OSV timer was disabled, suspended, or failed
before logging. Treat OSV freshness as unknown; do not add a product alert or
change cadence based on this internal marker alone. The next useful action is a
version/configuration-specific investigation, not more frequent polling.

### Unverified and Evidence

The OSV scheduler's effective configuration and failure path remain unverified.
Evidence remains in ignored `var/dt-lab/runs/<run>/` artifacts and the bounded
log summary; no raw log was committed.

## 2026-09-17 — Bounded quiet-window check

- Status: read-only check completed; no matching task events
- Target: Dependency-Track 4.14.3 bundled container
- Scope: 2026-09-16 23:38:40–2026-09-17 00:05:00 UTC logs

### Purpose and Observed Facts

Checked a longer bounded window for OSV, NIST, EPSS, and scheduler-control
events after the previous spot check. No matching task lines were emitted, and
the command performed no mutation. The container and marker state were not
changed by the lab.

### Interpretation and Product Decision

The quiet window is inconclusive and does not distinguish host suspension from
task scheduling delay. Defer further polling until a meaningful runtime
interval has elapsed; keep the observation lab-only and product freshness
unknown.

### Unverified and Evidence

The next OSV recurrence remains unverified. No raw log artifact was retained;
future sanitized evidence uses `var/dt-lab/runs/<run>/`.

## 2026-09-17 — Runtime continuity spot check

- Status: read-only spot check completed; no new datasource event
- Target: Dependency-Track 4.14.3 bundled container
- Scope: container state, OSV markers, and a bounded ten-minute log window

### Purpose and Performed Work

Verify that the post-restart observation baseline remains valid. Checked runtime
metadata and markers, then searched logs from 2026-09-16 23:28:35–23:38:40 UTC.
No state or configuration was changed.

### Observed Facts

- Container remains running with start time 2026-09-15 21:59:46 UTC and
  `restart_count=1`.
- All OSV markers are unchanged from the post-restart initial run.
- No scheduler or datasource task lines appeared in the ten-minute window.

### Interpretation and Product Decision

This short quiet window adds no evidence about OSV timer health. Continue with
longer, bounded checks after sufficient runtime; keep product freshness
unknown unless a supported contract is available.

### Unverified and Evidence

The next OSV recurrence and effective timer runtime remain unverified. Any
future artifacts use ignored `var/dt-lab/runs/<run>/` paths.

## 2026-09-17 — Post-restart cadence checkpoint

- Status: read-only checkpoint completed; post-restart recurrence still unverified
- Target: Dependency-Track 4.14.3 bundled container
- Scope: runtime metadata, OSV markers, and bounded logs

### Purpose and Performed Work

Continue from the verified 2026-09-15 restart boundary. Confirm the container
remains stable, inspect the OSV markers, summarize logs from the restart through
2026-09-16 23:28 UTC, and search the expected recurrence window for datasource
errors. No state was changed.

### Observed Facts

- Container remains running with the same start time
  (2026-09-15 21:59:46 UTC) and `restart_count=1`.
- OSV markers still show the post-restart initial run around 22:00 UTC on
  2026-09-15; no later marker is present.
- The post-restart window includes the initial OSV/NIST/EPSS executions, nine
  Portfolio Metrics pairs, and two Internal Component Identification pairs.
  No datasource error or exception was found around the expected 24-hour OSV
  recurrence window.

### Interpretation and Product Decision

The container and control timers are active, but a second OSV recurrence is not
yet evidenced despite more than 24 hours of wall-clock time. Host suspension,
fixed-delay scheduling, or task timing remain possible explanations; this does
not justify changing product freshness behavior. Continue bounded observation
until another OSV marker or a reproducible failure signal appears.

### Unverified and Evidence

Effective timer runtime and the next incremental update remain unverified.
Evidence paths use ignored run patterns under `var/dt-lab/runs/<run>/`.

## 2026-09-17 — Restart boundary discovered

- Status: read-only follow-up completed; recurrence interpretation reset
- Target: Dependency-Track 4.14.3 bundled container
- Scope: OSV markers, bounded logs, and container runtime metadata

### Purpose and Performed Work

Reconcile the unchanged OSV markers after the prior observation window. Read
the marker files, summarized logs from 2026-09-16 07:53:30–23:12:20 UTC, and
inspected container start/restart metadata. No container or datasource mutation
was performed by the lab.

### Observed Facts

- OSV modified markers remained at approximately 2026-09-15 22:00 UTC; full
  markers remained at the initial 2026-09-11 values.
- The bounded log window contained three Portfolio Metrics pairs and one
  Internal Component Identification pair, with no OSV/NIST/EPSS task lines.
- Container metadata reports `started=2026-09-15T21:59:46Z`,
  `restart_count=1`, and `running`. This restart occurred after the previous
  marker observation and was not initiated by the lab command.

### Interpretation and Product Decision

The 2026-09-15 22:00 OSV update is temporally adjacent to the container restart
and cannot be used as evidence of a steady-state 24-hour recurrence. The timer
observation window must be restarted from this process start; continue with
read-only monitoring and do not infer a scheduler failure from the absence of a
later update.

### Unverified and Evidence

The first post-restart incremental recurrence remains unverified. Evidence is
kept under ignored paths using `var/dt-lab/runs/<run>/...` patterns.

## 2026-09-16 — OSV interval follow-up

- Status: read-only follow-up completed; no second OSV recurrence observed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: OSV markers and bounded scheduler logs; no state mutation

### Purpose and Performed Work

Continue the post-incremental observation without restarting Dependency-Track.
Read the OSV marker files and inspected the 2026-09-16 03:37:10–07:53:30 UTC
log window.

### Observed Facts

- All four modified markers remained at approximately 2026-09-15 22:00 UTC;
  full markers remained at their initial 2026-09-11 values.
- The window contained four Portfolio Metrics log lines (two start/end pairs).
  No OSV, NIST, EPSS, or Internal Component Identification lines appeared.
- The container was not restarted and no Dependency-Track state was changed.

### Interpretation and Product Decision

The unchanged marker during this four-hour window is consistent with the
configured OSV cadence and does not establish a failure. Keep waiting for the
next effective OSV timer execution; do not promote internal marker data into
product freshness logic.

### Unverified and Evidence

The next incremental cycle and failure-specific diagnostics remain unverified.
Evidence remains in ignored paths using the patterns
`var/dt-lab/runs/<run>/osv-internal-markers.json` and
`var/dt-lab/runs/<run>/datasource-log-window.json`.

## 2026-09-16 — Post-incremental stability check

- Status: read-only follow-up completed; no new OSV cycle yet
- Target: Dependency-Track 4.14.3 bundled container
- Scope: OSV markers and bounded scheduler logs; no state mutation

### Purpose and Performed Work

Check whether the successful 2026-09-15 incremental OSV update is followed by
normal scheduler activity without restarting the container. Read the marker
files and inspected a bounded 2026-09-16 00:16:30–03:37:10 UTC log window.

### Observed Facts

- All four OSV modified markers remained at approximately 2026-09-15 22:00 UTC;
  full markers remained at the initial 2026-09-11 values.
- The window contained one Internal Component Identification start/end pair and
  three Portfolio Metrics start/end pairs (six matching log lines). No OSV,
  NIST, or EPSS task lines appeared.
- No container restart or mutation was performed.

### Interpretation and Product Decision

The scheduler control tasks continue to run while the OSV marker remains
unchanged for this short interval. This is compatible with a 24-hour OSV
cadence and does not indicate failure. Continue count-based observation until
the next expected effective OSV cycle; keep internal markers lab-only.

### Unverified and Evidence

The next incremental cycle, task failure diagnostics, and timer behavior across
host suspension remain unverified. Evidence paths are retained only as ignored
run artifacts: `var/dt-lab/runs/<run>/osv-internal-markers.json` and
`var/dt-lab/runs/<run>/datasource-log-window.json`.

## 2026-09-16 — OSV incremental recurrence observed

- Status: read-only observation completed; first incremental recurrence confirmed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: OSV internal markers and bounded datasource/scheduler logs; GHSA remains disabled

### Purpose and Performed Work

Re-check the OSV success markers after additional effective runtime without
restarting the container. Read the four ecosystem marker pairs, then ran the
strict marker summarizer and a bounded log summarizer. The commands were
read-only; no datasource, Project, Analysis, credential, container, or GitHub
Issue state was changed.

### Observed Facts

- All four `*-modified.csv.ts` markers advanced to approximately
  2026-09-15 22:00 UTC, while the four full `.zip.ts` markers remained at the
  2026-09-11 initial mirror times.
- The bounded window 2026-09-15 02:31:19–2026-09-16 00:16:30 UTC contained
  two OSV task starts/completions and eight incremental-download start/completion
  pairs. NIST and EPSS also completed; GHSA was not observed because it is
  disabled.
- Portfolio Metrics had five start/end pairs and Internal Component
  Identification one pair. The marker summary assessed all ecosystems as
  `within-threshold` for the caller-supplied 30-hour threshold at
  2026-09-16 00:16:20 UTC. Raw input was not persisted.

### Interpretation and Product Decision

The first effective recurring OSV execution is now evidenced as a successful
incremental update. This validates that the scheduler and OSV datasource can
progress after the initial full mirror; full archives are not rewritten for an
incremental run. Keep this marker diagnostic lab-only and version-coupled, and
do not infer upstream completeness or product freshness solely from it.

### Unverified and Evidence

Per-ecosystem record: `var/dt-lab/runs/<run>/osv-internal-markers.json`.
Log-window record: `var/dt-lab/runs/<run>/datasource-log-window.json`.
The exact task cadence under host suspension, subsequent incremental cycles,
and independent datasource health remain unverified.

## 2026-09-15 — OSV first-recurrence progress and GHSA log contract

- Status: OSV recurrence pending; bounded read-only follow-up completed
- Target: Dependency-Track 4.14.3 bundled container
- Scope: OSV markers and scheduled-task logs; GHSA remains disabled

### Purpose and Performed Work

Continue waiting for the first effective 24-hour OSV recurrence without forcing
a restart, while using shorter diagnostics rather than blocking lab progress.
An initial read-only command combined a full-history Docker log scan with marker
inspection but did not return in a useful time and was interrupted by the user.
It performed no write. Replaced it with a marker-only read and a 20-second-capped
log query limited to 2026-09-14 11:00–2026-09-15 02:31 UTC.

Captured the unchanged eight OSV marker lines through the strict marker
summarizer with an explicit observation time and 30-hour diagnostic threshold.
Separately reviewed the exact 4.14.3 `GitHubAdvisoryMirrorTask` implementation
because GHSA is disabled and therefore unavailable for live parser validation.
Added synthetic tests for both its initial and incremental start messages and
both success outcomes. No datasource, Project, Analysis, credential, container,
or GitHub Issue state was changed.

### Observed Facts

- At 2026-09-15 02:31:19 UTC, every OSV full and incremental marker still held
  its initial 2026-09-11 value. Ages ranged from 336,375 to 336,535 seconds
  (about 93 hours 26 minutes to 93 hours 29 minutes), so no newer successful OSV
  update was recorded.
- The bounded 15.5-hour log window contained four Portfolio Metrics start/end
  pairs and one Internal Component Identification start/end pair, but no OSV,
  NIST, or EPSS task event.
- The first Portfolio Metrics pair in that bounded window was already present
  in the preceding full-window summary. Combining non-overlapping starts yields
  approximately 22 hourly control executions since process start: the initial
  execution plus about 21 repeat intervals, still fewer than 24.
- The interrupted full-history command produced no retained evidence. The
  replacement marker summary persisted no raw input and its 422-byte input
  digest matched the prior marker snapshot because all marker lines were
  unchanged.
- GHSA 4.14.3 logs a full or modified-since message at start and either a
  successfully-mirrored count or already-up-to-date message on success. This is
  verified against source and synthetic tests only; no live GHSA call occurred.

### Interpretation and Product Decision

The new control count remains consistent with the first 24-hour fixed-delay
mirror recurrence not yet being due in effective runtime. Wall-clock OSV marker
age now exceeds 93 hours, but it still must not be interpreted as a scheduler
failure on this intermittently suspended host. Continue without restart until
at least three more non-overlapping hourly control starts have occurred, then
capture a narrow mirror window and markers again.

GHSA classifier support is now reproducible but remains `implemented`, not live
evidence. Do not enable GHSA merely to complete parser coverage. Its future
enablement still requires an explicit, separately reviewed global datasource
experiment and credential decision.

### Unverified and Evidence

The first OSV/NVD recurrence, incremental results, independent mirror timer
health, and suspend/resume timer semantics remain unverified. The next check is
count-based, not a wall-clock deadline. Local evidence pattern:
`var/dt-lab/runs/<run>/osv-internal-markers.json` (ignored). Synthetic tests:
`lab/dependency_track/tests/test_datasource_freshness.py`.

- [GitHubAdvisoryMirrorTask 4.14.3](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/tasks/GitHubAdvisoryMirrorTask.java)

## 2026-09-14 — OSV internal success-marker and scheduler-control diagnostic

- Status: read-only observation completed; first recurrence remains pending
- Target: Dependency-Track 4.14.3 bundled container
- Scope: version-coupled OSV filesystem metadata; no API or state mutation

### Purpose and Performed Work

Follow up the absent datasource lifecycle logs with an independent success
signal and a scheduler control. Reviewed the exact 4.14.3 `TaskScheduler` and
`OsvDownloadTask` source, its Alpine 3.8.0 scheduler implementation, then
compared them with the target OpenAPI and runtime. The OpenAPI contains no
datasource task-status endpoint, and an unauthenticated status-only request to
the bundled `/metrics` path returned 404.

The implementation schedules OSV shortly after process start and then at the
configured cadence captured during scheduler construction. Alpine creates a
separate `java.util.Timer` for each event and uses fixed-delay `Timer.schedule`.
After successful processing, `OsvDownloadTask` writes ecosystem-specific full
and incremental timestamp marker files containing the operation start time. A
successful full update writes both markers; a successful incremental update
rewrites the incremental marker.

Read only those eight marker files for the configured Go, npm, PyPI, and
RubyGems ecosystems. Added a strict, 4.14.3-specific lab summarizer that requires
both markers for every declared ecosystem, a caller-supplied observation time
and maximum age. It rejects unexpected, duplicate, malformed, or incomplete
input and reports future timestamps as a distinct clock/state anomaly. The
summarizer stores normalized timestamps and an input digest, not raw paths or
input. Extended the log summarizer with hourly Portfolio Metrics and six-hour
Internal Component Identification control tasks, then summarized the full
observation window. No restart or forced mirror was performed.

### Observed Facts

- All four full and incremental marker pairs were present and equal within each
  ecosystem. Their values ranged from 2026-09-11 05:02:24 UTC to 05:05:03 UTC,
  matching the recorded initial full-mirror starts.
- At 2026-09-14 06:00:53 UTC, the latest ecosystem marker ages ranged from
  262,549 to 262,709 seconds (about 72 hours 56 minutes to 72 hours 58 minutes).
- With an explicitly supplied 30-hour diagnostic threshold, all four ecosystems
  were `older-than-threshold`. No newer successful incremental or full OSV
  update was recorded in this datastore after the initial mirror.
- The command persisted 422 bytes of normalized marker input metadata as a
  digest and summary under ignored `var/`; it did not persist the raw stream.
- The earlier initial-run logs, later log-window absence, and marker ages agree,
  but they are not independent implementations: both originate from the same DT
  process and version.
- Across 2026-09-11 05:01–2026-09-14 11:34 UTC, 1,911 timestamped log lines
  contained 19 completed Portfolio Metrics executions and three completed
  Internal Component Identification executions. Only the initial OSV, NIST,
  and EPSS task executions appeared. No retained line matched the searched
  scheduler-thread exception or uncaught-exception patterns.
- Portfolio Metrics is configured by DT for a one-hour cadence, but only 18
  repeat intervals occurred after its initial execution during about 78.5 hours
  of wall-clock observation. Its run times had large wall-clock gaps. This is
  consistent with the local host or runtime being suspended between work
  sessions; the control does not prove every independent timer is healthy.

### Interpretation and Product Decision

This narrows the previous `unknown`: the lab can now state that DT 4.14.3 did
not record a later successful OSV update on this datastore. It still cannot
distinguish a scheduler event that never ran from one that failed before marker
write, nor prove upstream completeness.

The control evidence changes the scheduler interpretation. Wall-clock age since
container start is not a valid substitute for elapsed timer cadence on this
intermittently available lab host. Eighteen observed one-hour repeat intervals
are fewer than the 24 needed for the first mirror recurrence and are consistent
with that recurrence not yet being due in effective timer time. This is an
inference from the task controls and Alpine implementation, not a measured JVM
timer clock. Keep the container active and observe the first 24-hour recurrence
without restarting; investigate an error path only if it then fails to appear.

Keep filesystem markers as lab diagnostics only. They are internal,
version-coupled, unavailable through the supported REST contract, and therefore
must not become a production adapter dependency. Product freshness remains
`unknown` unless a supported success signal is available. Production monitoring
must distinguish datasource age from scheduler/runtime availability; otherwise
a suspended or unavailable runtime can be mislabeled as an upstream mirror
failure. Any age threshold must be configuration and a breach must alert
operators rather than change priority or Analysis state.

### Unverified and Evidence

The first 24-hour effective-timer recurrence, suspend/resume timer semantics,
failure-notification delivery, each independent timer's health, NVD/EPSS success
timestamps, supported metrics in split deployments, and behavior after upgrade
remain unverified. Local evidence paths:
`var/dt-lab/runs/<run>/osv-internal-markers.json` (ignored). Reproducible checks:
`lab/dependency_track/tests/test_datasource_markers.py`.

The scheduler-control summary uses
`var/dt-lab/runs/<run>/datasource-log-window.json` (ignored); reproducible checks
are in `lab/dependency_track/tests/test_datasource_freshness.py`.

The disabled GHSA task had no live event to validate. Its exact 4.14.3 source
does not emit the generic start/completion phrases used by the other mirrors:
it starts with either a full or modified-since message and completes with either
a mirrored count or an already-up-to-date message. The lab classifier now
encodes those four official phrases with synthetic coverage. This makes it
runnable for a future explicitly approved GHSA experiment; it is not live GHSA
evidence and does not enable GHSA or supply a token.

- [TaskScheduler 4.14.3](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/tasks/TaskScheduler.java)
- [OsvDownloadTask 4.14.3](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/tasks/OsvDownloadTask.java)
- [AlpineTaskScheduler 3.8.0](https://github.com/stevespringett/Alpine/blob/alpine-parent-3.8.0/alpine-server/src/main/java/alpine/server/tasks/AlpineTaskScheduler.java)
- [GitHubAdvisoryMirrorTask 4.14.3](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/tasks/GitHubAdvisoryMirrorTask.java)

## 2026-09-14 — Datasource task log-window freshness observation

- Status: initial-run control verified; later freshness remains inconclusive
- Target: Dependency-Track 4.14.3 bundled container
- Scope: read-only Docker state and logs; no DT setting, restart, or API mutation

### Purpose and Performed Work

Test whether the configured 24-hour mirror cadence can be confirmed by observed
task execution rather than configuration alone. Reviewed the official recurring
task and OSV behavior documentation and the target's retained OpenAPI contract.
The OpenAPI contract exposes configuration but no datasource task-status read
endpoint. Inspected the running container identity, health, start time, restart
count, and bounded timestamped Docker log windows.

Added a lab-only parser and CLI that classify OSV, NIST, EPSS, and GitHub
Advisory mirror lifecycle events. It persists no raw messages or identifiers:
only the supplied window, input SHA-256 and byte count, task/event/timestamp
metadata, bounded OSV ecosystem names, counts, and an interpretation boundary.
Validated the parser first against the retained initial-mirror log window, then
against two later 30-hour windows. No credential, Analysis state, Project,
datasource setting, or GitHub Issue was changed.

### Observed Facts

- The container was healthy on image `dependencytrack/bundled:4.14.3`, had run
  since 2026-09-11 05:01:51 UTC, and reported zero restarts at observation time.
- The 2026-09-11 05:01:50–05:16:00 UTC control contained 256 timestamped lines.
  OSV emitted four full-download starts, four ecosystem completions, and one
  overall completion. NIST and EPSS each emitted an overall completion. GitHub
  Advisory emitted no event, consistent with its separately observed disabled
  configuration. This confirms the parser recognizes the target's real format.
- The 2026-09-12 19:23:06–2026-09-14 01:23:06 UTC window contained 150
  timestamped non-empty log lines but no classified OSV, NIST, EPSS, or GitHub
  Advisory lifecycle event. A separate earlier 30-hour sample contained 794
  timestamped lines and likewise contained no event for those four tasks.
- Narrow checks around expected daily hours also produced no matching
  datasource/scheduler event. No raw log was persisted by the new command.
- These observations do not establish whether a scheduler invocation occurred
  without matching logs, whether retained data was current, or whether any
  upstream source had changed.

### Interpretation and Product Decision

Enabled settings, a configured interval, process health, and uptime are not
sufficient freshness evidence. Adopt an explicit `unknown` freshness outcome
when neither a successful synchronization timestamp nor an equivalent bounded
observation is available. `not-observed` remains a statement about the supplied
log window only and must not become a priority, suppression, Analysis, or Issue
decision. Retain the lab summarizer as diagnostic evidence; do not import it
into the product runtime or infer source completeness from Finding labels.

Before productizing datasource freshness, identify a stable last-success signal
or supported task telemetry and define per-source stale thresholds in config.
Investigate scheduler timing and log retention without restarting DT merely to
force a run, since restart-triggered execution would not validate steady-state
recurrence. The later scheduler-control diagnostic found independent recurring
tasks still active but fewer than 24 one-hour repeat intervals; it supersedes a
wall-clock-only interpretation of this window.

### Unverified and Evidence

Steady-state scheduler execution, timer reset semantics, log-driver completeness,
the exact cause of the absent later events, upstream change handling, and last
successful synchronization timestamps remain unverified. Upgrade behavior also
requires revalidation.

- Local evidence pattern: `var/dt-lab/runs/<run>/datasource-log-window.json`
- Reproducible synthetic checks:
  `lab/dependency_track/tests/test_datasource_freshness.py`
- [Official recurring tasks](https://docs.dependencytrack.org/getting-started/recurring-tasks/)
- [Official OSV integration](https://docs.dependencytrack.org/datasources/osv/)

## 2026-09-13 — Product audit-sink and assessment-input visibility

- Status: completed synthetic validation and read-only live follow-up
- Target: Dependency-Track 4.14.3; 26 accessible lab Projects; GitHub disabled
- Source evidence: 2026-09-11 product read-only and real-corpus validations

### Purpose and Performed Work

Apply the smallest product change justified by the recorded observation that a
successful read-only sync silently lost its configured JSONL record when the
parent directory did not exist. Kept the sink optional and non-authoritative,
but routed its boolean write result through one CLI warning boundary for both
successful and handled-failure events. Added synthetic CLI tests for successful
and failed sink writes in machine-readable output mode.

Extended the action-neutral Finding assessment with vulnerability source,
severity, nullable numeric CVSS and EPSS, and suppression. After the tests
passed, ran `sync --dry-run --no-github --output json` against all accessible
Projects because the local optional Project selector was empty. The sandboxed
attempt failed at the first DT request and wrote a failed sync event; the same
read-only command then completed through the authorized local-network path.

### Observed Facts

- A simulated sink failure emits one warning on stderr while the successful sync
  remains exit code zero and stdout remains valid JSON.
- A simulated successful sink write emits no warning.
- A synthetic HIGH-severity Finding without numeric CVSS or EPSS remains P3 under
  the unchanged rules, while source, severity, null scores, Analysis state, and
  suppression are now explicit in the action-neutral assessment.
- The live run processed 26 Projects and 1,066 Finding associations. Every
  assessment contained the new fields. Sources were GITHUB 477, NVD 505, and
  OSV 84; priorities were P0 31, P1 63, P2 208, and P3 764.
- Numeric CVSS was absent on 561 assessments: 477 GITHUB and 84 OSV. Of these,
  543 were P3 and 18 CRITICAL-severity records were P1 under the existing
  severity rule. All 135 HIGH-severity records without numeric CVSS were P3.
- Numeric EPSS was absent on the same 561 assessments. No Finding was suppressed
  at observation time.
- The live run was dry-run with GitHub disabled: actions and create, update, and
  close counts were all zero.
- The product change does not alter the orchestrator result, retry the sink, or
  create its parent directory. The synthetic sink tests contact no external
  system; the separate live follow-up performed only DT and KEV reads.

### Interpretation and Product Decision

Adopt the verified gap as a product constraint: optional audit persistence must
not replace the primary synchronization result, but its loss must be observable.
stderr preserves the stdout JSON contract for downstream consumers. Operators
remain responsible for provisioning and monitoring the configured evidence path.
The assessment projection also adopts the earlier real-corpus requirement that
missing numeric scores remain visible. This is observability, not a severity
fallback or triage-policy change.

### Unverified and Evidence

Centralized log collection, alert delivery, disk-full behavior, concurrent
append durability, and a real deployment filesystem failure remain unverified.
The current data cannot justify a textual-severity fallback or any priority
change; PoC, exposure, applicability, and reachability remain separate missing
inputs. Reproducible tests are in `tests/unit/test_cli.py` and
`tests/unit/test_orchestrator.py`. Local evidence is ignored at
`var/dt-lab/validation-2026-09-13/sync.jsonl`; it contains environment-specific
identifiers and must not be committed.

## 2026-09-11 — Rails after OSV and evidence-join readiness

- Status: Rails corpus observation completed; identity readiness assessed offline
- Target: DT 4.14.3 after initial OSV synchronization
- Input: pinned OpenProject 17.7.2 schema-valid CycloneDX 1.6 derivative

### Purpose and Performed Work

Complete the four-language corpus check and determine whether real Findings
provide stable identity for future PoC and asset-context joins. Imported the
unchanged Rails derivative into a fresh run-marked Project and retained nine
observations. Compared the summary with the earlier retained run. Separately
tested the existing exploit-lab capture loader on the three prior post-OSV
captures, without external intelligence requests or target probing.

### Observed Facts

- The Rails run completed from 09:08:49 to 09:11:15 UTC (about 146 seconds).
  DT's BOM log reported about five seconds for BOM processing itself; that does
  not include all asynchronous work and observation retrieval.
- DT retained 16,742 Components, matching the earlier run, from 17,831 input
  records. The BOM log reported deduplication and an incomplete graph because
  the metadata root was not a graph entry; this is not evidence of reachability.
- Findings increased from 285 NVD records to 619: NVD 307, GITHUB 311, OSV 1.
  These are associations, not unique flaws. The NVD records alone represented
  147 unique primary CVE IDs.
- All 619 Findings had PURLs and Component UUIDs. Their PURL types were gem 496,
  npm 94, deb 26, pypi 2, and generic 1. All aliases were empty. EPSS was populated
  for 307 Finding projections. The Project was retained for follow-up.
- In the preceding Go/n8n/Airflow captures, all 83 Findings had PURLs and Component
  UUIDs, only seven primary IDs were CVEs, and aliases were empty. The existing
  CVE-only exploit loader rejected each capture on a GO or GHSA identifier.
  No external PoC requests were issued by that local loader check.

### Interpretation and Product Decision

Component joins are feasible for these Findings, but vulnerability-ID resolution
is a prerequisite for CVE-based enrichment. Do not relabel unresolved identifiers
as absent PoC or silently discard them. Record resolution coverage and preserve
original source/ID before evaluating mapping providers. This loader behavior is
fail-closed but prevents current mixed-source captures from entering the sampler.

Defer triage-rule changes as agreed by the user. First validate source-attributed
PoC evidence and deployment-specific internet-facing evidence as separate inputs.
There is no supplied deployment inventory for these public software artifacts:
their exposure remains unknown. A public repository or service URL cannot fill
that gap, and the incomplete graph cannot establish vulnerable-code reachability.

### Limits and Local Evidence

The earlier corpus run used older source data; the increase is not attributable
solely to OSV with a frozen baseline. No applicability decisions, priority-rule
changes, exposure probes, Analysis mutations, or GitHub Issue operations occurred.
The product was not rerun on Rails in this step. Cross-source deduplication,
CVE mapping, actual PoC coverage, and deployed exposure remain unverified.

- Rails: `var/dt-lab/runs/6e2c1aa2-43cf-4bd9-9854-d5d6b7d657c0/` (ignored).
- Earlier Rails: `var/dt-lab/runs/91ab16d8-3221-408f-be67-93bd50bea233/`.
- Other inputs: `var/dt-lab/runs/26008b9d-bb03-49ca-81a3-c325c48a66e1/`.
- Local identifier counts are reproducible from `findings.json` and
  `summary.json`; loader failures were observed in the execution transcript.

## 2026-09-11 — Completed OSV mirror and real-corpus reassessment

- Status: initial mirror completed; three real inputs and product assessments observed
- Target: DT 4.14.3; pinned CycloneDX 1.6 inputs; GitHub operations disabled

### Purpose and Performed Work

Waited for explicit mirror completion before rerunning the unchanged OTel OBI,
n8n, and converted Airflow corpus artifacts in fresh run-marked Projects.
Captured nine observations per import with the existing runner. Compared their
summaries with retained earlier runs, then ran the product CLI separately for
each new Project with `--dry-run --no-github` and a local JSONL log.

### Observed Facts

The mirror began at 05:02:24.484 UTC and reported completion at 05:15:02.718 UTC
(about 12 minutes 38 seconds). Per-ecosystem parsing totals were RubyGems 4,778,
PyPI 25,560, Go 9,212, and npm 228,941 (268,491 advisory inputs, not unique CVEs).
The four downloaded ZIP files totalled 265,066,730 bytes. A mid-run observation
showed npm at 80%, about 188% CPU and 5.483 GiB memory of the 8 GiB limit; this
was a point observation, not a peak measurement.

| Same pinned input | Components before/after | Earlier Findings | New Findings by source | Product priorities |
| --- | ---: | --- | --- | --- |
| OTel OBI 0.12.2 | 233 / 233 | NVD 7 | NVD 7, GITHUB 3, OSV 12 | P2 5, P3 17 |
| n8n 2.36.8 | 1,458 / 1,458 | 0 | GITHUB 42 | P3 42 |
| Airflow 3.3.0, converted 1.6 | 121 / 121 | 0 | GITHUB 10, OSV 9 | P3 19 |

- All three imports and product dry-runs completed; no Issues were created,
  updated, or closed. The new Projects were retained for follow-up observations.
- All 83 Finding projections had no aliases. EPSS appeared in seven Go Finding
  projections; n8n and Airflow had no populated numeric CVSS or EPSS fields in
  their recorded coverage. All had severity fields.
- n8n had 19 HIGH, 22 MEDIUM, and one LOW Finding; Airflow had ten HIGH and nine
  MEDIUM Findings. Despite HIGH labels, all were P3 in the product dry-run.
- Go had seven HIGH, three MEDIUM, and twelve UNASSIGNED Findings.

### Interpretation and Product Decisions

Source configuration materially changes the observed inventory of vulnerabilities
for identical SBOM input. This supports using DT's existing ecosystem mirrors
instead of adding parallel package-vulnerability matching to sbom-ops.

`vulnerability.source=GITHUB` does not prove that the GHSA mirror is enabled:
these records appeared after OSV ingestion with GHSA disabled. Preserve source
labels and distinguish advisory identity/source from acquisition mechanism.

The current priority engine requires numeric CVSS for P2; HIGH severity alone
does not satisfy that rule. Consequently missing enrichment can produce P3,
which must not be presented as evidence of low risk. Next evaluate an explicit
missing-score indicator and a reviewed configurable severity fallback, without
silently changing policy. Alias absence also limits CVE-based KEV correlation
and cross-source deduplication; do not infer separate records are distinct flaws
or enable OSV alias sync automatically.

### Limits and Evidence

Earlier runs occurred at different times, so this is not a frozen-feed causal
comparison. Findings count Component/vulnerability associations, not distinct
flaws or verified applicability. Numeric field absence was measured on the
Finding projection, not all possible upstream data. Rails/OpenProject remains
the next real-corpus case. Incremental mirror behavior, sustained freshness,
full post-import quiescence, and unique-vulnerability comparison remain open.

- New run: `var/dt-lab/runs/26008b9d-bb03-49ca-81a3-c325c48a66e1/` (ignored).
- Earlier summaries: the retained run directories for the same three corpus IDs.
- Product logs: `var/dt-lab/osv-enablement-20260911/corpus-sync.jsonl` (ignored).
- Mirror timestamps and resource sample were observed in Docker command output;
  no full container log containing unrelated configuration was persisted.

## 2026-09-11 — Audited OSV enablement and first mirror start

- Status: configuration verified; initial mirror started, completion pending
- Target: original bundled DT 4.14.3, after cold backup and isolated recovery test
- Scope: instance-wide OSV selection; no Analysis or GitHub Issue changes

### Purpose and Performed Work

Implemented a repository-only `configure-osv` command with a domain plan,
baseline checks, explicit execution/instance confirmation, recovery-evidence
hash, exclusive durable JSONL audit, non-retried POST, and independent readback.
The client holds only API communication; the service owns the exact four-source
policy. Full settings and API errors are not copied to the audit.

Reviewed the target OpenAPI and official 4.14.3 ConfigPropertyResource and
OsvDownloadTask implementations. OSV splits its configuration on semicolons.
The requested legacy `/usage/vex/` and `/usage/analysis/` documentation URLs
returned HTTP 404; no Analysis/VEX behavior was changed by this experiment.

Ran a live dry-run, then executed the reviewed change using the user-authorized
existing key and retained recovery evidence. Rechecked after a readback mismatch,
corrected set comparison, and verified without another configuration POST.
Restarted the original DT explicitly to initiate mirroring after no start message
was observed immediately following the settings change.

### Observed Facts

- Preview saw OSV ecosystems null; proposed `Go;npm;PyPI;RubyGems`.
- The first execution wrote its intent and sent the update. DT returned the
  selected ecosystems as `RubyGems;PyPI;Go;npm`. Exact string comparison rejected
  the readback, and the audit correctly ended as failed despite the applied
  setting. No automatic rollback was attempted.
- An independent read confirmed the exact four ecosystems; GHSA and OSV alias
  sync remained false. Set-aware validation then succeeded with no second POST.
- Added a regression for reordered settings and no-op execution. All 76 lab
  tests passed; all 67 product tests passed. Ruff passed. Multi-file Black hung
  and was interrupted; individual-file Black runs completed successfully.
- After restart, DT logged at 05:02:24 UTC: the OSV mirror started for RubyGems,
  PyPI, Go, and npm. A subsequent check found DT running/healthy, with no mirror
  completion message yet observed. The background mirror remains active in DT;
  no shell polling process was left running.

### Interpretation and Remaining Work

Configuration comparison must use ecosystem-set semantics, not serialization
order. Write failure and post-write verification failure must be distinguished
operationally by the durable intent and readback. The command does not implement
server-side concurrency protection; serialize configuration experiments. Recovery
evidence is a human-reviewed attestation, not proof reconstructed by the command.

Observe successful mirror completion or errors before interpreting new Findings
or importing the real corpus. Initial mirror duration, storage growth, freshness,
and extra detections remain unverified. Existing DT Projects can be reanalyzed
as sources change; this is not confined to a single Project. OSV disablement is
not data rollback. GHSA and GitHub Issue synchronization remain deferred.

### Local Evidence and Sources

- `var/dt-lab/osv-enablement-20260911/{preview,execute,verify}.jsonl` (ignored).
- Recovery evidence: `var/dt-lab/restore-tests/osv-baseline-20260911/README.md`.
- [OSV task, DT 4.14.3](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/tasks/OsvDownloadTask.java)
- [Configuration resource, DT 4.14.3](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/resources/v1/ConfigPropertyResource.java)

## 2026-09-11 — Isolated restoration of the OSV baseline

- Status: bounded recovery validation completed
- Target: exact local image used by bundled DT 4.14.3
- Safety: separate data copy, Docker network `none`, no published ports

### Purpose and Performed Work

Validate that the cold backup can start a usable database before the OSV mirror
experiment. Copied the entire backup into an ignored restore-test directory;
the original backup was not started or modified. Before startup, the copied H2
SHA-256 matched the backup manifest. Started a separately named container on the
original immutable image ID, with an 8 GiB memory limit and two CPUs.

Checked Docker health, the internal API, authentication, Project count, selected
source settings, and portfolio metrics using container-local curl. The API key
was supplied through standard input, not process arguments or a persisted file.
Only selected non-secret fields were output. Stopped the validation container
after the checks and confirmed that the original DT remained running/healthy.
No mirror settings or GitHub Issue state were changed.

### Observed Facts

- Restored container became healthy; internal `/api/version` returned HTTP 200.
- Docker reported network `none` and no host port bindings.
- Existing-key authentication succeeded, returning 22 Projects.
- Source settings matched the recorded baseline: NVD and EPSS enabled, GHSA
  disabled, OSV ecosystems null, and OSV alias synchronization disabled.
- Portfolio metrics reported 22 Projects, 36 Components, 191 vulnerabilities,
  12 vulnerable Projects, and 19 vulnerable Components. The 191 aggregate agrees
  numerically with the preceding Finding count but is not row-level equality.
- The isolated container was stopped successfully and retained with its data.

### Interpretation and Limits

The backup supports database startup, existing-key authentication, selected
configuration recovery, and inventory aggregates on the same image. It is now
sufficient evidence to proceed with a bounded, explicitly audited mirror
experiment. This does not test a full original-volume replacement, every row,
all encrypted external credentials, cross-version recovery, or external
integrations. Network isolation intentionally prevents mirror synchronization;
no source freshness conclusion follows from this run.

### Local Evidence and Reproduction

- Immutable baseline: `var/dt-lab/backups/osv-baseline-*/` (ignored, private).
- Restore copy and manifest: `var/dt-lab/restore-tests/osv-baseline-20260911/`.
- Container: `dt-lab-restore-osv-20260911` (stopped; not auto-removed).
- Start a separate copy with the baseline image ID, `--network none`, no `-p`,
  and its `/data` bind mount; inspect health and use `docker exec` for local API
  checks. Never point the test container at the immutable backup or live volume.

## 2026-09-11 — Cold backup before OSV mirror experiment

- Status: backup completed; isolated restoration remains unverified
- Target: running bundled DT 4.14.3, Docker volume mounted at `/data`

### Purpose and Performed Work

Following the user's instruction to continue the proposed four-ecosystem lab
work, inspected the local datastore and prepared recovery evidence before any
global OSV configuration change. The data directory used about 5.4 GiB, with
an H2 `db.mv.db` file of 2,541,670,400 bytes. The filesystem reported 128 GiB
available before copying.

Created an ignored backup parent with mode 0700 and a new private directory.
Stopped the exact existing container with a 60-second timeout, copied its entire
`/data` directory, and restarted it. An EXIT trap guarded restart if copying
failed. Calculated the copied H2 file's SHA-256 and retained it in a local backup
manifest. No source data was deleted or overwritten.

### Observed Facts and Decision

The copy completed (about 5.4 GiB). The original container restarted; the
production client's authenticated Project listing subsequently succeeded with
22 Projects. This checks API recovery and count continuity, not all inventory
or configuration equality. No OSV settings, alias settings, or GHSA credentials
were changed, and no GitHub Issue operations were performed.

A checksum and successful original-instance restart do not prove the copied
database can be restored. Keep the backup untouched and test a separate copy
with the same image and outbound networking blocked before changing mirrors.
This backup contains sensitive material and must remain private and ignored.

### Unverified and Local Evidence

Isolated restore/startup, baseline configuration/Finding equality, encryption
material usability, and OSV synchronization are still unverified. Backup and
local manifest: `var/dt-lab/backups/osv-baseline-*/` (ignored). The recovery
procedure is documented in the lab README. The backup is not a full-database
reset feature or part of run-scoped Project cleanup.

## 2026-09-11 — OSV/GHSA readiness and local corpus denominators

- Status: local preparation completed; no new live DT experiment
- Inputs: six pinned local corpus artifacts; official DT v4.14 datasource docs

### Purpose and Performed Work

Determine a bounded source-enablement experiment for the actual corpus. Ran
`validate-corpus --require-local`: all six artifacts passed integrity checks
(30,835,677 bytes total). This command did not perform full schema validation.
Counted top-level Component PURL types in four selected compatible inputs.

### Observed Facts

| Input | Top-level Components | Relevant PURL counts |
| --- | ---: | --- |
| OTel OBI 0.12.2 | 233 | golang 219; github 7; maven 1; missing 6 |
| n8n 2.36.8 | 1,458 | npm 1,458 |
| OpenProject 17.7.2 schema-valid derivative | 17,831 | gem 1,432; npm 1,338; pypi 12; missing 14,141 |
| Airflow 3.3.0 CycloneDX 1.6 derivative | 121 | pypi 121 |

OpenProject also has cargo 174, deb 283, github 229, nuget 219, maven 1,
and generic 2. Counts describe source records, not unique packages or the
post-ingestion DT inventory. Original invalid/compatibility inputs remain pinned
and separate from derivatives.

### Interpretation and Next Experiment

1. Preserve a baseline and verified backup of the existing DT datastore before
   a global mirror change. Source settings affect the whole instance, including
   existing lab Projects. Record the backup/restore procedure and configuration.
2. Initially select OSV ecosystems Go, npm, PyPI, and RubyGems; keep OSV alias
   synchronization disabled. Review and explicitly approve this administrative
   change before execution. Do not enable GHSA simultaneously, so effects can
   be distinguished.
3. Observe mirror completion/errors separately from BOM event completion.
   Use the same pinned inputs in disposable run-marked Projects. Capture
   complete inventory, Finding sources/identifiers/aliases, EPSS presence,
   suppression, processing duration, and the GitHub-disabled product assessment.
4. Compare per ecosystem and stable package identity, retaining both raw
   Finding counts and unique vulnerability counts. Empty results are not proof
   of safety; all-Component counts are not a coverage denominator. Do not infer
   that missing PURLs make all other matching impossible.
5. Evaluate GHSA separately after OSV. DT's documented GHSA mirror needs a PAT
   without assigned scopes. Do not copy the existing GitHub CLI credential into
   DT implicitly. GitHub Issue synchronization remains the last work item.

### Limits, Recovery, and Sources

OSV is documented as preview in DT v4.14. Disabling it clears ecosystem
selection but retains mirrored vulnerabilities, so toggling it off is not a
data rollback. A verified datastore restore is needed to recover the exact
baseline. No backup, restore, mirror change, or new import was performed here.
Mirror duration, disk growth, synchronization health, and additional Findings
remain unmeasured. Local evidence inputs: `var/dt-lab/corpus/` (ignored); pinned
hashes and reproduction inputs: `lab/dependency_track/corpus/corpus.yaml`.

- [Official OSV integration](https://docs.dependencytrack.org/datasources/osv/)
- [Official GHSA integration](https://docs.dependencytrack.org/datasources/github-advisories/)

## 2026-09-11 — Datasource configuration after user-granted permission

- Status: configuration observed; synchronization health still unverified
- Target: existing DT 4.14.3 instance

### Purpose and Performed Work

After the user added SYSTEM_CONFIGURATION to the existing read team, confirmed
the permission through the existing lab client's team observation and read
GET `/api/v1/configProperty` through that client's request method. No settings
were changed. Only permission presence, configuration field names, boolean
values, and explicitly selected ecosystem/cadence/timestamp values were output.
The full settings response was not persisted because it may contain secrets.

### Observed Facts

- SYSTEM_CONFIGURATION was present and the settings read succeeded (102 items).
- Initial filtering by group names returned no selected settings. Inspection
  established that source configuration uses group `vuln-source`; an empty
  filter result was not treated as evidence of disabled sources.
- `github.advisories.enabled=false`; `epss.enabled=true`; `nvd.enabled=true`.
- `google.osv.enabled` was null. Its description defines a list of ecosystems
  to mirror, not a boolean. No OSV ecosystems were configured in this response.
- `nvd.api.enabled=false` and `nvd.api.download.feeds=false`.
- NVD, GHSA, and OSV mirror cadence settings were each 24 hours.
- GHSA and NVD API latest-observed-modification timestamp fields were null.
  These fields describe upstream modification times, not last successful runs.

### Interpretation and Product Decision

The configuration explains a concrete coverage limitation: GHSA was disabled
and OSV had no configured ecosystems. The NVD-only Finding observation must not
be generalized to all ecosystem coverage or to vulnerability absence. Review
the required OSV ecosystems and GHSA setup before enabling sources and comparing
real SBOMs again. GitHub Advisories is vulnerability intelligence and is separate
from the deferred GitHub Issue synchronization workflow.

### Unverified and Evidence

NVD/EPSS last successful synchronization, mirror failures, historical settings,
and runtime analyzer behavior remain unverified. Enabled flags and cadence do
not establish freshness. No permission or datasource mutation was made by the
agent. Selected non-secret observations are recorded above from the execution
transcript; no raw settings file was retained. Existing local target contract:
`var/dt-lab/openapi.json` (ignored). The product dry-run evidence remains at
`var/dt-lab/validation-2026-09-11/sync.jsonl` (ignored).

## 2026-09-11 — Product read-only validation and source visibility

- Status: partial live validation; inventory and assessment completed
- Target: Dependency-Track bundled 4.14.3, healthy local Docker container
- Scope: existing accessible lab Projects; no BOM upload or DT/GitHub mutation

### Purpose and Performed Work

Exercise the product against the existing inventory before testing work-item
transitions. Checked API connectivity and container health, listed Projects
using the product client, and ran the product CLI with `--dry-run --no-github
--output json`. Independently read Findings through the product client to count
source, EPSS, suppression, and Analysis projections. Read the current team's
permission names through the existing lab client, and inspected the retained
target OpenAPI contract for configuration access.

### Observed Facts

- An initial sandbox connection failed, and the first host-side probe timed out.
  A later host-side OpenAPI probe returned HTTP 200. The cause of the transient
  timeout was not established.
- All 22 accessible Projects had lab names. Both CLI runs processed 191 Findings:
  P0 31, P1 38, P2 57, P3 65. GitHub operations were disabled; create/update/close
  counts were zero and the action list was empty.
- The independent read found ten empty Projects. All 191 Findings had source
  NVD and a non-null EPSS value. None were suppressed; 11 had `NOT_SET` Analysis
  and 180 had no Analysis state. These are time-specific observations.
- The current team had VIEW_BADGES, VIEW_POLICY_VIOLATION, VIEW_PORTFOLIO,
  VIEW_VULNERABILITY, and VULNERABILITY_ANALYSIS. It lacked SYSTEM_CONFIGURATION,
  which the retained OpenAPI requires for GET `/v1/configProperty`. No settings
  request or permission change was performed.
- The first CLI run returned its result but did not save the optional sync log
  because the parent directory was absent. The sink returns false on OSError
  and the CLI ignores that return value. Created the directory and repeated
  the read-only run to retain its JSONL result.

### Interpretation and Product Decision

The current inventory-to-priority path works against this lab instance. Reuse
DT EPSS. NVD-only observations do not prove other analyzers are disabled, nor
do empty Projects prove vulnerability absence. Obtain a redacted administrator
observation of enabled analyzers/mirrors, last successful synchronization, and
failures before interpreting ecosystem coverage. Preserve the read-key scope.

GitHub-disabled runs produce assessments but do not exercise Issue planning,
routing, or closure. No suppressed Finding was available, so the suppression
boundary remains covered by prior live evidence and product regression tests,
not newly verified here. Make optional audit-sink failures visible in a follow-up.

### Unverified and Local Evidence

Real-SBOM representativeness, datasource configuration/freshness, current
suppression transitions, analysis-in-progress behavior, and GitHub task
transitions remain unverified. The separate aggregate read and permission check
were captured in the execution transcript, not raw response files.

- Product result: `var/dt-lab/validation-2026-09-11/sync.jsonl` (ignored).
- Retained contract: `var/dt-lab/openapi.json` (ignored; not refreshed this run).
- Reproduce with the existing CLI after creating the log's parent directory:
  `sbom-ops sync --dry-run --no-github --output json --sync-log-file <local-path>`.
  Load local credentials without printing them; inventory counts may change.

This is the single durable record of live Dependency-Track experiments. It
records why an experiment was run, what was done, what was observed, and how
the evidence affects the product direction. A result is recorded even when the
run fails, stops partway, or remains inconclusive.

Raw request and response evidence remains local under
`var/dt-lab/runs/<run-id>/` and is intentionally ignored by Git. This ledger
must therefore contain every fact needed for review without copying secrets,
instance-specific UUIDs, timestamps, or entire payloads into the repository.

## Recording Rules

- Update this ledger in the same change as every attempted live experiment.
- Label status as `completed`, `partial`, `failed`, or `inconclusive`.
- Separate observed facts from interpretation and product decisions.
- State the Dependency-Track and CycloneDX versions that bound the result.
- Record negative results and unresolved questions; absence of evidence is not
  evidence that a capability is absent.
- Link local evidence by its stable path pattern. Do not commit raw evidence,
  credentials, Project UUIDs, Component UUIDs, or Finding UUIDs.
- An implemented scenario is not a verified behavior until a live result is
  recorded here.

## Entry Template

```markdown
## YYYY-MM-DD — Experiment title

- Status: completed | partial | failed | inconclusive
- Target: Dependency-Track x.y.z; CycloneDX x.y
- Scenarios: scenario-id

### Purpose

State the hypothesis and product decision the run must inform.

### Performed

Describe the inputs, API operations, safety boundary, and repetitions.

### Observed Facts

Record only behavior supported by the retained evidence.

### Interpretation and Product Decision

Separate inference from facts and state use, constraint, minimal gap, or defer.

### Unverified

List remaining uncertainty and the next discriminating experiment.

### Local Evidence

- `var/dt-lab/runs/<run-id>/<scenario-id>/` (ignored; local only)
```

## 2026-09-09 — Product regression from recorded suppression evidence

### Purpose and Performed

Encode the 2026-09-01 DT 4.14.3 suppression observation in a product service
regression. No new live experiment or API change was performed. The test supplies
a suppressed Finding while automatic closure is enabled and its existing task
already has one missing observation.

### Observed Facts

The product test passes: the task remains open, its missing counter is cleared,
and its inventory marker becomes ACTIVE. No new Issue is created. ACTIVE here
is the work-item inventory marker, not a change to DT Analysis or suppression.

### Interpretation and Product Decision

Adopt the existing DT capability and encode the constraint in product tests;
no second suppression workflow is needed. This verifies service behavior with
a fixture derived from recorded evidence, not current live API behavior.
ROADMAP.md now prioritizes product risks and defers further lab review/storage
machinery until a concrete need exists.

### Unverified and Local Evidence

Current deployment behavior and a real GitHub closure dry-run remain unverified
by this test. Reproducible evidence: `tests/unit/test_orchestrator.py`, test
`test_suppressed_finding_cancels_pending_absence_closure`. No raw artifact or
environment-specific identifier was generated.

## 2026-08-27 — Project Versions and Dependency Graph

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `lifecycle-project-versions`,
  `portfolio-direct-transitive-graph`

### Purpose

Determine whether DT identifiers are stable across releases and whether its
graph projections contain enough direct, transitive, and Service context for
sbom-ops to avoid reconstructing the CycloneDX graph.

### Performed

Imported two releases of one named Project and a separate graph sample into
run-suffixed Projects. Queried the Project, Component inventory, direct
Components, Services, dependency graph, Findings, metrics, and CycloneDX
Project export.

### Observed Facts

- A retained Component with the same PURL had different Component UUIDs in two
  Project versions.
- `onlyDirect=true` returned the root dependencies in the sample graph.
- Component-to-Service edges appeared in Component `directDependencies` and
  the dependency-graph response. The Project CycloneDX re-export did not
  include those Service edges in `dependencies`.
- CycloneDX Project JSON export required
  `Accept: application/vnd.cyclonedx+json`; generic JSON returned `406`.

### Interpretation and Product Decision

Component UUID is a Project-version-scoped API locator, not a cross-release
business identifier. sbom-ops should retain stable package identity such as
PURL when reconciling releases. It may consume DT graph projections for impact
context, but it must not assume that Project re-export preserves every Service
edge. The media-type requirement is a verified client contract.

### Unverified

Parent-child Project aggregation, large graph behavior, and whether these
projections change in a later DT release remain unverified.

### Local Evidence

- `var/dt-lab/runs/<run-id>/lifecycle-project-versions/` (ignored; local only)
- `var/dt-lab/runs/<run-id>/portfolio-direct-transitive-graph/` (ignored; local
  only)

## 2026-08-27 — Vulnerability Sources, Aliases, and EPSS

- Status: partial
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-multiple-sources-aliases`

### Purpose

Determine which vulnerability-source, alias, CVSS, and EPSS normalization DT
already provides so sbom-ops does not duplicate datasource logic.

### Performed

Imported a sample containing package and CPE identity, then captured Findings,
Vulnerabilities, metrics, dependency graph, and CycloneDX export. Repeated the
scenario to distinguish stable API shape from one processing pass.

### Observed Facts

- With the current datasource configuration, PURL-only samples produced no NVD
  Findings; adding matching CPEs produced NVD Findings.
- NVD Findings included EPSS score and percentile as well as CVSS fields.
- GitHub and OSV vulnerability records were not present in this environment.

### Interpretation and Product Decision

DT remains the preferred source for EPSS and normalized Finding data. sbom-ops
must not infer that a datasource is enabled or that an absent source has no
matching vulnerability. Cross-source alias correlation remains an open
hypothesis because the required source records were absent.

### Unverified

GitHub and OSV mirror availability, cross-source alias correlation, and timing
after datasource refresh remain unverified.

### Local Evidence

- `var/dt-lab/runs/<run-id>/triage-multiple-sources-aliases/` (ignored; local
  only)

## 2026-08-28 — Run-Scoped Cleanup and Repeatability

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `identity-same-name-different-purl`

### Purpose

Provide reproducible data reset for disposable experiments without resetting
DT global state or risking deletion of unrelated Projects.

### Performed

Repeated an import with unique run-suffixed Project versions. Recorded Project
identity in a run ledger, previewed cleanup, verified the live name, version,
and UUID, executed deletion with a dedicated key, and retained immutable local
cleanup audits. Also repeated cleanup against an already absent Project.

### Observed Facts

- A verified run Project was deleted while local observations remained.
- Repeating cleanup for the absent Project completed without a second deletion.
- Cleanup required a run UUID and matching `dt-lab-` name and run marker; no
  prefix-wide or database-wide reset was performed.
- Older pre-ledger runs can remain marked `running` after an interrupted or
  legacy execution. Current runs write an explicit terminal failure record.

### Interpretation and Product Decision

Use isolated Project versions plus run-scoped cleanup as the lab reset model.
Do not add full-database reset or prefix-only bulk deletion. A run status is
operational evidence and must not be interpreted as a scientific conclusion
without this human-reviewed ledger.

### Unverified

Cleanup behavior across a DT upgrade and concurrent deletion by another actor
remain unverified.

### Local Evidence

- `var/dt-lab/runs/<run-id>/projects.json` (ignored; local only)
- `var/dt-lab/runs/<run-id>/cleanups/` (ignored; local only)

## 2026-08-29 — Analysis Delegation Contract and Read Baseline

- Status: partial
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-analysis-states`, `triage-delegation-boundary`

### Purpose

Find the maximum safe portion of human security triage that can remain
authoritative in DT, while keeping remediation task state in GitHub or Jira and
avoiding a second triage state machine in sbom-ops.

### Performed

Compared the official Analysis, audit, suppression, permission, and REST API
documentation with the live v4.14.3 OpenAPI contract. Inspected lab-team
permissions without exposing API keys, implemented an explicitly gated
Analysis-state scenario, and performed a read-only baseline lookup for an
untriaged synthetic Finding. No Analysis mutation was made in this entry.

### Observed Facts

- The live OpenAPI exposes `GET` and `PUT` for `/api/v1/analysis`; the write
  contract requires `VULNERABILITY_ANALYSIS`.
- The existing read, upload, and cleanup lab teams did not have
  `VULNERABILITY_ANALYSIS` at the time of this baseline.
- An untriaged Finding projected `analysis.isSuppressed=false` from the Finding
  API, while `GET /api/v1/analysis` returned `404` for the same Component and
  vulnerability UUIDs with and without the optional Project query.
- The live `AnalysisRequest` OpenAPI enum includes `RESOLVED`. The v4.14
  Analysis States guide does not list `RESOLVED` among its documented states.

### Interpretation and Product Decision

The APIs and audit model make DT a plausible authority for human triage
decisions, but this is not yet an adoption decision. sbom-ops remains read-only
for Analysis until a live mutation cycle verifies state projection, comments,
history, suppression, metrics, and the disputed `RESOLVED` state. The absence
of a pre-existing Analysis resource means consumers must distinguish a `404`
audit lookup from the Finding projection's default unsuppressed state.

### Unverified

Live write responses, audit history and comment preservation, suppression and
metrics projection, `RESOLVED` acceptance, VEX round-trip behavior,
API-visible change detection, and reconciliation with work-management state
remain unverified.

### Local Evidence

- `var/dt-lab/openapi.json` and `var/dt-lab/openapi-inventory.json` (ignored;
  local only)
- Future live mutation evidence:
  `var/dt-lab/runs/<run-id>/triage-analysis-states/` (ignored; local only)

## 2026-08-30 — Real-World Multi-Ecosystem Corpus Baseline

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.6 and 1.7 inputs
- Scenarios: `go-otel-obi-0-12-2`, `typescript-n8n-2-36-8`,
  `rails-openproject-17-7-2`,
  `rails-openproject-17-7-2-schema-valid`,
  `python-airflow-3-3-0-cdx-1-7`, `python-airflow-3-3-0-cdx-1-6`

### Purpose

Add production-shaped Go, TypeScript, Rails, and Python SBOMs to expose scale,
generator, ecosystem, graph, and CycloneDX compatibility behavior that small
synthetic fixtures cannot represent. Keep the inputs reproducible without
committing large upstream payloads.

### Performed

Downloaded official release SBOMs for OpenTelemetry OBI 0.12.2, n8n 2.36.8,
and Apache Airflow 3.3.0 for Python 3.12. Matched the OBI and n8n files against
their GitHub release-asset digests. Verified OpenProject 17.7.2's CycloneDX
attestation with Cosign against its immutable image digest, GitHub Actions OIDC
issuer, and expected workflow identity before extracting the predicate.
Converted Airflow's CycloneDX 1.7 input to 1.6 with CycloneDX CLI v0.33.1 and
pinned both hashes. An attempted historical Airflow 3.2.0 documentation URL
returned `404`, so it was not cataloged. Validated each available file's hash,
CycloneDX envelope, declared version, and top-level counts.

Ran every cataloged input by explicit ID. The official OpenProject predicate
failed CycloneDX 1.6 schema validation and DT ingestion because one `formatador`
external reference contained an unexpanded Ruby expression. Preserved that
signed input, removed only the invalid reference into a separately hash-pinned
derived file, verified the derived file with CycloneDX CLI v0.33.1, and ran it
as the large-scale case. Captured all paginated Components, direct Components,
dependency graph, Findings, Vulnerabilities, metrics, and CycloneDX 1.5
re-export. Verified and deleted every run-scoped Project, including Projects
left by failed uploads. An initial restricted-network invocation failed before
an HTTP status and was repeated with permitted local access; it did not provide
scientific evidence.

### Observed Facts

- OBI is CycloneDX 1.6 with 233 Components and one dependency entry. Of its
  Components, 219 use `pkg:golang` PURLs. Its metadata root is a generated
  temporary-path `file` without a version.
- n8n is CycloneDX 1.6 with 1,458 npm Components and no dependency entries. Its
  metadata root identifies n8n 2.36.8 as an application.
- The signed OpenProject predicate is CycloneDX 1.6 with 17,831 Components and
  869 dependency entries, but the official CycloneDX CLI rejected one
  `https://github.com/geemus/#{s.name}` external-reference URL. DT returned
  HTTP `400`. Removing only that reference produced a schema-valid document
  with unchanged Component and dependency counts.
- The official Airflow document is CycloneDX 1.7 with 121 PyPI Components and
  one dependency entry. The 1.6 conversion retains those top-level counts and
  root Component identity.
- The five hash-and-envelope-validated acquired or initially derived files total
  19,764 Components and 16,721,778 bytes; this count does not include the later
  schema-valid OpenProject derivation.
- DT accepted OBI's 233 Components and returned all 233 across three pages. It
  reported seven NVD Findings, all with EPSS data. It returned zero direct
  Components because the source graph did not connect the metadata root to the
  dependency node; its 1.5 re-export retained 233 Components and 216 edges.
- DT accepted all 1,458 n8n Components across fifteen pages. The submitted BOM
  had no dependency entries; the direct graph and re-export contained no
  edges. The current datasource configuration produced zero Findings.
- DT rejected the official Airflow CycloneDX 1.7 input with HTTP `400`, then
  accepted the 1.6 conversion and returned all 121 Components. The accepted
  input produced zero Findings in the current datasource configuration.
- Failed Airflow 1.7 and original OpenProject uploads still auto-created empty
  Projects. Both were discoverable from the failed run ledger and deleted by
  verified run-scoped cleanup.
- DT consumed the schema-valid OpenProject derivation as 16,742 Components
  after de-duplicating 17,831 input records. The source had 3,690 PURL records
  representing 2,385 unique PURLs; all 2,385 unique PURLs remained present in
  the API result. The two exact duplicate no-PURL records were also collapsed.
- The OpenProject BOM processing log reported 5.561 seconds. The complete
  paginated Component observation took 47.963 seconds, and the full run took
  about 140 seconds in this local environment. The API returned all 16,742
  Components and 285 NVD Findings: 7 critical, 70 high, 91 medium, and 117 low.
  All 285 included EPSS data.
- The 285 OpenProject Finding rows represented 144 distinct NVD IDs. All had a
  severity, description, references, publication time, analyzer attribution,
  EPSS score, and EPSS percentile. CVSS v3 was present for 281, CVSS v4 for
  132, CWE data for 282, and Component latest-version metadata for 209 rows.
  None had a recommendation or aliases in this NVD-only result.
- Every OpenProject Finding projected `analysis.isSuppressed=false`, but none
  projected an Analysis state. This matches the earlier distinction between a
  default Finding projection and an existing Analysis decision trail.
- OpenProject's metadata root was absent from its graph entries. DT warned that
  the graph was incomplete and returned zero direct Components even though its
  1.5 re-export contained 2,426 edges across 665 non-empty dependency entries.
- The DT analyzer warned that platform-suffixed gem versions such as Nokogiri
  builds were invalid under its gem-version scheme and retried them with its
  generic scheme.
- Immediate Project deletion after a successful BOM event raced the still
  running Repository Metadata analyzer. The backend subsequently logged an
  asynchronous lookup of a deleted Component. BOM event-token completion did
  not prove that this separate worker had quiesced.

### Interpretation and Product Decision

Synthetic BOMs remain the deterministic behavioral contract; this real-world
corpus is a separate integration and stress layer. Upstream SBOM shape varies
materially, so sbom-ops must not infer dependency reachability from inventory
size or treat missing graph entries and generator metadata as DT behavior. Run
artifacts only by explicit ID, verify their hash before upload, retrieve every
paginated Component response, and compare original input, DT projections, and
DT re-export separately.

Require full CycloneDX schema validation before a production upload; a signed
attestation proves provenance, not schema validity. Treat DT's normalized and
de-duplicated inventory as authoritative after successful ingestion, while
retaining source counts for reconciliation. A zero Finding count is bounded by
the enabled datasources and is not evidence that the submitted software has no
vulnerabilities. Root-connected graph quality must be assessed independently
from inventory completeness.

Fail closed on unsupported CycloneDX versions and surface the rejection; the
Airflow pair does not authorize automatic conversion. If an operator elects a
conversion, it remains an explicit, separately pinned preprocessing decision.
Failed auto-create uploads require compensating run-scoped cleanup. Immediate
automatic cleanup is removed from the lab because event-token completion does
not cover repository metadata analysis; cleanup now occurs only through a
separate reviewed command after target quiescence.

DT already supplies most quantitative and explanatory NVD context needed by
the Priority Engine and optional LLM summary. sbom-ops should consume severity,
EPSS, CVSS, CWE, description, references, source, and analyzer attribution
rather than recalculate them. It must still distinguish a Finding
(Project-Component-vulnerability matrix entry) from a unique vulnerability ID;
the 285-to-144 difference proves that CVE-only task identity would collapse
separate remediation contexts. Recommendations remain an allowed LLM or human
proposal, never an automatic DT Analysis decision. Alias absence remains a
datasource limitation rather than an empty authoritative conclusion.

### Unverified

The full DT de-duplication identity algorithm, semantic loss beyond top-level
counts in the Airflow conversion, correctness of generic fallback for
platform-suffixed gem versions, GitHub/OSV enrichment, and larger-scale limits
remain unverified. The 285 OpenProject Findings provide a useful future corpus
for read-only prioritization and triage-delegation experiments, but a separate
run and a preflight-validated key with `VULNERABILITY_ANALYSIS` and no unrelated
write permission are required before mutating any decision state.

### Local Evidence

- `var/dt-lab/corpus/<upstream-release>/` (ignored; local only)
- `var/dt-lab/tools/` (ignored; local only)
- `var/dt-lab/runs/<run-id>/<artifact-id>/` (ignored; local only)
- `var/dt-lab/runs/<run-id>/cleanups/` (ignored; local only)

## 2026-08-31 — Shared Analysis Key Preflight

- Status: failed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-analysis-states`

### Purpose

Determine whether the existing orchestrator read key can safely replace the
optional dedicated Analysis key for the explicit Analysis-state experiment.

### Performed

Invoked the Analysis-state scenario with its explicit scenario selector and
mutation opt-in, leaving `SBOM_OPS_DT_ANALYSIS_API_KEY` unset so the runner used
`SBOM_OPS_DT_API_KEY`. The runner queried `GET /api/v1/team/self` before run
directory or Project creation. After the preflight rejected that key, queried
the team permissions for each configured lab key without recording key values.

### Observed Facts

- The orchestrator key reported `VIEW_BADGES`, `VIEW_POLICY_VIOLATION`,
  `VIEW_PORTFOLIO`, and `VIEW_VULNERABILITY`; it did not report
  `VULNERABILITY_ANALYSIS`.
- The upload key reported `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`.
- The cleanup key reported `PORTFOLIO_MANAGEMENT`, `VIEW_PORTFOLIO`,
  `VULNERABILITY_ANALYSIS`, and `VULNERABILITY_MANAGEMENT`.
- The required-permission preflight stopped the scenario before a run directory,
  Project, BOM upload, or Analysis mutation was created.
- An initial restricted-network invocation failed before receiving an HTTP
  response and did not add behavioral evidence.

### Interpretation and Product Decision

The dedicated Analysis environment variable is optional: the lab may reuse the
orchestrator key when its team includes `VULNERABILITY_ANALYSIS`. Existing
read-only permissions are accepted alongside that permission. The cleanup key
is not selected automatically because it also grants Project and vulnerability
management capabilities that are outside the Analysis experiment allowlist.
This keeps the user's requested credential reuse compatible with fail-closed
preflight and prevents an accidental expansion of the experiment's authority.

### Unverified

The actual Analysis decision cycle remains unverified. Add
`VULNERABILITY_ANALYSIS` to the team behind `SBOM_OPS_DT_API_KEY`, or configure
a dedicated Analysis-only key, then repeat this scenario.

### Local Evidence

- No run directory was created; the failure occurred during preflight.

## 2026-08-31 — Analysis Decision Cycle with the Shared Read Key

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-analysis-states`

### Purpose

Verify that Dependency-Track can remain authoritative for Finding Analysis
state, suppression, comments, and audit history when the existing orchestrator
key is explicitly granted `VULNERABILITY_ANALYSIS`.

### Performed

Repeated the previously failed scenario with `SBOM_OPS_DT_ANALYSIS_API_KEY`
unset. The runner reused `SBOM_OPS_DT_API_KEY`, verified its team permissions,
created one run-scoped disposable Project, imported the synthetic Log4Shell BOM,
and selected only the NVD `CVE-2021-44228` Finding by Project, Component PURL,
vulnerability ID, and source. Applied and verified the explicit decision cycle
`IN_TRIAGE` → `EXPLOITABLE` → `NOT_AFFECTED` → `FALSE_POSITIVE` → `RESOLVED` →
`NOT_SET`, capturing the update response, appropriate suppressed or unsuppressed
Finding projection, Analysis trail, metrics, and expected-versus-observed values
after every action.

### Observed Facts

- The shared key reported `VIEW_BADGES`, `VIEW_POLICY_VIOLATION`,
  `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`, and `VULNERABILITY_ANALYSIS`; the
  permission preflight passed.
- The imported Project contained one Component and ten NVD Findings. The exact
  selector isolated `CVE-2021-44228`; the other nine Findings were not mutated.
- All six requested states were accepted. For every action, the update response,
  Finding projection, and Analysis trail immediately agreed with the requested
  state and suppression flag.
- The explicitly suppressed `NOT_AFFECTED` and `FALSE_POSITIVE` decisions were
  visible through the suppressed Finding projection. The other four actions
  were visible through the unsuppressed projection.
- The final `NOT_SET` action restored the Finding to unsuppressed while retaining
  the prior audit trail. The trail contained 26 comments generated from state,
  justification, response, details, suppression, and caller-comment changes
  across the six updates.
- Immediate Project metrics remained unchanged throughout the decision cycle:
  zero audited Findings, ten unaudited Findings, zero suppressed Findings, and
  the same risk score. The synchronous Finding and Analysis endpoints therefore
  changed before the Project metrics projection in this run.
- The completed run retained 35 API observations. The disposable Project remains
  available for evidence review and later run-scoped cleanup after target
  quiescence.

### Interpretation and Product Decision

Dependency-Track can own the authoritative human Analysis decision, suppression
flag, comments, and audit history. sbom-ops should read and reconcile that state
instead of creating a duplicate triage state machine. It may use the shared
orchestrator key for this explicitly gated local experiment when the permission
preflight passes; a dedicated Analysis-only key remains the preferred deployment
boundary.

Finding and Analysis responses are suitable for immediate post-write
verification. Project metrics are not: the unchanged values show that metric
refresh timing must be treated as asynchronous and must not be used to confirm
an Analysis write without a separate convergence wait. `RESOLVED` is accepted
by the DT 4.14.3 API, but its intended product semantics still require comparison
with the UI and VEX behavior before sbom-ops relies on it.

### Unverified

Metric convergence time, UI presentation of `RESOLVED`, VEX import/export
effects, concurrent analyst edits, idempotent replay, comment-only updates,
bulk triage, and the precise boundary between DT Analysis and GitHub/Jira task
state remain unverified. These belong in the planned
`triage-delegation-boundary` scenario.

### Local Evidence

- `var/dt-lab/runs/<run-id>/analysis-key-team.json` (ignored; local only)
- `var/dt-lab/runs/<run-id>/triage-analysis-states/` (ignored; local only)

## 2026-08-31 — CycloneDX VEX Export Observation

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-analysis-states` (read-only follow-up)

### Purpose

Determine whether DT's generated CycloneDX VEX is a suitable authoritative
projection of the current Analysis decision for downstream reconciliation.

### Performed

Using the completed disposable Analysis run, requested
`GET /api/v1/vex/cyclonedx/project/{uuid}` with `download=false` and
`version=1.5` through the shared orchestrator key. No Project, Finding, or
Analysis state was changed.

### Observed Facts

- DT returned HTTP 200 with `Content-Type: application/vnd.cyclonedx+json`.
- The response declared CycloneDX 1.5 and contained `bomFormat`, `metadata`,
  `serialNumber`, `specVersion`, `version`, and `vulnerabilities` top-level
  fields; it did not contain a `components` collection.
- The VEX contained ten vulnerability entries with ten unique IDs. The first
  entry was `CVE-2021-44228` from NVD and included the current Analysis detail.
- The endpoint is guarded by `VULNERABILITY_ANALYSIS` in the live OpenAPI
  contract, even though this observation is read-only from the lab's point of
  view.

### Interpretation and Product Decision

DT's VEX export is a vulnerability-centric projection of the Project's current
audit state, not a replacement for the SBOM inventory or Component graph. The
product should consume it only when a VEX-specific integration is needed and
must retain the source Project/Finding coordinates for reconciliation. The
read-only export observation is now available in the lab adapter; VEX upload,
round-trip processing, and approval policy remain separate work.

### Unverified

VEX import behavior, whether every Analysis state maps to an expected VEX
response, preservation of comments and suppression across a round trip, schema
validation failures, and concurrent VEX or Analysis edits remain unverified.
These are the scope of the planned `triage-vex-round-trip` scenario.

### Local Evidence

- `var/dt-lab/runs/<run-id>/triage-analysis-states/` (ignored; local only)
- `var/dt-lab/openapi.json` (ignored; local only)

## 2026-08-31 — CycloneDX VEX Analysis Round Trip

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-vex-round-trip`

### Purpose

Determine whether a reviewed Dependency-Track Analysis decision survives a
DT-generated CycloneDX VEX export and re-import, and identify which Analysis,
suppression, targeting, and audit semantics sbom-ops may safely delegate to DT.

### Performed

Created one run-scoped disposable Project from a dedicated synthetic Log4Shell
SBOM and selected the NVD `CVE-2021-44228` Finding by Project, Component PURL,
vulnerability ID, and source. Seeded `NOT_AFFECTED` with
`CODE_NOT_REACHABLE`, detail, a caller comment, and explicit suppression;
exported CycloneDX VEX 1.5; reset the Finding to unsuppressed `NOT_SET`; uploaded
the unchanged export to the same Project; waited for its event token; compared
the Finding, Analysis trail, and second VEX export; and finally restored and
verified unsuppressed `NOT_SET`.

### Observed Facts

- The Analysis-key preflight passed with `VULNERABILITY_ANALYSIS` and only the
  allowed read permissions. The Project contained one Component and ten NVD
  Findings; only the exact `CVE-2021-44228` target was mutated.
- The first export contained ten vulnerability entries but no Components
  collection. Every `affects.ref` was the Project UUID. The target entry
  contained `state=not_affected`, `justification=code_not_reachable`, and the
  exact Analysis detail; it did not contain the explicit suppression flag or
  the caller comment.
- After the explicit reset, the target Finding projected `NOT_SET` and
  `isSuppressed=false`. The unchanged exported VEX was accepted by multipart
  `POST /api/v1/vex`, and its asynchronous event token completed.
- The imported Finding and Analysis trail projected `NOT_AFFECTED`,
  `CODE_NOT_REACHABLE`, `NOT_SET` response, and the exact original detail. The
  second VEX export preserved the target Analysis object and `affects` reference.
- The imported Finding also projected `isSuppressed=true`, even though the VEX
  document had no suppression field. The import added state, justification, and
  detail audit comments attributed to `CycloneDX VEX`; it did not add the
  original caller comment as a VEX-authored comment or add an explicit
  suppression audit comment.
- The final restore projected `NOT_SET` and `isSuppressed=false`. The run
  completed with 18 retained observations. Its disposable Project remains for
  reviewed, run-scoped cleanup after target quiescence.

### Interpretation and Product Decision

DT 4.14.3 can own the reviewed VEX-backed applicability state and its audit
projection. sbom-ops should not create an independent VEX state machine or
rewrite the decision automatically; it should reconcile DT's Finding/Analysis
state and keep human approval ahead of VEX publication or downstream task
closure.

The returned suppression is a DT projection derived during import, not a
CycloneDX field that round-tripped verbatim. Consumers must therefore treat
Analysis state and DT suppression as separate facts even when this version
couples `NOT_AFFECTED` import to suppression. Caller comments and actor identity
are not portable through this VEX document: the semantic detail survives, while
the import audit actor is DT's `CycloneDX VEX` identity.

The generated document was Project-scoped: its Project UUID reference can apply
one vulnerability decision across affected Components in that Project. The
one-Component run does not prove Component-level isolation. Before accepting
supplier VEX or automating task closure, sbom-ops needs an explicit targeting
check and evidence for multiple Components sharing a vulnerability.

### Unverified

Component-scoped versus Project-scoped `affects` matching, multiple Components
sharing one CVE, externally generated VEX identifiers, fresh-Project transfer,
idempotent replay, concurrent analyst edits, schema rejection, authorship,
metrics convergence, and mappings for `EXPLOITABLE`, `FALSE_POSITIVE`, and
`RESOLVED` remain unverified. The next discriminating experiment should compare
Project and Component `bom-ref` targets in one multi-Component Project.

### Local Evidence

- `var/dt-lab/runs/<run-id>/analysis-key-team.json` (ignored; local only)
- `var/dt-lab/runs/<run-id>/triage-vex-round-trip/` (ignored; local only)

## 2026-08-31 — Identical VEX Replay

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-vex-round-trip`

### Purpose

Determine whether retrying the exact same VEX import is idempotent in both the
current Analysis projection and its audit trail, rather than judging retry
safety only from the final Finding state.

### Performed

Repeated the guarded Analysis-to-VEX round trip in a new disposable Project.
After the first unchanged DT-generated VEX import completed and its Finding,
trail, and re-export were captured, uploaded the same local VEX bytes to the same
Project a second time, waited for the second event token, and captured the same
three projections again before the final `NOT_SET` restore.

### Observed Facts

- Both multipart VEX uploads returned tokens that completed successfully.
- After the first import, the target projected `NOT_AFFECTED`,
  `CODE_NOT_REACHABLE`, the original detail, and `isSuppressed=true`. Its trail
  contained 13 comments, including three attributed to `CycloneDX VEX`.
- After the identical replay, Finding state, suppression, VEX Analysis, and
  `affects` were unchanged. The trail still contained 13 comments: the replay
  added zero state, justification, detail, suppression, or other comments.
- The final restore again projected unsuppressed `NOT_SET`. The completed run
  retained 22 observations, and its disposable Project remains available for
  later reviewed cleanup.

### Interpretation and Product Decision

On DT 4.14.3, an identical VEX replay against the same Project and already
matching Analysis state was state-idempotent and audit-idempotent in this case.
A future product VEX uploader may retry an identical payload after an ambiguous
transport outcome, provided it still waits for the returned event token and
reconciles the exact target state. Retaining a payload digest and token outcome
would reduce unnecessary uploads, but a second authoritative workflow record is
not needed for this observed behavior.

This does not authorize automatic VEX publication or task closure. Human review
and exact Project/Finding identity remain required, and replay safety must be
revalidated when the payload, baseline Analysis state, or DT version changes.

### Unverified

Replay after concurrent analyst changes, replay after a partial or failed event,
different VEX serial/version values with identical Analysis, cross-Project
reuse, and multiple target Findings remain unverified. Project-scoped versus
Component-scoped `affects` is still the next higher-value targeting experiment.

### Local Evidence

- `var/dt-lab/runs/<run-id>/triage-vex-round-trip/` (ignored; local only)

## 2026-08-31 — VEX Targeting Probe: DT-exported Component Reference

- Status: failed safely; evidence retained and state restored
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-vex-targeting`

### Purpose

Determine whether a Component `bom-ref` from DT's SBOM re-export can constrain
one VEX Analysis decision to one of two Components that share the same
vulnerability.

### Performed

Created one run-scoped disposable Project containing `log4j-core` 2.14.1 and
2.13.3, selected the NVD `CVE-2021-44228` Finding for each version, and uploaded
a one-entry VEX whose `affects.ref` was the primary Component's `bom-ref` from
DT's CycloneDX SBOM export. Waited for the import token and captured both
Findings. The first implementation then requested each Analysis trail as though
an Analysis row necessarily existed; DT returned HTTP 404 for the untouched
control Finding, so the run failed and executed its emergency restore for both
targets.

### Observed Facts

- The Project contained two Components and nineteen NVD Findings. Both exact
  Component/version selectors had an NVD `CVE-2021-44228` Finding.
- DT's SBOM export represented each Component `bom-ref` as a DT UUID rather than
  preserving the PURL-valued `bom-ref` from the imported SBOM.
- Multipart `POST /api/v1/vex` accepted the schema-valid VEX containing the
  DT-exported Component UUID, and its asynchronous token completed.
- Neither the primary nor the control Finding changed: both remained clean,
  unsuppressed, and without an Analysis state.
- `GET /api/v1/analysis` returned HTTP 404 for a Finding that had no Analysis
  row. This is a meaningful absence, not evidence that Finding observation or
  the VEX event failed.
- Emergency restore wrote and verified unsuppressed `NOT_SET` for both Findings.
  The disposable Project and failed-run evidence remain for reviewed cleanup.

### Interpretation and Product Decision

A DT-exported Component UUID must not be assumed to be a valid exact-match VEX
target merely because the upload is accepted. For this DT version and fixture,
it matched neither Finding. The lab now preserves a 404 Analysis observation as
`trail_present=false` so untouched controls remain part of the evidence rather
than aborting the experiment.

This failed attempt is not enough to select the product targeting rule. The
next run must compare the original imported SBOM `bom-ref` and DT's
Project-level `affects.ref` against the same two Findings, with restoration
between candidates.

### Unverified

Matching with the original input Component `bom-ref`, Project-wide expansion,
supplier-generated identifiers, other Component/vulnerability combinations,
cross-Project reuse, and concurrent analyst edits remain unverified.

### Local Evidence

- `var/dt-lab/runs/<run-id>/triage-vex-targeting/` (ignored; local only)

## 2026-08-31 — VEX Targeting Probe: Bare References and Project Scope

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-vex-targeting`

### Purpose

Compare two bare Component references with DT's generated Project reference in
one Project where two Component versions share the same vulnerability.

### Performed

Repeated the two-Component Log4Shell probe with optional Analysis-trail absence
preserved as evidence. Uploaded one-entry VEX documents in sequence using the
primary Component's DT-exported UUID `bom-ref`, its original PURL-valued source
SBOM `bom-ref`, and the Project-level reference from DT's VEX export. Captured
both Findings and trails after every import, restored both targets between
candidates, and performed a final verified restore.

### Observed Facts

- Both bare Component references were schema-valid and their asynchronous VEX
  tokens completed, but neither changed the primary or control Finding.
- Before an explicit Analysis row existed, the trail observation was HTTP 404.
  After the first restore created `NOT_SET` rows, the source-reference probe
  left both rows and their two existing comments unchanged.
- The Project-level reference changed both Component Findings for
  `CVE-2021-44228` to `NOT_AFFECTED` and `isSuppressed=true`. Each Analysis trail
  contained seven comments after the import.
- The final restore verified both Findings as `NOT_SET` and unsuppressed. The
  successful run retained 36 observations, and its disposable Project remains
  available for reviewed cleanup.

### Implementation Corroboration

The official DT 4.14.3 `CycloneDXVexImporter` indexes `metadata.component` and
`components[]` from the uploaded VEX itself. An `affects.ref` that resolves to
the VEX metadata Component is Project-scoped; one that resolves to a declared
non-metadata Component is matched to Project Components by `ComponentIdentity`;
an otherwise unresolved reference is skipped. This explains the live result
without treating successful schema validation or token completion as proof that
a target was found.

### Interpretation and Product Decision

`affects.ref` is resolved in the context of the uploaded VEX document, not by
looking up the target Project's inventory UUID or source SBOM reference in
isolation. sbom-ops must therefore reject or flag an unresolved bare reference
rather than reporting a successful decision merely because DT accepted the
upload. A Project-scoped reference is unsafe when only one Component Finding
was reviewed because DT deliberately expands it to every vulnerable Component
for the matching vulnerability in that Project.

The next probe must make the Component target self-contained by including its
identity in the VEX `components[]` collection and verify that only the primary
Finding changes.

### Unverified

Exact matching with a VEX-declared Component, ambiguous Component identities,
nested Components, BOM-Link Project references, supplier-generated documents,
cross-Project reuse, and concurrent analyst edits remain unverified.

### Local Evidence

- `var/dt-lab/runs/<run-id>/triage-vex-targeting/` (ignored; local only)
- [DT 4.14.3 `CycloneDXVexImporter`](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/parser/cyclonedx/CycloneDXVexImporter.java)

## 2026-09-01 — Triage Delegation Reconciliation Boundary

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-delegation-boundary`

### Purpose

Determine which Analysis state can remain authoritative in DT, whether DT
exposes a reliable incremental change cursor, how identical writes affect the
audit trail, and what minimum reconciliation state sbom-ops must retain without
building a duplicate triage database.

### Performed

Created a run-scoped disposable Log4Shell Project and performed six guarded
Analysis actions against one exact Finding: seed `IN_TRIAGE`, append a comment
without changing the decision, replay that exact request, toggle suppression
on, toggle it off, and restore unsuppressed `NOT_SET`. For every action, captured
the PUT response, Analysis trail, default Finding view, Project metrics, and
semantic and audit digests. The first completed run retained 35 observations.

After confirming from the live OpenAPI that `suppressed=true` means "includes
suppressed findings", refined the harness to capture both default and
include-suppressed views after every action and repeated the full experiment.
The refined run retained 41 observations. Both Projects remain available for
reviewed cleanup.

### Observed Facts

- Seeding `IN_TRIAGE` added three audit comments: state change, detail change,
  and the caller comment. The trail and Finding projected the requested state,
  detail, and suppression value immediately.
- A comment-only PUT left the requested, trail, and Finding decision digests
  unchanged but added one caller comment and changed the audit digest.
- Replaying the exact same PUT added the identical caller comment a second time
  with a later timestamp. Decision digests again remained unchanged. Analysis
  PUT is therefore state-idempotent but not audit-idempotent when `comment` is
  non-empty.
- Suppression-only and unsuppression-only PUTs each added two comments: DT's
  automatic suppression transition and the caller comment. State remained
  `IN_TRIAGE`.
- While suppressed, the default Project Finding response fell from ten to nine
  and omitted the exact target. The same request with `suppressed=true` returned
  all ten and projected the target as suppressed. After unsuppression, the
  target returned to the default view.
- Neither Finding nor Analysis GET responses exposed `ETag` or `Last-Modified`.
  Their OpenAPI schemas expose no Analysis revision or update timestamp. Audit
  comments have timestamps, but only inside the per-Finding Analysis trail.
- Immediate Project metrics remained unchanged throughout, including
  `findingsAudited=0` and `suppressed=0`; they are not a write-verification or
  change-detection signal.
- The final action projected `NOT_SET` and `isSuppressed=false`. The harness now
  also rejects any Analysis sequence whose final action leaves a target in
  another state and performs a verified emergency reset after a failed sequence.

### Interpretation and Product Decision

DT can remain authoritative for human Analysis decisions, detail, suppression,
caller comments, and their audit history. sbom-ops must not copy that trail into
a second triage state machine. GitHub or Jira remains authoritative for the
remediation task lifecycle.

DT 4.14.3 does not provide an API-visible incremental cursor for Analysis
changes. Reconciliation must read a complete Project Finding snapshot with
`suppressed=true` and compare a normalized semantic digest over stable Finding
identity, state, justification, response, detail, and suppression. Absence from
the default view is not Finding resolution and must never drive Issue closure.

The minimum sbom-ops reconciliation state is the stable Finding key, last
observed semantic digest, observation outcome/time, and the external work-item
correlation already required for idempotency. A separate audit digest or last
comment timestamp is needed only if comment changes trigger work-item updates;
the comments themselves remain authoritative in DT. A comment timestamp cannot
serve as a global cursor because it requires an Analysis GET for a Finding that
is already known.

Future Analysis writes must not blindly retry a request containing a comment.
They require read-before-write reconciliation and explicit workflow intent,
because DT accepts a duplicate caller comment. This does not change the MVP:
sbom-ops remains read-only for Analysis, and humans retain the final security
decision.

### Unverified

Concurrent analyst and orchestrator writes, notification/webhook delivery as an
optimization over full scans, bulk Analysis operations, metrics convergence
time, task update policy for comment-only changes, and ambiguity after partial
transport failure remain unverified. None of these block DT from owning triage
state, but they constrain any future product Analysis writer.

### Local Evidence

- `var/dt-lab/runs/<run-id>/triage-delegation-boundary/` (ignored; local only)
- [DT 4.14.3 `AnalysisResource`](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/resources/v1/AnalysisResource.java)
- [DT 4.14.3 `AnalysisCommentUtil`](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/util/AnalysisCommentUtil.java)

## 2026-09-01 — Self-contained Component-scoped VEX

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `triage-vex-targeting`

### Purpose

Verify that a Component reference becomes exact and actionable when the same
VEX document declares the target Component identity, and compare that scope
with unresolved and Project-scoped forms.

### Performed

Extended the two-Component Log4Shell probe with a fourth VEX form. It copied the
primary Component from DT's CycloneDX SBOM export into the VEX `components[]`
collection and pointed `affects.ref` to that declared Component's `bom-ref`.
Executed the bare DT-exported reference, bare source-SBOM reference,
self-contained Component reference, and Project reference in sequence. Captured
the primary and control Finding/trail projection after every upload, restored
both Findings between candidates, and validated the generated self-contained
document against the CycloneDX 1.5 schema.

### Observed Facts

- Both bare references again completed without changing either Finding.
- The self-contained Component VEX changed only `log4j-core` 2.14.1 to
  `NOT_AFFECTED` and `isSuppressed=true`. The 2.13.3 control remained `NOT_SET`
  and unsuppressed.
- The subsequent Project-scoped VEX changed both versions to `NOT_AFFECTED` and
  suppressed both Findings.
- The generated self-contained VEX passed the official CycloneDX CLI 1.5 schema
  validation. DT accepted each upload and completed every event token.
- The final restore verified both Findings as `NOT_SET` and unsuppressed. The
  run retained 45 observations, and its disposable Project remains available
  for reviewed cleanup.

### Interpretation and Product Decision

DT 4.14.3 Component targeting is document-relative and identity-based. An exact
Component decision requires an `affects.ref` that resolves to a non-metadata
Component declared in the same VEX; DT then matches that declared identity to
the target Project. A valid document and completed token do not guarantee that
an unresolved reference affected anything, while a metadata Project reference
can intentionally affect multiple Components.

A future sbom-ops VEX plan must classify every reference before upload as
unresolved, Component-scoped, or Project-scoped. It must reject unresolved
references, require explicit broad-scope approval for Project targets, preview
the exact expected Finding set, and reconcile that set after token completion.
Schema validation alone is insufficient. The decision and the target-set diff
remain human-approved; neither LLM output nor an accepted DT upload may expand
scope automatically.

### Unverified

Ambiguous identity matches, nested Component declarations, BOM-Link Project
references, range-bearing `affects.versions`, non-PURL identities,
supplier-generated signatures, cross-Project reuse, and concurrent analyst
changes remain unverified.

### Local Evidence

- `var/dt-lab/runs/<run-id>/triage-vex-targeting/` (ignored; local only)
- [DT 4.14.3 `CycloneDXVexImporter`](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/parser/cyclonedx/CycloneDXVexImporter.java)

## 2026-09-02 — Invalid CycloneDX Rejection and Project Side Effect

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `robustness-invalid-cyclonedx`

### Purpose

Determine whether a schema-invalid BOM is rejected synchronously with enough
structured detail for deterministic classification, whether it receives a
processing token, and whether coordinate upload with `autoCreate=true` leaves
state that must be reconciled or cleaned.

### Performed

Created a small CycloneDX 1.5 fixture whose single Component uses a value
outside the schema's `type` enumeration. Explicitly selected the negative
scenario and uploaded it by a fresh run-suffixed Project name and version.
Required HTTP 400, `application/problem+json`, and Project creation before
capturing the Project, Component, and Finding views. The run ledger was written
before upload and the resulting Project was retained for reviewed cleanup.

### Observed Facts

- `POST /api/v1/bom` returned HTTP 400 with
  `Content-Type: application/problem+json`; it did not return a processing
  token.
- The RFC 9457 response had status 400, title `The uploaded BOM is invalid`,
  detail `Schema validation failed`, and an `errors` entry identifying the
  invalid `$.components[0].type` enumeration value.
- The input evidence recorded the filename, 835-byte size, and SHA-256 without
  storing the API key or multipart body.
- DT created the run-suffixed Project despite rejecting the BOM. The Project
  lookup succeeded, while its captured Component and Finding collections were
  both empty.
- The completed scenario retained five observations: upload rejection, Project
  lookup, Project, Components, and Findings.

### Interpretation and Product Decision

Schema rejection is a deterministic client-input failure. sbom-ops must not
retry HTTP 400, wait for a nonexistent token, or reduce the problem response to
an opaque transport failure. Safe RFC 9457 fields are useful diagnostics, while
local schema validation remains an early feedback mechanism rather than a
replacement for DT validation.

The product upload path already targets an existing Project UUID and should
retain that boundary. Lab and corpus coordinate uploads need a pre-request
ledger and compensating, explicitly reviewed cleanup because `autoCreate` is
not atomic with BOM validation. A rejected upload is not evidence that DT made
no state change.

### Unverified

Malformed JSON and XML responses, unsupported CycloneDX-version rejection,
other schema violations, Project behavior when `autoCreate=false`, permission
failures, and response stability in later DT versions remain unverified.
Asynchronous failures after token acceptance remain a separate experiment.

### Local Evidence

- `var/dt-lab/runs/<run-id>/robustness-invalid-cyclonedx/` (ignored; local only)

## 2026-09-02 — CycloneDX JSON and XML Equivalence

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `robustness-json-xml-equivalence`

### Purpose

Determine whether sbom-ops can pass validated CycloneDX JSON and XML through
the same upload boundary, or whether serialization changes DT inventory,
identity, dependency, Finding, or re-export semantics enough to require product
normalization.

### Performed

Created equivalent JSON and XML fixtures with two Components and a direct plus
transitive dependency chain. Uploaded JSON and then XML into the same fresh
run-suffixed Project version. Compared normalized summaries, all observed
Component/Finding/Vulnerability UUID mappings, the direct dependency graph, and
DT's normalized CycloneDX JSON re-export.

The first run used PURLs without CPEs. Both formats produced the same inventory
but no Findings, including on a later read, so that attempt could not test
Finding equivalence. Added the same CPEs to both fixtures and repeated the full
run in a new Project. Both Projects remain available for reviewed cleanup.

### Observed Facts

- Both JSON and XML uploads were accepted by the same multipart BOM endpoint,
  returned processing tokens, and resolved to the same Project UUID within
  each run.
- In the refined run, both steps projected two Components, one direct
  Component, and the same direct and transitive dependency relationships.
- The refined JSON and XML steps each returned the same 15 NVD Findings and 15
  Project vulnerabilities. Their Finding, Component, and vulnerability UUID
  mappings were identical. The count reflects this target's data on the run
  date and is not a deterministic product contract.
- The normalized DT CycloneDX re-export was identical after both inputs,
  including the Project-to-direct and direct-to-transitive dependency edges.
- All four comparison checks passed: summary semantics, identity UUIDs,
  dependency graph, and BOM re-export.
- The Project `lastBomImportFormat` value was `CycloneDX 1.5` after both steps;
  it did not distinguish JSON from XML.
- The PURL-only attempt yielded zero Findings in both formats. Adding identical
  CPEs made the repeated experiment non-empty without changing its
  serialization comparison.

### Interpretation and Product Decision

For the exercised CycloneDX 1.5 inventory, dependency, and vulnerability
fields, DT normalizes JSON and XML to the same observable model. The product
upload adapter should remain format-neutral and pass either validated
serialization to the existing-Project endpoint. A JSON/XML conversion layer
would add complexity without improving this verified path.

Identifier quality is a separate input concern. The PURL-only result does not
prove that DT generally requires CPE or cannot analyze PURLs; it shows only
that this target and datasource state produced no Findings for that exact
input. Format tests must use the same sufficiently discriminating identifiers
on both sides and must not interpret two empty Finding sets as strong
equivalence evidence.

### Unverified

CycloneDX versions other than 1.5, XML-specific advanced fields, namespaces and
extensions, hashes, Services, compositions, signatures, large documents,
schema-invalid XML, and format equivalence across a DT upgrade remain
unverified. Findings from other vulnerability sources and concurrent datasource
updates may require a settled snapshot before comparison.

### Local Evidence

- `var/dt-lab/runs/<run-id>/robustness-json-xml-equivalence/` (ignored; local
  only)

## 2026-09-02 — Parent/Child Portfolio and Default Risk Collection

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `portfolio-parent-child`

### Purpose

Determine whether DT can remain authoritative for Project hierarchy and child
enumeration, and whether creating that hierarchy is sufficient for a parent to
represent child risk without separate collection-logic management.

### Performed

Uploaded an empty root application by fresh run-suffixed coordinates, then
uploaded a child application containing one vulnerable Component while passing
the observed root UUID in the multipart `parentUUID` field. Waited for both BOM
tokens, captured Project, Component, Finding, metrics, and CycloneDX export
views, retrieved the parent's complete paginated children collection, and
compared the Project and risk projections on both sides.

The first invocation was blocked before any HTTP exchange by the execution
sandbox's localhost socket policy and was retained as a failed run. Repeating
with authorized local access completed. A second successful run verified the
improved evidence contract: each normal upload response was retained, and no
lifecycle delta was generated between the distinct parent and child Projects.

### Observed Facts

- Both coordinate uploads returned successful JSON responses with asynchronous
  processing tokens, and both tokens completed.
- The child Project's nested `parent` UUID matched the created root. The root's
  `GET /api/v1/project/{uuid}/children` response returned HTTP 200,
  `X-Total-Count: 1`, and exactly that child.
- Both Project projections reported `collectionLogic=NONE`.
- The child projected one Component, ten NVD Findings, and
  `inheritedRiskScore=44.0` on this instance at the time of the run. The empty
  parent projected zero Components, zero Findings, and
  `inheritedRiskScore=0.0`. These live counts and scores are observations, not
  deterministic product assertions.
- The successful two-step run completed in about eleven seconds. The initial
  sandbox failure did not reach DT and therefore says nothing about DT's API
  behavior.

### Interpretation and Product Decision

Use DT as the hierarchy inventory: sbom-ops does not need to duplicate
parent/child storage or derive child membership from SBOM content. It should
consume the child projection or paginated children endpoint when hierarchy is
needed.

Do not treat Project parenthood as a risk or remediation aggregation boundary.
The verified default keeps child risk separate. Any future use of aggregate
collection logic requires a separately gated experiment and explicit
`PORTFOLIO_MANAGEMENT` workflow; the production MVP and read-only lab key must
not change it implicitly.

### Unverified

The `AGGREGATE_DIRECT_CHILDREN`, `AGGREGATE_DIRECT_CHILDREN_AND_SELF`,
`AGGREGATE_LATEST_VERSION_CHILDREN`, and
`AGGREGATE_LATEST_VERSION_CHILDREN_AND_SELF` modes; deeper hierarchies; risk
propagation timing; moving or orphaning a child; deletion behavior; permission
failures; and behavior after a Dependency-Track upgrade remain unverified.

### Local Evidence

- `var/dt-lab/runs/<run-id>/portfolio-parent-child/` (ignored; local only)

## 2026-09-03 — Least-Privilege Routing Tags and Project Properties

- Status: completed
- Target: Dependency-Track 4.14.3; CycloneDX 1.5
- Scenarios: `portfolio-tags-properties`

### Purpose

Determine whether DT tags or Project properties can be the authoritative owner
and work-repository routing metadata without granting the CI upload or
orchestrator read credentials broad portfolio-management permission.

### Performed

Uploaded the same one-Component SBOM twice to one fresh run-suffixed Project.
The initial request supplied an alpha owner/repository tag pair; after its token
completed, the second request supplied a different beta pair. Captured both
upload responses, the upload team's permission projection, Project tags after
each step, and paginated Project queries for the initial and requested tags.
Finally called the dedicated Project properties read endpoint with the
orchestrator read key. No tag-management or portfolio-management mutation was
performed.

### Observed Facts

- The upload key had exactly `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`.
- The initial upload returned HTTP 200, completed its processing token, and the
  Project contained exactly the requested alpha tags. Both tag-filter queries
  returned the Project with `X-Total-Count: 1`.
- The changed upload also returned HTTP 200 and completed its token, but the
  Project retained both alpha tags and contained neither requested beta tag.
- Queries for both retained alpha tags still returned the Project. Queries for
  both missing beta tags returned empty collections with `X-Total-Count: 0`.
  The Project projection and tag-filter endpoints agreed in every case.
- `GET /api/v1/project/{uuid}/property` with the orchestrator read key returned
  HTTP 403. No property values were observable through that endpoint.
- The successful two-step run used one Project and completed in about eleven
  seconds. The execution tool displayed a much longer wait, but retained run
  timestamps show that delay was not Dependency-Track processing time.

### Interpretation and Product Decision

Keep the existing YAML Project-to-work-repository mapping as the authoritative
MVP routing configuration. DT tags are useful for portfolio selection and as a
consistency signal, but a successful BOM upload cannot be treated as proof that
changed tags were applied. A CI key should not receive
`PORTFOLIO_MANAGEMENT` merely to reconcile routing metadata.

Reject Project properties as the least-privilege routing source for this DT
version because even the dedicated read endpoint requires a write-level
portfolio permission. A future DT-authoritative routing workflow would need a
separate management identity, exact post-write reconciliation, conflict and
removal semantics, and an explicit migration away from YAML.

### Unverified

Tag replacement and removal with a dedicated `PORTFOLIO_MANAGEMENT` identity;
concurrent changes; tag normalization and case behavior; commas or unusual
Unicode in tag names; portfolio ACL filtering; inactive and child Project query
options; tag deletion after Project cleanup; property type serialization and
redaction; and behavior after a Dependency-Track upgrade remain unverified.

### Local Evidence

- `var/dt-lab/runs/<run-id>/portfolio-tags-properties/` (ignored; local only)
- [DT 4.14.3 `BomResource`](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/resources/v1/BomResource.java)
