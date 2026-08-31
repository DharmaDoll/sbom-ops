# Dependency-Track Lab Experiment Ledger

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
