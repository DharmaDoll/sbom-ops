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
run and the exact least-privilege Analysis key are required before mutating any
decision state.

### Local Evidence

- `var/dt-lab/corpus/<upstream-release>/` (ignored; local only)
- `var/dt-lab/tools/` (ignored; local only)
- `var/dt-lab/runs/<run-id>/<artifact-id>/` (ignored; local only)
- `var/dt-lab/runs/<run-id>/cleanups/` (ignored; local only)
