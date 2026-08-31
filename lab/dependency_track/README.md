# Dependency-Track Behavior Lab

This repository-only lab turns assumptions about Dependency-Track into
repeatable observations before any behavior is adopted as a product contract.
It is not part of the `sbom-ops` runtime package or wheel.

## Boundary

```text
project goal -> hypothesis -> DT experiment -> observed facts -> human decision
                                                               ├─ use DT capability
                                                               ├─ encode constraint
                                                               ├─ implement minimal gap
                                                               └─ reject or defer

src/sbom_ops -----------------------------------------------X-> dt_lab
```

- Product code under `src/sbom_ops/` must never import `dt_lab`.
- Lab code may reuse the product's generic HTTP transport, but it has its own
  Dependency-Track adapter, domain models, orchestration, CLI, and tests.
- Raw responses and target-specific OpenAPI documents remain under
  `var/dt-lab/` and are ignored by Git.
- Lab code is not candidate product code. Only minimal, reviewed, stable
  contract examples may enter `tests/fixtures/`; product behavior must follow
  an explicit evidence-backed decision.
- Live Finding counts, scores, UUIDs, timestamps, and datasource timing are not
  deterministic contracts.

## Decision Loop

The lab exists to find the shortest reliable route to the project goal by using
Dependency-Track's existing capabilities as fully as practical. It is not a
scenario-completion project.

For each hypothesis:

1. State the product decision that the experiment must inform.
2. Verify the official contract, target version, endpoint, permission, request,
   response, and mutation boundary.
3. Run the smallest reproducible experiment and retain raw local evidence.
4. Separate observed facts from inference and environment-specific behavior.
5. Make one reviewed decision:
   - use the DT capability and keep sbom-ops integration thin
   - encode a verified DT constraint in product fixtures, tests, and docs
   - implement only the orchestration gap DT does not provide
   - reject or defer the hypothesis with evidence

Every attempted live experiment must update
[`EXPERIMENTS.md`](EXPERIMENTS.md). That single append-only-style ledger owns
the durable purpose, performed work, observed facts, interpretation, product
decision, and remaining uncertainty. Raw evidence under `var/dt-lab/` is local
supporting material, not a durable result. Failed, partial, and inconclusive
runs are recorded too.

Prioritize scenarios that retire the largest product risk or remove the most
duplicate implementation. A `planned` scenario is an uncertainty backlog item;
it need not be implemented when another experiment or official contract already
answers its decision questions.

## Layout

```text
lab/dependency_track/
├── README.md
├── EXPERIMENTS.md
├── corpus/
│   └── corpus.yaml
├── fixtures/
├── scenarios/
│   ├── scenarios.yaml
│   └── sboms/
├── src/dt_lab/
│   ├── cli.py
│   ├── client.py
│   ├── cleanup.py
│   ├── domain.py
│   └── service.py
└── tests/
```

There are two deliberately separate SBOM input paths:

| Path | Contents | Source of truth | Use |
| --- | --- | --- | --- |
| `scenarios/sboms/` | Small committed synthetic CycloneDX fixtures | `scenarios/scenarios.yaml` | Deterministic behavior and regression checks |
| `var/dt-lab/corpus/` | Downloaded or explicitly derived upstream SBOMs, ignored by Git | `corpus/corpus.yaml` | Integration, compatibility, and scale experiments |

`corpus/corpus.yaml` does not populate, generate, or synchronize
`scenarios/sboms/`. A corpus run verifies the selected local artifact and builds
an in-memory lab manifest so both paths can reuse the observation runner without
mixing their inputs or evidence. A real-world observation may later justify a
small reviewed synthetic fixture, but that is an explicit product decision, not
an automatic copy.

The normal `sbom-ops` installation intentionally exposes no lab console script.
Use the repository Make targets so execution is visibly lab-scoped.

## Commands

Validate the synthetic scenario manifest and run the lab tests without
contacting Dependency-Track:

```bash
make dt-lab-validate
make dt-lab-test
```

Capture the target instance's OpenAPI document and build its inventory:

```bash
make dt-lab-openapi
```

Run implemented scenarios against an isolated local instance:

```bash
export SBOM_OPS_DT_BASE_URL=http://localhost:8080
export SBOM_OPS_SBOM_UPLOAD_API_KEY=replace-with-upload-key
export SBOM_OPS_DT_API_KEY=replace-with-read-key
make dt-lab-run
```

The default command skips every scenario with mutation actions. For local
evaluation, add `VULNERABILITY_ANALYSIS` to the existing orchestrator read team;
the lab then reuses `SBOM_OPS_DT_API_KEY`:

```bash
make dt-lab-triage-analysis
```

For stricter credential separation, set `SBOM_OPS_DT_ANALYSIS_API_KEY` to a
dedicated key with only `VULNERABILITY_ANALYSIS`; this optional override takes
precedence over the read key.

This command is explicit opt-in for `triage-analysis-states`. It creates a new
run-suffixed `dt-lab-triage-analysis` Project, selects one synthetic Log4Shell
Finding by PURL, vulnerability ID, and source, and records the decision cycle
`IN_TRIAGE` → `EXPLOITABLE` → `NOT_AFFECTED` → `FALSE_POSITIVE` → `RESOLVED` →
`NOT_SET`. Each action retains the PUT response, audit trail, suppressed or
unsuppressed Finding view, metrics, and a compact verification record under the
ignored run directory. The final action restores the disposable Finding before
optional run-scoped cleanup.

The VEX round-trip experiment uses the same credential and opt-in boundary:

```bash
make dt-lab-triage-vex
```

It creates a separate run-suffixed `dt-lab-triage-vex` Project, seeds one
reviewed `NOT_AFFECTED` Analysis decision, exports CycloneDX VEX 1.5, restores
the Finding to `NOT_SET`, uploads that exact exported document, and compares
the resulting Finding, Analysis trail, and re-exported VEX. It then replays the
same document to distinguish state idempotency from duplicate audit history. It
records Analysis semantic preservation separately from the DT suppression
projection because CycloneDX VEX does not represent Dependency-Track's Finding
suppression flag. The scenario finally restores `NOT_SET`; a failed round trip
also attempts and verifies an emergency restore. Evidence remains under the
ignored run directory for review before any separate cleanup.

The optional cleanup key is deliberately separate from upload and read access.
Its team needs `VIEW_PORTFOLIO` to verify each live Project and
`PORTFOLIO_MANAGEMENT` to delete it:

```bash
export SBOM_OPS_DT_CLEANUP_API_KEY=replace-with-cleanup-key
```

Use the module directly to select scenarios or include every OpenAPI tag:

```bash
PYTHONPATH=src:lab/dependency_track/src \
python -m dt_lab.cli run-scenarios \
  --scenario identity-same-name-different-purl \
  --scenario lifecycle-add-remove-components

PYTHONPATH=src:lab/dependency_track/src \
python -m dt_lab.cli openapi-inventory \
  var/dt-lab/openapi.json \
  --all-tags \
  --output var/dt-lab/openapi-inventory-all.json
```

## Real-World SBOM Corpus

The synthetic scenario BOMs remain the deterministic contract fixtures. The
real-world corpus complements them with upstream scale, generator quirks, mixed
package ecosystems, and incomplete graphs. Its committed catalog is
[`corpus/corpus.yaml`](corpus/corpus.yaml); downloaded payloads and provenance
evidence stay under ignored `var/dt-lab/corpus/`.

The catalog currently pins these inputs:

| Ecosystem | Upstream release | Input | Intended probe |
| --- | --- | --- | --- |
| Go | OpenTelemetry OBI 0.12.2 | Official CycloneDX 1.6 release asset | Go PURLs and a sparse graph |
| TypeScript/npm | n8n 2.36.8 | Authoritative CycloneDX 1.6 release SBOM | Large npm inventory without dependency entries |
| Rails/Ruby | OpenProject 17.7.2 | Verified CycloneDX 1.6 OCI attestation | Signed upstream input-quality rejection |
| Rails/Ruby | OpenProject 17.7.2 | Schema-valid derivation of the verified attestation | Production-scale, mixed container inventory |
| Python | Apache Airflow 3.3.0 for Python 3.12 | Official CycloneDX 1.7 SBOM | Compatibility with a newer specification |
| Python | Apache Airflow 3.3.0 for Python 3.12 | CycloneDX CLI v0.33.1 conversion to 1.6 | Controlled compatibility comparison |

Acquire the release assets into their cataloged paths:

```bash
mkdir -p \
  var/dt-lab/corpus/otel-obi-0.12.2 \
  var/dt-lab/corpus/n8n-2.36.8 \
  var/dt-lab/corpus/airflow-3.3.0-py312

curl --fail --location \
  https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/download/v0.12.2/obi-v0.12.2-linux-amd64.cyclonedx.json \
  --output var/dt-lab/corpus/otel-obi-0.12.2/sbom.cdx.json

curl --fail --location \
  'https://github.com/n8n-io/n8n/releases/download/n8n%402.36.8/sbom-source.cdx.json' \
  --output var/dt-lab/corpus/n8n-2.36.8/sbom.cdx.json

curl --fail --location \
  https://airflow.apache.org/docs/apache-airflow/3.3.0/sbom/apache-airflow-sbom-3.3.0-python3.12-python-only.json \
  --output var/dt-lab/corpus/airflow-3.3.0-py312/sbom.cdx.json
```

OpenProject is extracted only after keyless verification of the signed
attestation against the immutable image digest and the expected GitHub Actions
workflow identity:

```bash
mkdir -p var/dt-lab/corpus/openproject-17.7.2

cosign verify-attestation \
  --type https://cyclonedx.org/bom/v1.6 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/opf/openproject-flavours/.github/workflows/core-docker.yml@refs/heads/dev$' \
  openproject/openproject@sha256:19a828d66e7c23322d1fbbaa974e7b712ef03c2badf1b10466ca45710e6bbbe5 \
  > var/dt-lab/corpus/openproject-17.7.2/verified-attestation.jsonl

jq -r '.payload' \
  var/dt-lab/corpus/openproject-17.7.2/verified-attestation.jsonl \
  | base64 --decode \
  | jq '.predicate' \
  > var/dt-lab/corpus/openproject-17.7.2/sbom.cdx.json
```

The signed OpenProject predicate contains one schema-invalid, unexpanded URL
on the `formatador` Component. Preserve that original as the rejection case.
The stress input removes only that external reference and must then pass the
official CycloneDX schema validator:

```bash
jq '(.components[] | select((.externalReferences // []) | any(.url == "https://github.com/geemus/#{s.name}")) | .externalReferences) |= map(select(.url != "https://github.com/geemus/#{s.name}"))' \
  var/dt-lab/corpus/openproject-17.7.2/sbom.cdx.json \
  > var/dt-lab/corpus/openproject-17.7.2/sbom-schema-valid.cdx.json

cyclonedx-cli validate \
  --input-file var/dt-lab/corpus/openproject-17.7.2/sbom-schema-valid.cdx.json \
  --input-version v1_6
```

Do not replace the source artifact or describe the derived file as attested.
Its provenance is the verified source plus the one documented transform and
the independently pinned derived hash.

Create the Airflow compatibility artifact with the official CycloneDX CLI:

```bash
cyclonedx-cli convert \
  --input-file var/dt-lab/corpus/airflow-3.3.0-py312/sbom.cdx.json \
  --output-file var/dt-lab/corpus/airflow-3.3.0-py312/sbom-v1.6.cdx.json \
  --output-format json \
  --output-version v1_6
```

Always validate all catalog hashes and CycloneDX envelopes before a live run:

```bash
make dt-lab-corpus-validate
```

This integrity command does not replace full CycloneDX schema validation. Run
the official `cyclonedx-cli validate` for an intended-success input before
upload. Keep intentionally invalid originals only as explicit rejection cases.

Runs require an explicit single artifact ID. This keeps a 17,000-plus Component
stress case or an intentionally unsupported-version probe from running by
accident. The Component observations retrieve every API page and fail if the
combined count disagrees with `X-Total-Count`.

```bash
make dt-lab-corpus-run \
  CORPUS_ID=go-otel-obi-0-12-2
```

Use a larger `DT_LAB_PROCESSING_TIMEOUT` when the target is resource-constrained.
Never interpret a source BOM's missing graph, missing PURL, or generator metadata
as a Dependency-Track behavior; compare the validated input, captured API
responses, and re-export separately. Record every attempted import in
[`EXPERIMENTS.md`](EXPERIMENTS.md), including rejected and timed-out inputs.

## Cleaning a Run

Each new run writes `projects.json` before uploading and updates the ledger with
the Project UUID after lookup. Cleanup is always scoped to one run. Preview the
plan locally first; this does not contact Dependency-Track:

```bash
make dt-lab-cleanup RUN_ID=25dfd88e-2673-462b-9f40-818279ecd8b5
```

After reviewing the targets, execute the verified deletion:

```bash
make dt-lab-cleanup \
  RUN_ID=25dfd88e-2673-462b-9f40-818279ecd8b5 \
  EXECUTE=1
```

Cleanup is intentionally a separate command. In Dependency-Track 4.14.3,
repository metadata analysis may continue after the BOM event token reports
completion. Immediate deletion was observed to race that worker. Inspect the
evidence, allow the target's background analysis to become quiet, preview the
cleanup, and only then execute it. A failed upload can still leave an
auto-created empty Project, so failed runs require the same explicit review and
cleanup rather than being abandoned.

Before every deletion, the lab checks all of the following:

1. The requested run ID is a canonical UUID and matches `run.json`.
2. The recorded Project name starts with `dt-lab-`.
3. The Project version ends with `-lab-<first-eight-run-id-characters>`.
4. A live name/version lookup returns the same identity.
5. The live UUID matches the recorded UUID, when one was captured.

Any mismatch fails closed. A missing Project is treated as already cleaned, so
the command is safe to repeat. Every preview and execution writes an immutable
audit record under `var/dt-lab/runs/<run-id>/cleanups/`. Raw observations and
audit files remain local and ignored; cleanup deletes only the verified DT
Projects. It does not delete local evidence or reset the entire DT database.

Reproducibility does not depend on cleaning a preceding run: every run already
uses a fresh Project version. Cleanup controls portfolio accumulation after the
result has been inspected. Datasource mirrors, global policies, users, teams,
and API keys remain stable experiment inputs and are intentionally not reset.

Runs created before `projects.json` was introduced can still be planned from
their captured `project-lookup.json` observations under the same checks.

The reduced
[`fixtures/dependency-track-openapi.json`](fixtures/dependency-track-openapi.json)
preserves the reviewed v4.14.3 delete contract (`204`, `401`, `403`, `404`) and
`PORTFOLIO_MANAGEMENT` requirement, plus the lookup contract and its
`VIEW_PORTFOLIO` requirement. It records Component pagination defaults and the
`X-Total-Count` response contract, the Analysis read/write contracts and
permissions, and the current-team preflight contract used to reject an
overprivileged Analysis key. Recheck it against the target instance's
`/api/openapi.json` before upgrading Dependency-Track.

## Scenario Contract

The source of truth is [`scenarios/scenarios.yaml`](scenarios/scenarios.yaml).
Each repository scenario declares a purpose, hypotheses, product decision
questions, isolated Project identity, implementation status, ordered SBOM
steps, and the API areas to observe. Implemented scenarios must reference
existing SBOM files; planned scenarios may omit steps. Manifest schema version 3
requires at least one hypothesis and one decision question for every scenario.
Analysis actions additionally declare an exact Finding selector and a complete
state, justification, response, detail, comment, and suppression decision. A
VEX round-trip step declares one non-`NOT_SET` seed decision and cannot be
combined with a normal Analysis action sequence. Its `replay_import` flag makes
the otherwise identical second import explicit in the scenario contract.

Project names must use the `dt-lab-` prefix. The manifest validator also checks
repository-level invariants such as unique CycloneDX serial numbers and valid
dependency references. New or changed valid samples must also pass the official
schema for their declared CycloneDX version.

Every run adds a unique suffix to the declared Project version. A step may
override that version to compare separate releases of one named Project without
deleting or overwriting an existing Project. Each completed step records raw
response envelopes, a stable-field summary, and any Component delta. Failed
runs rewrite `run.json` with `status=failed`, a timestamp, completed-step count,
and a sanitized error.

The lab must not write Analysis, VEX, suppression, policy, or administrative
state unless a scenario explicitly covers that mutation, uses a disposable
Project and least-privilege lab key, and requires an explicit CLI opt-in.
Project cleanup is the sole generally available mutation: it requires a
dedicated cleanup key, a run-scoped ledger, live identity verification, and
an explicit `cleanup-run --execute` command after evidence review and target
quiescence.

Analysis mutation has a second independent gate. The scenario must be selected
by ID and `--allow-analysis-mutation` must be present. The lab prefers
`SBOM_OPS_DT_ANALYSIS_API_KEY` and falls back to `SBOM_OPS_DT_API_KEY`. Mutating
scenarios are excluded when `run-scenarios` is invoked without `--scenario`.
Before a Project is created, `/api/v1/team/self` must include
`VULNERABILITY_ANALYSIS`; only the read-only `VIEW_BADGES`,
`VIEW_POLICY_VIOLATION`, `VIEW_PORTFOLIO`, and `VIEW_VULNERABILITY` permissions
may appear alongside it.

The planned `triage-delegation-boundary` scenario determines how much security
triage can stay in DT rather than being duplicated in sbom-ops. Its evidence
must cover Analysis decisions and history, comments, suppression, VEX state,
permissions, API-visible change detection, and reconciliation behavior. The
result must identify separately:

- security decisions that are authoritative in DT
- orchestration state needed only for idempotency and reconciliation
- remediation task state that remains authoritative in GitHub or Jira
- actions that still require explicit human approval or workflow logic

This scenario must not assume that every DT feature should be used. Its goal is
the maximum safe delegation that simplifies the product without weakening the
human decision boundary.

## Branch Workflow

The lab is physically present on `main`, but experiments are developed on
short-lived branches such as `lab/analysis-states` or `lab/vex-round-trip`.
Long-lived lab branches are prohibited because they drift from production
contracts and hide dependency or security updates.

Before merging an experiment:

1. Rebase or merge the latest `main` into the short-lived branch.
2. Update [`EXPERIMENTS.md`](EXPERIMENTS.md) with the purpose, performed work,
   observed facts, interpretation or decision, unverified questions, target
   versions, and local evidence path pattern.
3. Keep only reproducible scenarios, stable lab code, reviewed fixtures,
   explicit product decisions or contract changes, and durable documentation.
4. Exclude credentials, raw observations, environment-specific UUIDs, and
   temporary investigation code.
5. Run product and lab tests independently.
6. Review every product change justified by lab evidence as a production API
   change, including official documentation and minimal fixture evidence. Do
   not copy exploratory lab modules into `src/sbom_ops/`.
7. Merge the branch and delete it.

## Experiment Results

Durable, reviewed observations and decisions live only in
[`EXPERIMENTS.md`](EXPERIMENTS.md). Do not duplicate result lists here; update
the ledger after every attempted live run and recheck version-bounded facts
during a Dependency-Track upgrade.
