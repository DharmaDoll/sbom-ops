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

Prioritize scenarios that retire the largest product risk or remove the most
duplicate implementation. A `planned` scenario is an uncertainty backlog item;
it need not be implemented when another experiment or official contract already
answers its decision questions.

## Layout

```text
lab/dependency_track/
├── README.md
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

The normal `sbom-ops` installation intentionally exposes no lab console script.
Use the repository Make targets so execution is visibly lab-scoped.

## Commands

Validate the corpus without contacting Dependency-Track:

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

For disposable successful runs, cleanup may be requested with the run itself:

```bash
make dt-lab-run CLEANUP=1
```

`CLEANUP=1` is equivalent to `--cleanup-on-success`. A failed scenario is never
cleaned automatically, so its DT Project and local observations remain
available for diagnosis.

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
`VIEW_PORTFOLIO` requirement. Recheck it against the target instance's
`/api/openapi.json` before upgrading Dependency-Track.

## Scenario Contract

The source of truth is [`scenarios/scenarios.yaml`](scenarios/scenarios.yaml).
Each repository scenario declares a purpose, hypotheses, product decision
questions, isolated Project identity, implementation status, ordered SBOM
steps, and the API areas to observe. Implemented scenarios must reference
existing SBOM files; planned scenarios may omit steps. Manifest schema version 2
requires at least one hypothesis and one decision question for every scenario.

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
`--execute` or `--cleanup-on-success`.

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
2. Keep only reproducible scenarios, stable lab code, reviewed fixtures,
   explicit product decisions or contract changes, and durable documentation.
3. Exclude credentials, raw observations, environment-specific UUIDs, and
   temporary investigation code.
4. Run product and lab tests independently.
5. Review every product change justified by lab evidence as a production API
   change, including official documentation and minimal fixture evidence. Do
   not copy exploratory lab modules into `src/sbom_ops/`.
6. Merge the branch and delete it.

## Current v4.14.3 Observations

The following behavior was reproduced against the repository's local v4.14.3
container on 2026-08-27. It must be rechecked during an upgrade:

- CycloneDX Project JSON export requires
  `Accept: application/vnd.cyclonedx+json`; generic JSON returned `406`.
- A retained Component with the same PURL received different Component UUIDs in
  different Project versions.
- `onlyDirect=true` returned only the root dependencies from the test graph.
- Component-to-Service edges appeared in Component `directDependencies` and the
  dependency-graph response, while Project CycloneDX re-export omitted those
  Service edges from `dependencies`.
- With the current datasource configuration, PURL-only samples produced no NVD
  Findings. Adding matching CPEs produced NVD Findings.
- NVD Findings included EPSS score and percentile plus CVSS fields. GitHub and
  OSV records were not present, so cross-source alias behavior remains
  intentionally unasserted.
