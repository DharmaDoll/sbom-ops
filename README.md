# Dependency-Track SBOM Operations

Security-as-a-Task orchestration for OWASP Dependency-Track SBOM workflows.

Dependency-Track owns inventory, vulnerability correlation, EPSS, and
VEX-derived analysis state. GitHub Issues own remediation workflow. `sbom-ops`
connects the two: it reads Dependency-Track findings, enriches them with CISA
KEV, calculates an operational priority, and optionally creates or updates
remediation issues. A reviewed asset inventory can show which service and
environment a Project belongs to, who owns it, which version is deployed, and
whether it is internet-facing. This is the missing business context around an
SBOM Finding.

The important boundary is intentional: sbom-ops can recommend and synchronize
work, but it must not approve exceptions, suppress findings, or overwrite
Dependency-Track analysis state automatically.

## What It Does Today

- Reads projects, findings, EPSS, suppression, and analysis state from Dependency-Track
- Uploads CycloneDX SBOMs to an existing Dependency-Track project as a CI helper
- Enriches findings with the CISA KEV catalog
- Retains per-Finding KEV matches in structured assessments
- Reports when a stale KEV cache was used in the run summary
- Reports whether the Finding snapshot stability check was not requested,
  completed, or had no Projects to inspect
- Includes Dependency-Track analyst notes in JSON assessments without treating
  them as automated decisions
- Calculates deterministic `P0` to `P3` priorities from configurable thresholds
- Explains unavailable or below-threshold EPSS/CVSS inputs in `P3` rationale;
  `P3` is the result of the configured rules, not a low-risk assertion
- Produces action-neutral finding assessments before any GitHub write
- Shows source-reported public-PoC presence and per-source counts when an
  optional snapshot supplies them; orders otherwise equal review results
  without changing P0–P3 or Issue actions
- Accepts an optional, reviewed Project/service/environment asset inventory;
  reports missing mappings and expired facts without changing priority
- Stores human-registered services and deployables in a local SQLite DB; reads
  DT Projects as association candidates and records explicit human approval
- Can run with GitHub Issue operations disabled via `--no-github`
- Supports YAML config, environment overrides, project-to-repository routing, JSON output, and optional JSONL sync logs
- Uses safe, opt-in issue closure after verified consecutive absence observations

## Quick Start

This is a local, operator-led rehearsal of the production shape:
register a service in sbom-ops, upload its SBOM **directly to DT**, inspect the
Project in DT, review the association, and compare one Finding with a dry-run.
No GitHub Issue or DT Analysis decision is changed. The companion
[operator exercise](docs/operations.md#運用担当者向けの初回演習) includes pause points and
questions to discuss after each step.

Prerequisites:

- Python 3.12 or newer
- Docker Engine and the Docker Compose plugin (only for the live DT steps)
- GitHub CLI only if you want to exercise GitHub Issue synchronization

Install locally:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

First, see the central use case without credentials or network access:

```bash
python examples/asset_scenario.py
```

The fictional scenario runs the real orchestrator against four fake DT
Projects with the same CVE. Its two inspectable inputs are the
[DT Project/Finding sample](examples/asset-scenario-dt.example.json) and
[asset inventory sample](examples/asset-inventory.example.json). The DT file
contains normalized offline test data, not a raw DT API response. The scenario
shows an internet-facing production service, an internal development
environment, an expired asset record, and a Project without a mapping. The
priority stays `P2` for all four because asset context is currently review
information, not an approved automatic priority rule. GitHub is disabled.

This JSON is an older evaluation input for deployment context. It is **not**
the SQLite registry used in the live exercise below, and its fictional UUIDs
must not be copied into a real DT Project.

Run the local test suite:

```bash
ruff check src tests
pytest -q tests
```

Start the local Dependency-Track evaluation stack:

```bash
docker compose -f examples/dependency-track/docker-compose.yml up -d
curl -fsS -o /dev/null http://localhost:8080/api/openapi.json
```

Open `http://localhost:8080`. For a newly created local stack, sign in with
the initial credentials below and change the password immediately. If you are
reusing an existing DT instance, use its current credentials instead:

```text
admin / admin
```

Create two local API keys in Dependency-Track (separate teams are preferable):

- SBOM upload key: `BOM_UPLOAD`, plus `PROJECT_CREATION_UPLOAD` if you use demo auto-create
- Orchestrator read key: `VIEW_PORTFOLIO` and `VIEW_VULNERABILITY`

Set the keys in your shell. An uncommitted `.env` is not loaded automatically:

```bash
export SBOM_OPS_DT_BASE_URL=http://localhost:8080
export SBOM_OPS_DT_API_KEY=replace-with-orchestrator-read-key
export SBOM_OPS_SBOM_UPLOAD_API_KEY=replace-with-upload-key
```

Register one disposable demo service in the local SQLite registry. The
timestamp makes the Project name unique; use the **same shell** for later
commands. The training version is only an exercise identifier. In CI, use an
immutable build or image identity instead.

```bash
mkdir -p var
export DEMO_SERVICE_ID="operator-demo-$(date +%s)"
export DEMO_PROJECT_NAME="$DEMO_SERVICE_ID/web"
export DEMO_PROJECT_VERSION="training-$(date +%s)"
sbom-ops assets --db var/assets.sqlite3 register-service \
  --service "$DEMO_SERVICE_ID" --owner training-team --criticality standard \
  --reason 'Local operator exercise; not a production deployment'
sbom-ops assets --db var/assets.sqlite3 register-deployable \
  --service "$DEMO_SERVICE_ID" --deployable web
sbom-ops assets --db var/assets.sqlite3 list
```

The first two lines in the list are your human-registered asset. There is no
DT UUID yet. Now simulate CI by uploading the bundled CycloneDX example
**directly to DT**, not through sbom-ops:

```bash
env -u SBOM_OPS_DT_PROJECT_UUID \
SBOM_OPS_DT_PROJECT_NAME="$DEMO_PROJECT_NAME" \
SBOM_OPS_DT_PROJECT_VERSION="$DEMO_PROJECT_VERSION" \
scripts/upload_bom.sh examples/sboms/vulnerable-demo.cdx.json
```

`env -u` prevents a previously exported Project UUID from redirecting this
upload. The script calls DT's BOM API; it is only a local stand-in for CI.
An accepted upload is not proof that DT analysis has finished.

In the DT UI, find the Project whose name and version match the two exported
values. Inspect its Components and one vulnerability Finding; note the Project
UUID, Component, vulnerability ID, score, and Analysis state. If there is no
Finding yet, check processing and data-source status instead of concluding
that the service is safe.

Read the DT Project back as an **untrusted association candidate**:

```bash
sbom-ops assets --db var/assets.sqlite3 candidates
```

Find the line with `name=$DEMO_PROJECT_NAME` and `status=candidate`. Compare
its UUID, name, and version with the UI and the upload command. Only after
that review, copy the UUID from the UI or candidate output and approve it:

```bash
export SBOM_OPS_DT_PROJECT_UUID=replace-with-reviewed-project-uuid
sbom-ops assets --db var/assets.sqlite3 approve \
  --service "$DEMO_SERVICE_ID" --deployable web \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --reviewer your-name
sbom-ops assets --db var/assets.sqlite3 candidates
sbom-ops assets --db var/assets.sqlite3 audit-links
```

The candidate should now say `status=reviewed`. This approves only the
Project-to-service association—not CI provenance, deployed version, exposure,
or vulnerability treatment. Do not approve a missing version or conflict.
The link audit should say `status=matched`; it reads DT again without changing
DT or the registry. `not_visible` means the read key did not return the
Project—it does **not** prove deletion. `identity_changed` and `ambiguous`
also need human review. The audit exits nonzero when there are no reviewed
links or any link is not matched.

You can also record a **human-reported**, unverified deployment. This
quick-start example deliberately says `unknown`; it does not assert that the
demo build is running or internet-facing:

```bash
export DEMO_OBSERVED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export DEMO_EXPIRES_AT="$(python -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
sbom-ops assets --db var/assets.sqlite3 report-deployment \
  --service "$DEMO_SERVICE_ID" --deployable web \
  --environment training --artifact "$DEMO_PROJECT_VERSION" \
  --status unknown --exposure unknown --reviewer your-name \
  --evidence 'Training declaration; runtime was not checked' \
  --observed-at "$DEMO_OBSERVED_AT" --expires-at "$DEMO_EXPIRES_AT"
sbom-ops assets --db var/assets.sqlite3 list
```

Each report is appended with a new ID. To correct one earlier claim for the
same service, deployable, environment, and artifact, submit a new report with
`--supersedes-report OLD_ID`; the old report remains visible in `assets list`.
Once the successor's observation time arrives, the old row is marked
`freshness=superseded` in that list.
Without this explicit link, incompatible overlapping claims remain a conflict.
The list shows whether each report is current, future-dated, or expired, but
neither this report nor the reviewed Project link proves a running workload.
`sync --asset-db` reports an exact artifact/version match only after the DT
Project UUID, name, and version match the reviewed link. It shows
`unverified_link`, `unreported`, `other_artifact`, `expired`,
`future_observation`, `conflict`, or `reported` per Project/environment.
`reported` means only that a current human claim was found. Conflicting
current claims remain unresolved. No claim changes a Finding, priority, DT
Analysis, or GitHub Issue.
For an existing schema-v1 or v2 registry, first take a non-overwriting backup and
explicitly migrate it with `sbom-ops assets --db PATH migrate --backup
BACKUP_PATH`; new registries use schema v3. Keep evidence text free of secrets.

For a persistent registry, check it and take a non-overwriting online backup
before making further changes:

```bash
sbom-ops assets --db var/assets.sqlite3 check
mkdir -p var/backups
sbom-ops assets --db var/assets.sqlite3 backup \
  --output "var/backups/assets-$(date +%Y%m%d-%H%M%S).sqlite3"
```

Keep backups out of Git, copy them to separate persistent storage, and test
opening a backup with
`sbom-ops assets --db BACKUP_PATH check`. A typo in `--db` now fails for
read/approval/backup commands instead of silently creating an empty DB.

Preview the runtime plan, then compare one DT Finding with sbom-ops. Both
commands are read-only with respect to DT Analysis and GitHub Issues:

```bash
sbom-ops plan --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --dry-run --no-github
sbom-ops sync \
  --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" \
  --wait-for-analysis \
  --asset-db var/assets.sqlite3 \
  --dry-run \
  --no-github
```

Check the vulnerability ID, Component, CVSS/EPSS, DT Analysis state, calculated
priority, and the reason for that priority. If they differ from the UI, record
the Project UUID, filters, suppression state, and observation time before
changing anything. A stable Finding snapshot is not proof that all DT
background analysis has finished. With `--asset-db`, `sync` opens the existing
SQLite registry read-only and shows `registry-project status=matched` only when
the reviewed Project UUID, name, and version still agree with DT. An unlinked,
changed, or ambiguous Project does not inherit the registered owner or
criticality. This context does not alter priority or GitHub Issue actions.
The separate `registry-deployment` line shows a time-bounded human claim only
when its artifact ID exactly matches the reviewed DT Project version. It is
not independent runtime proof; missing, expired, or conflicting claims do not
change priority. The older `--asset-inventory` JSON is a separate evaluation
input, not the SQLite registry.
The sample BOM can produce many Findings. Choose **one** in DT and search the
CLI output for its `vulnerability=` ID; do not review every row in the first
session.

For a deeper artifact-to-SBOM-to-deployment exercise, the repository also
contains a tiny [Go container sample](examples/identity-demo/main.go). It
requires Go, Docker, Trivy, and a local DT instance; see the
[operator guide](docs/operations.md#固定成果物を使ったローカル通し検証).
The CI workflow also packages this demo image as a short-lived artifact;
the [CI artifact exercise](docs/operations.md#ciが作った成果物での確認実行待ち)
explains how to verify and use it after a successful main run.

## Optional Evaluation Inputs

To check the CISA KEV feed on every run instead of accepting a still-fresh local
cache, add `--refresh-kev`. Conditional HTTP validation may still reuse an
unchanged cached feed. If refresh fails, stale-cache fallback remains controlled
by `intelligence.kev_cache_allow_stale`; the result reports when stale data was
used. New cache files carry a versioned SHA-256 checksum; malformed or altered
versioned caches are ignored. The checksum detects accidental corruption, not
malicious rewriting of the local cache. Refreshes use an adjacent SQLite lock
file and require a local filesystem; lock wait is bounded, and lock errors fail
the sync rather than risk concurrent cache access.

For machine-readable output:

```bash
sbom-ops sync \
  --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" \
  --wait-for-analysis \
  --dry-run \
  --no-github \
  --output json
```

At this point you should be able to see the core idea without granting GitHub
write access: Dependency-Track provides the inventory and analysis facts,
sbom-ops calculates the operational priority, and the Issue step remains an
explicit final action. JSON assessments include the Component UUID, PURL, name,
and version where Dependency-Track provides them, alongside the vulnerability
and priority fields. This preserves the inventory identity for downstream
review; it does not claim that external CVE-level evidence applies to that
Component.

An optional, precomputed advisory snapshot can be attached to a sync for review:

```bash
sbom-ops sync \
  --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" \
  --dry-run --no-github --output json \
  --advisory-snapshot examples/advisory-snapshot.example.json
```

The example is synthetic. The snapshot loader performs no network requests;
records are joined only by the Finding's primary vulnerability ID or explicit
Dependency-Track aliases. JSON output retains source, signal, freshness,
completeness, record counts, and references per Finding, plus matching
Project/environment exposure observations at the run level. Expired exposure
is reported as effectively `unknown`. An invalid optional snapshot emits a
warning and the Dependency-Track sync continues without it. These observations
do not change priority, Dependency-Track analysis, or GitHub actions. The result
also records the snapshot's declared creation time and SHA-256 digest so the
exact input can be identified later. See
[`SPEC.md`](SPEC.md#advisory-evidence-and-deployment-context) for the v1 schema
and semantics. The isolated Exploit Intelligence lab can export a Vuls sample
to this format; see its [handoff instructions](lab/exploit_intelligence/README.md#product-snapshot-handoff).

An explicit `published_poc` signal adds a source-by-source `poc_reports`
presence/count summary. If it is fresh, unexpired, and reported, otherwise
equal Findings appear first in JSON and text review output; P0–P3 and GitHub
actions do not change. The Vuls lab exporter emits general `exploit-record`
references, **not** PoC counts, so those samples do not trigger the ordering.
An [offline Vulnerability-Lookup handoff](lab/exploit_intelligence/README.md#product-snapshot-handoff)
can convert PoC-labelled Sightings with an explicit expiry window. Unknown or
stale PoC data never means "no PoC". The product does not run PoCs.

To use your own reviewed asset inventory, copy the example to a local file,
replace the fictional Project UUIDs with accessible DT Project UUIDs, and run:

```bash
sbom-ops sync \
  --config examples/config.yaml \
  --dry-run --no-github --output json \
  --asset-inventory path/to/reviewed-assets.json
```

The JSON result keeps asset deployments separate from individual Findings.
It lists selected DT Projects without a mapping and inventory Project UUIDs
that DT did not return. Each deployment has a source, observation time, and
expiry; after expiry, its effective owner, deployed version, deployment,
exposure, and criticality become unknown. The inventory is never used to
change priority or Issue state automatically. See the
[asset inventory contract](SPEC.md#asset-inventory-context).
This manual UUID join is for evaluation; it does not verify that the deployed
build matches the Project's SBOM. The proposed production identity flow is in
the [operator guide](docs/operations.md#sbomと稼働資産を結ぶ運用フロー一部実装).
No external asset register is assumed. The first SQLite-backed registry stores
services, deployables, and reviewed DT Project links; it does **not** yet prove
that an SBOM belongs to a deployed build or replace the optional JSON input.
Read-only EKS/ECS discovery can later add separate runtime observations; it
cannot replace human ownership or business-criticality decisions. SQLite on
local persistent storage is the first, single-host backend.

In a real pipeline, use the same `projectName=service_id/deployable_id` rule
and an immutable artifact-derived `projectVersion`. The CI credential needs
`BOM_UPLOAD` and, if it creates Projects, `PROJECT_CREATION_UPLOAD`. CI never
writes the SQLite DB. See the [operator guide](docs/operations.md#sbomと稼働資産を結ぶ運用フロー一部実装).

## Enabling GitHub Issue Sync

After reviewing dry-run output, provide GitHub repository settings and a token.
For local use, the GitHub CLI credential store is convenient:

```bash
export SBOM_OPS_GITHUB_OWNER=your-org
export SBOM_OPS_GITHUB_REPO=your-repo
export GH_TOKEN="$(gh auth token)"
```

Then remove `--no-github`. Keep `--dry-run` until labels, issue body, and
routing behavior are confirmed:

```bash
sbom-ops sync \
  --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" \
  --wait-for-analysis \
  --dry-run
```

`SBOM_OPS_GITHUB_TOKEN` is also supported. Do not commit tokens or place real
secrets in documentation.

## Configuration

`sync` and `plan` accept `--config PATH`. If omitted, `SBOM_OPS_CONFIG_FILE` is
used. Precedence is:

1. CLI flags
2. Environment variables
3. YAML config file
4. Code defaults

Use `env:VARIABLE_NAME` in YAML for secrets:

```yaml
dependency_track:
  base_url: http://localhost:8080
  api_key: env:SBOM_OPS_DT_API_KEY

github:
  enabled: false
  # token: env:SBOM_OPS_GITHUB_TOKEN
  # owner: acme
  # repo: service-a
```

See [`examples/config.yaml`](examples/config.yaml) for a complete example and
[`SPEC.md`](SPEC.md) for the full configuration contract.

## Core Commands

```bash
sbom-ops plan --config examples/config.yaml --no-github
sbom-ops sync --config examples/config.yaml --dry-run --no-github
sbom-ops sync --config examples/config.yaml --dry-run --no-github --output json
sbom-ops upload path/to/bom.cdx.json --project "$SBOM_OPS_DT_PROJECT_UUID"
sbom-ops assets --db var/assets.sqlite3 audit-links
sbom-ops assets --db var/assets.sqlite3 check
mkdir -p var/backups
sbom-ops assets --db var/assets.sqlite3 backup --output var/backups/assets.sqlite3
make dt-lab-validate
make dt-lab-test
make dt-lab-openapi
make dt-lab-run
make dt-lab-parent-child
make dt-lab-routing-metadata
make dt-lab-triage-analysis
make dt-lab-triage-delegation
make dt-lab-triage-vex
make dt-lab-triage-vex-targeting
make dt-lab-invalid-cyclonedx
make dt-lab-json-xml-equivalence
make dt-lab-corpus-validate
make dt-lab-corpus-run CORPUS_ID=go-otel-obi-0-12-2
make dt-lab-cleanup RUN_ID=<run-uuid>
make dt-lab-cleanup RUN_ID=<run-uuid> EXECUTE=1
make exploit-lab-validate
make exploit-lab-test
# With a local go-exploitdb server on 127.0.0.1:1326:
make exploit-lab-run
# With a pinned Vuls CLI and vuls.db:
make exploit-lab-vuls-db-run
# With one or more retained DT lab findings.json captures:
make exploit-lab-dt-sample DT_FINDINGS='path/to/findings.json ...'
# Bounded online enrichment (one retained record per signal by default):
make exploit-lab-vulnerability-lookup-run
# DT Finding sample; public bulk use is guarded at 25 CVEs unless raised explicitly:
make exploit-lab-vulnerability-lookup-dt-sample DT_FINDINGS='path/to/findings.json ...'
# Compare retained online and vuls.db results containing the same CVE set:
make exploit-lab-vulnerability-lookup-compare \
  VULS_RESULT='path/to/vuls-result.json' \
  VULNERABILITY_LOOKUP_RESULT='path/to/vulnerability-lookup-result.json'
make infra-gcp-poc-fmt-check
make infra-gcp-poc-validate
```

The Dependency-Track behavior lab is repository-only and is not installed by
`pip install sbom-ops`. Its adapter, scenarios, and tests live under
[`lab/dependency_track/`](lab/dependency_track/README.md). Product tests and lab
tests are intentionally separate. Committed
`lab/dependency_track/scenarios/sboms/` files are small synthetic fixtures;
`lab/dependency_track/corpus/corpus.yaml` catalogs real-world SBOMs whose
payloads remain ignored under `var/dt-lab/corpus/`. The catalog never generates
or overwrites the synthetic fixtures. New experiments use short-lived branches
and their observations are reviewed as decision evidence. The outcome is an
explicit choice to use a DT capability, encode a verified DT constraint,
implement only the missing orchestration gap, or reject/defer the hypothesis;
lab modules are never copied into `src/sbom_ops/` as a shortcut.
Lab cleanup is run-scoped and dry-run by default; destructive execution requires
a separate key and explicit `EXECUTE=1` after the target's asynchronous analysis
has become quiet.

The repository-only
[`Exploit Intelligence lab`](lab/exploit_intelligence/README.md) is also kept
outside the product package. Vulnerability-Lookup is the preferred online
enrichment candidate, the maintained Vuls `vuls.db` CLI is its comparison and
offline candidate, and the archived `go-exploitdb` API is only a pinned
behavioral baseline. Public exploit records, Sightings, KEV assertions, EPSS,
and vendor VEX remain separately attributed advisory evidence and never
directly set DT Analysis state or product priority. Snapshot-bound human reviews
can be compared for inter-reviewer agreement in the lab, but agreement is never
treated as correctness or an automatic promotion gate.

## Documentation

The active documentation has four primary entry points:

- [`README.md`](README.md): local quick start and command overview
- [`SPEC.md`](SPEC.md): normative product and Google Cloud deployment contract
- [`ARCHITECTURE.md`](ARCHITECTURE.md): stable boundaries and repository layout
- [`ROADMAP.md`](ROADMAP.md): current status, backlog, and delivery order

Supporting guides are grouped by purpose:

- Operations: [`use cases`](docs/use-cases.md), [`data sources`](docs/data-sources.md),
  [`runbook`](docs/operations.md), and
  [`Dependency-Track setup`](docs/dependency-track/setup.md)
- Dependency-Track development: [`production API contract`](docs/dependency-track/api.md)
  and [`behavior lab`](lab/dependency_track/README.md)
- Threat intelligence experiments:
  [`Exploit Intelligence lab`](lab/exploit_intelligence/README.md)
- Policies: [`priority`](docs/priority-policy.md) and
  [`VEX`](docs/vex.md)
- Decisions and infrastructure: [`ADRs`](docs/adr/README.md) and the
  [`GCP PoC`](infra/gcp/poc/README.md)

## Design Principles

1. SBOM is the source of truth for software composition.
2. Dependency-Track is the source of truth for inventory and vulnerability analysis state.
3. GitHub Issues are the source of truth for remediation workflow.
4. Threat intelligence drives operational prioritization.
5. AI can assist triage, but must not replace security decisions.
