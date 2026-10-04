# ADR 0002: Advisory Evidence and Deployment Context Boundaries

Status: Accepted

Date: 2026-10-03

## Context

The Dependency-Track lab and real-SBOM corpus establish that package inventory
identity can be retained in product assessments, but published exploit
references are noisy, source-specific, and often joined only at CVE level. The
lab found duplicate URLs, broad index/advisory links, source-native categories,
stale or inaccessible artifacts, and differences between `available`,
`not_observed`, and `unknown`. None of these observations establishes that a
specific Component is affected or that a deployed vulnerable function is
reachable.

Internet exposure is a separate Project/deployment-context fact. A public source
repository, package URL, SBOM service URL, or public PoC does not establish that
the affected service is deployed or internet-facing. The public software corpus
contains no authoritative deployment inventory.

## Decision

Adopt a product boundary for presenting advisory evidence and deployment
context, without adopting an exploitability score or changing the current
priority policy.

Product-facing evidence must preserve these independent dimensions:

- Finding and Component identity, including the original vulnerability source
  and identifier.
- Vulnerability-level source observations with `available`, `not_observed`, or
  `unknown` outcome, observation time, source revision/freshness, and total,
  retained, and completeness counts.
- Source-native evidence identifiers, URLs, provider, and type/flags without
  promoting provider claims (including Nuclei `verified`) into sbom-ops
  verification.
- Published PoC/reference, exploitation report, scanner template, affected
  product applicability, code reachability, and internet exposure as separate
  concepts.
- Project and deployment-environment exposure observations with provenance,
  observation time, expiry, and `confirmed`, `rejected`, `unknown`, or `conflict`
  states.
- Human review state and reviewer provenance separately from machine/source
  observations.

An evidence-to-Finding join may use the primary CVE identifier or an explicit,
source-attributed alias already supplied by Dependency-Track. It must retain the
original identifier and Finding key. Lab-only candidate mappings, `related` or
`upstream` references, and free text are not product join keys until separately
reviewed and accepted.

The initial product presentation is advisory only. Evidence availability,
source type, exposure, and reachability must not automatically change priority,
Dependency-Track Analysis/VEX, suppression, Issue state, or remediation
workflow. `not_observed` is scoped to a successful source query and snapshot;
transport failures, expired data, unsupported identifiers, and incomplete
queries remain `unknown`.

No source is selected or represented as complete by this ADR. Optional evidence
acquisition must not block the core Dependency-Track assessment and must not
require runtime access to the lab package. Product source adoption still needs
a versioned handoff contract, measured limits, and explicit failure tests.

## Consequences

- A generic `has_poc` or `exploited` boolean is not an acceptable product DTO.
- Public-corpus Projects keep deployment exposure `unknown` unless an
  authoritative inventory or reviewed operator observation says otherwise.
- A CVE-level evidence record may be shown next to a Component only as a
  review lead, never as a claim of applicability.
- Product sync accepts an optional, bounded precomputed evidence snapshot. The
  isolated lab has an offline Vuls-sample exporter; the product runtime does not
  import or call the lab. Snapshot timestamp and digest are returned for review.
  Live provider acquisition and authoritative deployment-inventory integration
  remain future work.
- Product sync also accepts a separate, reviewed asset-inventory snapshot for
  Project/service/environment, owner, deployment, exposure, and business
  criticality. Its synthetic scenario demonstrates the context boundary. The
  inventory is presented beside assessments, with unmapped and expired records
  made visible; it is not an automatic priority or Issue-routing input. The
  two snapshot types are not silently merged when their exposure reports differ.
- The contract can be rolled back by disabling the optional evidence handoff;
  no Dependency-Track state or GitHub workflow state is mutated by presentation.

## Validation Plan

- Use synthetic fixtures for malformed, stale, incomplete, duplicate, and
  conflicting observations; verify these remain `unknown` or explicit conflict.
- Export a retained real-SBOM sample, load it with the product parser, and
  verify that the snapshot preserves source counts, provenance, and three-state
  outcomes. Product unit tests separately verify exact alias joins and unchanged
  priority.
- Confirm that an evidence-source outage does not block the core sync result.
- Do not infer internet exposure for the public corpus. Validate exposure only
  against a supplied deployment inventory or reviewed operator observation.
- Run the fictional asset scenario with the same CVE in production and
  development, plus expired and unmatched inventory records; verify that
  priority and Issue actions remain unchanged while the context is visible.

## References

- [Exploit Intelligence lab candidate advisory presentation contract](../../lab/exploit_intelligence/README.md#candidate-advisory-presentation-contract)
- [Dependency-Track lab evidence-join readiness](../../lab/dependency_track/EXPERIMENTS.md#2026-09-11--rails-after-osv-and-evidence-join-readiness)
- [Exploit Intelligence lab evidence ledger](../../lab/exploit_intelligence/EXPERIMENTS.md)
