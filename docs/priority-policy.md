# Priority Policy

## P0
Known Exploited Vulnerability
Immediate response

Example SLA (separate remediation policy)
- 48 hours

---

## P1
Critical
High EPSS

Example SLA (separate remediation policy)
- Next release

---

## P2
High severity
Planned remediation

---

## P3
Medium
Low
Monitor only

## Triage ownership

Priority is an operational decision generated from Dependency-Track data and
the configured policy. Security team owns the final triage decision, including
whether a finding is exploitable, not affected, a false positive, suppressed,
or accepted as risk.

sbom-ops may recommend a priority and create or update a GitHub Issue, but it
must not automatically approve exceptions, accept risk, or change
Dependency-Track analysis state.

Priority expresses work ordering; an SLA expresses a due date and escalation
policy. They must remain separate domain concepts. Asset criticality, exposure,
reachability, and compensating controls are future `PriorityContext` inputs and
must not be inferred from CVSS alone.
