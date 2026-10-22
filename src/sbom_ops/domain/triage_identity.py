"""Explicit CVE linkage for reference triage, independent of PoC adoption."""

import re
from dataclasses import dataclass

from sbom_ops.domain.models import Finding

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")


@dataclass(frozen=True)
class TriageCveLink:
    finding_key: str
    original_id: str
    original_source: str | None
    aliases: tuple[str, ...]
    candidates: tuple[str, ...]
    cve: str | None
    reasons: tuple[str, ...]


def resolve_triage_cve(finding: Finding) -> TriageCveLink:
    """Use only an unambiguous direct ID/explicit alias, never free-text search."""
    if not isinstance(finding, Finding):
        raise ValueError("typed finding required")
    if (
        not isinstance(finding.vulnerability_id, str)
        or not isinstance(finding.vulnerability_aliases, tuple)
        or any(not isinstance(value, str) for value in finding.vulnerability_aliases)
    ):
        raise ValueError("finding identifier and aliases must be strings")
    candidates: set[str] = set()
    reasons: set[str] = set()
    for raw in (finding.vulnerability_id, *finding.vulnerability_aliases):
        value = raw.strip().upper()
        if raw.isascii() and _CVE.fullmatch(value):
            candidates.add(value)
        elif value.startswith("CVE-"):
            # Do not hide a malformed second candidate behind a valid first one.
            reasons.add("invalid_cve_identifier")
    if not finding.vulnerability_id.strip():
        reasons.add("missing_original_identifier")
    if not candidates:
        reasons.add("no_cve_candidate")
    elif len(candidates) > 1:
        reasons.add("multiple_cve_candidates")
    ordered = tuple(sorted(candidates))
    return TriageCveLink(
        finding_key=finding.finding_key(),
        original_id=finding.vulnerability_id,
        original_source=finding.vulnerability_source,
        aliases=finding.vulnerability_aliases,
        candidates=ordered,
        cve=ordered[0] if len(ordered) == 1 and not reasons else None,
        reasons=tuple(sorted(reasons)),
    )
