"""Read reviewed mappings only for PoC acquisition and post-workflow display."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from sbom_ops.domain.advisory import AdvisorySnapshot
from sbom_ops.domain.models import FindingAssessment
from sbom_ops.domain.poc import PocTargets, select_poc_targets
from sbom_ops.domain.poc_identity import PocIdentity, resolve_poc_identity
from sbom_ops.storage.identifier_candidates import IdentifierStore


def read_poc_identity(
    store: IdentifierStore, original_id: str, dt_source: str, *, now: datetime
) -> PocIdentity:
    decision, observation, latest = store.review_context(original_id, dt_source)
    return resolve_poc_identity(
        original_id,
        dt_source,
        decision,
        observation,
        latest_observation_id=latest,
        now=now,
    )


def select_reviewed_poc_targets(
    payload: object, store: IdentifierStore, *, max_cves: int, now: datetime
) -> tuple[PocTargets, tuple[PocIdentity, ...]]:
    # Validate the entire input first. Never trust prior enrichment from its JSON.
    base = select_poc_targets(payload, max_cves=max_cves)
    store.require_reviews()
    cves = set(base.cves)
    unresolved: set[str] = set()
    mappings: dict[tuple[str, str], PocIdentity] = {}
    for row in payload["assessments"]:
        direct = select_poc_targets(
            {"status": "succeeded", "assessments": [row]}, max_cves=max_cves
        )
        if direct.cves:
            continue  # DT primary ID / explicit aliases take precedence.
        identifier = row["vulnerability_id"].strip()
        source = row.get("vulnerability_source") or "UNKNOWN"
        if not isinstance(source, str) or len(source) > 128:
            raise ValueError("invalid vulnerability source")
        key = (identifier, source)
        if key not in mappings:
            mappings[key] = read_poc_identity(store, *key, now=now)
        mapping = mappings[key]
        if mapping.usable(now):
            cves.add(mapping.cve)
        else:
            unresolved.add(identifier)
    if len(cves) > max_cves:
        raise ValueError(
            "CVE count exceeds max_cves; narrow the input or raise the limit"
        )
    return PocTargets(tuple(sorted(cves)), tuple(sorted(unresolved))), tuple(
        mappings.values()
    )


def attach_reviewed_poc(
    assessments: tuple[FindingAssessment, ...],
    snapshot: AdvisorySnapshot,
    store: IdentifierStore,
    *,
    now: datetime,
) -> tuple[FindingAssessment, ...]:
    """Do not mutate Finding IDs, aliases, risk inputs or workflow results."""
    store.require_reviews()
    result = []
    mappings: dict[tuple[str, str], PocIdentity] = {}
    for item in assessments:
        direct = select_poc_targets(
            {
                "status": "succeeded",
                "assessments": [
                    {
                        "vulnerability_id": item.vulnerability_id,
                        "vulnerability_aliases": list(item.vulnerability_aliases),
                    }
                ],
            },
            max_cves=1000,
        )
        mapping = None
        observations = ()
        if not direct.cves:
            key = (
                item.vulnerability_id.strip(),
                item.vulnerability_source or "UNKNOWN",
            )
            if key not in mappings:
                mappings[key] = read_poc_identity(store, *key, now=now)
            mapping = mappings[key]
            if mapping.usable(now):
                observations = tuple(
                    row
                    for row in snapshot.observations_for(mapping.cve)
                    if row.signal == "published_poc"
                )
        result.append(
            replace(item, poc_identity=mapping, reviewed_poc_observations=observations)
        )
    return tuple(result)


def reviewed_target_is_current(
    store: IdentifierStore,
    cve: str,
    direct_cves: tuple[str, ...],
    mappings: tuple[PocIdentity, ...],
    *,
    now: datetime,
) -> bool:
    if cve in direct_cves:
        return True
    for selected in mappings:
        if selected.cve != cve or not selected.usable(now):
            continue
        current = read_poc_identity(
            store, selected.original_id, selected.dt_source, now=now
        )
        if current.usable(now) and current.review_id == selected.review_id:
            return True
    return False
