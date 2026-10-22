"""Group reviewed findings into repair candidates without changing inventory."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from sbom_ops.domain.asset_registry import RegistryProjectStatus, validate_identifier
from sbom_ops.domain.models import Priority
from sbom_ops.domain.review import FindingReview


@dataclass(frozen=True)
class RemediationGroup:
    """A repair candidate, not a risk decision or an authorized Issue operation."""

    key: str
    basis: str
    service_id: str | None
    deployable_id: str | None
    members: tuple[FindingReview, ...]

    @property
    def highest_observed_priority(self) -> Priority:
        # Include suppressed findings: this is an observation, not an instruction
        # to override DT analysis or to create an Issue.
        return min(row.assessment.priority for row in self.members)

    @property
    def finding_keys(self) -> tuple[str, ...]:
        return tuple(sorted({row.assessment.finding_key for row in self.members}))

    def as_dict(self) -> dict[str, object]:
        return {
            "group_key": self.key,
            "basis": self.basis,
            "service_id": self.service_id,
            "deployable_id": self.deployable_id,
            "finding_keys": list(self.finding_keys),
            "finding_count": len(self.finding_keys),
            "project_uuids": sorted(
                {row.assessment.project_uuid for row in self.members}
            ),
            "highest_observed_priority": self.highest_observed_priority.value,
            "members": [row.as_dict() for row in self.members],
        }


def _identity_text(value: str | None) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value.strip() == value
        and all(character.isprintable() for character in value)
    )


def _group_identity(row: FindingReview) -> tuple[tuple[str, ...], str]:
    item = row.assessment
    fallback = ("finding", item.project_uuid, item.finding_key)
    asset = row.asset
    if (
        row.asset_status != RegistryProjectStatus.MATCHED.value
        or asset is None
        or asset.status is not RegistryProjectStatus.MATCHED
        or asset.project_uuid != item.project_uuid
    ):
        return fallback, "asset_not_verified"
    if not asset.service_id or not asset.deployable_id:
        return fallback, "asset_identity_missing"
    try:
        validate_identifier(asset.service_id, label="service_id")
        validate_identifier(asset.deployable_id, label="deployable_id")
    except ValueError:
        return fallback, "asset_identity_missing"
    if (
        not _identity_text(item.component_purl)
        or not item.component_purl.startswith("pkg:")
        or len(item.component_purl) <= 4
    ):
        return fallback, "package_identity_missing"
    if not _identity_text(item.vulnerability_source) or not _identity_text(
        item.vulnerability_id
    ):
        return fallback, "vulnerability_identity_missing"
    # Treat the full PURL as an opaque exact identifier, including version,
    # qualifiers and subpath. Do not infer equivalence from display names, CVE
    # aliases, PoC mappings or similar package coordinates.
    return (
        "service_deployable",
        asset.service_id,
        asset.deployable_id,
        item.component_purl,
        item.vulnerability_source,
        item.vulnerability_id,
    ), "verified_asset_and_exact_identity"


def build_remediation_groups(
    rows: Sequence[FindingReview],
) -> tuple[RemediationGroup, ...]:
    """Stable across build UUIDs and owners; incomplete identities stay individual.

    Only the selected, observed rows belong to the result. A missing member does
    not mean resolved. Repository routing is deliberately not inferred here.
    """
    buckets: dict[tuple[str, ...], list[FindingReview]] = defaultdict(list)
    reasons: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for row in rows:
        identity, reason = _group_identity(row)
        buckets[identity].append(row)
        reasons[identity].add(reason)
    result = []
    for identity, members in buckets.items():
        digest = hashlib.sha256(
            json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()
        ).hexdigest()
        grouped = identity[0] == "service_deployable"
        result.append(
            RemediationGroup(
                key=f"repair-v1:{digest}",
                basis=(
                    next(iter(reasons[identity]))
                    if len(reasons[identity]) == 1
                    else "incomplete_identity"
                ),
                service_id=identity[1] if grouped else None,
                deployable_id=identity[2] if grouped else None,
                members=tuple(
                    sorted(
                        members,
                        key=lambda row: (
                            row.assessment.priority,
                            row.assessment.project_uuid,
                            row.assessment.finding_key,
                        ),
                    )
                ),
            )
        )
    return tuple(
        sorted(result, key=lambda group: (group.highest_observed_priority, group.key))
    )
