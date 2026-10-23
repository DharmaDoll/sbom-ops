"""Compose read-only evidence; never change priorities or remediation state."""

from dataclasses import dataclass
from datetime import UTC, datetime

from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegistryProjectObservation,
)
from sbom_ops.domain.kev import KevSnapshot
from sbom_ops.domain.models import Finding
from sbom_ops.domain.triage_assets import AssetTriageEvidence, join_asset_evidence
from sbom_ops.domain.triage_evidence import (
    TriageEvidenceContext,
    TriageFactor,
    TriageObservation,
    TriageSubject,
    VulnerabilityIdentity,
    build_triage_evidence,
)
from sbom_ops.domain.triage_identity import TriageCveLink, resolve_triage_cve
from sbom_ops.domain.vulnrichment import VulnrichmentReport


@dataclass(frozen=True)
class FindingTriageContext:
    identity: TriageCveLink
    assets: AssetTriageEvidence | None
    kev: KevSnapshot | None
    cisa: VulnrichmentReport | None
    evidence: TriageEvidenceContext | None
    reasons: tuple[str, ...]


def compose_triage_context(
    finding: Finding,
    snapshot: AssetRegistrySnapshot,
    project: RegistryProjectObservation,
    *,
    environment: str,
    now: datetime,
    kev: KevSnapshot | None = None,
    cisa: VulnrichmentReport | None = None,
) -> FindingTriageContext:
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("evaluation time must be timezone-aware")
    now = now.astimezone(UTC)
    if project.project_uuid != finding.project_uuid:
        raise ValueError("finding and Project identity mismatch")
    link = resolve_triage_cve(finding)
    if link.cve is None:
        return FindingTriageContext(link, None, kev, cisa, None, link.reasons)
    identity = VulnerabilityIdentity(link.cve, "CVE")
    assets = join_asset_evidence(
        snapshot, project, identity, environment=environment, now=now
    )
    observations = list(assets.observations)
    reasons = set(assets.reasons)
    if kev is None:
        reasons.add("kev_unavailable")
    else:
        if not kev.complete:
            reasons.add("kev_incomplete")
        if kev.mode == "stale":
            reasons.add("kev_stale_fallback")
        if kev.expires_at <= kev.checked_at:
            reasons.add("kev_validity_disabled")
        else:
            observations.append(
                TriageObservation(
                    evidence_id=f"kev:{kev.revision}:{link.cve}",
                    vulnerability=identity,
                    factor=TriageFactor.KEV,
                    value=kev.membership(link.cve, now=kev.checked_at),
                    source=kev.source,
                    source_record=link.cve,
                    source_revision=kev.revision,
                    observed_at=kev.checked_at,
                    expires_at=kev.expires_at,
                )
            )
    if cisa is None:
        reasons.add("cisa_unavailable")
    else:
        allowed = {
            TriageFactor.AUTOMATABLE,
            TriageFactor.TECHNICAL_IMPACT,
            TriageFactor.KNOWN_EXPLOITATION,
        }
        if cisa.cve != link.cve or any(
            item.vulnerability != identity or item.factor not in allowed
            for item in cisa.observations
        ):
            raise ValueError("CISA report does not match the resolved CVE contract")
        reasons.update(cisa.reasons)
        if cisa.retrieved_at.utcoffset() is None:
            raise ValueError("CISA retrieval time must be timezone-aware")
        if cisa.retrieved_at > now:
            reasons.add("cisa_retrieval_in_future")
        else:
            observations.extend(cisa.observations)
    evidence = build_triage_evidence(
        TriageSubject(
            link.finding_key, identity, assets.asset, assets.asset is not None
        ),
        tuple(observations),
        now=now,
    )
    return FindingTriageContext(
        link, assets, kev, cisa, evidence, tuple(sorted(reasons))
    )
