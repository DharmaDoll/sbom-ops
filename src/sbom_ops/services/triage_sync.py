"""Present reference evidence alongside, never inside, priority decisions."""

from dataclasses import asdict, dataclass
from datetime import datetime

from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegistryProjectObservation,
)
from sbom_ops.domain.kev import KevSnapshot
from sbom_ops.domain.models import Finding
from sbom_ops.domain.triage_guidance import actions_as_dict, suggest_triage_actions
from sbom_ops.domain.triage_identity import resolve_triage_cve
from sbom_ops.domain.triage_input import SelectedCisaSnapshot, TriageInput
from sbom_ops.domain.triage_reference import evaluate_reference
from sbom_ops.services.reference_policy import load_reference_policy
from sbom_ops.services.triage_context import (
    FindingTriageContext,
    compose_triage_context,
)


@dataclass(frozen=True)
class SyncTriageContext:
    context: FindingTriageContext
    environment: str
    evaluated_at: datetime
    selected_cisa: SelectedCisaSnapshot | None
    asset_owner: str | None = None

    def guidance(self) -> dict[str, object]:
        asset = self.context.assets.asset if self.context.assets else None
        reference = evaluate_reference(self.context.evidence, load_reference_policy())
        owner = self.asset_owner if asset is not None else None
        return {
            "asset": asdict(asset) if asset else None,
            "asset_owner": owner,
            "actions": actions_as_dict(
                suggest_triage_actions(reference, asset_owner=owner)
            ),
            "automatic_actions": False,
        }

    def reference_result(self) -> dict[str, object]:
        return evaluate_reference(
            self.context.evidence, load_reference_policy()
        ).as_dict()

    def as_dict(self) -> dict[str, object]:
        context = self.context
        cisa = context.cisa
        kev = context.kev
        return {
            "identity": asdict(context.identity),
            "environment": self.environment,
            "evaluated_at": self.evaluated_at.isoformat(),
            "reasons": list(context.reasons),
            "evidence": context.evidence.as_dict() if context.evidence else None,
            "reference": self.reference_result(),
            "guidance": self.guidance(),
            "asset_reports": (
                [asdict(item) for item in context.assets.reports]
                if context.assets
                else []
            ),
            "pending_asset_corrections": (
                [asdict(item) for item in context.assets.pending_corrections]
                if context.assets
                else []
            ),
            "kev": (
                {
                    "source": kev.source,
                    "revision": kev.revision,
                    "checked_at": kev.checked_at.isoformat(),
                    "expires_at": kev.expires_at.isoformat(),
                    "mode": kev.mode,
                    "complete": kev.complete,
                }
                if kev
                else None
            ),
            "cisa": (
                {
                    "snapshot_id": self.selected_cisa.snapshot_id,
                    "revision": cisa.revision,
                    "cve": cisa.cve,
                    "retrieved_at": cisa.retrieved_at.isoformat(),
                    "assessed_at": (
                        cisa.assessed_at.isoformat() if cisa.assessed_at else None
                    ),
                    "exploitation": cisa.exploitation,
                    "latest_verified": False,
                    "observations": [item.as_dict() for item in cisa.observations],
                }
                if cisa and self.selected_cisa
                else None
            ),
            "priority_changed": False,
            "deadline_calculated": False,
        }


def build_sync_triage(
    finding: Finding,
    registry: AssetRegistrySnapshot,
    project: RegistryProjectObservation,
    inputs: TriageInput,
    *,
    kev: KevSnapshot | None,
    now: datetime,
) -> SyncTriageContext:
    identity = resolve_triage_cve(finding)
    selected = next(
        (item for item in inputs.cisa if item.snapshot.cve == identity.cve), None
    )
    context = compose_triage_context(
        finding,
        registry,
        project,
        environment=inputs.environment,
        now=now,
        kev=kev,
        cisa=selected.snapshot.report() if selected else None,
    )
    asset = context.assets.asset if context.assets else None
    owners = [
        service.owner
        for service in registry.services
        if asset is not None and service.service_id == asset.service_id
    ]
    owner = owners[0] if len(owners) == 1 else None
    return SyncTriageContext(context, inputs.environment, now, selected, owner)
