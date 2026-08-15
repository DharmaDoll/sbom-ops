from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sbom_ops.domain.models import FindingState, RemediationState


class MissingFindingAction(StrEnum):
    NOOP = "NOOP"
    MARK_MISSING = "MARK_MISSING"
    CLOSE = "CLOSE"


@dataclass(frozen=True)
class MissingFindingDecision:
    action: MissingFindingAction
    finding_state: FindingState
    remediation_state: RemediationState
    missing_count: int
    reason: str


def decide_missing_finding(
    previous_missing_count: int,
    *,
    automatic_closure_enabled: bool,
    scan_verified: bool,
    confirmations_required: int,
) -> MissingFindingDecision:
    """Plan a safe workflow action for a finding absent from one sync result."""
    if confirmations_required < 2:
        raise ValueError("confirmations_required must be at least 2")
    if not automatic_closure_enabled:
        return MissingFindingDecision(
            action=MissingFindingAction.NOOP,
            finding_state=FindingState.UNKNOWN,
            remediation_state=RemediationState.OPEN,
            missing_count=previous_missing_count,
            reason="automatic_closure_disabled",
        )
    if not scan_verified:
        return MissingFindingDecision(
            action=MissingFindingAction.NOOP,
            finding_state=FindingState.UNKNOWN,
            remediation_state=RemediationState.OPEN,
            missing_count=previous_missing_count,
            reason="analysis_completion_not_verified",
        )

    missing_count = previous_missing_count + 1
    if missing_count >= confirmations_required:
        return MissingFindingDecision(
            action=MissingFindingAction.CLOSE,
            finding_state=FindingState.RESOLVED,
            remediation_state=RemediationState.CLOSED,
            missing_count=missing_count,
            reason="consecutive_absence_confirmed",
        )
    return MissingFindingDecision(
        action=MissingFindingAction.MARK_MISSING,
        finding_state=FindingState.MISSING,
        remediation_state=RemediationState.OPEN,
        missing_count=missing_count,
        reason="awaiting_absence_confirmation",
    )
