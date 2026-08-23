from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sbom_ops.domain.models import AnalysisState, FindingState, RemediationState


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


@dataclass(frozen=True)
class WorkflowState:
    """A point-in-time view of the three independently owned workflow states.

    ``analysis_state`` is an observation from Dependency-Track.  It is carried
    through the domain model, but never transitioned or written by this module.
    ``remediation_state`` is derived only from an explicitly verified finding
    resolution, so an analysis value cannot close a remediation issue by itself.
    """

    finding_state: FindingState
    analysis_state: AnalysisState
    remediation_state: RemediationState


def transition_remediation_state(
    finding_state: FindingState,
    *,
    resolution_confirmed: bool = False,
) -> RemediationState:
    """Derive remediation state from a finding transition.

    A remediation remains open for active, missing, and unknown findings.  It
    may be closed only when the absence confirmation rule has explicitly
    produced a resolved finding.  This keeps Dependency-Track analysis
    (which is read-only here) independent from remediation workflow state.
    """
    if finding_state == FindingState.RESOLVED and resolution_confirmed:
        return RemediationState.CLOSED
    return RemediationState.OPEN


def observe_workflow_state(
    *,
    finding_state: FindingState,
    analysis_state: AnalysisState,
    resolution_confirmed: bool = False,
) -> WorkflowState:
    """Build a workflow snapshot without mutating Dependency-Track analysis."""
    return WorkflowState(
        finding_state=finding_state,
        analysis_state=analysis_state,
        remediation_state=transition_remediation_state(
            finding_state,
            resolution_confirmed=resolution_confirmed,
        ),
    )


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
            remediation_state=transition_remediation_state(FindingState.UNKNOWN),
            missing_count=previous_missing_count,
            reason="automatic_closure_disabled",
        )
    if not scan_verified:
        return MissingFindingDecision(
            action=MissingFindingAction.NOOP,
            finding_state=FindingState.UNKNOWN,
            remediation_state=transition_remediation_state(FindingState.UNKNOWN),
            missing_count=previous_missing_count,
            reason="analysis_completion_not_verified",
        )

    missing_count = previous_missing_count + 1
    if missing_count >= confirmations_required:
        return MissingFindingDecision(
            action=MissingFindingAction.CLOSE,
            finding_state=FindingState.RESOLVED,
            remediation_state=transition_remediation_state(
                FindingState.RESOLVED,
                resolution_confirmed=True,
            ),
            missing_count=missing_count,
            reason="consecutive_absence_confirmed",
        )
    return MissingFindingDecision(
        action=MissingFindingAction.MARK_MISSING,
        finding_state=FindingState.MISSING,
        remediation_state=transition_remediation_state(FindingState.MISSING),
        missing_count=missing_count,
        reason="awaiting_absence_confirmation",
    )
