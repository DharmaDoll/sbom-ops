from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sbom_ops.domain.models import AnalysisState, FindingState, RemediationState


class GitHubWriteAuthorizationError(ValueError):
    """GitHub writes need an explicit grant for this invocation."""


def require_github_write_permission(
    *,
    enabled: bool,
    dry_run: bool,
    write_requested: bool,
) -> None:
    if any(type(value) is not bool for value in (enabled, dry_run, write_requested)):
        raise GitHubWriteAuthorizationError("GitHub execution flags must be booleans")
    # Both read-only switches take precedence, even over a requested write.
    if enabled and not dry_run and not write_requested:
        raise GitHubWriteAuthorizationError(
            "GitHub writes require --github-write for this invocation; "
            "use --dry-run to preview or --no-github to skip GitHub"
        )


class MissingFindingAction(StrEnum):
    NOOP = "NOOP"


@dataclass(frozen=True)
class MissingFindingDecision:
    action: MissingFindingAction
    finding_state: FindingState
    remediation_state: RemediationState
    missing_count: int
    reason: str

    def as_dict(self) -> dict[str, str | int]:
        return {
            "action": self.action.value,
            "finding_state": self.finding_state.value,
            "remediation_state": self.remediation_state.value,
            "missing_count": self.missing_count,
            "reason": self.reason,
        }


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


def decide_missing_finding() -> MissingFindingDecision:
    """Absence from a read is not proof of resolution, even after stable reads.

    There is no artifact/analysis completion evidence source yet. Historical
    missing counts therefore cannot be accepted or advanced by this decision.
    """
    return MissingFindingDecision(
        action=MissingFindingAction.NOOP,
        finding_state=FindingState.UNKNOWN,
        remediation_state=transition_remediation_state(FindingState.UNKNOWN),
        missing_count=0,
        reason="absence_not_verified",
    )
