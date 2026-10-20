from sbom_ops.domain.models import AnalysisState, FindingState, RemediationState
from sbom_ops.domain.workflow import (
    MissingFindingAction,
    decide_missing_finding,
    observe_workflow_state,
    transition_remediation_state,
)


def test_missing_finding_stays_unknown_and_open() -> None:
    decision = decide_missing_finding()

    assert decision.action == MissingFindingAction.NOOP
    assert decision.finding_state == FindingState.UNKNOWN
    assert decision.remediation_state == RemediationState.OPEN
    assert decision.missing_count == 0
    assert decision.reason == "absence_not_verified"


def test_repeated_absence_never_accumulates_resolution_evidence() -> None:
    for _ in range(10):
        assert decide_missing_finding().as_dict() == {
            "action": "NOOP",
            "finding_state": "UNKNOWN",
            "remediation_state": "OPEN",
            "missing_count": 0,
            "reason": "absence_not_verified",
        }


def test_analysis_observation_does_not_close_remediation() -> None:
    state = observe_workflow_state(
        finding_state=FindingState.ACTIVE,
        analysis_state=AnalysisState.NOT_AFFECTED,
    )

    assert state.analysis_state == AnalysisState.NOT_AFFECTED
    assert state.finding_state == FindingState.ACTIVE
    assert state.remediation_state == RemediationState.OPEN


def test_remediation_closes_only_after_verified_finding_resolution() -> None:
    assert transition_remediation_state(FindingState.RESOLVED) == RemediationState.OPEN
    assert (
        transition_remediation_state(
            FindingState.RESOLVED,
            resolution_confirmed=True,
        )
        == RemediationState.CLOSED
    )


def test_reappeared_finding_reopens_remediation() -> None:
    state = observe_workflow_state(
        finding_state=FindingState.ACTIVE,
        analysis_state=AnalysisState.IN_TRIAGE,
    )

    assert state.remediation_state == RemediationState.OPEN
