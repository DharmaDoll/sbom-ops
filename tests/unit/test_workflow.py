import pytest

from sbom_ops.domain.models import AnalysisState, FindingState, RemediationState
from sbom_ops.domain.workflow import (
    GitHubWriteAuthorizationError,
    MissingFindingAction,
    decide_missing_finding,
    observe_workflow_state,
    require_github_write_permission,
    transition_remediation_state,
)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("write_requested", [False, True])
def test_write_authorization_matrix(
    enabled: bool, dry_run: bool, write_requested: bool
) -> None:
    flags = dict(enabled=enabled, dry_run=dry_run, write_requested=write_requested)
    if enabled and not dry_run and not write_requested:
        with pytest.raises(GitHubWriteAuthorizationError, match="--github-write"):
            require_github_write_permission(**flags)
    else:
        require_github_write_permission(**flags)


@pytest.mark.parametrize("value", [1, "true", None])
def test_truthy_non_boolean_is_not_a_write_grant(value: object) -> None:
    with pytest.raises(GitHubWriteAuthorizationError, match="booleans"):
        require_github_write_permission(
            enabled=True, dry_run=False, write_requested=value
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
