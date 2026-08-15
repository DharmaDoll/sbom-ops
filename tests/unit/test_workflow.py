import pytest

from sbom_ops.domain.models import FindingState, RemediationState
from sbom_ops.domain.workflow import MissingFindingAction, decide_missing_finding


def test_missing_finding_stays_open_when_automatic_closure_is_disabled() -> None:
    decision = decide_missing_finding(
        0,
        automatic_closure_enabled=False,
        scan_verified=True,
        confirmations_required=2,
    )

    assert decision.action == MissingFindingAction.NOOP
    assert decision.finding_state == FindingState.UNKNOWN
    assert decision.remediation_state == RemediationState.OPEN


def test_missing_finding_stays_open_when_scan_is_not_verified() -> None:
    decision = decide_missing_finding(
        0,
        automatic_closure_enabled=True,
        scan_verified=False,
        confirmations_required=2,
    )

    assert decision.action == MissingFindingAction.NOOP
    assert decision.reason == "analysis_completion_not_verified"


def test_missing_finding_requires_consecutive_confirmations() -> None:
    first = decide_missing_finding(
        0,
        automatic_closure_enabled=True,
        scan_verified=True,
        confirmations_required=2,
    )
    second = decide_missing_finding(
        first.missing_count,
        automatic_closure_enabled=True,
        scan_verified=True,
        confirmations_required=2,
    )

    assert first.action == MissingFindingAction.MARK_MISSING
    assert first.finding_state == FindingState.MISSING
    assert second.action == MissingFindingAction.CLOSE
    assert second.finding_state == FindingState.RESOLVED
    assert second.remediation_state == RemediationState.CLOSED


def test_missing_finding_never_allows_one_run_closure() -> None:
    with pytest.raises(ValueError, match="at least 2"):
        decide_missing_finding(
            0,
            automatic_closure_enabled=True,
            scan_verified=True,
            confirmations_required=1,
        )
