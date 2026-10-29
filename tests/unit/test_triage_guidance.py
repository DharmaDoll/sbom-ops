from dataclasses import asdict, replace

import pytest

from sbom_ops.domain.triage_guidance import suggest_triage_actions
from sbom_ops.domain.triage_reference import ReferenceResult
from sbom_ops.services.reference_policy import load_reference_policy


@pytest.mark.parametrize(
    "status", ["missing", "unknown", "expired", "future", "conflict"]
)
@pytest.mark.parametrize(
    "factor", ["public_exposure", "kev", "automatable", "technical_impact"]
)
def test_missing_factor_routes_to_role_without_changing_reference(factor, status):
    reference = ReferenceResult(
        load_reference_policy(), None, None, "pending", (f"{factor}:{status}",)
    )
    before = asdict(reference)
    actions = suggest_triage_actions(reference, asset_owner="asset-team")
    assert len(actions) == 1
    action = actions[0]
    assert action.code == f"confirm_{factor}"
    assert action.reason == status
    assert action.role == ("asset" if factor == "public_exposure" else "security")
    assert action.assignee == ("asset-team" if factor == "public_exposure" else None)
    assert action.instruction
    assert asdict(reference) == before


def test_missing_owner_and_unresolved_cve_are_explicit():
    reference = ReferenceResult(
        load_reference_policy(), None, None, "pending", ("cve_unresolved",)
    )
    actions = suggest_triage_actions(reference, asset_owner=None)
    assert [a.code for a in actions] == [
        "identify_asset_owner",
        "confirm_cve_unresolved",
    ]
    assert all(a.assignee is None for a in actions)


def test_matched_reference_does_not_invent_forensic_requirement():
    reference = ReferenceResult(
        load_reference_policy(),
        "no/no/no/partial",
        None,
        "not_specified_by_reference",
        (),
    )
    actions = suggest_triage_actions(reference, asset_owner="team")
    assert [a.code for a in actions] == ["review_remediation"]
    required = suggest_triage_actions(
        replace(reference, forensic_triage="specified_by_reference"), asset_owner="team"
    )
    assert required[-1].code == "plan_forensic_triage"
    assert required[-1].assignee is None
