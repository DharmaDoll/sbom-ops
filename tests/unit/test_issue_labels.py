from __future__ import annotations

import pytest

from sbom_ops.domain.issue_labels import IssueLabelError, label_names, plan_issue_labels
from sbom_ops.domain.models import Priority


@pytest.mark.parametrize("priority", list(Priority))
def test_only_reserved_priority_labels_are_replaced(priority: Priority) -> None:
    current = (
        "sbom",
        "sbom-P0",
        "sbom-P1",
        "sbom-P2",
        "sbom-P3",
        "bug",
        "sbom-P0-note",
        "other-P1",
    )
    plan = plan_issue_labels(current, "sbom", priority)
    assert plan.add == ()
    assert set(plan.remove) == {
        f"sbom-{item.value}" for item in Priority if item != priority
    }
    assert plan.desired == ("sbom", f"sbom-{priority.value}")


def test_custom_namespace_and_case_variants() -> None:
    plan = plan_issue_labels(("OPS", "Ops-p1", "sbom-P0", "human"), "ops", Priority.P2)
    assert plan.add == ("ops-P2",)
    assert plan.remove == ("Ops-p1",)
    assert plan_issue_labels(("OPS", "OPS-p2"), "ops", Priority.P2).add == ()


def test_missing_base_label_is_restored_without_deleting_other_labels() -> None:
    plan = plan_issue_labels(("human", "sbom-P1"), "sbom", Priority.P1)
    assert plan.add == ("sbom",)
    assert plan.remove == ()
    assert label_names([{"name": "human", "id": 1}, "sbom"]) == ("human", "sbom")


@pytest.mark.parametrize(
    "payload",
    [None, {}, "bug", [None], [{}], [True], [""], ["\n"], ["a\x00b"], ["bug", "BUG"]],
)
def test_invalid_labels_are_not_an_empty_set(payload: object) -> None:
    with pytest.raises(IssueLabelError):
        label_names(payload)
