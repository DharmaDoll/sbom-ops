from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from sbom_ops.domain.asset_registry import (
    RegistryProjectObservation,
    RegistryProjectStatus,
    RegistrySnapshotStatus,
)
from sbom_ops.domain.models import AnalysisState, FindingAssessment, Priority, Severity
from sbom_ops.domain.slack import Notification, SlackPolicy
from sbom_ops.services.orchestrator import RunResult
from sbom_ops.services.slack_input import notifications

NOW = datetime(2026, 10, 29, tzinfo=UTC)


def document() -> dict[str, object]:
    item = FindingAssessment(
        "build-a",
        "finding-a",
        "CVE-2026-1000",
        "NVD",
        Severity.CRITICAL,
        9.5,
        None,
        Priority.P1,
        AnalysisState.NOT_SET,
        False,
        ("Critical severity",),
        component_purl="pkg:npm/example@1",
        component_name="example",
    )
    asset = RegistryProjectObservation(
        "build-a",
        "example/web",
        "v1",
        RegistryProjectStatus.MATCHED,
        service_id="example",
        deployable_id="web",
        owner="team-example",
    )
    return RunResult(
        run_id="example",
        duration_seconds=0,
        kev_used_stale_cache=False,
        projects_processed=2,
        findings_processed=2,
        issues_created=0,
        issues_updated=0,
        issues_closed=0,
        dry_run=True,
        assessments=(
            item,
            replace(item, project_uuid="build-b", finding_key="finding-b"),
        ),
        registry_snapshot_status=RegistrySnapshotStatus.LOADED,
        registry_projects=(
            asset,
            replace(asset, project_uuid="build-b", dt_version="v2"),
        ),
    ).as_dict()


def build(
    doc: dict[str, object], policy: SlackPolicy | None = None
) -> tuple[Notification, ...]:
    return notifications(
        doc, policy or SlackPolicy(), observed_at=NOW.isoformat(), now=NOW
    )


def test_reuses_verified_grouping_and_preserves_input() -> None:
    doc = document()
    original = deepcopy(doc)
    output = build(doc)
    assert len(output) == 1
    assert "2 Finding" in output[0].text and "team-example" in output[0].text
    assert output[0].key == doc["remediation_groups"][0]["group_key"]
    assert "EPSS未取得" in output[0].text
    assert doc == original
    assert len(build(doc, SlackPolicy(grouping="finding"))) == 2
    doc["registry_projects"] = []
    for row in doc["review_queue"]:
        row.update(asset=None, asset_status="unlinked")
    output = build(doc)
    assert len(output) == 2 and all("未割当" in n.text for n in output)


@pytest.mark.parametrize("state", ["NOT_AFFECTED", "FALSE_POSITIVE"])
def test_analysis_exclusions_and_suppression(state: str) -> None:
    doc = document()
    for rows in (doc["assessments"], doc["review_queue"]):
        rows[0]["analysis_state"] = state
        rows[1]["is_suppressed"] = True
    assert build(doc) == ()


def test_stable_fingerprint_and_configured_changes() -> None:
    doc = document()
    first = build(doc)[0]
    doc["run_id"] = "next-run"
    assert build(doc)[0].fingerprint == first.fingerprint
    for row in doc["review_queue"]:
        row["asset"]["owner"] = "new-owner"
    for asset in doc["registry_projects"]:
        asset["owner"] = "new-owner"
    assert build(doc)[0].fingerprint != first.fingerprint
    assert (
        build(doc, SlackPolicy(change_fields=("priority",)))[0].fingerprint
        == build(document(), SlackPolicy(change_fields=("priority",)))[0].fingerprint
    )


def test_failed_incomplete_future_stale_inputs_rejected() -> None:
    for change in ({"status": "failed"}, {"findings_processed": 99}):
        with pytest.raises(ValueError):
            build({**document(), **change})
    for observed in ("2026-10-30T00:00:00Z", "2020-01-01T00:00:00Z"):
        with pytest.raises(ValueError):
            notifications(document(), SlackPolicy(), observed_at=observed, now=NOW)


def test_duplicate_identity_and_untrusted_rendering() -> None:
    doc = document()
    for rows in (doc["assessments"], doc["review_queue"]):
        rows[1]["finding_key"] = rows[0]["finding_key"]
    with pytest.raises(ValueError, match="duplicate"):
        build(doc)
    doc = document()
    malicious = "<!channel> <@U123> @here https://hooks.slack.com/services/synthetic"
    for rows in (doc["assessments"], doc["review_queue"]):
        for row in rows:
            row["component_name"] = malicious
            row["rationale"] = [malicious]
            row["analysis_detail"] = "PRIVATE-ANALYSIS"
            row["description"] = "PRIVATE-DESCRIPTION"
    output = build(doc)[0].text
    assert "<!" not in output and "<@" not in output and "@here" not in output
    assert "hooks.slack.com" not in output
    assert "PRIVATE-" not in output


def test_known_asset_is_displayed_even_when_package_cannot_be_grouped() -> None:
    doc = document()
    for rows in (doc["assessments"], doc["review_queue"]):
        for row in rows:
            row["component_purl"] = None
    output = build(doc)
    assert len(output) == 2
    assert all("サービス/配布単位: example / web" in item.text for item in output)
