from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

from sbom_ops import cli
from sbom_ops.domain.models import (
    AnalysisSnapshotStatus,
    AnalysisState,
    FindingAssessment,
    Priority,
    Severity,
)
from sbom_ops.services.orchestrator import RunResult


class FakeOrchestrator:
    def __init__(self, config):
        self.config = config

    def run(self) -> RunResult:
        return RunResult(
            run_id="run-1",
            duration_seconds=0.1,
            kev_used_stale_cache=False,
            projects_processed=1,
            findings_processed=2,
            issues_created=0,
            issues_updated=0,
            issues_closed=0,
            dry_run=True,
            analysis_snapshot_status=AnalysisSnapshotStatus.NOT_REQUESTED,
            assessments=(
                FindingAssessment(
                    project_uuid="project-1",
                    finding_key="v2:project-1:digest",
                    vulnerability_id="GHSA-ABCD-1234-5678",
                    vulnerability_source="GITHUB",
                    severity=Severity.HIGH,
                    cvss_score=None,
                    epss_score=None,
                    priority=Priority.P3,
                    analysis_state=AnalysisState.NOT_SET,
                    is_suppressed=False,
                    rationale=("Default monitoring priority",),
                    analysis_detail="analyst note",
                    in_kev=False,
                    component_uuid="component-1",
                    component_purl="pkg:pypi/example@1.2.3",
                    component_name="example",
                    component_version="1.2.3",
                    vulnerability_aliases=("CVE-2026-1001",),
                ),
            ),
        )


def test_sync_log_failure_is_visible_without_breaking_json_result(
    monkeypatch, capsys
) -> None:
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file="missing/log.jsonl"))
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(cli, "append_sync_event", lambda path, payload: False)

    assert cli.run_sync(config, "json") == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["run_id"] == "run-1"
    assert payload["assessments"][0]["component_purl"] == ("pkg:pypi/example@1.2.3")
    assert payload["assessments"][0]["in_kev"] is False
    assert payload["assessments"][0]["analysis_detail"] == "analyst note"
    assert payload["assessments"][0]["vulnerability_aliases"] == ["CVE-2026-1001"]
    assert payload["analysis_snapshot_status"] == "not_requested"
    assert captured.err == (
        "warning: sync log could not be written; primary sync result is unchanged\n"
    )


def test_sync_log_success_does_not_emit_warning(monkeypatch, capsys) -> None:
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file="sync.jsonl"))
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(cli, "append_sync_event", lambda path, payload: True)

    assert cli.run_sync(config, "json") == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "succeeded"
    assert captured.err == ""


def test_text_result_makes_missing_scores_explicit(monkeypatch, capsys) -> None:
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)

    assert cli.run_sync(config, "text") == 0

    captured = capsys.readouterr()
    assert "analysis_snapshot_status=not_requested" in captured.out.splitlines()[0]
    assert (
        "component=example@1.2.3 purl=pkg:pypi/example@1.2.3 "
        "source=GITHUB dt_aliases=CVE-2026-1001 severity=HIGH "
        "cvss=unavailable cvss_version=unavailable epss=unavailable "
        "in_kev=false analysis=NOT_SET suppressed=false "
        "rationale=Default monitoring priority" in captured.out
    )


def test_text_result_discloses_stale_kev_cache(monkeypatch, capsys) -> None:
    class StaleKevOrchestrator(FakeOrchestrator):
        def run(self) -> RunResult:
            return replace(super().run(), kev_used_stale_cache=True)

    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    monkeypatch.setattr(cli, "Orchestrator", StaleKevOrchestrator)

    assert cli.run_sync(config, "text") == 0

    captured = capsys.readouterr()
    assert "kev_used_stale_cache=true" in captured.out.splitlines()[0]
