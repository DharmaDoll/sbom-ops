from __future__ import annotations

import json
from types import SimpleNamespace

from sbom_ops import cli
from sbom_ops.domain.models import (
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
    assert json.loads(captured.out)["run_id"] == "run-1"
    assert captured.err == (
        "warning: sync log could not be written; " "primary sync result is unchanged\n"
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
    assert (
        "source=GITHUB severity=HIGH cvss=unavailable epss=unavailable "
        "analysis=NOT_SET suppressed=false rationale=Default monitoring priority"
        in captured.out
    )
