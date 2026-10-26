"""Offline lookup CLI never runs sync or writes back into the saved result."""

import json
import socket
import sys
from pathlib import Path

import pytest

from sbom_ops.cli import main
from sbom_ops.services.orchestrator import RunResult


def test_empty_lookup_is_scoped_not_an_absence_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = RunResult(
        run_id="offline-run",
        duration_seconds=0,
        kev_used_stale_cache=False,
        projects_processed=0,
        findings_processed=0,
        issues_created=0,
        issues_updated=0,
        issues_closed=0,
        dry_run=True,
    ).as_dict()
    path = tmp_path / "sync.json"
    raw = json.dumps(payload)
    path.write_text(raw)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("lookup tried network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "lookup",
            "--findings",
            str(path),
            "--cve",
            "CVE-2026-1234",
            "--output",
            "json",
        ],
    )
    assert main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "no_match_in_input"
    assert output["source_run_id"] == "offline-run"
    assert output["scope"] == "saved_sync_only"
    assert output["results"] == [] and output["warnings"]
    assert path.read_text() == raw


def test_invalid_lookup_file_is_error_not_empty_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "sync.json"
    path.write_text('{"status":"failed"}')
    monkeypatch.setattr(
        sys,
        "argv",
        ["sbom-ops", "lookup", "--findings", str(path), "--purl", "pkg:pypi/example@1"],
    )
    assert main() == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "入力" in output.err
