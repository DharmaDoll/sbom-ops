"""Search the saved output of existing offline operator examples."""

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from sbom_ops.cli import main


@pytest.mark.parametrize(
    "stage", ["unapproved", "parallel", "stopped", "conflict", "expired"]
)
def test_lifecycle_cve_lookup_preserves_both_artifacts_and_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stage: str,
) -> None:
    script = Path(__file__).parents[2] / "examples/lifecycle_scenario.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--output", "sync", "--stage", stage],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    original = json.loads(completed.stdout)
    path = tmp_path / "sync.json"
    path.write_text(completed.stdout)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "lookup",
            "--findings",
            str(path),
            "--cve",
            "CVE-2026-1000",
            "--output",
            "json",
        ],
    )
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["matched_finding_count"] == 2
    assert [entry["finding"] for entry in result["results"]] == original["review_queue"]
    assert {entry["finding"]["project_uuid"] for entry in result["results"]} == {
        "fictional-build-a",
        "fictional-build-b",
    }
    for entry in result["results"]:
        assert entry["lifecycle_evidence_status"] == "loaded"
        view = entry["lifecycle_evidence"][0]
        assert view["project_uuid"] == entry["finding"]["project_uuid"]
        if stage == "unapproved":
            assert entry["finding"]["asset"] is None
            # No approved identity: never borrow another asset's evidence.
            assert view["records"] == []
        else:
            assert len(view["records"]) == 4
            assert entry["finding"]["asset"]["owner"] == "team-checkout"
            matched = [r for r in view["records"] if r["status"] == "matched"]
            assert len(matched) == 1
            artifact = entry["finding"]["asset"]["dt_version"]
            assert matched[0]["evidence"]["artifact_id"] == artifact
            if artifact == "build-a":
                assert (
                    matched[0]["evidence"]["sbom_ref"]
                    == "fictional/build-a-corrected.cdx.json"
                )
    assert path.read_text() == completed.stdout


def test_lookup_cli_reads_real_review_output_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    examples = Path(__file__).parents[2] / "examples"
    completed = subprocess.run(
        [sys.executable, str(examples / "review_scenario.py"), "--output", "json"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    payload = json.loads(completed.stdout)
    path = tmp_path / "sync.json"
    path.write_text(completed.stdout, encoding="utf-8")
    selected = payload["review_queue"][0]
    expected = [
        row
        for row in payload["review_queue"]
        if row["vulnerability_id"] == selected["vulnerability_id"]
        and row["vulnerability_source"] == selected["vulnerability_source"]
    ]

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("lookup attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    arguments = [
        "sbom-ops",
        "lookup",
        "--findings",
        str(path),
        "--vulnerability-id",
        selected["vulnerability_id"],
        "--source",
        selected["vulnerability_source"],
    ]
    monkeypatch.setattr(sys, "argv", [*arguments, "--output", "json"])
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "matched"
    assert result["source_run_id"] == payload["run_id"]
    assert [entry["finding"] for entry in result["results"]] == expected
    assert all(
        entry["lifecycle_evidence_status"] == "not_requested"
        for entry in result["results"]
    )
    monkeypatch.setattr(sys, "argv", arguments)
    assert main() == 0
    text = capsys.readouterr().out
    assert "保存済み結果の逆引き" in text and "資産・担当" in text
    assert "影響なし・修正済みの意味ではありません" in text
    assert path.read_text(encoding="utf-8") == completed.stdout
