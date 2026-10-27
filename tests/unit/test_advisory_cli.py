import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from test_advisory_feed_parser import RDF
from test_lookup_input import context_run

from sbom_ops.cli import main


@pytest.mark.parametrize("output", ["json", "review"])
def test_offline_review_cli_preserves_inputs(tmp_path, monkeypatch, capsys, output):
    feed = tmp_path / "feed.rdf"
    raw = RDF.replace(b"CVE-2026-1000", b"CVE-2026-1234")
    feed.write_bytes(raw)
    findings = tmp_path / "sync.json"
    payload = json.dumps(context_run())
    findings.write_text(payload)

    def forbidden(*args, **kwargs):
        raise AssertionError("network forbidden")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "advisories",
            "review-file",
            "--feed",
            str(feed),
            "--source",
            "jpcert",
            "--findings",
            str(findings),
            "--output",
            output,
        ],
    )
    assert main() == 0
    text = capsys.readouterr().out
    assert "team-shop" in text
    assert "example-run" in text
    assert "https://example.test/wr#1" in text
    if output == "json":
        result = json.loads(text)
        assert result["articles"][1]["status"] == "cve_not_observed"
    assert feed.read_bytes() == raw
    assert findings.read_text() == payload


def test_invalid_feed_is_sanitized_error(tmp_path, monkeypatch, capsys):
    feed = tmp_path / "bad.rdf"
    feed.write_text("private-input")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "advisories",
            "review-file",
            "--feed",
            str(feed),
            "--source",
            "jpcert",
            "--findings",
            "missing.json",
        ],
    )
    assert main() == 2
    output = capsys.readouterr()
    assert not output.out
    assert "private-input" not in output.err


def test_shipped_sample_with_lifecycle_exercise(tmp_path, monkeypatch, capsys):
    root = Path(__file__).parents[2]
    run = subprocess.run(
        [
            sys.executable,
            str(root / "examples/lifecycle_scenario.py"),
            "--output",
            "sync",
            "--stage",
            "stopped",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    findings = tmp_path / "sync.json"
    findings.write_text(run.stdout)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "advisories",
            "review-file",
            "--feed",
            str(root / "examples/advisory-feed.example.rdf"),
            "--source",
            "jpcert",
            "--findings",
            str(findings),
            "--output",
            "json",
        ],
    )
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert len(result["articles"]) == 3
    assert result["articles"][1]["status"] == "cve_not_observed"
    assert result["lookups"]["CVE-2026-1000"]["status"] == "matched"
    assert result["lookups"]["CVE-2099-999999"]["status"] == "no_match_in_input"
