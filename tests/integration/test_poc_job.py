from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from sbom_ops.domain.poc import PocRunBusy
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.run_lock import exclusive_run, poc_lock_path


@pytest.fixture
def job():
    path = Path(__file__).parents[2] / "scripts" / "refresh_poc.py"
    spec = importlib.util.spec_from_file_location("refresh_poc_script", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def args(tmp_path, job):
    db = tmp_path / "assets.sqlite3"
    with AssetRegistry(db, create_if_missing=True):
        pass
    config = tmp_path / "config.yaml"
    config.write_text("# synthetic test config\n")
    return job.build_parser().parse_args(
        [
            "--config",
            str(config),
            "--project",
            "fictional-project",
            "--db",
            str(db),
            "--execute",
        ]
    )


@pytest.mark.parametrize(
    "poc_code,review_code,expected",
    [(0, 0, 0), (1, 0, 1), (0, 2, 2), (3, 0, 3), (2, 0, 2)],
)
def test_job_stages_and_failure_codes(
    job, args, monkeypatch, poc_code, review_code, expected
):
    calls = []

    def execute(command, *, stdout, timeout, check):
        calls.append(command)
        assert timeout == 900 and check is False
        if stdout is not None:
            stdout.write(
                json.dumps({"status": "succeeded", "assessments": []}).encode()
            )
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(
            returncode=poc_code if "poc-fetch" in command else review_code
        )

    monkeypatch.setattr(job.subprocess, "run", execute)
    assert job.run(args) == expected
    assert len(calls) == (3 if poc_code in (0, 1) else 2)
    for command in (calls[0], *calls[2:]):
        assert "--no-github" in command and "--dry-run" in command
        assert command[command.index("--project") + 1] == "fictional-project"
    fetch = calls[1]
    assert "--execute" in fetch
    assert fetch[fetch.index("--db") + 1] == args.db
    assert not Path(fetch[fetch.index("--findings") + 1]).exists()  # temp input cleaned


@pytest.mark.parametrize("failure", ["exit", "timeout", "bad_json", "failed_json"])
def test_bad_sync_never_fetches_or_reuses_old_file(job, args, monkeypatch, failure):
    calls = []
    old = Path(args.db).parent / "findings.json"
    old.write_text('{"status":"succeeded","assessments":[]}')

    def execute(command, *, stdout, timeout, check):
        calls.append(command)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, timeout)
        stdout.write(
            b"{}" if failure == "bad_json" else b'{"status":"failed","assessments":[]}'
        )
        return SimpleNamespace(returncode=2 if failure == "exit" else 0)

    monkeypatch.setattr(job.subprocess, "run", execute)
    if failure in ("bad_json", "failed_json"):
        with pytest.raises(ValueError):
            job.run(args)
    else:
        assert job.run(args) == 2
    assert len(calls) == 1
    assert old.read_text() == '{"status":"succeeded","assessments":[]}'
    assert not list(Path(args.db).parent.glob("poc-job-*"))
    with exclusive_run(poc_lock_path(args.db, job=True)):
        pass


def test_job_lock_stops_duplicate_before_sync(job, args, monkeypatch):
    monkeypatch.setattr(
        job.subprocess, "run", lambda *a, **k: pytest.fail("unexpected process")
    )
    with exclusive_run(poc_lock_path(args.db, job=True)):
        with pytest.raises(PocRunBusy):
            job.run(args)


def test_preview_without_files_or_credentials(job, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        job.subprocess, "run", lambda *a, **k: pytest.fail("unexpected process")
    )
    args = job.build_parser().parse_args(
        [
            "--config",
            str(tmp_path / "missing.yaml"),
            "--project",
            "fictional",
            "--db",
            str(tmp_path / "missing.sqlite3"),
        ]
    )
    assert job.run(args) == 0
    assert json.loads(capsys.readouterr().out)["github"] is False
    assert list(tmp_path.iterdir()) == []
