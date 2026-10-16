from __future__ import annotations

import json
import subprocess
import sys

import pytest

from sbom_ops import cli
from sbom_ops.domain.poc import PocRunBusy
from sbom_ops.storage.run_lock import exclusive_run, poc_lock_path


def test_busy_cli_process_exits_before_read_or_network(tmp_path):
    db = tmp_path / "assets.sqlite3"
    command = [
        sys.executable,
        "-m",
        "sbom_ops.cli",
        "poc-fetch",
        "--execute",
        "--db",
        str(db),
        "--findings",
        str(tmp_path / "missing.json"),
    ]
    with exclusive_run(poc_lock_path(db)):
        completed = subprocess.run(command, capture_output=True, text=True, timeout=5)
    assert completed.returncode == 3
    assert json.loads(completed.stdout)["status"] == "busy"
    assert not db.exists()
    assert completed.stderr == ""


def test_exception_releases_lock_and_keeps_inode(tmp_path):
    path = poc_lock_path(tmp_path / "assets.sqlite3")
    with pytest.raises(ValueError):
        with exclusive_run(path):
            inode = path.stat().st_ino
            with pytest.raises(PocRunBusy):
                with exclusive_run(path):
                    pytest.fail("overlapping lock acquired")
            raise ValueError("example failure")
    with exclusive_run(path):
        assert path.stat().st_ino == inode
    assert path.stat().st_mode & 0o777 == 0o600


def test_killed_process_does_not_leave_stale_lock(tmp_path):
    path = poc_lock_path(tmp_path / "assets.sqlite3")
    program = (
        "import sys; from pathlib import Path; "
        "from sbom_ops.storage.run_lock import exclusive_run; "
        "lock=exclusive_run(Path(sys.argv[1])); lock.__enter__(); "
        "print('locked', flush=True); sys.stdin.read(1)"
    )
    with subprocess.Popen(
        [sys.executable, "-c", program, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    ) as process:
        try:
            assert process.stdout.readline().strip() == "locked"
            with pytest.raises(PocRunBusy):
                with exclusive_run(path):
                    pytest.fail("child lock bypassed")
        finally:
            process.kill()
            process.communicate(timeout=5)
    with exclusive_run(path):
        pass


def test_db_symlink_uses_same_lock_and_lock_symlink_is_rejected(tmp_path):
    db = tmp_path / "assets.sqlite3"
    db.touch()
    alias = tmp_path / "alias.sqlite3"
    alias.symlink_to(db)
    assert poc_lock_path(alias) == poc_lock_path(db)
    target = tmp_path / "other.txt"
    target.write_text("untouched")
    poc_lock_path(db).symlink_to(target)
    with pytest.raises(OSError):
        with exclusive_run(poc_lock_path(db)):
            pytest.fail("lock symlink accepted")
    assert target.read_text() == "untouched"


def test_preview_does_not_create_lock_and_cli_failure_releases_it(
    tmp_path, monkeypatch
):
    db = tmp_path / "assets.sqlite3"
    args = cli.build_parser().parse_args(
        ["poc-fetch", "--db", str(db), "--findings", str(tmp_path / "missing.json")]
    )
    with pytest.raises(FileNotFoundError):
        cli.run_poc_fetch(args)
    assert not poc_lock_path(db).exists()
    args.execute = True
    with pytest.raises(FileNotFoundError):
        cli.run_poc_fetch(args)
    with exclusive_run(poc_lock_path(db)):
        pass
