from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from sbom_ops.domain.issue_intent import IssueIntentError, IssueJournalBusy
from sbom_ops.storage.issue_journal import IssueJournal


@pytest.fixture
def journal_path(tmp_path: Path) -> Path:
    path = tmp_path / "workflow.sqlite3"
    IssueJournal.initialize(path)
    return path


def test_reservation_is_durable_and_confirmation_preserves_original_run(
    journal_path: Path,
) -> None:
    assert journal_path.stat().st_mode & 0o777 == 0o600
    with IssueJournal(journal_path) as journal:
        intent = journal.reserve("ACME/App", "v2:project:key", "original-run")
    with IssueJournal(journal_path) as journal:
        assert journal.records() == (intent,)
        journal.confirm(intent, 12, "recovery-run")
    with IssueJournal(journal_path, read_only=True) as journal:
        saved = journal.records()[0]
        assert saved.repository == "acme/app"
        assert saved.run_id == "original-run"
        assert saved.state == "confirmed"
        assert saved.issue_number == 12
        assert saved.confirmed_run_id == "recovery-run"
        assert set(asdict(saved)) == {
            "intent_id",
            "repository",
            "finding_key",
            "run_id",
            "state",
            "created_at",
            "issue_number",
            "confirmed_at",
            "confirmed_run_id",
        }


def test_init_never_replaces_existing_file_and_missing_file_is_not_created(
    journal_path: Path,
) -> None:
    before = journal_path.read_bytes()
    with pytest.raises(FileExistsError):
        IssueJournal.initialize(journal_path)
    missing = journal_path.with_name("missing.sqlite3")
    with pytest.raises(FileNotFoundError):
        IssueJournal(missing)
    assert not missing.exists()
    assert journal_path.read_bytes() == before


def test_read_only_never_records_or_confirms(journal_path: Path) -> None:
    with IssueJournal(journal_path) as journal:
        intent = journal.reserve("acme/app", "key", "run")
    before = journal_path.read_bytes()
    with IssueJournal(journal_path, read_only=True) as journal:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            journal.reserve("acme/app", "another-key", "run")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            journal.confirm(intent, 1, "run")
    assert journal_path.read_bytes() == before


def test_identity_is_repository_scoped_and_case_insensitive(journal_path: Path) -> None:
    with IssueJournal(journal_path) as journal:
        first = journal.reserve("Acme/App", "key", "run")
        with pytest.raises(IssueIntentError, match="already exists"):
            journal.reserve("acme/app", "key", "next-run")
        journal.confirm(first, 1, "run")
        with pytest.raises(IssueIntentError, match="already exists"):
            journal.reserve("ACME/APP", "key", "next-run")
        journal.reserve("acme/other", "key", "run")
        assert len(journal.records()) == 2


def test_confirmation_failure_rolls_back_and_does_not_overwrite(
    journal_path: Path,
) -> None:
    with IssueJournal(journal_path) as journal:
        intent = journal.reserve("acme/app", "key", "run")
        for value in (0, -1, True, "12"):
            with pytest.raises(IssueIntentError):
                journal.confirm(intent, value, "run")
        with pytest.raises(IssueIntentError):
            journal.confirm(intent, 12, "")
        assert journal.records() == (intent,)
        journal.confirm(intent, 12, "run")
        with pytest.raises(IssueIntentError, match="not pending"):
            journal.confirm(intent, 99, "next-run")
        assert journal.records()[0].issue_number == 12


@pytest.mark.parametrize("read_only", [False, True])
def test_writer_lock_is_exclusive_even_through_hard_link(
    journal_path: Path,
    read_only: bool,
) -> None:
    alias = journal_path.with_name("alias.sqlite3")
    os.link(journal_path, alias)
    with IssueJournal(journal_path):
        with pytest.raises(IssueJournalBusy):
            IssueJournal(alias, read_only=read_only)
    with IssueJournal(journal_path, read_only=True):
        with pytest.raises(IssueJournalBusy):
            IssueJournal(journal_path)
    with IssueJournal(journal_path) as journal:
        assert journal.records() == ()


def test_process_crash_keeps_intent_but_releases_lock(journal_path: Path) -> None:
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sys
from sbom_ops.storage.issue_journal import IssueJournal
journal = IssueJournal(sys.argv[1])
journal.reserve('acme/app', 'key', 'crashed-run')
os._exit(17)
""",
            str(journal_path),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert child.returncode == 17, child.stderr
    with IssueJournal(journal_path) as journal:
        assert journal.records()[0].state == "pending"
        assert journal.records()[0].run_id == "crashed-run"
        with pytest.raises(IssueIntentError):
            journal.reserve("acme/app", "key", "next-run")


def test_other_process_cannot_take_writer_lock(journal_path: Path) -> None:
    with IssueJournal(journal_path):
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import sys
from sbom_ops.domain.issue_intent import IssueJournalBusy
from sbom_ops.storage.issue_journal import IssueJournal
try:
    IssueJournal(sys.argv[1])
except IssueJournalBusy:
    sys.exit(3)
sys.exit(1)
""",
                str(journal_path),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    assert child.returncode == 3, child.stderr


def test_rejects_unrelated_db_public_file_and_symlink(journal_path: Path) -> None:
    alias = journal_path.with_name("link.sqlite3")
    alias.symlink_to(journal_path)
    with pytest.raises(OSError):
        IssueJournal(alias)
    journal_path.chmod(0o644)
    with pytest.raises(IssueIntentError, match="private"):
        IssueJournal(journal_path)
    journal_path.chmod(0o600)
    with sqlite3.connect(journal_path) as db:
        db.execute("PRAGMA application_id = 0")
    with pytest.raises(IssueIntentError, match="invalid workflow"):
        IssueJournal(journal_path)


@pytest.mark.parametrize(
    "changes",
    [
        {"created_at": "bad"},
        {"created_at": None},
        {"created_at": "2026-10-21"},
        {"repository": "/app"},
        {"repository": "Acme/app"},
        {"state": "failed"},
        {"issue_number": 1},
        {"run_id": " "},
    ],
)
def test_persisted_intent_validation(journal_path: Path, changes: dict) -> None:
    with IssueJournal(journal_path) as journal:
        intent = journal.reserve("acme/app", "key", "run")
    with pytest.raises(IssueIntentError):
        replace(intent, **changes)


def test_rejects_corrupt_persisted_record_and_releases_lock(journal_path: Path) -> None:
    with IssueJournal(journal_path) as journal:
        journal.reserve("acme/app", "key", "run")
    with sqlite3.connect(journal_path) as db:
        db.execute("UPDATE issue_create_intents SET created_at = 'invalid'")
    for _ in range(2):
        with pytest.raises(IssueIntentError, match="timestamp"):
            IssueJournal(journal_path)


@pytest.mark.parametrize("read_only", [False, True])
def test_fifo_is_rejected_without_waiting_for_another_process(
    tmp_path: Path,
    read_only: bool,
) -> None:
    path = tmp_path / "fifo"
    os.mkfifo(path, 0o600)
    with pytest.raises(IssueIntentError, match="regular file"):
        IssueJournal(path, read_only=read_only)
