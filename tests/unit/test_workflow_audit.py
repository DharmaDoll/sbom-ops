from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from sbom_ops.domain.issue_intent import IssueIntentError
from sbom_ops.domain.workflow_audit import WorkflowAudit
from sbom_ops.storage.issue_journal import IssueJournal


def test_audit_has_stable_id_and_excludes_exception_text() -> None:
    audit = WorkflowAudit()
    audit.start()
    operation = audit.begin("update_body", "acme/app", "finding", 12)
    audit.outcome(operation, "operation_unknown", error_type="OSError")
    audit.fail(OSError("SECRET_RESPONSE_SENTINEL"))
    payload = audit.as_dict()
    assert "SECRET_RESPONSE_SENTINEL" not in json.dumps(payload)
    assert {event.run_id for event in audit.events} == {audit.run_id}
    assert audit.events[1].operation_id == audit.events[2].operation_id
    assert [event.event for event in audit.events] == [
        "run_started",
        "operation_started",
        "operation_unknown",
        "run_failed",
    ]


def test_failed_audit_sink_keeps_memory_evidence_and_marks_gap() -> None:
    audit = WorkflowAudit()
    audit.start()

    def failed(event: object) -> None:
        raise OSError("disk full")

    with pytest.raises(OSError):
        audit.attach(failed)
    assert audit.persistence_failed
    assert audit.events[0].event == "run_started"
    audit.detach()
    audit.fail(OSError("disk full"))
    assert audit.events[-1].event == "run_failed"


def legacy_journal(path: Path) -> None:
    IssueJournal.initialize(path)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE workflow_events")
        db.execute("PRAGMA user_version = 1")


def test_legacy_migration_preserves_intents_and_requires_new_backup(
    tmp_path: Path,
) -> None:
    path, backup = tmp_path / "workflow.db", tmp_path / "before.db"
    legacy_journal(path)
    with IssueJournal(path, _allow_legacy=True) as journal:
        intent = journal.reserve("acme/app", "key", "old-run")
    with pytest.raises(IssueIntentError, match="migrate"):
        IssueJournal(path)
    with IssueJournal(path, read_only=True) as journal:
        assert journal.records() == (intent,)
        assert journal.events() == ()
    IssueJournal.migrate(path, backup)
    assert backup.stat().st_mode & 0o777 == 0o600
    with IssueJournal(backup, read_only=True) as old:
        assert old.schema_version == 1
        assert old.records() == (intent,)
    with IssueJournal(path) as upgraded:
        assert upgraded.schema_version == 2
        assert upgraded.records() == (intent,)
        audit = WorkflowAudit()
        audit.start()
        audit.attach(upgraded.append_event)
        audit.emit("run_succeeded")
        assert upgraded.events(audit.run_id) == tuple(audit.events)
        assert upgraded.events("unrelated-run") == ()


def test_migration_never_overwrites_backup_or_partially_upgrades(
    tmp_path: Path,
) -> None:
    path, backup = tmp_path / "workflow.db", tmp_path / "before.db"
    legacy_journal(path)
    backup.write_text("keep this")
    with pytest.raises(FileExistsError):
        IssueJournal.migrate(path, backup)
    assert backup.read_text() == "keep this"
    with IssueJournal(path, read_only=True) as journal:
        assert journal.schema_version == 1
    # A broken legacy schema fails transactionally after producing its backup.
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE workflow_events (invalid TEXT)")
    with pytest.raises(sqlite3.OperationalError):
        IssueJournal.migrate(path, tmp_path / "broken-backup.db")
    with IssueJournal(path, read_only=True) as journal:
        assert journal.schema_version == 1


def test_audit_events_are_append_only_and_read_only_access_cannot_write(
    tmp_path: Path,
) -> None:
    path = tmp_path / "workflow.db"
    IssueJournal.initialize(path)
    audit = WorkflowAudit()
    audit.start()
    with IssueJournal(path) as journal:
        journal.append_event(audit.events[0])
        with pytest.raises(sqlite3.IntegrityError):
            journal.append_event(audit.events[0])
        assert journal.events() == tuple(audit.events)
    with IssueJournal(path, read_only=True) as journal:
        with pytest.raises(sqlite3.OperationalError):
            journal.append_event(audit.events[0])


def test_corrupt_audit_record_fails_without_exposing_raw_payload(
    tmp_path: Path,
) -> None:
    path = tmp_path / "workflow.db"
    IssueJournal.initialize(path)
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO workflow_events(event_id,run_id,event_json) "
            "VALUES ('a','b','SECRET')"
        )
    with IssueJournal(path, read_only=True) as journal:
        with pytest.raises(IssueIntentError, match="invalid workflow audit"):
            journal.events()


def test_process_crash_leaves_unfinished_operation_evidence(tmp_path: Path) -> None:
    path = tmp_path / "workflow.db"
    IssueJournal.initialize(path)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sys
from sbom_ops.storage.issue_journal import IssueJournal
from sbom_ops.domain.workflow_audit import WorkflowAudit
journal = IssueJournal(sys.argv[1])
audit = WorkflowAudit(run_id='crashed-run')
audit.start()
audit.attach(journal.append_event)
audit.begin('update_body', 'acme/app', 'key', 12)
os._exit(19)
""",
            str(path),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert child.returncode == 19, child.stderr
    with IssueJournal(path, read_only=True) as journal:
        events = journal.events("crashed-run")
    assert [event.event for event in events] == ["run_started", "operation_started"]
    assert events[1].issue_number == 12
