from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sbom_ops.clients.slack import SlackOutcome
from sbom_ops.domain.slack import Notification, SlackPolicy
from sbom_ops.services.slack import deliver
from sbom_ops.storage.slack import SlackJournal


class Sender:
    def __init__(self, outcomes: tuple[SlackOutcome, ...] = ()) -> None:
        self.calls = []
        self.outcomes = list(outcomes)

    def post(
        self, channel: str, text: str, *, thread_ts: str | None = None
    ) -> SlackOutcome:
        self.calls.append((channel, text, thread_ts))
        return (
            self.outcomes.pop(0)
            if self.outcomes
            else SlackOutcome("confirmed", ts=f"100.{len(self.calls)}")
        )


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "slack.sqlite3"
    SlackJournal.initialize(path)
    return path


def notification(key: str = "one") -> Notification:
    return Notification(
        key,
        "fingerprint",
        "P1",
        "candidate content",
        "2026-10-29T00:00:00Z",
        "source-run",
    )


def run(
    db: Path,
    sender: Sender,
    *,
    items: tuple[Notification, ...] | None = None,
    now: float = 1000,
    **kwargs: Any,
) -> dict[str, object]:
    policy = kwargs.pop("policy", SlackPolicy(enabled=True, min_interval_seconds=0))
    with SlackJournal(db) as journal:
        return deliver(
            items or (notification(),),
            policy,
            journal=journal,
            sender=sender,
            execute=True,
            clock=lambda: now,
            pause=lambda _: None,
            **kwargs,
        )


def test_restart_duplicate_changed_reminder_threads(db: Path) -> None:
    sender = Sender()
    assert run(db, sender)["attempted"] == 1
    assert run(db, sender)["notifications"][0]["reason"] == "duplicate"
    assert len(sender.calls) == 1
    assert (
        run(db, sender, items=(replace(notification(), fingerprint="new"),))[
            "attempted"
        ]
        == 1
    )
    assert sender.calls[1][2] == "100.1"
    # Returning to a previously seen state is still a significant transition.
    assert run(db, sender, now=1100)["attempted"] == 1
    assert (
        run(
            db,
            sender,
            now=1200,
            policy=SlackPolicy(
                enabled=True, min_interval_seconds=0, reminder_seconds=100
            ),
        )["attempted"]
        == 1
    )
    assert sender.calls[-1][2] == "100.1"


@pytest.mark.parametrize("state", ["unknown", "rate_limited", "rejected"])
def test_partial_failure_stops_remaining_and_unknown_blocks_destination(
    db: Path, state: str
) -> None:
    sender = Sender(
        (
            SlackOutcome("confirmed", ts="100.1"),
            SlackOutcome(state, error="test", retry_seconds=50),
        )
    )
    items = (notification("one"), notification("two"), notification("three"))
    result = run(db, sender, items=items)
    assert result["status"] == "stopped"
    assert len(sender.calls) == 2
    assert result["notifications"][2]["state"] == "not_attempted"
    again = run(db, sender, items=items, now=1020)
    if state == "unknown":
        assert again["attempted"] == 0
        assert all(r["reason"] == "blocked_unknown" for r in again["notifications"])
    elif state == "rate_limited":
        assert again["attempted"] == 0
    with SlackJournal(db, read_only=True) as journal:
        assert [r.state for r in journal.records()][:2] == ["confirmed", state]


def test_429_retry_is_explicit_bounded_and_does_not_sleep_retry_after(db: Path) -> None:
    sender = Sender(
        tuple(SlackOutcome("rate_limited", retry_seconds=10) for _ in range(3))
    )
    assert run(db, sender)["attempted"] == 1
    assert run(db, sender, now=1010)["attempted"] == 0
    assert run(db, sender, now=1009, retry_failed=True)["attempted"] == 0
    assert run(db, sender, now=1010, retry_failed=True)["attempted"] == 1
    assert run(db, sender, now=1020, retry_failed=True)["attempted"] == 1
    assert run(db, sender, now=1030, retry_failed=True)["attempted"] == 0
    assert len(sender.calls) == 3


@pytest.mark.parametrize(
    "dry_run,enabled,execute",
    [(True, True, True), (False, False, True), (False, True, False)],
)
def test_preview_has_no_journal_or_network_writes(
    db: Path, dry_run: bool, enabled: bool, execute: bool
) -> None:
    before = db.read_bytes()
    sender = Sender()
    with SlackJournal(db, read_only=True) as journal:
        result = deliver(
            (notification(),),
            SlackPolicy(enabled=enabled),
            journal=journal,
            sender=sender,
            dry_run=dry_run,
            execute=execute,
        )
    assert result["mode"] == "preview"
    assert not sender.calls
    assert before == db.read_bytes()


@pytest.mark.parametrize("stage", ["reserve", "finish"])
def test_audit_failure_stops_and_survives_restart(
    db: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    sender = Sender()

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError("synthetic disk full")

    with monkeypatch.context() as m:
        m.setattr(SlackJournal, stage, fail)
        with pytest.raises(OSError):
            run(db, sender, items=(notification(), notification("two")))
    assert len(sender.calls) == (1 if stage == "finish" else 0)
    if stage == "finish":
        assert run(db, sender)["notifications"][0]["reason"] == "blocked_unknown"
        assert len(sender.calls) == 1


def test_pending_manual_confirmation_is_audited_and_no_resend(db: Path) -> None:
    class Crash(Sender):
        def post(self, *args: object, **kwargs: object) -> SlackOutcome:
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        run(db, Crash())
    with SlackJournal(db) as journal:
        intent = journal.records()[0]
        assert intent.state == "pending"
        journal.finish(
            intent.intent_id, state="confirmed", now=1010, ts="100.5", actor="operator"
        )
        assert journal.audit()[-1]["actor"] == "operator"
    sender = Sender()
    assert run(db, sender, now=1100)["attempted"] == 0


def test_lock_missing_permissions_symlink_and_readonly(
    db: Path, tmp_path: Path
) -> None:
    with SlackJournal(db):
        with pytest.raises(BlockingIOError):
            SlackJournal(db)
    with pytest.raises(FileNotFoundError):
        SlackJournal(tmp_path / "missing")
    link = tmp_path / "link"
    link.symlink_to(db)
    with pytest.raises(OSError):
        SlackJournal(link)
    db.chmod(0o644)
    with pytest.raises(ValueError):
        SlackJournal(db)


def test_process_crash_leaves_pending_and_releases_os_lock(db: Path) -> None:
    import os
    import subprocess
    import sys

    code = """
import os, sys
from sbom_ops.domain.slack import Delivery
from sbom_ops.storage.slack import SlackJournal
journal = SlackJournal(sys.argv[1])
journal.reserve(Delivery('crash', 'C00000000', 'one', 'fingerprint', 'new',
                        'run', 'pending', 100, 100, 1, 0, None, None, 'hash'))
os._exit(9)
"""
    child = subprocess.run(
        [sys.executable, "-c", code, str(db)], env=os.environ.copy(), timeout=10
    )
    assert child.returncode == 9
    sender = Sender()
    assert run(db, sender)["notifications"][0]["reason"] == "blocked_unknown"
    assert not sender.calls


def test_pacing_and_run_limit(db: Path) -> None:
    sender = Sender()
    waits = []
    with SlackJournal(db) as journal:
        result = deliver(
            (notification(), notification("two"), notification("three")),
            SlackPolicy(enabled=True, max_messages=2),
            journal=journal,
            sender=sender,
            execute=True,
            clock=lambda: 1000,
            pause=waits.append,
        )
    assert len(sender.calls) == 2 and waits == [1]
    assert result["notifications"][2]["reason"] == "run_limit"


def test_auth_rejection_blocks_new_candidates_until_failed_candidate_recovers(
    db: Path,
) -> None:
    sender = Sender((SlackOutcome("rejected", error="missing_scope"),))
    run(db, sender)
    result = run(db, sender, items=(notification("another"),), now=2000)
    assert result["attempted"] == 0
    assert result["status"] == "stopped"
    result = run(
        db, sender, items=(notification("another"),), now=2000, retry_failed=True
    )
    assert result["attempted"] == 0
    result = run(
        db,
        sender,
        items=(notification("another"), notification()),
        now=2000,
        retry_failed=True,
    )
    assert result["attempted"] == 2
    assert result["notifications"][0]["key"] == "one"
