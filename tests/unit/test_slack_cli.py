import json
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_slack_input import document

from sbom_ops.cli import main
from sbom_ops.clients.slack import SlackClient, SlackOutcome
from sbom_ops.storage.slack import SlackJournal


def invoke(
    monkeypatch: pytest.MonkeyPatch, path: Path, config: Path, *options: str
) -> int:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "slack",
            "notify",
            "--findings",
            str(path),
            "--config",
            str(config),
            "--observed-at",
            datetime.now(UTC).isoformat(),
            "--output",
            "json",
            *options,
        ],
    )
    return main()


@pytest.mark.parametrize(
    "enabled,options,posts",
    [
        (False, (), 0),
        (False, ("--execute",), 0),
        (True, (), 0),
        (True, ("--execute", "--dry-run"), 0),
        (True, ("--execute",), 1),
    ],
)
def test_cli_write_gates_stdout_and_unchanged_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    enabled: bool,
    options: tuple[str, ...],
    posts: int,
) -> None:
    path, config, db = (
        tmp_path / name for name in ("sync.json", "config.json", "slack.db")
    )
    path.write_text(json.dumps(document()))
    original = path.read_bytes()
    config.write_text(
        json.dumps(
            {
                "enabled": enabled,
                "channel": "C12345678",
                "dt_url": "https://dt.example.test",
                "report_url": "https://reports.example.test",
                "record_url": "https://work.example.test",
            }
        )
    )
    SlackJournal.initialize(db)
    db_before = db.read_bytes()
    calls = []

    def post(
        self: SlackClient, channel: str, text: str, *, thread_ts: str | None = None
    ) -> SlackOutcome:
        calls.append((channel, text))
        return SlackOutcome("confirmed", ts="100.123")

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("unexpected external access, including DT/GitHub")

    monkeypatch.setattr(SlackClient, "post", post)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setenv("SBOM_OPS_SLACK_BOT_TOKEN", "synthetic-not-a-credential")
    assert invoke(monkeypatch, path, config, "--db", str(db), *options) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(calls) == posts
    assert "team-example" in output["notifications"][0]["text"]
    assert "synthetic-not-a-credential" not in str(output)
    assert path.read_bytes() == original
    if not posts:
        assert db.read_bytes() == db_before
    else:
        assert invoke(monkeypatch, path, config, "--db", str(db), *options) == 0
        again = json.loads(capsys.readouterr().out)
        assert again["attempted"] == 0 and len(calls) == 1


def test_preview_without_db_or_token_and_failed_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path, config = tmp_path / "sync.json", tmp_path / "config.json"
    path.write_text(json.dumps(document()))
    config.write_text("{}")
    monkeypatch.delenv("SBOM_OPS_SLACK_BOT_TOKEN", raising=False)
    assert invoke(monkeypatch, path, config) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "preview"
    path.write_text('{"status":"failed", "error":"secret-response"}')
    assert invoke(monkeypatch, path, config) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["kind"] == "processing_error"
    assert "secret-response" not in str(output)
    assert "notifications" not in output


def test_confirm_requires_correct_destination_and_explicit_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from test_slack_delivery import Sender, run

    db = tmp_path / "journal.db"
    SlackJournal.initialize(db)
    run(db, Sender((SlackOutcome("unknown"),)))
    with SlackJournal(db, read_only=True) as journal:
        row = journal.records()[0]
    command = [
        "sbom-ops",
        "slack",
        "confirm",
        "--db",
        str(db),
        "--intent",
        row.intent_id,
        "--channel",
        row.channel,
        "--ts",
        "123.456",
        "--actor",
        "operator",
    ]
    before = db.read_bytes()
    monkeypatch.setattr(sys, "argv", command)
    assert main() == 0
    capsys.readouterr()
    assert before == db.read_bytes()
    monkeypatch.setattr(sys, "argv", command + ["--execute"])
    assert main() == 0
    with SlackJournal(db, read_only=True) as journal:
        assert journal.records()[0].ts == "123.456"
        assert journal.audit()[-1]["actor"] == "operator"
