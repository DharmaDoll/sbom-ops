"""Offline teaching scenarios use the same evidence join and renderer as sync."""

import importlib.util
import json
import socket
import sqlite3
from pathlib import Path

import pytest


def test_triage_exercise_matches_context_and_never_connects(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline exercise attempted network or database access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    path = Path(__file__).parents[2] / "examples/triage_scenario.py"
    assert path.is_file(), "the runnable triage exercise is missing"
    spec = importlib.util.spec_from_file_location("triage_example", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = path.with_name("triage-scenario.example.json")
    original = source.read_bytes()
    result = module.run_scenario()
    assert result == module.run_scenario()
    assert result["fictional"] is True
    rows = {case["name"]: case["context"] for case in result["cases"]}
    assert set(rows) == {"public", "internal", "missing", "expired", "unassigned"}
    assert {row["identity"]["cve"] for row in rows.values()} == {"CVE-2026-0001"}
    assert rows["public"]["reference"]["calendar_days"] == 3
    assert rows["internal"]["reference"]["calendar_days"] == 14
    assert rows["public"]["reference"]["forensic_triage"] == "specified_by_reference"
    assert (
        rows["internal"]["reference"]["forensic_triage"] == "not_specified_by_reference"
    )
    for name in ("missing", "expired"):
        assert rows[name]["reference"]["status"] == "pending"
        action = next(
            a
            for a in rows[name]["guidance"]["actions"]
            if a["code"] == "confirm_public_exposure"
        )
        assert action["role"] == "asset"
        assert action["assignee"] == "checkout-team"
        assert action["reason"] == ("unknown" if name == "missing" else "expired")
    assert rows["unassigned"]["guidance"]["asset_owner"] is None
    assert all(a["assignee"] is None for a in rows["unassigned"]["guidance"]["actions"])
    for row in rows.values():
        assert row["guidance"]["asset"]["environment"] == row["environment"]
        assert row["reference"]["due_at"] is None
        assert row["reference"]["organizational_sla_adopted"] is False
        assert row["priority_changed"] is False
        assert row["guidance"]["automatic_actions"] is False
    module.main(["--output", "json"])
    assert json.loads(capsys.readouterr().out) == json.loads(json.dumps(result))
    module.main([])
    text = capsys.readouterr().out
    assert "架空" in text and "未割当" in text
    assert "3暦日" in text and "14暦日" in text
    assert "確認先" in text and "次の行動" in text
    assert "理由: 期限切れ" in text
    assert "理由: 不明" in text
    assert "理由: 資産担当が未登録" in text
    assert "調査不要・侵害なしの意味ではありません" in text
    assert source.read_bytes() == original
