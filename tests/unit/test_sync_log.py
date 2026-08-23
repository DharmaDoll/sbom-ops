from __future__ import annotations

import json

from sbom_ops.services.sync_log import append_sync_event


def test_append_sync_event_writes_one_jsonl_record(tmp_path) -> None:
    path = tmp_path / "sync.jsonl"

    assert append_sync_event(str(path), {"status": "succeeded", "run_id": "run-1"})

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "status": "succeeded",
        "run_id": "run-1",
    }


def test_append_sync_event_does_not_raise_for_unwritable_sink(tmp_path) -> None:
    path = tmp_path / "missing" / "sync.jsonl"

    assert append_sync_event(str(path), {"status": "failed"}) is False
