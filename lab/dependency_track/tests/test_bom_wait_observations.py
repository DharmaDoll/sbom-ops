import pytest
from dt_lab import client as client_module
from dt_lab.client import DependencyTrackLabApiError, DependencyTrackLabClient
from dt_lab.domain import BomProcessingObservation


@pytest.mark.parametrize("response_seconds", [0.25, 3.0])
def test_first_idle_response_records_actual_elapsed_time(
    monkeypatch: pytest.MonkeyPatch, response_seconds: float
) -> None:
    clock = [0.0]
    monkeypatch.setattr(client_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        client_module.time, "sleep", lambda _: pytest.fail("idle must not sleep")
    )
    client = DependencyTrackLabClient("https://dtrack.example", "synthetic-key")
    records: list[BomProcessingObservation] = []
    calls: list[str] = []

    def request(path: str) -> dict[str, bool]:
        calls.append(path)
        clock[0] += response_seconds
        return {"processing": False}

    monkeypatch.setattr(client, "_request_json", request)
    client.wait_for_bom_processing("unused", timeout=2, on_progress=records.append)
    assert len(calls) == 1
    assert records[-1].status == "token_idle"
    assert records[-1].elapsed_seconds == response_seconds
    assert records[-1].poll_attempts == records[-1].valid_responses == 1
    assert records[-1].last_processing is False


def test_sleep_interruption_preserves_last_valid_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "synthetic-key")
    records: list[BomProcessingObservation] = []
    calls: list[str] = []

    def request(path: str) -> dict[str, bool]:
        calls.append(path)
        return {"processing": True}

    def interrupt(_: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(client, "_request_json", request)
    monkeypatch.setattr(client_module.time, "sleep", interrupt)
    with pytest.raises(KeyboardInterrupt):
        client.wait_for_bom_processing("unused", on_progress=records.append)
    assert len(calls) == 1
    assert records[-1].status == "interrupted"
    assert records[-1].poll_attempts == records[-1].valid_responses == 1
    assert records[-1].last_processing is True


@pytest.mark.parametrize("fail_at,expected_calls", [(1, 0), (2, 0), (3, 1)])
def test_recording_failure_stops_wait_without_another_poll(
    monkeypatch: pytest.MonkeyPatch, fail_at: int, expected_calls: int
) -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "synthetic-key")
    calls: list[str] = []
    records: list[BomProcessingObservation] = []

    def request(path: str) -> dict[str, bool]:
        calls.append(path)
        return {"processing": True}

    def record(item: BomProcessingObservation) -> None:
        records.append(item)
        if len(records) == fail_at:
            raise OSError("synthetic storage failure")

    monkeypatch.setattr(client, "_request_json", request)
    monkeypatch.setattr(
        client_module.time, "sleep", lambda _: pytest.fail("must stop before sleep")
    )
    with pytest.raises(OSError, match="synthetic storage failure"):
        client.wait_for_bom_processing("unused", on_progress=record)
    assert len(calls) == expected_calls
    assert len(records) == fail_at
    assert all(item.status == "waiting" for item in records)


@pytest.mark.parametrize(
    "outcome", ["idle", "timeout", "malformed", "interrupt", "error"]
)
def test_wait_records_progress_without_tokens(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    clock = [0.0]
    monkeypatch.setattr(client_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        client_module.time,
        "sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    client = DependencyTrackLabClient("https://dtrack.example", "synthetic-key")
    records: list[BomProcessingObservation] = []
    calls: list[str] = []

    def request(path: str) -> dict[str, object]:
        calls.append(path)
        clock[0] += 0.25
        if len(calls) == 1:
            return {"processing": True}
        if outcome == "interrupt":
            raise KeyboardInterrupt
        if outcome == "error":
            raise DependencyTrackLabApiError("private failure text")
        if outcome == "malformed":
            return {"processing": "false"}
        return {"processing": outcome != "idle"}

    monkeypatch.setattr(client, "_request_json", request)
    expected = (
        KeyboardInterrupt if outcome == "interrupt" else DependencyTrackLabApiError
    )
    if outcome == "idle":
        client.wait_for_bom_processing(
            "private-token", timeout=2, poll_interval=0.5, on_progress=records.append
        )
    else:
        with pytest.raises(expected):
            client.wait_for_bom_processing(
                "private-token",
                timeout=2,
                poll_interval=0.5,
                on_progress=records.append,
            )
    data = [record.as_dict() for record in records]
    assert data[0]["status"] == "waiting"
    assert data[0]["poll_attempts"] == 0
    assert (
        data[-1]["status"]
        == {
            "idle": "token_idle",
            "timeout": "timed_out",
            "malformed": "failed",
            "interrupt": "interrupted",
            "error": "failed",
        }[outcome]
    )
    assert data[-1]["poll_attempts"] == len(calls)
    assert data[-1]["valid_responses"] == (
        len(calls) if outcome in {"idle", "timeout"} else 1
    )
    assert data[-1]["elapsed_seconds"] == clock[0]
    assert data[-1]["elapsed_seconds"] > 0
    assert "private" not in repr(data)
    assert "synthetic-key" not in repr(data)
    assert any(
        row["poll_attempts"] == 1 and row["valid_responses"] == 0 for row in data
    )


@pytest.mark.parametrize(
    "timeout,interval",
    [(0, 1), (-1, 1), (float("nan"), 1), (float("inf"), 1), (1, -1), (1, float("inf"))],
)
def test_invalid_wait_limits_do_not_call_api(
    monkeypatch: pytest.MonkeyPatch, timeout: float, interval: float
) -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "synthetic-key")
    monkeypatch.setattr(
        client, "_request_json", lambda *_: pytest.fail("must not call API")
    )
    with pytest.raises(ValueError):
        client.wait_for_bom_processing(
            "unused", timeout=timeout, poll_interval=interval
        )
