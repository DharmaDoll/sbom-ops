import json
from pathlib import Path

import pytest
from dt_lab import service


def test_measurement_replacement(tmp_path: Path) -> None:
    path = tmp_path / "bom-processing.json"
    service._write_measurement_json(path, {"status": "waiting"})
    service._write_measurement_json(path, {"status": "token_idle"})
    assert json.loads(path.read_text()) == {"status": "token_idle"}
    assert path.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("failure", ["serialization", "fsync", "replace", "interrupt"])
def test_failed_measurement_keeps_previous_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    path = tmp_path / "bom-processing.json"
    service._write_measurement_json(path, {"status": "waiting"})
    previous = path.read_bytes()

    def fail(*_: object) -> None:
        if failure == "interrupt":
            raise KeyboardInterrupt
        raise OSError("synthetic storage failure")

    payload: dict[str, object] = {"status": "token_idle"}
    expected: type[BaseException] = OSError
    if failure == "serialization":
        payload["invalid"] = object()
        expected = TypeError
    elif failure == "fsync":
        monkeypatch.setattr(service.os, "fsync", fail)
    else:
        monkeypatch.setattr(service.os, "replace", fail)
        if failure == "interrupt":
            expected = KeyboardInterrupt
    with pytest.raises(expected):
        service._write_measurement_json(path, payload)
    assert path.read_bytes() == previous
    assert list(tmp_path.iterdir()) == [path]
