import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sbom_ops.domain.vulnrichment import VulnrichmentError
from sbom_ops.domain.vulnrichment_snapshot import (
    MAX_RECORD_BYTES,
    MAX_SNAPSHOT_BYTES,
    VulnrichmentSnapshot,
)


@pytest.fixture
def payload() -> dict:
    return json.loads(
        (Path(__file__).parents[1] / "fixtures/vulnrichment_synthetic.json").read_text()
    )


def capture(payload: object) -> VulnrichmentSnapshot:
    return VulnrichmentSnapshot.capture(
        payload,
        cve="CVE-2026-0001",
        revision="a" * 40,
        retrieved_at=datetime(2026, 10, 23, tzinfo=UTC),
        max_age=timedelta(hours=1, microseconds=7),
    )


def test_roundtrip_preserves_source_times_and_expired_evidence() -> None:
    payload = json.loads(
        (Path(__file__).parents[1] / "fixtures/vulnrichment_synthetic.json").read_text()
    )
    retrieved = datetime(2026, 10, 23, tzinfo=UTC)
    snapshot = VulnrichmentSnapshot.capture(
        payload,
        cve="CVE-2026-0001",
        revision="a" * 40,
        retrieved_at=retrieved,
        max_age=timedelta(hours=1),
    )
    restored = VulnrichmentSnapshot.from_json(snapshot.to_json())
    report = restored.report()
    assert report == snapshot.report()
    assert report.retrieved_at == retrieved
    assert report.assessed_at == datetime(2026, 10, 21, 12, tzinfo=UTC)
    assert report.exploitation == "poc"
    assert all(
        o.expires_at == datetime(2026, 10, 21, 13, tzinfo=UTC)
        for o in report.observations
    )


def test_original_mutation_does_not_change_snapshot(payload: dict) -> None:
    snapshot = capture(payload)
    serialized = snapshot.to_json()
    payload["containers"] = {}
    assert snapshot.to_json() == serialized
    with pytest.raises(FrozenInstanceError):
        snapshot.cve = "CVE-2026-0002"


def test_microseconds_are_preserved_without_float_rounding(payload: dict) -> None:
    original = capture(payload)
    restored = VulnrichmentSnapshot.from_json(original.to_json())
    assert restored.max_age == timedelta(hours=1, microseconds=7)
    assert restored.report() == original.report()


def test_missing_cisa_remains_unknown_after_restore(payload: dict) -> None:
    payload["containers"] = {}
    original = capture(payload)
    restored = VulnrichmentSnapshot.from_json(original.to_json())
    assert restored.report().observations == ()
    assert restored.report().reasons == ("missing_cisa_ssvc",)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("source", "https://other.example"),
        ("cve", "CVE-2026-0002"),
        ("revision", "main"),
        ("retrieved_at", "2026-10-23T00:00:00"),
        ("retrieved_at", "2026-10-20T00:00:00Z"),
        ("retrieved_at", "invalid"),
        ("retrieved_at", None),
        ("max_age_microseconds", True),
        ("max_age_microseconds", 1.0),
        ("max_age_microseconds", 0),
        ("max_age_microseconds", -1),
        ("max_age_microseconds", 10**30),
        ("record", []),
    ],
)
def test_invalid_persisted_fields_are_rejected(
    payload: dict,
    field: str,
    value: object,
) -> None:
    data = json.loads(capture(payload).to_json())
    data[field] = value
    with pytest.raises(VulnrichmentError):
        VulnrichmentSnapshot.from_json(json.dumps(data))


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_snapshot_contract_has_no_implicit_defaults(payload: dict, change: str) -> None:
    data = json.loads(capture(payload).to_json())
    if change == "missing":
        del data["max_age_microseconds"]
    else:
        data["approved"] = True
    with pytest.raises(VulnrichmentError, match="invalid_snapshot_fields"):
        VulnrichmentSnapshot.from_json(json.dumps(data))


@pytest.mark.parametrize(
    "serialized",
    [
        '{"schema_version":1,"schema_version":1}',
        '{"record":{"duplicate":1,"duplicate":2}}',
        '{"value":NaN}',
        '{"value":Infinity}',
        "[" * 2000,
        "not-json",
        "\ud800",
        "[]",
    ],
)
def test_unsafe_or_malformed_json_is_rejected(serialized: str) -> None:
    with pytest.raises(VulnrichmentError):
        VulnrichmentSnapshot.from_json(serialized)


def test_size_limits_apply_to_record_and_envelope(payload: dict) -> None:
    payload["description"] = "x" * MAX_RECORD_BYTES
    with pytest.raises(VulnrichmentError, match="snapshot_size_or_type"):
        capture(payload)
    with pytest.raises(VulnrichmentError, match="snapshot_size_or_type"):
        VulnrichmentSnapshot.from_json(" " * (MAX_SNAPSHOT_BYTES + 1))


def test_invalid_source_record_is_not_trusted_on_restore(payload: dict) -> None:
    data = json.loads(capture(payload).to_json())
    data["record"]["cveMetadata"]["state"] = "REJECTED"
    with pytest.raises(VulnrichmentError, match="record_not_published"):
        VulnrichmentSnapshot.from_json(json.dumps(data))
