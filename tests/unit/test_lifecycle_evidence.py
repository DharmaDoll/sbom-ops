import json
from dataclasses import replace

import pytest

from sbom_ops.domain import lifecycle_evidence
from sbom_ops.domain.lifecycle_evidence import parse_evidence, validate_correction


@pytest.mark.parametrize("kind", ["source", "build", "unknown"])
def test_storage_serialization_preserves_evidence(kind: str) -> None:
    item = parse_evidence(
        document(
            kind=kind,
            actor="運用担当",
            source_repository="https://example.test/repo",
            source_revision="a" * 40,
            observed_at="2026-10-25T09:00:00+09:00",
            artifact_digest="sha256:" + "b" * 64,
            sbom_digest="sha256:" + "c" * 64,
        )
    )
    raw = lifecycle_evidence.serialize_evidence(item)
    assert parse_evidence(raw) == item
    payload = json.loads(raw)
    assert payload["schema_version"] == 1
    assert payload["observed_at"] == "2026-10-25T00:00:00+00:00"
    assert payload["actor"] == "運用担当"
    assert "recorded_at" not in payload
    assert "record_id" not in payload


def test_storage_serialization_preserves_correction() -> None:
    item = parse_evidence(document(supersedes_id=42, reason="SBOM訂正"))
    assert parse_evidence(lifecycle_evidence.serialize_evidence(item)) == item


def document(**changes: object) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "service_id": "shop",
            "deployable_id": "api",
            "kind": "build",
            "artifact_id": "build-a",
            "sbom_ref": "boms/a.json",
            "actor": "operator",
            **changes,
        }
    )


@pytest.mark.parametrize("kind", ["source", "build", "unknown"])
def test_explicit_kind_and_independent_digests(kind: str) -> None:
    result = parse_evidence(
        document(
            kind=kind,
            source_repository="https://example.test/repo",
            source_revision="a" * 40,
            artifact_digest="sha256:" + "b" * 64,
            sbom_digest="sha256:" + "c" * 64,
        )
    )
    assert result.kind == kind
    assert result.artifact_digest != result.sbom_digest
    assert result.artifact_id == "build-a"


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"kind": "runtime"},
        {"artifact_id": None},
        {"kind": "source"},
        {"source_repository": "https://example.test/repo"},
        {"actor": ""},
        {"actor": " operator"},
        {"unexpected": 1},
        {"sbom_ref": "https://user:password@example.test/bom"},
        {"sbom_ref": "https://example.test/bom?token=synthetic"},
        {"sbom_ref": "../bom.json"},
        {"sbom_ref": "/tmp/bom.json"},
        {"sbom_ref": "https://example.test/bom#secret"},
        {"artifact_digest": "sha256:invalid"},
        {"supersedes_id": True, "reason": "fix"},
        {"reason": "fix"},
        {"supersedes_id": 1},
        {"kind": "unknown", "supersedes_id": 1, "reason": "fix"},
        {"observed_at": "2026-10-25T00:00:00"},
    ],
)
def test_invalid_inputs_are_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        parse_evidence(document(**changes))


@pytest.mark.parametrize(
    "raw", ['{"kind":"build","kind":"source"}', '{"value":NaN}', "[]", "[" * 2000]
)
def test_invalid_json_is_rejected(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_evidence(raw)


def test_size_limit_counts_utf8_bytes() -> None:
    raw = document()
    assert parse_evidence(raw + " " * (65536 - len(raw.encode()))).kind == "build"
    with pytest.raises(ValueError):
        parse_evidence(raw + " " * (65537 - len(raw.encode())))


def test_source_can_exist_without_artifact_and_time_is_normalized() -> None:
    item = parse_evidence(
        document(
            kind="source",
            artifact_id=None,
            source_repository="https://example.test/repo",
            source_revision="a" * 40,
            observed_at="2026-10-25T09:00:00+09:00",
        )
    )
    assert item.artifact_id is None
    assert item.observed_at.isoformat() == "2026-10-25T00:00:00+00:00"


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"artifact_id": "build-b"},
        {"service_id": "other"},
        {"kind": "source", "source_repository": "repo", "source_revision": "a" * 40},
    ],
)
def test_correction_preserves_target(change: dict[str, object]) -> None:
    old = parse_evidence(document())
    new = parse_evidence(
        document(
            sbom_ref="boms/fixed.json",
            supersedes_id=1,
            reason="correct metadata",
            **change,
        )
    )
    if change:
        with pytest.raises(ValueError):
            validate_correction(old, new, previous_id=1)
    else:
        validate_correction(old, new, previous_id=1)
        with pytest.raises(ValueError):
            validate_correction(old, new, previous_id=2)


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"source_revision": "b" * 40},
        {"source_repository": "other-repo"},
        {"deployable_id": "worker"},
    ],
)
def test_source_correction_preserves_source_identity(change: dict[str, object]) -> None:
    old = parse_evidence(
        document(
            kind="source",
            artifact_id=None,
            source_repository="repo",
            source_revision="a" * 40,
        )
    )
    new = replace(
        old,
        sbom_ref="boms/fixed.json",
        supersedes_id=7,
        reason="correct source inventory",
        **change,
    )
    if change:
        with pytest.raises(ValueError):
            validate_correction(old, new, previous_id=7)
    else:
        validate_correction(old, new, previous_id=7)


@pytest.mark.parametrize(
    "change",
    [
        {"actor": False},
        {"service_id": []},
        {"kind": None},
        {"artifact_id": "x" * 513},
        {"observed_at": "not a datetime"},
        {"sbom_ref": "https://user:synthetic@example.test/bom"},
        {"source_revision": "a" * 40},
    ],
)
def test_direct_construction_does_not_bypass_validation(
    change: dict[str, object],
) -> None:
    old = parse_evidence(document())
    with pytest.raises(ValueError):
        replace(old, **change)


@pytest.mark.parametrize(
    "reference",
    [
        "https://bad host.test/bom",
        "https://example.test/a b.json",
        "https://example.test:invalid/bom",
        "a/%2e%2e/bom",
        "a\\bom",
    ],
)
def test_malformed_or_ambiguous_reference_is_rejected(reference: str) -> None:
    with pytest.raises(ValueError):
        parse_evidence(document(sbom_ref=reference))
