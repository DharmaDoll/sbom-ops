import json
from copy import deepcopy
from pathlib import Path

import pytest

from sbom_ops.domain.sbom_quality import QualityCheck
from sbom_ops.domain.sbom_quality_document import evaluate_document
from sbom_ops.domain.sbom_quality_input import QualityInputError
from sbom_ops.services.sbom_quality_input import read_quality_input


@pytest.mark.parametrize("version", ["1.5", "1.6"])
def test_document_fields_come_from_original_locations(version: str) -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": version,
        "version": 2,
        "metadata": {
            "authors": [{"name": "Example team"}],
            "timestamp": "2026-10-24T12:34:56Z",
            "lifecycles": [{"phase": "build"}],
            "tools": [{"name": "example-generator", "version": "1.0"}],
        },
        # Synthetic envelope shape only; this is not a cryptographic signature.
        "signature": {"algorithm": "ES256", "value": "dGVzdA"},
    }
    before = deepcopy(document)
    checks = evaluate_document(document)
    assert len(checks) == 9
    assert all(check.subject == "" for check in checks)
    expected = {
        "sbom_author": "/metadata/authors/0/name",
        "sbom_signature": "/signature",
        "format_name": "/bomFormat",
        "format_version": "/specVersion",
        "generation_context": "/metadata/lifecycles",
        "timestamp": "/metadata/timestamp",
        "tool_name": "/metadata/tools/0/name",
        "tool_version": "/metadata/tools/0/version",
        "sbom_version": "/version",
    }
    assert {check.field.value: check.evidence_paths for check in checks} == {
        key: (value,) for key, value in expected.items()
    }
    assert all(check.state.value == "present" for check in checks)
    assert all(check.as_dict()["verification"] == "not_performed" for check in checks)
    assert document == before


def _document(**metadata: object) -> dict[str, object]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": metadata}


def _check(document: dict[str, object], field: str) -> QualityCheck:
    return next(
        check for check in evaluate_document(document) if check.field.value == field
    )


def test_missing_is_not_filled_with_default_or_component_metadata() -> None:
    document = _document(
        component={
            "version": "10",
            "authors": [{"name": "supplier"}],
            "signature": {"algorithm": "ES256", "value": "dGVzdA"},
        }
    )
    checks = evaluate_document(document)
    assert sum(check.state.value == "missing" for check in checks) == 7
    assert _check(document, "sbom_version").evidence_paths == ()
    assert _check(document, "sbom_author").state.value == "missing"
    assert _check(document, "sbom_signature").state.value == "missing"


@pytest.mark.parametrize("value", [None, True, 0, -1, "1", 1.0])
def test_bad_sbom_version_is_invalid_not_missing(value: object) -> None:
    result = _check(_document() | {"version": value}, "sbom_version")
    assert result.state.value == "invalid"
    assert result.evidence_paths == ("/version",)


@pytest.mark.parametrize(
    "value",
    [
        "2026-02-30T12:00:00Z",
        "2026-10-24",
        "2026-10-24T12:00:00",
        "2026-10-24T12:00:00+00:60",
        "2026-10-24T12:00:00+24:00",
        "2026-10-24T12:00:61Z",
        "2026-10-24 12:00:00Z",
        None,
        123,
    ],
)
def test_bad_timestamp(value: object) -> None:
    assert _check(_document(timestamp=value), "timestamp").state.value == "invalid"


@pytest.mark.parametrize(
    "value", ["2026-10-24t12:00:00z", "2026-10-24T12:00:00.123+09:00"]
)
def test_timestamp_offsets_and_lowercase(value: str) -> None:
    assert _check(_document(timestamp=value), "timestamp").state.value == "present"


@pytest.mark.parametrize("value", ["2016-12-31T23:59:60Z", "2026-10-24T12:00:00-00:00"])
def test_leap_second_or_unknown_offset_remains_unverified(value: str) -> None:
    assert _check(_document(timestamp=value), "timestamp").state.value == "unverifiable"


@pytest.mark.parametrize("version,expected", [("1.5", "missing"), ("1.6", "present")])
def test_bom_manufacturer_is_version_specific(version: str, expected: str) -> None:
    document = _document(manufacturer={"name": "BOM team"})
    document["specVersion"] = version
    assert _check(document, "sbom_author").state.value == expected


def test_legacy_manufacture_and_tool_vendor_are_not_bom_author() -> None:
    document = _document(
        manufacture={"name": "component maker"},
        supplier={"name": "supplier"},
        tools=[{"vendor": "generator company"}],
    )
    assert _check(document, "sbom_author").state.value == "missing"


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"name": 42}, "invalid"),
        ({"name": ""}, "invalid"),
        ({}, "unverifiable"),
        (None, "invalid"),
    ],
)
def test_manufacturer_identity_type(value: object, expected: str) -> None:
    assert _check(_document(manufacturer=value), "sbom_author").state.value == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, "invalid"),
        ([], "invalid"),
        ([42], "invalid"),
        ([{"name": ""}], "invalid"),
        ([{"name": 42}], "invalid"),
        ([{}], "unverifiable"),
        ([{"email": "team@example.invalid"}], "present"),
    ],
)
def test_author_structure_and_identity(value: object, expected: str) -> None:
    assert _check(_document(authors=value), "sbom_author").state.value == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ([{"phase": "build"}, {"phase": "operations"}], "present"),
        ([{"name": "custom step"}], "unverifiable"),
        ([{"phase": "build", "name": "custom"}], "invalid"),
        ([{"phase": "unknown-phase"}], "invalid"),
        ([{"phase": []}], "invalid"),
        ([], "invalid"),
        (None, "invalid"),
    ],
)
def test_lifecycle_mapping(value: object, expected: str) -> None:
    assert (
        _check(_document(lifecycles=value), "generation_context").state.value
        == expected
    )


@pytest.mark.parametrize("version", ["1.5", "1.6"])
def test_new_tools_keep_name_and_version_pairs(version: str) -> None:
    document = _document(
        tools={
            "components": [{"name": "first", "version": "1", "type": "application"}],
            "services": [{"name": "second", "version": "2"}],
        }
    )
    document["specVersion"] = version
    result = _check(document, "tool_version")
    assert result.state.value == "present"
    assert result.evidence_paths == (
        "/metadata/tools/components/0/version",
        "/metadata/tools/services/0/version",
    )
    document["metadata"]["tools"]["services"][0].pop("version")
    assert _check(document, "tool_version").state.value == "invalid"
    assert _check(document, "tool_name").state.value == "present"


def test_tool_fields_cannot_be_borrowed_from_another_tool() -> None:
    document = _document(tools=[{"name": "one"}, {"version": "two"}])
    assert _check(document, "tool_name").state.value == "invalid"
    assert _check(document, "tool_version").state.value == "invalid"
    document = _document(tools=[{"name": "one"}])
    assert _check(document, "tool_version").state.value == "missing"
    assert _check(document, "tool_version").evidence_paths == ()


@pytest.mark.parametrize(
    "tools", [None, [], {}, [None], {"components": None}, {"other": []}]
)
def test_invalid_tools_structure(tools: object) -> None:
    checks = evaluate_document(_document(tools=tools))
    assert all(
        check.state.value == "invalid"
        for check in checks
        if check.field.value.startswith("tool_")
    )


@pytest.mark.parametrize(
    "signature,expected",
    [
        ({"algorithm": "ES256", "value": "dGVzdA"}, "present"),
        ({"signers": [{"algorithm": "ES256", "value": "dGVzdA"}]}, "present"),
        ({"chain": [{"algorithm": "ES256", "value": "dGVzdA"}]}, "present"),
        ({}, "invalid"),
        (None, "invalid"),
        ({"signers": []}, "invalid"),
        ({"algorithm": "ES256"}, "invalid"),
        ({"algorithm": "ES256", "value": "bad value"}, "invalid"),
    ],
)
def test_signature_is_only_an_envelope_observation(
    signature: object, expected: str
) -> None:
    result = _check(_document() | {"signature": signature}, "sbom_signature")
    assert result.state.value == expected
    assert result.as_dict()["verification"] == "not_performed"


@pytest.mark.parametrize("state", ["unknown", "withheld"])
def test_declaration_applies_only_to_absence_and_keeps_its_source(state: str) -> None:
    document = _document(
        properties=[
            {"name": "sbom-ops:quality:timestamp:state", "value": state},
            {"name": "sbom-ops:quality:timestamp:reason", "value": "author statement"},
        ]
    )
    result = _check(document, "timestamp")
    assert result.state.value == state
    assert result.declaration.source_path == "/metadata/properties/0"
    document["metadata"]["timestamp"] = "2026-10-24T12:00:00Z"
    result = _check(document, "timestamp")
    assert result.state.value == "invalid"
    assert result.reason == "declaration_conflicts_with_observation"


def test_bad_declaration_is_a_document_error() -> None:
    with pytest.raises(QualityInputError, match="^invalid_quality_declaration$"):
        evaluate_document(
            _document(
                properties=[
                    {"name": "sbom-ops:quality:timestamp:state", "value": "unknown"}
                ]
            )
        )


def test_real_local_file_to_document_observations_preserves_input(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bom.json"
    raw = json.dumps(_document(timestamp="2026-10-24T12:00:00Z")).encode()
    path.write_bytes(raw)
    checks = evaluate_document(read_quality_input(path).document)
    assert len(checks) == 9
    assert {
        check.field.value for check in checks if check.state.value == "present"
    } == {
        "format_name",
        "format_version",
        "timestamp",
    }
    assert path.read_bytes() == raw
