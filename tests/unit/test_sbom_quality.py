import json
from dataclasses import FrozenInstanceError, replace

import pytest

from sbom_ops.domain.sbom_quality import (
    QualityCheck,
    QualityDeclaration,
    QualityField,
    QualityState,
    apply_declaration,
)


def test_declaration_does_not_hide_a_present_value() -> None:
    check = QualityCheck(
        QualityField.COMPONENT_VERSION,
        "/components/0",
        QualityState.PRESENT,
        ("/components/0/version",),
        "field_present",
    )
    declaration = QualityDeclaration(
        check.field,
        check.subject,
        QualityState.UNKNOWN,
        "/components/0/properties/0",
        "Version is not known",
    )
    result = apply_declaration(check, declaration)
    assert result.state is QualityState.INVALID
    assert result.reason == "declaration_conflicts_with_observation"
    assert result.evidence_paths == check.evidence_paths
    assert result.declaration == declaration


def missing_check() -> QualityCheck:
    return QualityCheck(
        QualityField.COMPONENT_VERSION,
        "/components/0",
        QualityState.MISSING,
        (),
        "field_missing",
    )


def declaration(state: QualityState = QualityState.UNKNOWN) -> QualityDeclaration:
    return QualityDeclaration(
        QualityField.COMPONENT_VERSION,
        "/components/0",
        state,
        "/components/0/properties/0",
        "Synthetic author declaration",
    )


@pytest.mark.parametrize("state", [QualityState.UNKNOWN, QualityState.WITHHELD])
def test_explicit_absence_keeps_source_without_claiming_verification(
    state: QualityState,
) -> None:
    original = missing_check()
    result = apply_declaration(original, declaration(state))
    assert result.state is state
    assert original.state is QualityState.MISSING
    payload = result.as_dict()
    assert payload["declaration"]["source_path"] == "/components/0/properties/0"
    assert payload["verification"] == "not_performed"
    assert payload["evidence_paths"] == []
    assert json.loads(json.dumps(payload)) == payload
    with pytest.raises(FrozenInstanceError):
        result.state = QualityState.PRESENT
    with pytest.raises(ValueError, match="already applied"):
        apply_declaration(result, declaration(state))


@pytest.mark.parametrize("declared", [QualityState.UNKNOWN, QualityState.WITHHELD])
@pytest.mark.parametrize(
    "observed", [QualityState.PRESENT, QualityState.INVALID, QualityState.UNVERIFIABLE]
)
def test_declaration_cannot_replace_observed_information(
    declared: QualityState,
    observed: QualityState,
) -> None:
    check = replace(
        missing_check(), state=observed, evidence_paths=("/components/0/version",)
    )
    result = apply_declaration(check, declaration(declared))
    assert result.state is QualityState.INVALID
    assert result.evidence_paths == check.evidence_paths
    assert result.as_dict()["verification"] == "not_performed"


@pytest.mark.parametrize(
    "changes",
    [
        {"subject": "/components/1"},
        {"field": QualityField.COMPONENT_NAME},
    ],
)
def test_declaration_cannot_cross_targets(changes: dict) -> None:
    with pytest.raises(ValueError, match="target mismatch"):
        apply_declaration(missing_check(), replace(declaration(), **changes))


@pytest.mark.parametrize(
    "changes",
    [
        {"field": "component_version"},
        {"state": "unknown"},
        {"state": QualityState.PRESENT},
        {"source_path": ""},
        {"source_path": "https://example.test/data"},
        {"subject": "/bad~2escape"},
        {"subject": "/bad\npath"},
        {"subject": "/" * 4097},
        {"reason": ""},
        {"reason": "x" * 2049},
        {"reason": " leading"},
    ],
)
def test_invalid_declaration_is_rejected(changes: dict) -> None:
    with pytest.raises(ValueError):
        replace(declaration(), **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"state": QualityState.UNKNOWN},
        {"state": QualityState.WITHHELD},
        {"state": QualityState.PRESENT},
        {"state": "missing"},
        {"evidence_paths": ["/components/0/version"]},
        {"evidence_paths": ("/components/0/version",)},
        {"evidence_paths": ("/x", "/x")},
        {"declaration": {}},
    ],
)
def test_result_cannot_invent_presence_or_declaration(changes: dict) -> None:
    with pytest.raises(ValueError):
        replace(missing_check(), **changes)


def test_document_root_and_escaped_pointer_are_preserved() -> None:
    check = QualityCheck(
        QualityField.SBOM_AUTHOR,
        "",
        QualityState.PRESENT,
        ("/metadata/a~1b~0c",),
        "field_present",
    )
    assert check.as_dict()["subject"] == ""
    assert check.as_dict()["evidence_paths"] == ["/metadata/a~1b~0c"]


def test_signature_presence_is_not_authenticity() -> None:
    check = QualityCheck(
        QualityField.SBOM_SIGNATURE,
        "",
        QualityState.PRESENT,
        ("/signature",),
        "signature_present",
    )
    assert check.as_dict()["verification"] == "not_performed"


def test_field_identifiers_cover_the_seventeen_elements() -> None:
    assert {field.value for field in QualityField} == {
        "sbom_author",
        "sbom_signature",
        "format_name",
        "format_version",
        "generation_context",
        "timestamp",
        "tool_name",
        "tool_version",
        "sbom_version",
        "component_producer",
        "dependency_relationship",
        "component_hash",
        "hash_algorithm",
        "component_identifier",
        "component_license",
        "component_name",
        "component_version",
    }
