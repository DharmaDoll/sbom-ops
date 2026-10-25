from copy import deepcopy

import pytest

from sbom_ops.domain.sbom_quality import (
    QualityCheck,
    QualityField,
    QualityState,
    apply_declaration,
)
from sbom_ops.domain.sbom_quality_declarations import read_quality_declarations


def test_component_declaration_keeps_its_target_and_original_location() -> None:
    properties = [
        {"name": "example:ordinary", "value": "unknown"},
        {"name": "sbom-ops:quality:component_version:state", "value": "unknown"},
        {"name": "sbom-ops:quality:component_version:reason", "value": "Not supplied"},
    ]
    (result,) = read_quality_declarations(properties, subject="/components/0")
    assert result.field is QualityField.COMPONENT_VERSION
    assert result.state is QualityState.UNKNOWN
    assert result.subject == "/components/0"
    assert result.source_path == "/components/0/properties/1"
    assert result.reason == "Not supplied"


def properties(
    field: str = "component_version", state: str = "unknown"
) -> list[dict[str, str]]:
    return [
        {"name": f"sbom-ops:quality:{field}:state", "value": state},
        {"name": f"sbom-ops:quality:{field}:reason", "value": "Synthetic reason"},
    ]


@pytest.mark.parametrize("field", list(QualityField))
def test_all_fields_are_read_only_and_scoped(field: QualityField) -> None:
    document = field.value in {
        "sbom_author",
        "sbom_signature",
        "format_name",
        "format_version",
        "generation_context",
        "timestamp",
        "tool_name",
        "tool_version",
        "sbom_version",
    }
    subject = "" if document else "/metadata/component/components/0"
    original = properties(field.value, "withheld")
    before = deepcopy(original)
    (result,) = read_quality_declarations(original, subject=subject)
    assert result.field is field
    assert result.state is QualityState.WITHHELD
    assert result.subject == subject
    assert original == before
    opposite = "/components/0" if document else ""
    with pytest.raises(ValueError, match="outside subject scope"):
        read_quality_declarations(original, subject=opposite)


def test_read_declaration_connects_to_observation_without_inventing_verification() -> (
    None
):
    (declaration,) = read_quality_declarations(properties(), subject="/components/0")
    check = QualityCheck(
        QualityField.COMPONENT_VERSION,
        "/components/0",
        QualityState.MISSING,
        (),
        "field_missing",
    )
    result = apply_declaration(check, declaration).as_dict()
    assert result["state"] == "unknown"
    assert result["verification"] == "not_performed"
    assert result["declaration"]["source_path"] == "/components/0/properties/0"
    assert read_quality_declarations([], subject="/components/0/components/0") == ()


@pytest.mark.parametrize("raw", [None, {}, "unknown", [None], [{}], [{"name": 1}]])
def test_malformed_properties_fail(raw: object) -> None:
    with pytest.raises(ValueError):
        read_quality_declarations(raw, subject="/components/0")


@pytest.mark.parametrize(
    "subject",
    [
        None,
        "relative",
        "/components/01",
        "/metadata",
        "/components/0/properties",
        "/components/0\n",
        "/" * 4001,
    ],
)
def test_invalid_subject_is_rejected_even_with_no_declarations(subject: object) -> None:
    with pytest.raises(ValueError):
        read_quality_declarations([], subject=subject)


@pytest.mark.parametrize("state", ["present", "UNKNOWN", " unknown", "", "invalid"])
def test_unrecognized_state_is_not_normalized(state: str) -> None:
    with pytest.raises(ValueError, match="invalid declaration state"):
        read_quality_declarations(properties(state=state), subject="/components/0")


@pytest.mark.parametrize(
    "case",
    [
        "state_missing",
        "reason_missing",
        "state_duplicate",
        "reason_duplicate",
        "unknown_field",
        "unknown_suffix",
        "extra_key",
        "nonstring",
        "empty_reason",
    ],
)
def test_incomplete_or_ambiguous_declaration_fails(case: str) -> None:
    raw = properties()
    if case == "state_missing":
        raw.pop(0)
    elif case == "reason_missing":
        raw.pop()
    elif case == "state_duplicate":
        raw.append(dict(raw[0]))
    elif case == "reason_duplicate":
        raw.append(dict(raw[1]))
    elif case == "unknown_field":
        raw = properties("component_verison")
    elif case == "unknown_suffix":
        raw[0]["name"] = "sbom-ops:quality:component_version:status"
    elif case == "extra_key":
        raw[0]["unexpected"] = "data"
    elif case == "nonstring":
        raw[0]["value"] = None
    else:
        raw[1]["value"] = ""
    with pytest.raises(ValueError):
        read_quality_declarations(raw, subject="/components/0")


def test_other_vendor_properties_do_not_become_declarations() -> None:
    assert (
        read_quality_declarations(
            [
                {"name": "example:version-state", "value": "unknown"},
                {"name": "example:version-state", "value": "withheld"},
            ],
            subject="/components/0",
        )
        == ()
    )


def test_reordered_properties_preserve_actual_source_position() -> None:
    raw = list(reversed(properties()))
    (result,) = read_quality_declarations(raw, subject="/components/1")
    assert result.source_path == "/components/1/properties/1"
    assert result.reason == "Synthetic reason"


def test_invalid_value_is_not_echoed_in_error() -> None:
    with pytest.raises(ValueError) as error:
        read_quality_declarations(
            properties(state="private-value"), subject="/components/0"
        )
    assert "private-value" not in str(error.value)
