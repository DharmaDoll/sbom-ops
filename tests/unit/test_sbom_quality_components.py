import json
from copy import deepcopy
from pathlib import Path

import pytest

from sbom_ops.domain.sbom_quality import QualityCheck, QualityField, QualityState
from sbom_ops.domain.sbom_quality_components import evaluate_components
from sbom_ops.domain.sbom_quality_input import QualityInputError
from sbom_ops.domain.sbom_quality_report import QualityPolicy, QualityRequirement
from sbom_ops.services.sbom_quality import evaluate_sbom_file
from sbom_ops.services.sbom_quality_input import read_quality_input


@pytest.mark.parametrize("version", ["1.5", "1.6"])
def test_eight_component_fields_from_original_file(
    tmp_path: Path, version: str
) -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": version,
        "components": [
            {
                "bom-ref": "library",
                "name": "example",
                "version": "1",
                "author": "Example team",
                "purl": "pkg:generic/example@1",
                "licenses": [{"license": {"name": "Example license"}}],
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            }
        ],
        "dependencies": [{"ref": "library", "dependsOn": []}],
    }
    path = tmp_path / "bom.json"
    raw = json.dumps(document).encode()
    path.write_bytes(raw)
    checks = evaluate_components(read_quality_input(path))
    assert len(checks) == 8
    assert {check.field.value for check in checks} == {
        "component_name",
        "component_version",
        "component_producer",
        "component_identifier",
        "component_license",
        "component_hash",
        "hash_algorithm",
        "dependency_relationship",
    }
    assert all(check.subject == "/components/0" for check in checks)
    assert all(check.state.value == "present" for check in checks)
    assert all(check.as_dict()["verification"] == "not_performed" for check in checks)
    assert path.read_bytes() == raw


def _save(tmp_path: Path, component: dict[str, object], **extra: object) -> Path:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [component],
    } | extra
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    return path


def _field(path: Path, field: str, subject: str = "/components/0") -> QualityCheck:
    return next(
        check
        for check in evaluate_components(read_quality_input(path))
        if check.field.value == field and check.subject == subject
    )


def test_nested_components_are_not_inherited_from_parent(tmp_path: Path) -> None:
    path = _save(
        tmp_path,
        {
            "name": "parent",
            "version": "1",
            "author": "parent team",
            "components": [{"name": "child"}],
        },
    )
    checks = evaluate_components(read_quality_input(path))
    assert len(checks) == 16
    assert (
        _field(path, "component_producer", "/components/0/components/0").state.value
        == "missing"
    )
    assert (
        _field(path, "component_version", "/components/0/components/0").state.value
        == "missing"
    )
    assert _field(
        path, "component_name", "/components/0/components/0"
    ).evidence_paths == ("/components/0/components/0/name",)


def test_manufacture_applies_only_to_target_not_children(tmp_path: Path) -> None:
    path = _save(
        tmp_path,
        {"name": "library"},
        metadata={"component": {"name": "app"}, "manufacture": {"name": "maker"}},
    )
    assert _field(path, "component_producer", "/metadata/component").evidence_paths == (
        "/metadata/manufacture/name",
    )
    assert _field(path, "component_producer").state.value == "missing"


@pytest.mark.parametrize("version,expected", [("1.5", "missing"), ("1.6", "present")])
def test_new_producer_fields_are_version_specific(
    tmp_path: Path, version: str, expected: str
) -> None:
    path = _save(
        tmp_path,
        {
            "manufacturer": {"name": "maker"},
            "authors": [{"email": "dev@example.invalid"}],
        },
        specVersion=version,
    )
    assert _field(path, "component_producer").state.value == expected


@pytest.mark.parametrize("value", [None, 42, "", "\n"])
def test_bad_component_text(tmp_path: Path, value: object) -> None:
    path = _save(tmp_path, {"name": value, "version": value})
    assert _field(path, "component_name").state.value == "invalid"
    assert _field(path, "component_version").state.value == "invalid"


@pytest.mark.parametrize(
    "hashes,expected",
    [
        ([{"alg": "SHA-256", "content": "a" * 64}], "present"),
        ([{"alg": "SHA-512", "content": "A" * 128}], "present"),
        ([{"alg": "SHA-256", "content": "a" * 40}], "invalid"),
        ([{"alg": "SHA-256"}, {"content": "a" * 64}], "invalid"),
        ([{"alg": "SHA-256", "content": "x" * 64}], "invalid"),
        ([{"alg": [], "content": "a" * 64}], "invalid"),
        ([{"alg": "invented", "content": "a" * 64}], "invalid"),
        ([{"alg": "BLAKE3", "content": "a" * 64}], "unverifiable"),
        ([], "invalid"),
        (None, "invalid"),
    ],
)
def test_hash_value_and_algorithm_are_a_pair(
    tmp_path: Path, hashes: object, expected: str
) -> None:
    path = _save(tmp_path, {"hashes": hashes})
    for field in ("component_hash", "hash_algorithm"):
        check = _field(path, field)
        assert check.state.value == expected
        assert check.as_dict()["verification"] == "not_performed"


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"bom-ref": "pkg:generic/example@1"}, "missing"),
        ({"purl": "pkg:generic/example@1"}, "present"),
        ({"purl": "not-a-purl"}, "invalid"),
        ({"purl": 42}, "invalid"),
        ({"swid": {"tagId": "tag-1", "name": "example"}}, "present"),
        ({"swid": {}}, "invalid"),
    ],
)
def test_identifiers_are_not_invented_from_bom_ref(
    tmp_path: Path, value: dict[str, object], expected: str
) -> None:
    assert (
        _field(_save(tmp_path, value), "component_identifier").state.value == expected
    )


@pytest.mark.parametrize(
    "licenses,expected",
    [
        ([{"license": {"name": "License text"}}], "present"),
        ([{"license": {"id": "MIT"}}], "unverifiable"),
        ([{"expression": "MIT OR Apache-2.0"}], "unverifiable"),
        ([{"license": {"id": "MIT", "name": "MIT"}}], "invalid"),
        ([{"expression": "MIT"}, {"expression": "Apache-2.0"}], "invalid"),
        ([{"license": {"name": 42}}], "invalid"),
        ([], "invalid"),
        (None, "invalid"),
    ],
)
def test_license_shapes_without_claiming_spdx_validation(
    tmp_path: Path, licenses: object, expected: str
) -> None:
    path = _save(tmp_path, {"licenses": licenses})
    assert _field(path, "component_license").state.value == expected


@pytest.mark.parametrize(
    "rows,expected",
    [
        ([{"ref": "a", "dependsOn": []}], "present"),
        ([{"ref": "a"}], "unverifiable"),
        ([], "missing"),
        ([{"ref": "a", "dependsOn": ["unknown"]}], "invalid"),
        ([{"ref": "a", "dependsOn": ["a", "a"]}], "invalid"),
        ([{"ref": "unknown", "dependsOn": []}], "invalid"),
        ([{"ref": "a", "dependsOn": []}, {"ref": "a", "dependsOn": []}], "invalid"),
        ([{"ref": "a", "dependsOn": [42]}], "invalid"),
        ([{"ref": "a", "dependsOn": None}], "invalid"),
        (None, "invalid"),
    ],
)
def test_dependency_rows_are_not_completeness_proof(
    tmp_path: Path, rows: object, expected: str
) -> None:
    path = _save(tmp_path, {"bom-ref": "a"}, dependencies=rows)
    check = _field(path, "dependency_relationship")
    assert check.state.value == expected
    if expected == "present":
        assert check.reason == "local_references_resolved_completeness_unverified"


def test_duplicate_bom_ref_makes_relationships_ambiguous(tmp_path: Path) -> None:
    path = _save(
        tmp_path,
        {"bom-ref": "same", "components": [{"bom-ref": "same"}]},
        dependencies=[{"ref": "same", "dependsOn": []}],
    )
    relationships = [
        check
        for check in evaluate_components(read_quality_input(path))
        if check.field.value == "dependency_relationship"
    ]
    assert len(relationships) == 2
    assert all(check.state.value == "invalid" for check in relationships)
    assert all(
        check.reason == "invalid_or_duplicate_bom_ref" for check in relationships
    )


def test_service_is_a_valid_target_but_author_is_not(tmp_path: Path) -> None:
    path = _save(
        tmp_path,
        {"bom-ref": "a"},
        services=[{"bom-ref": "service", "name": "api"}],
        dependencies=[{"ref": "a", "dependsOn": ["service"]}],
    )
    assert _field(path, "dependency_relationship").state.value == "present"
    path = _save(
        tmp_path,
        {"bom-ref": "a"},
        metadata={"authors": [{"bom-ref": "person", "name": "dev"}]},
        dependencies=[{"ref": "a", "dependsOn": ["person"]}],
    )
    assert _field(path, "dependency_relationship").state.value == "invalid"


def test_component_declarations_do_not_propagate(tmp_path: Path) -> None:
    path = _save(
        tmp_path,
        {
            "properties": [
                {
                    "name": "sbom-ops:quality:component_version:state",
                    "value": "unknown",
                },
                {
                    "name": "sbom-ops:quality:component_version:reason",
                    "value": "not supplied",
                },
            ],
            "components": [{}],
        },
    )
    assert _field(path, "component_version").state.value == "unknown"
    assert (
        _field(path, "component_version", "/components/0/components/0").state.value
        == "missing"
    )


def test_malformed_graph_without_components_is_not_success(tmp_path: Path) -> None:
    path = _save(
        tmp_path, {}, components=[], dependencies=[{"ref": "unknown", "dependsOn": []}]
    )
    with pytest.raises(QualityInputError, match="^invalid_dependency_graph$"):
        evaluate_sbom_file(path)


def test_quick_start_file_to_complete_report_and_explicit_policy() -> None:
    path = Path("examples/sboms/vulnerable-demo.cdx.json")
    before = path.read_bytes()
    report = evaluate_sbom_file(path)
    assert len(report["checks"]) == 49
    assert sum(report["summary"].values()) == 49
    assert report["scope"]["component_count"] == 5
    assert report["exit_code"] == 0
    policy = QualityPolicy(
        "required-hashes",
        (QualityRequirement(QualityField.COMPONENT_HASH, (QualityState.PRESENT,)),),
    )
    enforced = evaluate_sbom_file(path, policy=policy)
    assert enforced["exit_code"] == 1
    assert len(enforced["policy"]["violations"]) == 5
    assert enforced["checks"] == report["checks"]
    assert path.read_bytes() == before


def test_evaluator_does_not_mutate_decoded_input(tmp_path: Path) -> None:
    source = read_quality_input(_save(tmp_path, {"name": "example"}))
    before = deepcopy(source.document)
    evaluate_components(source)
    assert source.document == before
