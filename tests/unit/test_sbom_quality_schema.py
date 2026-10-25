import json
import socket
import sys
from copy import deepcopy
from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from sbom_ops import cli
from sbom_ops.domain.sbom_quality import QualityField, QualityState
from sbom_ops.domain.sbom_quality_report import QualityPolicy, QualityRequirement
from sbom_ops.services.sbom_quality import evaluate_sbom_file


@pytest.fixture
def validator() -> Draft202012Validator:
    schema = json.loads(
        files("sbom_ops")
        .joinpath("data/sbom-quality-report.schema.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_packaged_schema_accepts_real_report(validator: Draft202012Validator) -> None:
    report = evaluate_sbom_file(Path("examples/sboms/vulnerable-demo.cdx.json"))
    validator.validate(report)


@pytest.mark.parametrize(
    "field,expected",
    [(QualityField.COMPONENT_NAME, 0), (QualityField.COMPONENT_HASH, 1)],
)
def test_enforced_outputs(
    validator: Draft202012Validator, field: QualityField, expected: int
) -> None:
    report = evaluate_sbom_file(
        Path("examples/sboms/vulnerable-demo.cdx.json"),
        policy=QualityPolicy(
            "test-v1", (QualityRequirement(field, (QualityState.PRESENT,)),)
        ),
    )
    assert report["exit_code"] == expected
    validator.validate(report)


@pytest.mark.parametrize("state", ["unknown", "withheld"])
@pytest.mark.parametrize("conflict", [False, True])
def test_declared_states_and_conflicts(
    validator: Draft202012Validator, tmp_path: Path, state: str, conflict: bool
) -> None:
    component = {
        "name": "example",
        "properties": [
            {"name": "sbom-ops:quality:component_version:state", "value": state},
            {
                "name": "sbom-ops:quality:component_version:reason",
                "value": "author statement",
            },
        ],
    }
    if conflict:
        component["version"] = "1"
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [component]}
        )
    )
    report = evaluate_sbom_file(path)
    check = next(
        check for check in report["checks"] if check["field"] == "component_version"
    )
    assert check["state"] == ("invalid" if conflict else state)
    validator.validate(report)


def test_unverifiable_observation_and_zero_component_violation(
    validator: Draft202012Validator, tmp_path: Path
) -> None:
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"lifecycles": [{"name": "custom"}]},
            }
        )
    )
    report = evaluate_sbom_file(
        path,
        policy=QualityPolicy(
            "test-v1",
            (QualityRequirement(QualityField.COMPONENT_NAME, (QualityState.PRESENT,)),),
        ),
    )
    assert report["summary"]["unverifiable"] == 1
    assert report["policy"]["violations"][0]["subject"] is None
    validator.validate(report)


@pytest.mark.parametrize("interrupted", [False, True])
def test_real_cli_error_outputs(
    validator: Draft202012Validator,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    interrupted: bool,
) -> None:
    def interrupt(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    if interrupted:
        monkeypatch.setattr("sbom_ops.sbom_quality_cli.evaluate_sbom_file", interrupt)
    monkeypatch.setattr(
        sys, "argv", ["sbom-ops", "sbom-quality", str(tmp_path / "missing.json")]
    )
    assert cli.main() == (130 if interrupted else 2)
    report = json.loads(capsys.readouterr().out)
    validator.validate(report)
    report["policy_version"] = None
    validator.validate(report)
    report["summary"] = {"present": 0}
    with pytest.raises(ValidationError):
        validator.validate(report)


@pytest.mark.parametrize(
    "location,value",
    [
        (("schema_version",), 2),
        (("schema_version",), True),
        (("policy_version",), None),
        (("extra",), "not part of contract"),
        (("status",), "error"),
        (("exit_code",), 2),
        (("exit_code",), 1),
        (("input", "sha256"), "not-a-digest"),
        (("input", "sha256"), "a" * 64 + "\n"),
        (("policy_version",), "v1\n"),
        (("checks", 0, "evidence_paths"), ["/bomFormat\n"]),
        (("checks", 0, "reason"), "recorded\n"),
        (("input", "byte_count"), -1),
        (("summary", "present"), -1),
        (("summary", "missing"), "24"),
        (("limitations",), []),
        (("checks",), []),
        (("scope", "limits", "max_bytes"), 0),
        (("scope", "format_version"), "2.0"),
        (("checks", 0, "verification"), "verified"),
        (("checks", 0, "evidence_paths"), []),
        (("checks", 0, "subject"), "/components/0"),
        (("checks", 0, "state"), "typo"),
        (("checks", 0, "field"), "typo"),
        (("checks", 0, "evidence_paths"), ["/bad~escape"]),
        (
            ("checks", 0, "declaration"),
            {
                "state": "unknown",
                "source_path": "/metadata/properties/0",
                "reason": "not supplied",
            },
        ),
        (("policy", "mode"), "enforce"),
    ],
)
def test_malformed_report_mutations_are_rejected(
    validator: Draft202012Validator, location: tuple, value: object
) -> None:
    report = evaluate_sbom_file(Path("examples/sboms/vulnerable-demo.cdx.json"))
    target = report
    for key in location[:-1]:
        target = target[key]
    target[location[-1]] = deepcopy(value)
    with pytest.raises(ValidationError):
        validator.validate(report)


def test_unknown_requires_matching_declaration(validator: Draft202012Validator) -> None:
    report = evaluate_sbom_file(Path("examples/sboms/vulnerable-demo.cdx.json"))
    check = next(check for check in report["checks"] if check["state"] == "missing")
    check["state"] = "unknown"
    with pytest.raises(ValidationError):
        validator.validate(report)
    check["declaration"] = {
        "state": "withheld",
        "source_path": "/metadata/properties/0",
        "reason": "not supplied",
    }
    with pytest.raises(ValidationError):
        validator.validate(report)


def test_all_refs_are_local_and_validation_uses_no_network(
    validator: Draft202012Validator, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("schema validation must be offline")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    pending = [validator.schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "$ref" in value:
                assert value["$ref"].startswith("#/")
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    validator.validate(
        evaluate_sbom_file(Path("examples/sboms/vulnerable-demo.cdx.json"))
    )
