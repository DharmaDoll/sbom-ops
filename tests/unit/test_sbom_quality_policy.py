import json
import sys
from pathlib import Path

import pytest

from sbom_ops import cli
from sbom_ops.domain.sbom_quality import QualityField, QualityState
from sbom_ops.domain.sbom_quality_input import QualityInputError
from sbom_ops.services.sbom_quality_policy import load_quality_policy


def test_policy_file_preserves_explicit_requirements(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    raw = json.dumps(
        {
            "schema_version": 1,
            "version": "company-v1",
            "requirements": [
                {"field": "component_version", "allowed_states": ["present", "unknown"]}
            ],
        }
    ).encode()
    path.write_bytes(raw)
    result = load_quality_policy(path)
    assert result.version == "company-v1"
    assert len(result.requirements) == 1
    assert result.requirements[0].field is QualityField.COMPONENT_VERSION
    assert result.requirements[0].allowed_states == (
        QualityState.PRESENT,
        QualityState.UNKNOWN,
    )
    assert path.read_bytes() == raw


def _policy(**changes: object) -> dict[str, object]:
    return {"schema_version": 1, "version": "test-v1", "requirements": []} | changes


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        {},
        _policy(schema_version=True),
        _policy(schema_version=2),
        _policy(version=""),
        _policy(version="secret\n"),
        _policy(version=42),
        _policy(extra="ignored?"),
        _policy(requirements=None),
        _policy(requirements=[{}]),
        _policy(requirements=[None]),
        _policy(requirements=[{"field": "typo", "allowed_states": ["present"]}]),
        _policy(requirements=[{"field": "component_name", "allowed_states": []}]),
        _policy(requirements=[{"field": "component_name", "allowed_states": ["typo"]}]),
        _policy(requirements=[{"field": "component_name", "allowed_states": [42]}]),
        _policy(
            requirements=[{"field": "component_name", "allowed_states": "present"}]
        ),
        _policy(
            requirements=[
                {"field": "component_name", "allowed_states": ["present", "present"]}
            ]
        ),
        _policy(
            requirements=[
                {
                    "field": "component_name",
                    "allowed_states": ["present"],
                    "extra": True,
                }
            ]
        ),
        _policy(
            requirements=[{"field": "component_name", "allowed_states": ["present"]}]
            * 2
        ),
    ],
)
def test_bad_policy_does_not_fall_back_to_report_only(
    tmp_path: Path, document: object
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document))
    with pytest.raises(QualityInputError, match="^invalid_policy$"):
        load_quality_policy(path)


@pytest.mark.parametrize(
    "raw,code",
    [
        (b'{"version":"private","version":"other"}', "policy_duplicate_json_key"),
        (b'{"private":NaN}', "policy_invalid_json"),
        (b'{"private":"\xff"}', "policy_invalid_utf8"),
        (b"[" * 9 + b"]" * 9, "policy_depth_limit_exceeded"),
    ],
)
def test_strict_json_read_errors_are_identified_as_policy_errors(
    tmp_path: Path, raw: bytes, code: str
) -> None:
    path = tmp_path / "private-policy.json"
    path.write_bytes(raw)
    with pytest.raises(QualityInputError) as caught:
        load_quality_policy(path)
    assert str(caught.value) == code


def test_policy_size_boundary(tmp_path: Path) -> None:
    raw = json.dumps(_policy()).encode()
    path = tmp_path / "policy.json"
    raw += b" " * (32 * 1024 - len(raw))
    path.write_bytes(raw)
    assert load_quality_policy(path).requirements == ()
    path.write_bytes(raw + b" ")
    with pytest.raises(QualityInputError, match="^policy_byte_limit_exceeded$"):
        load_quality_policy(path)


@pytest.mark.parametrize("declaration,expected", [(False, 1), (True, 0)])
def test_cli_unknown_requires_explicit_declaration_not_just_a_missing_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    declaration: bool,
    expected: int,
) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            _policy(
                requirements=[
                    {
                        "field": "component_version",
                        "allowed_states": ["present", "unknown"],
                    }
                ]
            )
        )
    )
    component = {"name": "example"}
    if declaration:
        component["properties"] = [
            {"name": "sbom-ops:quality:component_version:state", "value": "unknown"},
            {
                "name": "sbom-ops:quality:component_version:reason",
                "value": "not supplied",
            },
        ]
    bom = tmp_path / "bom.json"
    bom.write_text(
        json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [component]}
        )
    )
    monkeypatch.setattr(
        sys, "argv", ["sbom-ops", "sbom-quality", str(bom), "--policy", str(policy)]
    )
    assert cli.main() == expected
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert captured.err == ""
    assert result["policy_version"] == "test-v1"
    observation = next(
        check for check in result["checks"] if check["field"] == "component_version"
    )
    assert observation["state"] == ("unknown" if declaration else "missing")


def test_example_policy_runs_against_quick_start(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "sbom-quality",
            "examples/sboms/vulnerable-demo.cdx.json",
            "--policy",
            "examples/sbom-quality-policy.example.json",
        ],
    )
    assert cli.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["policy_version"] == "example-inventory-basics-v1"
    assert result["policy"]["mode"] == "enforce"
    assert len(result["checks"]) == 49


@pytest.mark.parametrize(
    "extra", [["--require", "component_name"], ["--policy-version", "override"]]
)
def test_policy_file_cannot_be_silently_overridden(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "sbom-quality",
            "unused.json",
            "--policy",
            "unused-policy.json",
            *extra,
        ],
    )
    if extra[0] == "--require":
        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == 2
        assert capsys.readouterr().out == ""
    else:
        assert cli.main() == 2
        assert json.loads(capsys.readouterr().out)["error"]["code"] == "invalid_policy"


def test_failed_policy_load_is_not_identified_as_default_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "private-missing.json"
    monkeypatch.setattr(
        sys, "argv", ["sbom-ops", "sbom-quality", "unused.json", "--policy", str(path)]
    )
    assert cli.main() == 2
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["policy_version"] is None
    assert result["error"]["code"] == "policy_read_failed"
    assert "checks" not in result
    assert "private-missing" not in captured.out + captured.err
