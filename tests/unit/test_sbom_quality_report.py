import json
from dataclasses import replace
from pathlib import Path

import pytest

from sbom_ops.domain.sbom_quality import (
    QualityCheck,
    QualityDeclaration,
    QualityField,
    QualityState,
    apply_declaration,
)
from sbom_ops.domain.sbom_quality_declarations import DOCUMENT_FIELDS
from sbom_ops.domain.sbom_quality_input import QualityInput
from sbom_ops.domain.sbom_quality_report import (
    QualityPolicy,
    QualityRequirement,
    build_quality_report,
)
from sbom_ops.services.sbom_quality_input import read_quality_input


def test_report_only_and_explicit_required_field_differ(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{}]}')
    source = read_quality_input(path)
    checks = tuple(
        QualityCheck(field, subject, QualityState.MISSING, (), "not_recorded")
        for field in QualityField
        for subject in (("",) if field in DOCUMENT_FIELDS else ("/components/0",))
    )
    report = build_quality_report(source, checks)
    policy = QualityPolicy(
        "company-v1",
        (QualityRequirement(QualityField.COMPONENT_VERSION, (QualityState.PRESENT,)),),
    )
    enforced = build_quality_report(source, checks, policy=policy)

    assert report["exit_code"] == 0
    assert report["status"] == "evaluated"
    assert report["summary"] == {
        "present": 0,
        "missing": 17,
        "unknown": 0,
        "withheld": 0,
        "invalid": 0,
        "unverifiable": 0,
    }
    assert report["policy"] == {"mode": "report", "requirements": [], "violations": []}
    assert enforced["checks"] == report["checks"]
    assert enforced["summary"] == report["summary"]
    assert enforced["exit_code"] == 1
    assert enforced["policy"]["violations"] == [
        {
            "field": "component_version",
            "subject": "/components/0",
            "state": "missing",
            "reason": "state_not_allowed",
        }
    ]


def _observations(
    tmp_path: Path, components: int = 2
) -> tuple[QualityInput, tuple[QualityCheck, ...]]:
    path = tmp_path / "sample.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"name": "synthetic"}] * components,
            }
        )
    )
    source = read_quality_input(path)
    checks = tuple(
        QualityCheck(field, subject, QualityState.MISSING, (), "not_recorded")
        for field in QualityField
        for subject in (
            ("",) if field in DOCUMENT_FIELDS else source.component_subjects
        )
    )
    return source, checks


def test_exact_coverage_and_stable_order(tmp_path: Path) -> None:
    source, checks = _observations(tmp_path)
    report = build_quality_report(source, checks)
    assert report == build_quality_report(source, tuple(reversed(checks)))
    assert len(report["checks"]) == 9 + 8 * 2
    assert sum(report["summary"].values()) == 25
    assert report["scope"]["component_count"] == 2
    assert report["input"] == {"sha256": source.sha256, "byte_count": source.byte_count}
    assert report["schema_version"] == 1
    assert report["evaluator_version"] == "sbom-quality-v1"
    assert report["policy_version"] == "report-only-v1"
    assert report["scope"]["limits"]["max_bytes"] == 32 * 1024 * 1024
    assert all(check["verification"] == "not_performed" for check in report["checks"])


@pytest.mark.parametrize("damage", ["missing", "duplicate", "extra", "wrong_scope"])
def test_incomplete_or_mis_scoped_checks_cannot_be_success(
    tmp_path: Path, damage: str
) -> None:
    source, checks = _observations(tmp_path)
    if damage == "missing":
        checks = checks[:-1]
    elif damage == "duplicate":
        checks += (checks[0],)
    elif damage == "extra":
        checks += (replace(checks[-1], subject="/components/20"),)
    else:
        checks = (replace(checks[0], subject="/components/0"),) + checks[1:]
    with pytest.raises(ValueError, match="incomplete or duplicate"):
        build_quality_report(source, checks)


def test_component_requirement_cannot_pass_with_zero_components(tmp_path: Path) -> None:
    source, checks = _observations(tmp_path, components=0)
    policy = QualityPolicy(
        "empty-test",
        (QualityRequirement(QualityField.COMPONENT_NAME, (QualityState.PRESENT,)),),
    )
    report = build_quality_report(source, checks, policy=policy)
    assert report["exit_code"] == 1
    assert report["policy"]["violations"] == [
        {
            "field": "component_name",
            "subject": None,
            "state": None,
            "reason": "no_applicable_components",
        }
    ]
    assert len(report["checks"]) == 9


def test_each_component_is_checked_and_unselected_fields_do_not_fail(
    tmp_path: Path,
) -> None:
    source, checks = _observations(tmp_path)
    checks = tuple(
        (
            replace(
                check,
                state=QualityState.PRESENT,
                evidence_paths=("/components/0/name",),
            )
            if check.field is QualityField.COMPONENT_NAME
            and check.subject == "/components/0"
            else check
        )
        for check in checks
    )
    policy = QualityPolicy(
        "names",
        (QualityRequirement(QualityField.COMPONENT_NAME, (QualityState.PRESENT,)),),
    )
    report = build_quality_report(source, checks, policy=policy)
    assert report["policy"]["violations"] == [
        {
            "field": "component_name",
            "subject": "/components/1",
            "state": "missing",
            "reason": "state_not_allowed",
        }
    ]
    assert report["summary"]["missing"] == 24


def test_explicit_allowed_states_do_not_rewrite_observations(tmp_path: Path) -> None:
    source, checks = _observations(tmp_path)
    policy = QualityPolicy(
        "temporary-reporting",
        (QualityRequirement(QualityField.SBOM_SIGNATURE, (QualityState.MISSING,)),),
    )
    report = build_quality_report(source, checks, policy=policy)
    assert report["exit_code"] == 0
    assert report["policy"]["mode"] == "enforce"
    assert report["policy"]["violations"] == []
    assert report["summary"]["missing"] == 25
    assert "signature_cryptography_not_verified" in report["limitations"]
    assert "no_compliance_certification" in report["limitations"]
    report["checks"].clear()
    report["scope"]["limits"]["max_bytes"] = 1
    assert len(build_quality_report(source, checks)["checks"]) == 25
    assert source.limits.max_bytes == 32 * 1024 * 1024


@pytest.mark.parametrize("states", [(), [], ("present",), (QualityState.PRESENT,) * 2])
def test_invalid_required_states_rejected(states: object) -> None:
    with pytest.raises(ValueError, match="invalid quality requirement"):
        QualityRequirement(QualityField.COMPONENT_NAME, states)


@pytest.mark.parametrize("version", ["", " company", "company\n", "x" * 129, None])
def test_invalid_policy_version_rejected(version: object) -> None:
    with pytest.raises(ValueError, match="invalid quality policy"):
        QualityPolicy(version)


def test_duplicate_policy_requirements_rejected() -> None:
    rule = QualityRequirement(QualityField.COMPONENT_NAME, (QualityState.PRESENT,))
    with pytest.raises(ValueError, match="duplicate quality requirement"):
        QualityPolicy("v1", (rule, rule))


@pytest.mark.parametrize(
    "change",
    [
        {"sha256": "not-a-hash"},
        {"byte_count": True},
        {"byte_count": 0},
        {"component_subjects": ("/components/0", "/components/0")},
        {"component_subjects": ("/metadata/tools/components/0",)},
    ],
)
def test_invalid_source_rejected(tmp_path: Path, change: dict[str, object]) -> None:
    source, checks = _observations(tmp_path)
    with pytest.raises(ValueError):
        build_quality_report(replace(source, **change), checks)


@pytest.mark.parametrize("state", list(QualityState))
def test_all_six_states_are_preserved_and_only_allowed_states_pass(
    tmp_path: Path, state: QualityState
) -> None:
    source, checks = _observations(tmp_path)
    observation = next(
        check for check in checks if check.field is QualityField.SBOM_SIGNATURE
    )
    if state in {QualityState.UNKNOWN, QualityState.WITHHELD}:
        observation = apply_declaration(
            observation,
            QualityDeclaration(
                QualityField.SBOM_SIGNATURE,
                "",
                state,
                "/metadata/properties/0",
                "author statement",
            ),
        )
    elif state is not QualityState.MISSING:
        observation = replace(observation, state=state, evidence_paths=("/signature",))
    checks = tuple(
        observation if check.field is observation.field else check for check in checks
    )
    policy = QualityPolicy(
        "selected-state", (QualityRequirement(observation.field, (state,)),)
    )
    allowed = build_quality_report(source, checks, policy=policy)
    required_present = build_quality_report(
        source,
        checks,
        policy=QualityPolicy(
            "present", (QualityRequirement(observation.field, (QualityState.PRESENT,)),)
        ),
    )
    assert allowed["exit_code"] == 0
    assert required_present["exit_code"] == (0 if state is QualityState.PRESENT else 1)
    assert allowed["checks"] == required_present["checks"]
    emitted = next(
        check for check in allowed["checks"] if check["field"] == "sbom_signature"
    )
    assert emitted == observation.as_dict()
    assert emitted["verification"] == "not_performed"
    assert "signature_cryptography_not_verified" in allowed["limitations"]


def test_policy_order_does_not_change_report(tmp_path: Path) -> None:
    source, checks = _observations(tmp_path)
    first = QualityRequirement(
        QualityField.TOOL_NAME, (QualityState.PRESENT, QualityState.UNKNOWN)
    )
    second = QualityRequirement(QualityField.COMPONENT_NAME, (QualityState.PRESENT,))
    assert build_quality_report(
        source, checks, policy=QualityPolicy("v1", (first, second))
    ) == build_quality_report(
        source,
        tuple(reversed(checks)),
        policy=QualityPolicy(
            "v1",
            (
                second,
                replace(first, allowed_states=tuple(reversed(first.allowed_states))),
            ),
        ),
    )
