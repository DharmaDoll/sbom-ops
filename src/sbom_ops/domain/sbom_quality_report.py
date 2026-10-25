"""Complete quality observations and explicitly selected CI requirements."""

import re
from dataclasses import asdict, dataclass

from sbom_ops.domain.sbom_quality import QualityCheck, QualityField, QualityState
from sbom_ops.domain.sbom_quality_declarations import DOCUMENT_FIELDS
from sbom_ops.domain.sbom_quality_input import QualityInput, QualityInputLimits

EVALUATOR_VERSION = "sbom-quality-v1"
LIMITATIONS = (
    "signature_cryptography_not_verified",
    "component_artifact_hashes_not_verified",
    "dependency_completeness_not_verified",
    "update_and_distribution_practices_not_verified",
    "full_cyclonedx_schema_not_validated",
    "identifier_semantics_not_verified",
    "spdx_catalog_and_expression_not_validated",
    "no_compliance_certification",
)


@dataclass(frozen=True)
class QualityRequirement:
    field: QualityField
    allowed_states: tuple[QualityState, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.field, QualityField)
            or not isinstance(self.allowed_states, tuple)
            or not self.allowed_states
            or any(not isinstance(state, QualityState) for state in self.allowed_states)
            or len(set(self.allowed_states)) != len(self.allowed_states)
        ):
            raise ValueError("invalid quality requirement")


@dataclass(frozen=True)
class QualityPolicy:
    version: str = "report-only-v1"
    requirements: tuple[QualityRequirement, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.version, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.version) is None
            or not isinstance(self.requirements, tuple)
            or any(
                not isinstance(rule, QualityRequirement) for rule in self.requirements
            )
        ):
            raise ValueError("invalid quality policy")
        if len({rule.field for rule in self.requirements}) != len(self.requirements):
            raise ValueError("duplicate quality requirement")


REPORT_ONLY = QualityPolicy()


def parse_quality_policy(value: object) -> QualityPolicy:
    """Strict versioned policy data; do not infer missing requirements."""
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "version", "requirements"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["requirements"], list)
        or len(value["requirements"]) > len(QualityField)
    ):
        raise ValueError("invalid quality policy document")
    requirements = []
    for item in value["requirements"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"field", "allowed_states"}
            or not isinstance(item["field"], str)
            or not isinstance(item["allowed_states"], list)
            or len(item["allowed_states"]) > len(QualityState)
            or any(not isinstance(state, str) for state in item["allowed_states"])
        ):
            raise ValueError("invalid quality requirement document")
        try:
            field = QualityField(item["field"])
            states = tuple(QualityState(state) for state in item["allowed_states"])
        except ValueError:
            raise ValueError("unknown quality policy value") from None
        requirements.append(QualityRequirement(field, states))
    return QualityPolicy(value["version"], tuple(requirements))


def build_quality_report(
    source: QualityInput,
    checks: tuple[QualityCheck, ...],
    *,
    policy: QualityPolicy = REPORT_ONLY,
) -> dict[str, object]:
    """Assemble a fresh JSON-ready report; never mutate observations or policy."""
    _validate_source(source)
    if not isinstance(policy, QualityPolicy):
        raise ValueError("typed quality policy required")
    if not isinstance(checks, tuple) or any(
        not isinstance(check, QualityCheck) for check in checks
    ):
        raise ValueError("immutable typed quality checks required")
    expected = {
        (subject, field)
        for field in QualityField
        for subject in (
            ("",) if field in DOCUMENT_FIELDS else source.component_subjects
        )
    }
    actual = {(check.subject, check.field) for check in checks}
    if actual != expected or len(actual) != len(checks):
        raise ValueError("incomplete or duplicate quality checks")
    ordered = sorted(checks, key=lambda check: (check.subject, check.field.value))
    summary = {state.value: 0 for state in QualityState}
    for check in ordered:
        summary[check.state.value] += 1
    requirements = sorted(policy.requirements, key=lambda rule: rule.field.value)
    violations = []
    for rule in requirements:
        applicable = [check for check in ordered if check.field is rule.field]
        if not applicable:
            # A required component field must not pass vacuously on an empty BOM.
            violations.append(
                {
                    "field": rule.field.value,
                    "subject": None,
                    "state": None,
                    "reason": "no_applicable_components",
                }
            )
        for check in applicable:
            if check.state not in rule.allowed_states:
                violations.append(
                    {
                        "field": check.field.value,
                        "subject": check.subject,
                        "state": check.state.value,
                        "reason": "state_not_allowed",
                    }
                )
    return {
        "schema_version": 1,
        "evaluator_version": EVALUATOR_VERSION,
        "policy_version": policy.version,
        "status": "evaluated",
        "exit_code": 1 if violations else 0,
        "input": {"sha256": source.sha256, "byte_count": source.byte_count},
        "scope": {
            "format_name": "CycloneDX",
            "format_version": source.document["specVersion"],
            "component_count": len(source.component_subjects),
            "limits": asdict(source.limits),
        },
        "checks": [check.as_dict() for check in ordered],
        "summary": summary,
        "limitations": list(LIMITATIONS),
        "policy": {
            "mode": "enforce" if requirements else "report",
            "requirements": [
                {
                    "field": rule.field.value,
                    "allowed_states": sorted(
                        state.value for state in rule.allowed_states
                    ),
                }
                for rule in requirements
            ],
            "violations": violations,
        },
    }


def _validate_source(source: QualityInput) -> None:
    if (
        not isinstance(source, QualityInput)
        or not isinstance(source.limits, QualityInputLimits)
        or not isinstance(source.sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", source.sha256) is None
        or type(source.byte_count) is not int
        or not 0 < source.byte_count <= source.limits.max_bytes
        or not isinstance(source.document, dict)
        or source.document.get("bomFormat") != "CycloneDX"
        or source.document.get("specVersion") not in ("1.5", "1.6")
        or not isinstance(source.component_subjects, tuple)
        or len(source.component_subjects) > source.limits.max_components
    ):
        raise ValueError("invalid quality source")
    for subject in source.component_subjects:
        if (
            not isinstance(subject, str)
            or len(subject) > 4000
            or re.fullmatch(
                r"(?:/metadata/component(?:/components/(?:0|[1-9][0-9]*))*"
                r"|(?:/components/(?:0|[1-9][0-9]*))+)",
                subject,
            )
            is None
        ):
            raise ValueError("invalid component subject")
    if len(set(source.component_subjects)) != len(source.component_subjects):
        raise ValueError("duplicate component subject")
