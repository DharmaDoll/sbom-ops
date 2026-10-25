"""SBOM quality observations, not compliance or authenticity decisions."""

import re
from dataclasses import dataclass, replace
from enum import StrEnum


class QualityField(StrEnum):
    SBOM_AUTHOR = "sbom_author"
    SBOM_SIGNATURE = "sbom_signature"
    FORMAT_NAME = "format_name"
    FORMAT_VERSION = "format_version"
    GENERATION_CONTEXT = "generation_context"
    TIMESTAMP = "timestamp"
    TOOL_NAME = "tool_name"
    TOOL_VERSION = "tool_version"
    SBOM_VERSION = "sbom_version"
    COMPONENT_PRODUCER = "component_producer"
    DEPENDENCY_RELATIONSHIP = "dependency_relationship"
    COMPONENT_HASH = "component_hash"
    HASH_ALGORITHM = "hash_algorithm"
    COMPONENT_IDENTIFIER = "component_identifier"
    COMPONENT_LICENSE = "component_license"
    COMPONENT_NAME = "component_name"
    COMPONENT_VERSION = "component_version"


class QualityState(StrEnum):
    PRESENT = "present"
    MISSING = "missing"
    UNKNOWN = "unknown"
    WITHHELD = "withheld"
    INVALID = "invalid"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class QualityDeclaration:
    field: QualityField
    subject: str
    state: QualityState
    source_path: str
    reason: str

    def __post_init__(self) -> None:
        _identity(self.field, self.subject)
        if not isinstance(self.state, QualityState) or self.state not in {
            QualityState.UNKNOWN,
            QualityState.WITHHELD,
        }:
            raise ValueError("declaration must explicitly state unknown or withheld")
        _pointer(self.source_path)
        if not self.source_path:
            raise ValueError("declaration requires an evidence location")
        _text(self.reason)


@dataclass(frozen=True)
class QualityCheck:
    field: QualityField
    subject: str
    state: QualityState
    evidence_paths: tuple[str, ...]
    reason: str
    declaration: QualityDeclaration | None = None

    def __post_init__(self) -> None:
        _identity(self.field, self.subject)
        if not isinstance(self.state, QualityState):
            raise ValueError("typed quality state required")
        _text(self.reason)
        if not isinstance(self.evidence_paths, tuple):
            raise ValueError("immutable evidence locations required")
        for path in self.evidence_paths:
            _pointer(path)
        if len(set(self.evidence_paths)) != len(self.evidence_paths):
            raise ValueError("duplicate evidence locations")
        if self.state is QualityState.PRESENT and not self.evidence_paths:
            raise ValueError("present requires evidence locations")
        if self.declaration is not None:
            if not isinstance(self.declaration, QualityDeclaration):
                raise ValueError("typed declaration required")
            if (self.declaration.field, self.declaration.subject) != (
                self.field,
                self.subject,
            ):
                raise ValueError("declaration target mismatch")
            if self.state not in {self.declaration.state, QualityState.INVALID}:
                raise ValueError("declaration and result disagree")
        if self.state in {QualityState.UNKNOWN, QualityState.WITHHELD}:
            if self.declaration is None or self.evidence_paths:
                raise ValueError(
                    "declared absence requires a declaration and no values"
                )
        if self.state is QualityState.MISSING and self.evidence_paths:
            raise ValueError("missing cannot have observed value locations")

    def as_dict(self) -> dict[str, object]:
        declaration = self.declaration
        return {
            "field": self.field.value,
            "subject": self.subject,
            "state": self.state.value,
            "evidence_paths": list(self.evidence_paths),
            "reason": self.reason,
            "verification": "not_performed",
            "declaration": (
                None
                if declaration is None
                else {
                    "state": declaration.state.value,
                    "source_path": declaration.source_path,
                    "reason": declaration.reason,
                }
            ),
        }


def apply_declaration(
    check: QualityCheck, declaration: QualityDeclaration
) -> QualityCheck:
    if not isinstance(check, QualityCheck) or not isinstance(
        declaration, QualityDeclaration
    ):
        raise ValueError("typed quality inputs required")
    if check.declaration is not None:
        raise ValueError("declaration already applied")
    if (check.field, check.subject) != (declaration.field, declaration.subject):
        raise ValueError("declaration target mismatch")
    # An author declaration cannot erase malformed or contradictory evidence.
    missing = check.state is QualityState.MISSING
    return replace(
        check,
        state=declaration.state if missing else QualityState.INVALID,
        reason=(
            "explicit_declaration"
            if missing
            else "declaration_conflicts_with_observation"
        ),
        declaration=declaration,
    )


def _identity(field: QualityField, subject: str) -> None:
    if not isinstance(field, QualityField):
        raise ValueError("typed quality field required")
    _pointer(subject)


def _pointer(value: str) -> None:
    # A location only: never interpreted as a filesystem path or fetched as a URL.
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or (value and (not value.startswith("/") or not value.isprintable()))
        or re.search(r"~(?![01])", value)
    ):
        raise ValueError("invalid JSON pointer location")


def _text(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or not value.isprintable()
        or value != value.strip()
    ):
        raise ValueError("invalid quality reason")
