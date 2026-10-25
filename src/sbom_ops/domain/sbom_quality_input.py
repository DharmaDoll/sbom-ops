"""Input bounds and source identity for offline SBOM quality inspection."""

from dataclasses import asdict, dataclass, field
from math import isfinite


class QualityInputError(ValueError):
    """A stable reason code without source values or filesystem paths."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class QualityInputLimits:
    max_bytes: int = 32 * 1024 * 1024
    max_depth: int = 64
    max_nodes: int = 250_000
    max_components: int = 10_000

    def __post_init__(self) -> None:
        if any(type(value) is not int or value <= 0 for value in asdict(self).values()):
            raise QualityInputError("invalid_limits")


@dataclass(frozen=True)
class QualityInput:
    # The decoded tree is internal evaluation input, not a public report.
    document: dict[str, object] = field(repr=False)
    sha256: str
    byte_count: int
    component_subjects: tuple[str, ...]
    limits: QualityInputLimits


def inspect_document(document: object, limits: QualityInputLimits) -> tuple[str, ...]:
    """Check bounded tree structure, not CycloneDX schema or field quality."""
    pending = [document]
    count = 0
    while pending:
        value = pending.pop()
        count += 1
        if count > limits.max_nodes:
            raise QualityInputError("node_limit_exceeded")
        if isinstance(value, dict):
            for key in value:
                _unicode(key)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            _unicode(value)
        elif isinstance(value, float) and not isfinite(value):
            raise QualityInputError("invalid_json")
    if not isinstance(document, dict):
        raise QualityInputError("invalid_document_structure")
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") not in (
        "1.5",
        "1.6",
    ):
        raise QualityInputError("unsupported_format")
    metadata = document.get("metadata", {})
    if not isinstance(metadata, dict):
        raise QualityInputError("invalid_document_structure")
    components = _children(document, "")
    if "component" in metadata:
        components.append(("/metadata/component", metadata["component"]))
    subjects = []
    while components:
        subject, component = components.pop()
        if not isinstance(component, dict):
            raise QualityInputError("invalid_component_structure")
        subjects.append(subject)
        if len(subjects) > limits.max_components:
            raise QualityInputError("component_limit_exceeded")
        components.extend(_children(component, subject))
    return tuple(sorted(subjects))


def _children(parent: dict[str, object], subject: str) -> list[tuple[str, object]]:
    children = parent.get("components", [])
    if not isinstance(children, list):
        raise QualityInputError("invalid_component_structure")
    return [
        (f"{subject}/components/{index}", child) for index, child in enumerate(children)
    ]


def _unicode(value: str) -> None:
    # JSON escape sequences can otherwise create unpaired UTF-16 surrogates.
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise QualityInputError("invalid_unicode")
