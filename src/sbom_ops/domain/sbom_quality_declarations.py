"""Read optional sbom-ops declarations, not a standard compliance assertion."""

import re

from sbom_ops.domain.sbom_quality import (
    QualityDeclaration,
    QualityField,
    QualityState,
)

PREFIX = "sbom-ops:quality:"
DOCUMENT_FIELDS = frozenset(
    {
        QualityField.SBOM_AUTHOR,
        QualityField.SBOM_SIGNATURE,
        QualityField.FORMAT_NAME,
        QualityField.FORMAT_VERSION,
        QualityField.GENERATION_CONTEXT,
        QualityField.TIMESTAMP,
        QualityField.TOOL_NAME,
        QualityField.TOOL_VERSION,
        QualityField.SBOM_VERSION,
    }
)


def read_quality_declarations(
    properties: object, *, subject: str
) -> tuple[QualityDeclaration, ...]:
    if not isinstance(subject, str) or len(subject) > 4000:
        raise ValueError("invalid declaration subject")
    component_path = (
        r"(?:/metadata/component(?:/components/(?:0|[1-9][0-9]*))*"
        r"|(?:/components/(?:0|[1-9][0-9]*))+)"
    )
    if subject and re.fullmatch(component_path, subject) is None:
        raise ValueError("invalid declaration subject")
    if not isinstance(properties, list):
        raise ValueError("quality properties must be an array")
    selected: dict[QualityField, dict[str, tuple[str, int]]] = {}
    for index, item in enumerate(properties):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("invalid property structure")
        name = item["name"]
        if not name.startswith(PREFIX):
            continue
        if set(item) != {"name", "value"} or not isinstance(item["value"], str):
            raise ValueError("invalid declaration property")
        parts = name[len(PREFIX) :].split(":")
        if len(parts) != 2 or parts[1] not in {"state", "reason"}:
            raise ValueError("unknown declaration property")
        try:
            field = QualityField(parts[0])
        except ValueError:
            raise ValueError("unknown declaration field") from None
        if (field in DOCUMENT_FIELDS) != (subject == ""):
            raise ValueError("declaration field outside subject scope")
        entries = selected.setdefault(field, {})
        if parts[1] in entries:
            raise ValueError("duplicate declaration property")
        entries[parts[1]] = (item["value"], index)
    base = f"{subject}/properties" if subject else "/metadata/properties"
    declarations = []
    for field, entries in sorted(selected.items()):
        if set(entries) != {"state", "reason"}:
            raise ValueError("declaration requires state and reason")
        value, index = entries["state"]
        if value not in {"unknown", "withheld"}:
            raise ValueError("invalid declaration state")
        declarations.append(
            QualityDeclaration(
                field=field,
                subject=subject,
                state=QualityState(value),
                source_path=f"{base}/{index}",
                reason=entries["reason"][0],
            )
        )
    return tuple(declarations)
