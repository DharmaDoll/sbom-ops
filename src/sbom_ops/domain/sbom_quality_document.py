"""Observe document-level fields; do not authenticate authors or signatures."""

import re
from datetime import datetime

from sbom_ops.domain.sbom_quality import (
    QualityCheck,
    apply_declaration,
)
from sbom_ops.domain.sbom_quality import (
    QualityField as Field,
)
from sbom_ops.domain.sbom_quality import (
    QualityState as State,
)
from sbom_ops.domain.sbom_quality_declarations import read_quality_declarations
from sbom_ops.domain.sbom_quality_input import QualityInputError

PHASES = frozenset(
    {
        "design",
        "pre-build",
        "build",
        "post-build",
        "operations",
        "discovery",
        "decommission",
    }
)


def evaluate_document(document: dict[str, object]) -> tuple[QualityCheck, ...]:
    """Evaluate nine document fields after bounded JSON reading, without I/O."""
    if (
        not isinstance(document, dict)
        or document.get("bomFormat") != "CycloneDX"
        or document.get("specVersion") not in ("1.5", "1.6")
    ):
        raise QualityInputError("unsupported_format")
    metadata = document.get("metadata", {})
    if not isinstance(metadata, dict):
        raise QualityInputError("invalid_document_structure")
    checks = [
        _observed(Field.FORMAT_NAME, "/bomFormat"),
        _observed(Field.FORMAT_VERSION, "/specVersion"),
        _version(document),
        _timestamp(metadata),
        _author(metadata, document["specVersion"]),
        _lifecycle(metadata),
        _signature(document),
        *_tools(metadata),
    ]
    try:
        declarations = read_quality_declarations(
            metadata.get("properties", []), subject=""
        )
    except ValueError:
        raise QualityInputError("invalid_quality_declaration") from None
    declared = {declaration.field: declaration for declaration in declarations}
    return tuple(
        sorted(
            (
                (
                    apply_declaration(check, declared[check.field])
                    if check.field in declared
                    else check
                )
                for check in checks
            ),
            key=lambda check: check.field.value,
        )
    )


def _observed(
    field: Field, path: str, state: State = State.PRESENT, reason: str = "recorded"
) -> QualityCheck:
    return QualityCheck(field, "", state, (path,), reason)


def _missing(field: Field) -> QualityCheck:
    return QualityCheck(field, "", State.MISSING, (), "not_recorded")


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.isprintable()


def _version(document: dict[str, object]) -> QualityCheck:
    if "version" not in document:
        return _missing(Field.SBOM_VERSION)
    value = document["version"]
    valid = type(value) is int and value >= 1
    return _observed(
        Field.SBOM_VERSION,
        "/version",
        State.PRESENT if valid else State.INVALID,
        "recorded" if valid else "invalid_sbom_version",
    )


def _timestamp(metadata: dict[str, object]) -> QualityCheck:
    field, path = Field.TIMESTAMP, "/metadata/timestamp"
    if "timestamp" not in metadata:
        return _missing(field)
    value = metadata["timestamp"]
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
            value,
        )
        is None
    ):
        return _observed(field, path, State.INVALID, "invalid_timestamp")
    leap = value[17:19] == "60"
    normalized = value[:17] + ("59" if leap else value[17:19]) + value[19:]
    try:
        datetime.fromisoformat(normalized.upper().replace("Z", "+00:00"))
    except ValueError:
        return _observed(field, path, State.INVALID, "invalid_timestamp")
    if leap or value.endswith("-00:00"):
        return _observed(
            field, path, State.UNVERIFIABLE, "timestamp_offset_or_leap_unverified"
        )
    return _observed(field, path)


def _author(metadata: dict[str, object], version: str) -> QualityCheck:
    paths: list[str] = []
    field = Field.SBOM_AUTHOR
    if "authors" in metadata:
        authors = metadata["authors"]
        if not isinstance(authors, list) or not authors:
            return _observed(
                field, "/metadata/authors", State.INVALID, "invalid_authors"
            )
        for index, author in enumerate(authors):
            path = f"/metadata/authors/{index}"
            if not isinstance(author, dict):
                return _observed(field, path, State.INVALID, "invalid_author")
            if any(
                key in author and not _text(author[key]) for key in ("name", "email")
            ):
                return _observed(field, path, State.INVALID, "invalid_author_identity")
            identities = [key for key in ("name", "email") if _text(author.get(key))]
            if not identities:
                return _observed(
                    field, path, State.UNVERIFIABLE, "author_identity_not_resolved"
                )
            paths.extend(f"{path}/{key}" for key in identities)
    if version == "1.6" and "manufacturer" in metadata:
        organization = metadata["manufacturer"]
        path = "/metadata/manufacturer"
        if not isinstance(organization, dict):
            return _observed(field, path, State.INVALID, "invalid_bom_manufacturer")
        if "name" in organization and not _text(organization["name"]):
            return _observed(
                field, path, State.INVALID, "invalid_bom_manufacturer_name"
            )
        if not _text(organization.get("name")):
            return _observed(
                field, path, State.UNVERIFIABLE, "author_identity_not_resolved"
            )
        paths.append(f"{path}/name")
    return (
        QualityCheck(field, "", State.PRESENT, tuple(paths), "recorded")
        if paths
        else _missing(field)
    )


def _lifecycle(metadata: dict[str, object]) -> QualityCheck:
    field, path = Field.GENERATION_CONTEXT, "/metadata/lifecycles"
    if "lifecycles" not in metadata:
        return _missing(field)
    values = metadata["lifecycles"]
    if not isinstance(values, list) or not values:
        return _observed(field, path, State.INVALID, "invalid_lifecycles")
    custom = False
    for value in values:
        if not isinstance(value, dict):
            return _observed(field, path, State.INVALID, "invalid_lifecycle")
        if (
            set(value) == {"phase"}
            and isinstance(value["phase"], str)
            and value["phase"] in PHASES
        ):
            continue
        if (
            set(value) <= {"name", "description"}
            and _text(value.get("name"))
            and ("description" not in value or isinstance(value["description"], str))
        ):
            custom = True
        else:
            return _observed(field, path, State.INVALID, "invalid_lifecycle")
    return _observed(
        field,
        path,
        State.UNVERIFIABLE if custom else State.PRESENT,
        "custom_lifecycle_mapping_unverified" if custom else "recorded",
    )


def _signature(document: dict[str, object]) -> QualityCheck:
    field, path = Field.SBOM_SIGNATURE, "/signature"
    if "signature" not in document:
        return _missing(field)
    value = document["signature"]
    if not isinstance(value, dict) or not value:
        return _observed(field, path, State.INVALID, "invalid_signature_envelope")
    groups = [name for name in ("signers", "chain") if name in value]
    if groups:
        signatures = value[groups[0]]
        if (
            len(groups) != 1
            or len(value) != 1
            or not isinstance(signatures, list)
            or not signatures
        ):
            return _observed(field, path, State.INVALID, "invalid_signature_envelope")
    else:
        signatures = [value]
    for signature in signatures:
        if (
            not isinstance(signature, dict)
            or not _text(signature.get("algorithm"))
            or not isinstance(signature.get("value"), str)
            or re.fullmatch(r"[A-Za-z0-9_-]+", signature["value"]) is None
        ):
            return _observed(field, path, State.INVALID, "invalid_signature_envelope")
    # Only envelope presence: keys/certificates/algorithms are neither trusted
    # nor used. Detached signatures are outside this input interface.
    return _observed(field, path, reason="signature_envelope_not_verified")


def _tools(metadata: dict[str, object]) -> tuple[QualityCheck, QualityCheck]:
    fields = (Field.TOOL_NAME, Field.TOOL_VERSION)
    if "tools" not in metadata:
        return tuple(_missing(field) for field in fields)
    tools = metadata["tools"]
    path = "/metadata/tools"
    entries: list[tuple[str, object]] = []
    if isinstance(tools, list):
        entries = [(f"{path}/{index}", tool) for index, tool in enumerate(tools)]
    elif isinstance(tools, dict) and set(tools) <= {"components", "services"}:
        for group in ("components", "services"):
            items = tools.get(group, [])
            if not isinstance(items, list):
                return tuple(
                    _observed(field, path, State.INVALID, "invalid_tools")
                    for field in fields
                )
            entries.extend(
                (f"{path}/{group}/{index}", item) for index, item in enumerate(items)
            )
    else:
        return tuple(
            _observed(field, path, State.INVALID, "invalid_tools") for field in fields
        )
    if not entries or any(not isinstance(item, dict) for _, item in entries):
        return tuple(
            _observed(field, path, State.INVALID, "invalid_tools") for field in fields
        )
    results = []
    for key, field in (("name", Field.TOOL_NAME), ("version", Field.TOOL_VERSION)):
        paths = tuple(
            f"{item_path}/{key}" for item_path, item in entries if key in item
        )
        if not paths:
            results.append(_missing(field))
        elif any(
            not _text(item.get(key))
            or (key == "version" and not _text(item.get("name")))
            for _, item in entries
        ):
            results.append(
                QualityCheck(
                    field, "", State.INVALID, paths, "incomplete_or_invalid_tool_field"
                )
            )
        else:
            results.append(QualityCheck(field, "", State.PRESENT, paths, "recorded"))
    return tuple(results)
