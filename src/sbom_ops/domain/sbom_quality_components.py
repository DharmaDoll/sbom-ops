"""Observe listed component fields, without artifact or license verification."""

import re

from sbom_ops.domain.sbom_quality import (
    QualityCheck,
    QualityField,
    QualityState,
    apply_declaration,
)
from sbom_ops.domain.sbom_quality_declarations import read_quality_declarations
from sbom_ops.domain.sbom_quality_dependencies import inspect_dependencies
from sbom_ops.domain.sbom_quality_input import QualityInput, QualityInputError

HASH_LENGTHS = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "BLAKE2b-256": 64,
    "BLAKE2b-384": 96,
    "BLAKE2b-512": 128,
}


def evaluate_components(source: QualityInput) -> tuple[QualityCheck, ...]:
    graph = inspect_dependencies(source.document)
    if graph.error_path is not None and not source.component_subjects:
        raise QualityInputError("invalid_dependency_graph")
    checks = []
    for subject in source.component_subjects:
        component = _resolve(source.document, subject)
        observed = [
            _scalar(component, subject, "name", QualityField.COMPONENT_NAME),
            _scalar(component, subject, "version", QualityField.COMPONENT_VERSION),
            _producer(component, subject, source.document),
            _identifier(component, subject),
            _licenses(component, subject),
            *_hashes(component, subject),
            graph.for_component(component, subject),
        ]
        try:
            declarations = read_quality_declarations(
                component.get("properties", []), subject=subject
            )
        except ValueError:
            raise QualityInputError("invalid_quality_declaration") from None
        declared = {declaration.field: declaration for declaration in declarations}
        checks.extend(
            (
                apply_declaration(check, declared[check.field])
                if check.field in declared
                else check
            )
            for check in observed
        )
    return tuple(sorted(checks, key=lambda check: (check.subject, check.field.value)))


def _resolve(document: dict[str, object], subject: str) -> dict[str, object]:
    value = document
    for part in subject.split("/")[1:]:
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.isprintable()


def _result(
    field: QualityField,
    subject: str,
    paths: tuple[str, ...] = (),
    state: QualityState | None = None,
    reason: str = "recorded",
) -> QualityCheck:
    return QualityCheck(
        field,
        subject,
        state or (QualityState.PRESENT if paths else QualityState.MISSING),
        paths,
        reason if paths else "not_recorded",
    )


def _scalar(
    component: dict[str, object], subject: str, key: str, field: QualityField
) -> QualityCheck:
    if key not in component:
        return _result(field, subject)
    return _result(
        field,
        subject,
        (f"{subject}/{key}",),
        QualityState.PRESENT if _text(component[key]) else QualityState.INVALID,
        "recorded" if _text(component[key]) else "invalid_text",
    )


def _producer(
    component: dict[str, object], subject: str, document: dict[str, object]
) -> QualityCheck:
    field = QualityField.COMPONENT_PRODUCER
    paths = []
    if "author" in component:
        check = _scalar(component, subject, "author", field)
        if check.state is QualityState.INVALID:
            return check
        paths.extend(check.evidence_paths)
    if document["specVersion"] == "1.6" and "authors" in component:
        authors = component["authors"]
        if not isinstance(authors, list) or not authors:
            return _result(
                field,
                subject,
                (f"{subject}/authors",),
                QualityState.INVALID,
                "invalid_authors",
            )
        for index, author in enumerate(authors):
            path = f"{subject}/authors/{index}"
            if not isinstance(author, dict) or any(
                key in author and not _text(author[key]) for key in ("name", "email")
            ):
                return _result(
                    field, subject, (path,), QualityState.INVALID, "invalid_author"
                )
            selected = [
                f"{path}/{key}" for key in ("name", "email") if _text(author.get(key))
            ]
            if not selected:
                return _result(
                    field,
                    subject,
                    (path,),
                    QualityState.UNVERIFIABLE,
                    "producer_identity_unresolved",
                )
            paths.extend(selected)
    organizations = []
    if document["specVersion"] == "1.6" and "manufacturer" in component:
        organizations.append((f"{subject}/manufacturer", component["manufacturer"]))
    if subject == "/metadata/component" and "manufacture" in document.get(
        "metadata", {}
    ):
        organizations.append(
            ("/metadata/manufacture", document["metadata"]["manufacture"])
        )
    for path, organization in organizations:
        if not isinstance(organization, dict) or (
            "name" in organization and not _text(organization["name"])
        ):
            return _result(
                field, subject, (path,), QualityState.INVALID, "invalid_manufacturer"
            )
        if "name" not in organization:
            return _result(
                field,
                subject,
                (path,),
                QualityState.UNVERIFIABLE,
                "producer_identity_unresolved",
            )
        paths.append(f"{path}/name")
    return _result(field, subject, tuple(paths))


def _hashes(component: dict[str, object], subject: str) -> tuple[QualityCheck, ...]:
    fields = (QualityField.COMPONENT_HASH, QualityField.HASH_ALGORITHM)
    if "hashes" not in component:
        return tuple(_result(field, subject) for field in fields)
    hashes = component["hashes"]
    path = f"{subject}/hashes"
    reason = "artifact_hash_not_verified"
    state = QualityState.PRESENT
    if not isinstance(hashes, list) or not hashes:
        state, reason = QualityState.INVALID, "invalid_hashes"
    else:
        for item in hashes:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("alg"), str)
                or not isinstance(item.get("content"), str)
            ):
                state, reason = QualityState.INVALID, "invalid_hash_pair"
                break
            alg, content = item["alg"], item["content"]
            if re.fullmatch(r"[a-fA-F0-9]+", content) is None or len(content) not in {
                32,
                40,
                64,
                96,
                128,
            }:
                state, reason = QualityState.INVALID, "invalid_hash_content"
                break
            if alg in HASH_LENGTHS and len(content) != HASH_LENGTHS[alg]:
                state, reason = QualityState.INVALID, "hash_algorithm_length_mismatch"
                break
            if alg not in HASH_LENGTHS and alg != "BLAKE3":
                state, reason = QualityState.INVALID, "unsupported_hash_algorithm"
                break
            if alg == "BLAKE3":
                state, reason = (
                    QualityState.UNVERIFIABLE,
                    "variable_digest_length_not_verified",
                )
    # Observe legacy algorithm names without computing or endorsing those hashes.
    return tuple(_result(field, subject, (path,), state, reason) for field in fields)


def _identifier(component: dict[str, object], subject: str) -> QualityCheck:
    field = QualityField.COMPONENT_IDENTIFIER
    paths = []
    for key in ("purl", "cpe", "swid"):
        if key not in component:
            continue
        path, value = f"{subject}/{key}", component[key]
        if key == "swid":
            valid = (
                isinstance(value, dict)
                and _text(value.get("tagId"))
                and _text(value.get("name"))
            )
        elif key == "purl":
            valid = (
                isinstance(value, str)
                and re.fullmatch(r"pkg:[a-z][a-z0-9.+-]*/[^\s]+", value) is not None
            )
        else:
            valid = _text(value) and value.startswith(("cpe:2.3:", "cpe:/"))
        if not valid:
            return _result(
                field,
                subject,
                (path,),
                QualityState.INVALID,
                "invalid_identifier_structure",
            )
        paths.append(path)
    return _result(
        field, subject, tuple(paths), reason="identifier_recorded_semantics_unverified"
    )


def _licenses(component: dict[str, object], subject: str) -> QualityCheck:
    field = QualityField.COMPONENT_LICENSE
    if "licenses" not in component:
        return _result(field, subject)
    path, licenses = f"{subject}/licenses", component["licenses"]
    if not isinstance(licenses, list) or not licenses:
        return _result(
            field, subject, (path,), QualityState.INVALID, "invalid_licenses"
        )
    state = QualityState.PRESENT
    for item in licenses:
        if not isinstance(item, dict) or ("license" in item) == ("expression" in item):
            return _result(
                field, subject, (path,), QualityState.INVALID, "invalid_license_choice"
            )
        if "expression" in item:
            if len(licenses) != 1 or not _text(item["expression"]):
                return _result(
                    field,
                    subject,
                    (path,),
                    QualityState.INVALID,
                    "invalid_license_expression",
                )
            state = QualityState.UNVERIFIABLE
        else:
            license_item = item["license"]
            if not isinstance(license_item, dict) or ("id" in license_item) == (
                "name" in license_item
            ):
                return _result(
                    field,
                    subject,
                    (path,),
                    QualityState.INVALID,
                    "invalid_license_identity",
                )
            key = "id" if "id" in license_item else "name"
            if not _text(license_item[key]):
                return _result(
                    field,
                    subject,
                    (path,),
                    QualityState.INVALID,
                    "invalid_license_identity",
                )
            if key == "id":
                state = QualityState.UNVERIFIABLE
    return _result(
        field,
        subject,
        (path,),
        state,
        (
            "spdx_catalog_or_expression_not_validated"
            if state is QualityState.UNVERIFIABLE
            else "license_recorded_not_verified"
        ),
    )
