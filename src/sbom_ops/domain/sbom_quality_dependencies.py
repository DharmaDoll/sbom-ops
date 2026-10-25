"""Inspect local dependency references without asserting graph completeness."""

from dataclasses import dataclass

from sbom_ops.domain.sbom_quality import QualityCheck, QualityField, QualityState


@dataclass
class DependencyObservations:
    rows: dict[str, tuple[str, dict[str, object]]]
    error_path: str | None = None
    error_reason: str = "invalid_dependency_graph"
    missing: bool = False

    def for_component(self, component: dict[str, object], subject: str) -> QualityCheck:
        field = QualityField.DEPENDENCY_RELATIONSHIP
        if self.error_path is not None:
            return QualityCheck(
                field,
                subject,
                QualityState.INVALID,
                (self.error_path,),
                self.error_reason,
            )
        if self.missing:
            return QualityCheck(
                field, subject, QualityState.MISSING, (), "not_recorded"
            )
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref:
            return QualityCheck(
                field,
                subject,
                QualityState.UNVERIFIABLE,
                (subject,),
                "component_reference_unavailable",
            )
        entry = self.rows.get(ref)
        if entry is None:
            return QualityCheck(
                field, subject, QualityState.MISSING, (), "dependency_row_not_recorded"
            )
        path, row = entry
        if "dependsOn" not in row:
            return QualityCheck(
                field,
                subject,
                QualityState.UNVERIFIABLE,
                (path,),
                "dependencies_not_declared",
            )
        return QualityCheck(
            field,
            subject,
            QualityState.PRESENT,
            (f"{path}/dependsOn",),
            "local_references_resolved_completeness_unverified",
        )


def inspect_dependencies(document: dict[str, object]) -> DependencyObservations:
    result = DependencyObservations({})
    # All bom-ref occurrences must be unique, including non-inventory objects.
    refs: dict[str, str] = {}
    pending: list[tuple[str, object]] = [("", document)]
    while pending:
        path, value = pending.pop()
        if isinstance(value, dict):
            if "bom-ref" in value:
                ref = value["bom-ref"]
                if (
                    not isinstance(ref, str)
                    or not ref
                    or not ref.isprintable()
                    or ref in refs
                ):
                    result.error_path = f"{path}/bom-ref"
                    result.error_reason = "invalid_or_duplicate_bom_ref"
                    return result
                refs[ref] = path
            pending.extend(
                (f"{path}/{key.replace('~', '~0').replace('/', '~1')}", child)
                for key, child in value.items()
            )
        elif isinstance(value, list):
            pending.extend(
                (f"{path}/{index}", child) for index, child in enumerate(value)
            )
    # Only components/services are dependency targets; license or author refs
    # do not turn into inventory nodes merely because they are unique.
    inventory: set[str] = set()
    containers: list[tuple[dict[str, object], bool]] = [(document, False)]
    metadata = document.get("metadata", {})
    if isinstance(metadata, dict):
        component = metadata.get("component")
        if isinstance(component, dict):
            containers.append((component, True))
        tools = metadata.get("tools")
        if isinstance(tools, dict):
            containers.append((tools, False))
    while containers:
        container, entity = containers.pop()
        ref = container.get("bom-ref")
        if entity and isinstance(ref, str):
            inventory.add(ref)
        for key in ("components", "services"):
            children = container.get(key, [])
            if not isinstance(children, list) or any(
                not isinstance(child, dict) for child in children
            ):
                result.error_path = (
                    "/dependencies" if "dependencies" in document else ""
                )
                result.error_reason = "invalid_dependency_inventory"
                return result
            containers.extend((child, True) for child in children)
    if "dependencies" not in document:
        result.missing = True
        return result
    dependencies = document["dependencies"]
    if not isinstance(dependencies, list):
        result.error_path = "/dependencies"
        return result
    for index, row in enumerate(dependencies):
        path = f"/dependencies/{index}"
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("ref"), str)
            or row["ref"] not in inventory
            or row["ref"] in result.rows
        ):
            result.error_path = path
            result.error_reason = "invalid_or_unresolved_dependency_reference"
            return result
        for key in ("dependsOn", "provides"):
            if key not in row:
                continue
            targets = row[key]
            if (
                not isinstance(targets, list)
                or any(
                    not isinstance(target, str) or target not in inventory
                    for target in targets
                )
                or len(set(targets)) != len(targets)
            ):
                result.error_path = f"{path}/{key}"
                result.error_reason = "invalid_or_unresolved_dependency_reference"
                return result
        result.rows[row["ref"]] = (path, row)
    return result
