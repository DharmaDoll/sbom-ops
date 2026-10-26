"""Local evidence registration; no external requests or inventory mutation."""

import json
from datetime import datetime
from pathlib import Path

from sbom_ops.domain.asset_registry import (
    RegistryProjectObservation,
)
from sbom_ops.domain.lifecycle_evidence import (
    MAX_INPUT_BYTES,
    LifecycleEvidence,
    RecordedEvidence,
    match_lifecycle_evidence,
    parse_evidence,
    serialize_evidence,
    validate_correction,
)
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.lifecycle_evidence import LifecycleEvidenceStore


def load_evidence(path: str | Path) -> LifecycleEvidence:
    with Path(path).open("rb") as source:
        content = source.read(MAX_INPUT_BYTES + 1)
    if len(content) > MAX_INPUT_BYTES:
        raise ValueError("evidence input exceeds 64 KiB")
    return parse_evidence(content.decode("utf-8"))


def evidence_history(
    db: str | Path, service_id: str, deployable_id: str
) -> tuple[RecordedEvidence, ...]:
    with AssetRegistry(db, read_only=True) as registry:
        if registry.get_deployable(service_id, deployable_id) is None:
            raise ValueError("asset is not registered")
    with LifecycleEvidenceStore(db, read_only=True) as store:
        return store.list_records(service_id, deployable_id)


def register_evidence(
    db: str | Path, item: LifecycleEvidence, *, apply: bool = False
) -> RecordedEvidence | None:
    history = evidence_history(db, item.service_id, item.deployable_id)
    with AssetRegistry(db, read_only=True) as registry:
        if registry.is_retired(item.service_id, item.deployable_id):
            raise ValueError("cannot register evidence for a retired asset")
    if item.supersedes_id is not None:
        previous = next((r for r in history if r.record_id == item.supersedes_id), None)
        if previous is None:
            raise ValueError("correction target does not exist")
        validate_correction(previous.evidence, item, previous_id=previous.record_id)
        if any(r.evidence.supersedes_id == item.supersedes_id for r in history):
            raise ValueError("correction target is already superseded")
    if apply:
        with LifecycleEvidenceStore(db) as store:
            return store.append(item)
    return None


def project_evidence_views(
    db: str | Path, projects: tuple[RegistryProjectObservation, ...], *, now: datetime
) -> tuple[str, tuple[dict[str, object], ...]]:
    """Read current approval state again; never mutate sync decisions."""
    with AssetRegistry(db, read_only=True) as registry:
        if registry.schema_version < 11:
            return "migration_required", ()
        snapshot, histories = registry.evidence_snapshot(
            tuple(
                (project.service_id, project.deployable_id)
                for project in projects
                if project.service_id and project.deployable_id
            )
        )
    views: list[dict[str, object]] = []
    for project in projects:
        records = (
            histories[(project.service_id, project.deployable_id)]
            if project.service_id and project.deployable_id
            else ()
        )
        statuses = match_lifecycle_evidence(snapshot, project, records, now=now)
        views.append(
            {
                "project_uuid": project.project_uuid,
                "project_status": project.status.value,
                "records": [
                    {
                        "record_id": record.record_id,
                        "status": statuses[record.record_id],
                        "recorded_at": record.recorded_at.isoformat(),
                        "evidence": json.loads(serialize_evidence(record.evidence)),
                    }
                    for record in records
                ],
            }
        )
    return "loaded", tuple(views)
