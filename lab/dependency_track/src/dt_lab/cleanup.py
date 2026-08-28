from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4

from dt_lab.domain import (
    DependencyTrackObservation,
    LabCleanupError,
    LabCleanupResult,
    LabCleanupTarget,
)


class DependencyTrackCleanupApi(Protocol):
    def observe_project_lookup(
        self, project_name: str, project_version: str
    ) -> DependencyTrackObservation: ...

    def delete_project(self, project_uuid: str) -> None: ...


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LabCleanupError(f"cannot read lab cleanup input: {path}") from exc
    if not isinstance(payload, dict):
        raise LabCleanupError(f"lab cleanup input must be a JSON object: {path}")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary_path = path.with_suffix(f"{path.suffix}.tmp")
    temporary_path.write_text(
        f"{json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)}\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)


def _validated_run_directory(output_directory: str | Path, run_id: str) -> Path:
    try:
        normalized_run_id = str(UUID(run_id))
    except ValueError as exc:
        raise LabCleanupError(f"invalid lab run id: {run_id!r}") from exc
    if normalized_run_id != run_id:
        raise LabCleanupError(f"lab run id must use canonical UUID form: {run_id!r}")
    output_root = Path(output_directory).resolve()
    run_directory = (output_root / normalized_run_id).resolve()
    if run_directory.parent != output_root or not run_directory.is_dir():
        raise LabCleanupError(f"lab run directory does not exist: {run_directory}")
    run_metadata = _read_json(run_directory / "run.json")
    if run_metadata.get("run_id") != normalized_run_id:
        raise LabCleanupError("lab run metadata does not match the requested run id")
    return run_directory


def _optional_uuid(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise LabCleanupError(f"{field_name} must be a UUID string or null")
    try:
        normalized = str(UUID(value))
    except ValueError as exc:
        raise LabCleanupError(f"{field_name} is not a valid UUID") from exc
    if normalized != value:
        raise LabCleanupError(f"{field_name} must use canonical UUID form")
    return normalized


def _required_string(payload: dict[str, Any], key: str, field_name: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise LabCleanupError(f"{field_name}.{key} must be a non-empty string")
    return value


def _ledger_targets(run_directory: Path, run_id: str) -> list[LabCleanupTarget]:
    ledger_path = run_directory / "projects.json"
    if not ledger_path.is_file():
        return []
    ledger = _read_json(ledger_path)
    if ledger.get("schema_version") != 1 or ledger.get("run_id") != run_id:
        raise LabCleanupError("lab Project ledger contract or run id is invalid")
    raw_projects = ledger.get("projects")
    if not isinstance(raw_projects, list):
        raise LabCleanupError("lab Project ledger projects must be a list")
    targets: list[LabCleanupTarget] = []
    for index, raw_project in enumerate(raw_projects):
        if not isinstance(raw_project, dict):
            raise LabCleanupError(f"lab Project ledger entry {index} must be an object")
        targets.append(
            LabCleanupTarget(
                project_name=_required_string(
                    raw_project, "project_name", f"projects[{index}]"
                ),
                project_version=_required_string(
                    raw_project, "project_version", f"projects[{index}]"
                ),
                project_uuid=_optional_uuid(
                    raw_project.get("project_uuid"),
                    f"projects[{index}].project_uuid",
                ),
            )
        )
    return targets


def _legacy_targets(run_directory: Path) -> list[LabCleanupTarget]:
    targets: list[LabCleanupTarget] = []
    for observation_path in sorted(run_directory.rglob("project-lookup.json")):
        observation = _read_json(observation_path)
        request = observation.get("request")
        response = observation.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise LabCleanupError(
                f"legacy Project lookup has no request/response: {observation_path}"
            )
        query = request.get("query")
        payload = response.get("payload")
        if (
            request.get("method") != "GET"
            or request.get("path") != "/api/v1/project/lookup"
            or response.get("status") != 200
            or not isinstance(query, dict)
            or not isinstance(payload, dict)
        ):
            raise LabCleanupError(
                f"legacy Project lookup contract is invalid: {observation_path}"
            )
        project_name = _required_string(query, "name", "project lookup query")
        project_version = _required_string(query, "version", "project lookup query")
        if (
            payload.get("name") != project_name
            or payload.get("version") != project_version
        ):
            raise LabCleanupError(
                f"legacy Project lookup identity mismatch: {observation_path}"
            )
        targets.append(
            LabCleanupTarget(
                project_name=project_name,
                project_version=project_version,
                project_uuid=_optional_uuid(
                    payload.get("uuid"), f"{observation_path} response UUID"
                ),
            )
        )
    return targets


def _deduplicated_targets(
    targets: list[LabCleanupTarget], run_id: str
) -> tuple[LabCleanupTarget, ...]:
    marker = f"-lab-{run_id[:8]}"
    deduplicated: dict[tuple[str, str], LabCleanupTarget] = {}
    for target in targets:
        if not target.project_name.startswith("dt-lab-"):
            raise LabCleanupError(
                f"refusing to clean non-lab Project: {target.project_name!r}"
            )
        if not target.project_version.endswith(marker):
            raise LabCleanupError(
                "refusing to clean Project without the requested run marker: "
                f"{target.project_name!r} {target.project_version!r}"
            )
        identity = (target.project_name, target.project_version)
        existing = deduplicated.get(identity)
        if (
            existing is not None
            and existing.project_uuid is not None
            and target.project_uuid is not None
            and existing.project_uuid != target.project_uuid
        ):
            raise LabCleanupError(
                f"conflicting UUIDs recorded for lab Project {identity!r}"
            )
        if existing is None or existing.project_uuid is None:
            deduplicated[identity] = target
    if not deduplicated:
        raise LabCleanupError("lab run has no recorded Projects to clean")
    return tuple(deduplicated[key] for key in sorted(deduplicated))


def load_cleanup_targets(
    output_directory: str | Path, run_id: str
) -> tuple[Path, tuple[LabCleanupTarget, ...]]:
    run_directory = _validated_run_directory(output_directory, run_id)
    targets = _ledger_targets(run_directory, run_id)
    if not targets:
        targets = _legacy_targets(run_directory)
    return run_directory, _deduplicated_targets(targets, run_id)


def _target_dict(target: LabCleanupTarget, status: str) -> dict[str, Any]:
    return {
        "project_name": target.project_name,
        "project_version": target.project_version,
        "project_uuid": target.project_uuid,
        "status": status,
    }


def _exception_status(exc: Exception) -> int | None:
    status = getattr(exc, "status", None)
    return status if isinstance(status, int) else None


def cleanup_lab_run(
    *,
    output_directory: str | Path,
    run_id: str,
    execute: bool = False,
    client: DependencyTrackCleanupApi | None = None,
) -> LabCleanupResult:
    run_directory, targets = load_cleanup_targets(output_directory, run_id)
    cleanup_id = str(uuid4())
    cleanup_directory = run_directory / "cleanups"
    cleanup_directory.mkdir(parents=True, exist_ok=True)
    audit_path = cleanup_directory / f"{cleanup_id}.json"
    started_at = datetime.now(UTC).isoformat()
    audit: dict[str, Any] = {
        "schema_version": 1,
        "cleanup_id": cleanup_id,
        "run_id": run_id,
        "mode": "execute" if execute else "dry-run",
        "status": "running" if execute else "planned",
        "started_at": started_at,
        "targets": [_target_dict(target, "pending") for target in targets],
    }
    if not execute:
        audit["completed_at"] = datetime.now(UTC).isoformat()
        audit["targets"] = [_target_dict(target, "planned") for target in targets]
        _write_json(audit_path, audit)
        return LabCleanupResult(
            run_id=run_id,
            cleanup_id=cleanup_id,
            executed=False,
            audit_path=str(audit_path),
            targets=targets,
            deleted_project_uuids=(),
            already_absent_projects=(),
        )
    if client is None:
        raise LabCleanupError("executed lab cleanup requires a Dependency-Track client")
    _write_json(audit_path, audit)
    target_results: list[dict[str, Any]] = []
    deleted: list[str] = []
    already_absent: list[str] = []
    failures: list[str] = []
    for target in targets:
        identity = f"{target.project_name}:{target.project_version}"
        try:
            live = client.observe_project_lookup(
                target.project_name, target.project_version
            )
        except Exception as exc:
            if _exception_status(exc) == 404:
                already_absent.append(identity)
                target_results.append(_target_dict(target, "already-absent"))
                continue
            failures.append(identity)
            target_result = _target_dict(target, "failed")
            target_result["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            target_results.append(target_result)
            continue
        payload = live.payload
        if (
            live.status != 200
            or not isinstance(payload, dict)
            or payload.get("name") != target.project_name
            or payload.get("version") != target.project_version
        ):
            failures.append(identity)
            target_result = _target_dict(target, "failed")
            target_result["error"] = {
                "type": "LabCleanupError",
                "message": "live Project identity did not match the cleanup plan",
            }
            target_results.append(target_result)
            continue
        try:
            live_uuid = _optional_uuid(payload.get("uuid"), "live Project UUID")
            if live_uuid is None:
                raise LabCleanupError("live Project lookup returned no UUID")
            if target.project_uuid is not None and live_uuid != target.project_uuid:
                raise LabCleanupError(
                    "live Project UUID did not match the recorded cleanup target"
                )
            client.delete_project(live_uuid)
        except Exception as exc:
            if _exception_status(exc) == 404:
                already_absent.append(identity)
                target_results.append(_target_dict(target, "already-absent"))
                continue
            failures.append(identity)
            target_result = _target_dict(target, "failed")
            target_result["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            target_results.append(target_result)
            continue
        deleted.append(live_uuid)
        target_result = _target_dict(target, "deleted")
        target_result["deleted_uuid"] = live_uuid
        target_results.append(target_result)
    audit.update(
        {
            "status": "failed" if failures else "completed",
            "completed_at": datetime.now(UTC).isoformat(),
            "targets": target_results,
            "deleted_count": len(deleted),
            "already_absent_count": len(already_absent),
            "failed_count": len(failures),
        }
    )
    _write_json(audit_path, audit)
    if failures:
        raise LabCleanupError(
            f"lab cleanup failed for {len(failures)} Project(s); audit={audit_path}"
        )
    return LabCleanupResult(
        run_id=run_id,
        cleanup_id=cleanup_id,
        executed=True,
        audit_path=str(audit_path),
        targets=targets,
        deleted_project_uuids=tuple(deleted),
        already_absent_projects=tuple(already_absent),
    )
