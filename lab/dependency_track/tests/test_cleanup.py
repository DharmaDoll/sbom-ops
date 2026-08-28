from __future__ import annotations

import json
from pathlib import Path

import pytest
from dt_lab.cleanup import cleanup_lab_run, load_cleanup_targets
from dt_lab.client import DependencyTrackLabApiError
from dt_lab.domain import DependencyTrackObservation, LabCleanupError

RUN_ID = "25dfd88e-2673-462b-9f40-818279ecd8b5"
PROJECT_UUID = "4c40cf70-57cf-4eee-8043-1f246fef3f7b"
PROJECT_NAME = "dt-lab-identity-purl"
PROJECT_VERSION = "1.0.0-lab-25dfd88e"


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_run(
    output_directory: Path,
    *,
    name: str = PROJECT_NAME,
    version: str = PROJECT_VERSION,
    project_uuid: str | None = PROJECT_UUID,
) -> Path:
    run_directory = output_directory / RUN_ID
    run_directory.mkdir()
    _write_json(
        run_directory / "run.json",
        {"run_id": RUN_ID, "status": "completed", "project_ledger": "projects.json"},
    )
    _write_json(
        run_directory / "projects.json",
        {
            "schema_version": 1,
            "run_id": RUN_ID,
            "projects": [
                {
                    "scenario_id": "identity-same-name-different-purl",
                    "step_id": "initial",
                    "project_name": name,
                    "project_version": version,
                    "project_uuid": project_uuid,
                }
            ],
        },
    )
    return run_directory


class FakeCleanupClient:
    def __init__(self, *, live_uuid: str = PROJECT_UUID) -> None:
        self.live_uuid = live_uuid
        self.deleted: list[str] = []

    def observe_project_lookup(
        self, project_name: str, project_version: str
    ) -> DependencyTrackObservation:
        return DependencyTrackObservation(
            method="GET",
            path="/api/v1/project/lookup",
            query=(("name", project_name), ("version", project_version)),
            status=200,
            headers=(),
            duration_seconds=0.01,
            payload={
                "uuid": self.live_uuid,
                "name": project_name,
                "version": project_version,
            },
        )

    def delete_project(self, project_uuid: str) -> None:
        self.deleted.append(project_uuid)


def test_cleanup_is_a_local_dry_run_by_default(tmp_path: Path) -> None:
    run_directory = _write_run(tmp_path)

    result = cleanup_lab_run(output_directory=tmp_path, run_id=RUN_ID)

    assert result.executed is False
    assert result.deleted_project_uuids == ()
    audit = json.loads(Path(result.audit_path).read_text(encoding="utf-8"))
    assert Path(result.audit_path).parent == run_directory / "cleanups"
    assert audit["mode"] == "dry-run"
    assert audit["status"] == "planned"
    assert audit["targets"][0]["status"] == "planned"


def test_cleanup_verifies_live_identity_then_deletes(tmp_path: Path) -> None:
    _write_run(tmp_path, project_uuid=None)
    client = FakeCleanupClient()

    result = cleanup_lab_run(
        output_directory=tmp_path,
        run_id=RUN_ID,
        execute=True,
        client=client,
    )

    assert client.deleted == [PROJECT_UUID]
    assert result.deleted_project_uuids == (PROJECT_UUID,)
    audit = json.loads(Path(result.audit_path).read_text(encoding="utf-8"))
    assert audit["status"] == "completed"
    assert audit["targets"][0]["status"] == "deleted"


def test_cleanup_refuses_a_live_uuid_mismatch(tmp_path: Path) -> None:
    _write_run(tmp_path)
    client = FakeCleanupClient(live_uuid="4fb5a5fc-6343-46f0-bb06-569564de3a95")

    with pytest.raises(LabCleanupError, match="cleanup failed"):
        cleanup_lab_run(
            output_directory=tmp_path,
            run_id=RUN_ID,
            execute=True,
            client=client,
        )

    assert client.deleted == []
    audits = list((tmp_path / RUN_ID / "cleanups").glob("*.json"))
    assert len(audits) == 1
    assert json.loads(audits[0].read_text(encoding="utf-8"))["status"] == "failed"


def test_cleanup_is_idempotent_when_project_is_already_absent(tmp_path: Path) -> None:
    _write_run(tmp_path)

    class MissingCleanupClient(FakeCleanupClient):
        def observe_project_lookup(
            self, project_name: str, project_version: str
        ) -> DependencyTrackObservation:
            raise DependencyTrackLabApiError("not found", status=404)

    result = cleanup_lab_run(
        output_directory=tmp_path,
        run_id=RUN_ID,
        execute=True,
        client=MissingCleanupClient(),
    )

    assert result.deleted_project_uuids == ()
    assert result.already_absent_projects == (f"{PROJECT_NAME}:{PROJECT_VERSION}",)


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("production-service", PROJECT_VERSION),
        (PROJECT_NAME, "1.0.0-lab-another1"),
    ],
)
def test_cleanup_refuses_targets_outside_the_run_boundary(
    tmp_path: Path, name: str, version: str
) -> None:
    _write_run(tmp_path, name=name, version=version)

    with pytest.raises(LabCleanupError, match="refusing to clean"):
        load_cleanup_targets(tmp_path, RUN_ID)


def test_cleanup_supports_legacy_runs_with_lookup_observations(tmp_path: Path) -> None:
    run_directory = tmp_path / RUN_ID
    run_directory.mkdir()
    _write_json(run_directory / "run.json", {"run_id": RUN_ID, "status": "completed"})
    _write_json(
        run_directory / "scenario" / "01-initial" / "project-lookup.json",
        {
            "request": {
                "method": "GET",
                "path": "/api/v1/project/lookup",
                "query": {"name": PROJECT_NAME, "version": PROJECT_VERSION},
            },
            "response": {
                "status": 200,
                "payload": {
                    "uuid": PROJECT_UUID,
                    "name": PROJECT_NAME,
                    "version": PROJECT_VERSION,
                },
            },
        },
    )

    _, targets = load_cleanup_targets(tmp_path, RUN_ID)

    assert len(targets) == 1
    assert targets[0].project_uuid == PROJECT_UUID


@pytest.mark.parametrize("run_id", ["../outside", RUN_ID.upper()])
def test_cleanup_requires_a_canonical_run_uuid(tmp_path: Path, run_id: str) -> None:
    with pytest.raises(LabCleanupError, match="invalid lab run id|canonical UUID"):
        load_cleanup_targets(tmp_path, run_id)
