from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from types import TracebackType

from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.asset_import import AssetRegistrationBatch
from sbom_ops.domain.asset_registry import (
    LifecycleAction,
    LifecycleChange,
    RegisteredDeployable,
    RegisteredService,
    ReportedDeployment,
    ReviewedProjectLink,
    ServiceChange,
    ServiceUpdate,
    validate_deployment_supersession,
)
from sbom_ops.domain.assets import BusinessCriticality, DeploymentStatus
from sbom_ops.storage.poc import POC_SCHEMA

_DEPLOYMENT_REPORTS_SCHEMA = """
    CREATE TABLE deployment_reports (
        report_id INTEGER PRIMARY KEY,
        service_id TEXT NOT NULL,
        deployable_id TEXT NOT NULL,
        environment TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        deployment_status TEXT NOT NULL,
        exposure_status TEXT NOT NULL,
        reviewer TEXT NOT NULL,
        evidence TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (service_id, deployable_id)
            REFERENCES deployables(service_id, deployable_id)
    )
"""

_DEPLOYMENT_SUPERSESSIONS_SCHEMA = """
    CREATE TABLE deployment_report_supersessions (
        superseded_report_id INTEGER PRIMARY KEY
            REFERENCES deployment_reports(report_id),
        successor_report_id INTEGER NOT NULL UNIQUE
            REFERENCES deployment_reports(report_id),
        CHECK (superseded_report_id != successor_report_id)
    )
"""

_SERVICE_CHANGES_SCHEMA = """
    CREATE TABLE service_changes (
        change_id INTEGER PRIMARY KEY,
        service_id TEXT NOT NULL REFERENCES services(service_id),
        actor TEXT NOT NULL,
        reason TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        before_json TEXT NOT NULL,
        after_json TEXT NOT NULL
    )
"""

_LIFECYCLE_SCHEMA = """
    CREATE TABLE asset_lifecycle_events (
        event_id INTEGER PRIMARY KEY,
        action TEXT NOT NULL,
        service_id TEXT NOT NULL REFERENCES services(service_id),
        deployable_id TEXT,
        project_uuid TEXT,
        actor TEXT NOT NULL,
        reason TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        before_json TEXT NOT NULL,
        after_json TEXT NOT NULL
    )
"""

CURRENT_SCHEMA_VERSION = 6


class AssetRegistry:
    def __init__(
        self,
        path: str | Path,
        *,
        create_if_missing: bool = False,
        read_only: bool = False,
    ) -> None:
        if create_if_missing and read_only:
            raise ValueError("asset DB cannot be created in read-only mode")
        self.path = Path(path)
        self._read_only = read_only
        if not self.path.parent.is_dir():
            raise ValueError(
                f"asset DB parent directory does not exist: {self.path.parent}"
            )
        if not create_if_missing and not self.path.is_file():
            raise ValueError(f"asset DB does not exist: {self.path}")
        if create_if_missing:
            try:
                descriptor = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600
                )
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        self._db = sqlite3.connect(
            f"{self.path.resolve().as_uri()}?mode={'ro' if read_only else 'rw'}",
            uri=True,
            timeout=5.0,
        )
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA busy_timeout = 5000")
        try:
            self._initialize(create_if_missing=create_if_missing)
        except (sqlite3.Error, ValueError):
            self._db.close()
            raise

    def __enter__(self) -> AssetRegistry:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._db.close()

    @property
    def schema_version(self) -> int:
        return self._schema_version

    def _initialize(self, *, create_if_missing: bool) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version in (1, 2, 3, 4, 5, 6):
            self._schema_version = version
            return
        if version != 0:
            raise ValueError(f"unsupported asset DB schema version: {version}")
        if not create_if_missing:
            raise ValueError(f"asset DB is not initialized: {self.path}")
        if self._db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        ).fetchone():
            raise ValueError("asset DB has tables but no supported schema version")
        with self._db:
            self._db.executescript("""
                CREATE TABLE services (
                    service_id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    criticality TEXT NOT NULL,
                    impact_reason TEXT NOT NULL
                );
                CREATE TABLE deployables (
                    service_id TEXT NOT NULL REFERENCES services(service_id),
                    deployable_id TEXT NOT NULL,
                    project_name TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (service_id, deployable_id)
                );
                CREATE TABLE reviewed_project_links (
                    project_uuid TEXT PRIMARY KEY,
                    project_name TEXT NOT NULL,
                    project_version TEXT NOT NULL,
                    service_id TEXT NOT NULL,
                    deployable_id TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    reviewed_at TEXT NOT NULL,
                    UNIQUE (project_name, project_version),
                    FOREIGN KEY (service_id, deployable_id)
                        REFERENCES deployables(service_id, deployable_id)
                );
                CREATE TABLE deployment_reports (
                    report_id INTEGER PRIMARY KEY,
                    service_id TEXT NOT NULL,
                    deployable_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    deployment_status TEXT NOT NULL,
                    exposure_status TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (service_id, deployable_id)
                        REFERENCES deployables(service_id, deployable_id)
                );
                CREATE TABLE deployment_report_supersessions (
                    superseded_report_id INTEGER PRIMARY KEY
                        REFERENCES deployment_reports(report_id),
                    successor_report_id INTEGER NOT NULL UNIQUE
                        REFERENCES deployment_reports(report_id),
                    CHECK (superseded_report_id != successor_report_id)
                );
                PRAGMA user_version = 3;
                """)
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(_SERVICE_CHANGES_SCHEMA)
            self._db.execute(_LIFECYCLE_SCHEMA)
            self._db.execute(POC_SCHEMA)
            self._db.execute("PRAGMA user_version = 6")
        self._schema_version = CURRENT_SCHEMA_VERSION

    def migrate(self) -> bool:
        """Explicitly upgrade an old DB after the operator has taken a backup."""
        if self._read_only:
            raise ValueError("cannot migrate a read-only asset DB")
        if self._schema_version == CURRENT_SCHEMA_VERSION:
            return False
        self.check_integrity()
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            if self._schema_version == 1:
                self._db.execute(_DEPLOYMENT_REPORTS_SCHEMA)
            if self._schema_version < 3:
                self._db.execute(_DEPLOYMENT_SUPERSESSIONS_SCHEMA)
            if self._schema_version < 4:
                self._db.execute(_SERVICE_CHANGES_SCHEMA)
            if self._schema_version < 5:
                self._db.execute(_LIFECYCLE_SCHEMA)
            self._db.execute(POC_SCHEMA)
            self._db.execute("PRAGMA user_version = 6")
            self.check_integrity()
        self._schema_version = CURRENT_SCHEMA_VERSION
        return True

    def check_integrity(self) -> None:
        results = self._db.execute("PRAGMA integrity_check").fetchall()
        if results != [("ok",)]:
            raise ValueError(f"asset DB integrity check failed: {results}")
        violations = self._db.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise ValueError(f"asset DB foreign key check failed: {violations}")

    def backup_to(self, destination: str | Path) -> Path:
        target_path = Path(destination)
        if not target_path.parent.is_dir():
            raise ValueError(
                f"backup parent directory does not exist: {target_path.parent}"
            )
        if target_path.exists():
            raise ValueError(f"backup already exists: {target_path}")
        self.check_integrity()
        with NamedTemporaryFile(
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            dir=target_path.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
        try:
            with sqlite3.connect(temporary_path) as backup_db:
                self._db.backup(backup_db)
            with AssetRegistry(temporary_path) as backup:
                backup.check_integrity()
            try:
                os.link(temporary_path, target_path)
            except FileExistsError as exc:
                raise ValueError(f"backup already exists: {target_path}") from exc
        finally:
            temporary_path.unlink(missing_ok=True)
        return target_path

    def register_service(self, service: RegisteredService) -> None:
        try:
            with self._db:
                self._db.execute(
                    "INSERT INTO services VALUES (?, ?, ?, ?)",
                    (
                        service.service_id,
                        service.owner.strip(),
                        service.criticality.value,
                        service.impact_reason.strip(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"service already registered: {service.service_id}"
            ) from exc

    def register_batch(self, batch: AssetRegistrationBatch) -> None:
        """Apply one reviewed registration atomically; never alter existing rows."""
        try:
            with self._db:
                for service in batch.services:
                    self._db.execute(
                        "INSERT INTO services VALUES (?, ?, ?, ?)",
                        (
                            service.service_id,
                            service.owner.strip(),
                            service.criticality.value,
                            service.impact_reason.strip(),
                        ),
                    )
                for deployable in batch.deployables:
                    if self.is_retired(deployable.service_id):
                        raise ValueError(
                            "cannot register a deployable under a retired service"
                        )
                    self._db.execute(
                        "INSERT INTO deployables VALUES (?, ?, ?)",
                        (
                            deployable.service_id,
                            deployable.deployable_id,
                            deployable.project_name,
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "asset registration conflicts with existing services or deployables"
            ) from exc

    def register_deployable(self, deployable: RegisteredDeployable) -> None:
        try:
            with self._db:
                self._db.execute("BEGIN IMMEDIATE")
                if self.is_retired(deployable.service_id):
                    raise ValueError(
                        "cannot register a deployable under a retired service"
                    )
                self._db.execute(
                    "INSERT INTO deployables VALUES (?, ?, ?)",
                    (
                        deployable.service_id,
                        deployable.deployable_id,
                        deployable.project_name,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"service missing or deployable already registered: "
                f"{deployable.project_name}"
            ) from exc

    def register_deployment(self, report: ReportedDeployment) -> ReportedDeployment:
        if self._schema_version < 2:
            raise ValueError("asset DB v1 requires an explicit backup and migration")
        if report.supersedes_report_id is not None and self._schema_version < 3:
            raise ValueError("asset DB v2 requires an explicit backup and migration")
        try:
            with self._db:
                if report.supersedes_report_id is not None:
                    previous = self._get_deployment_report(report.supersedes_report_id)
                    if previous is None:
                        raise ValueError("superseded deployment report does not exist")
                    validate_deployment_supersession(previous, report)
                cursor = self._db.execute(
                    "INSERT INTO deployment_reports (service_id, deployable_id, "
                    "environment, artifact_id, deployment_status, exposure_status, "
                    "reviewer, evidence, observed_at, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        report.service_id,
                        report.deployable_id,
                        report.environment,
                        report.artifact_id,
                        report.deployment_status.value,
                        report.exposure_status.value,
                        report.reviewer.strip(),
                        report.evidence.strip(),
                        report.observed_at,
                        report.expires_at,
                    ),
                )
                if report.supersedes_report_id is not None:
                    self._db.execute(
                        "INSERT INTO deployment_report_supersessions VALUES (?, ?)",
                        (report.supersedes_report_id, cursor.lastrowid),
                    )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "deployment subject is not registered or report was already superseded"
            ) from exc
        return ReportedDeployment(
            service_id=report.service_id,
            deployable_id=report.deployable_id,
            environment=report.environment,
            artifact_id=report.artifact_id,
            deployment_status=report.deployment_status,
            exposure_status=report.exposure_status,
            reviewer=report.reviewer.strip(),
            evidence=report.evidence.strip(),
            observed_at=report.observed_at,
            expires_at=report.expires_at,
            report_id=cursor.lastrowid,
            supersedes_report_id=report.supersedes_report_id,
        )

    @staticmethod
    def _report_from_row(row: tuple[object, ...]) -> ReportedDeployment:
        return ReportedDeployment(
            service_id=str(row[1]),
            deployable_id=str(row[2]),
            environment=str(row[3]),
            artifact_id=str(row[4]),
            deployment_status=DeploymentStatus(str(row[5])),
            exposure_status=ExposureStatus(str(row[6])),
            reviewer=str(row[7]),
            evidence=str(row[8]),
            observed_at=str(row[9]),
            expires_at=str(row[10]),
            report_id=int(row[0]),
            supersedes_report_id=int(row[11]) if row[11] is not None else None,
        )

    def _get_deployment_report(self, report_id: int) -> ReportedDeployment | None:
        row = self._db.execute(
            "SELECT report_id, service_id, deployable_id, environment, artifact_id, "
            "deployment_status, exposure_status, reviewer, evidence, observed_at, "
            "expires_at FROM deployment_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()
        return self._report_from_row((*row, None)) if row else None

    def list_deployment_reports(self) -> tuple[ReportedDeployment, ...]:
        if self._schema_version < 2:
            return ()
        if self._schema_version >= 3:
            suffix = (
                "s.superseded_report_id FROM deployment_reports d "
                "LEFT JOIN deployment_report_supersessions s "
                "ON s.successor_report_id = d.report_id"
            )
        else:
            suffix = "NULL FROM deployment_reports d"
        rows = self._db.execute(
            "SELECT d.report_id, d.service_id, d.deployable_id, d.environment, "
            "d.artifact_id, d.deployment_status, d.exposure_status, d.reviewer, "
            "d.evidence, d.observed_at, d.expires_at, "
            + suffix
            + " ORDER BY d.report_id"
        ).fetchall()
        return tuple(self._report_from_row(row) for row in rows)

    def list_deployables(self) -> tuple[RegisteredDeployable, ...]:
        rows = self._db.execute(
            "SELECT service_id, deployable_id FROM deployables "
            "ORDER BY service_id, deployable_id"
        ).fetchall()
        return tuple(RegisteredDeployable(*row) for row in rows)

    def get_deployable(
        self, service_id: str, deployable_id: str
    ) -> RegisteredDeployable | None:
        row = self._db.execute(
            "SELECT service_id, deployable_id FROM deployables "
            "WHERE service_id = ? AND deployable_id = ?",
            (service_id, deployable_id),
        ).fetchone()
        return RegisteredDeployable(*row) if row else None

    def linked_uuid(self, project_name: str, project_version: str) -> str | None:
        row = self._db.execute(
            "SELECT project_uuid FROM reviewed_project_links "
            "WHERE project_name = ? AND project_version = ?",
            (project_name, project_version),
        ).fetchone()
        return str(row[0]) if row else None

    def linked_coordinates(self, project_uuid: str) -> tuple[str, str] | None:
        row = self._db.execute(
            "SELECT project_name, project_version FROM reviewed_project_links "
            "WHERE project_uuid = ?",
            (project_uuid,),
        ).fetchone()
        return (str(row[0]), str(row[1])) if row else None

    def list_links(self) -> tuple[ReviewedProjectLink, ...]:
        rows = self._db.execute(
            "SELECT project_uuid, project_name, project_version, service_id, "
            "deployable_id, reviewer, reviewed_at FROM reviewed_project_links "
            "ORDER BY project_name, project_version"
        ).fetchall()
        return tuple(ReviewedProjectLink(*row) for row in rows)

    def link_project(
        self,
        *,
        deployable: RegisteredDeployable,
        project_uuid: str,
        project_version: str,
        reviewer: str,
    ) -> ReviewedProjectLink:
        if not reviewer.strip():
            raise ValueError("reviewer is required")
        reviewed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        link = ReviewedProjectLink(
            project_uuid=project_uuid,
            project_name=deployable.project_name,
            project_version=project_version,
            service_id=deployable.service_id,
            deployable_id=deployable.deployable_id,
            reviewer=reviewer.strip(),
            reviewed_at=reviewed_at,
        )
        try:
            with self._db:
                self._db.execute("BEGIN IMMEDIATE")
                if self.is_retired(deployable.service_id, deployable.deployable_id):
                    raise ValueError("cannot approve a link to a retired asset")
                self._db.execute(
                    "INSERT INTO reviewed_project_links VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        link.project_uuid,
                        link.project_name,
                        link.project_version,
                        link.service_id,
                        link.deployable_id,
                        link.reviewer,
                        link.reviewed_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Project UUID or name/version already reviewed") from exc
        return link

    def list_services(self) -> tuple[RegisteredService, ...]:
        rows = self._db.execute(
            "SELECT service_id, owner, criticality, impact_reason "
            "FROM services ORDER BY service_id"
        ).fetchall()
        return tuple(
            RegisteredService(row[0], row[1], BusinessCriticality(row[2]), row[3])
            for row in rows
        )

    def get_service(self, service_id: str) -> RegisteredService | None:
        row = self._db.execute(
            "SELECT service_id, owner, criticality, impact_reason "
            "FROM services WHERE service_id = ?",
            (service_id,),
        ).fetchone()
        return (
            RegisteredService(row[0], row[1], BusinessCriticality(row[2]), row[3])
            if row
            else None
        )

    def update_service(self, update: ServiceUpdate) -> ServiceChange:
        """Persist the reviewed values and their audit entry in one transaction."""
        if self._read_only:
            raise ValueError("cannot update a read-only asset DB")
        if self._schema_version < 4:
            raise ValueError("service update requires an explicit backup and migration")
        before, after = update.before, update.after
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            if self.get_service(before.service_id) != before:
                raise ValueError(
                    "service changed since review; review the update again"
                )
            changed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            self._db.execute(
                "UPDATE services SET owner = ?, criticality = ?, impact_reason = ? "
                "WHERE service_id = ?",
                (
                    after.owner,
                    after.criticality.value,
                    after.impact_reason,
                    after.service_id,
                ),
            )
            cursor = self._db.execute(
                "INSERT INTO service_changes "
                "(service_id, actor, reason, changed_at, before_json, after_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    after.service_id,
                    update.actor,
                    update.reason,
                    changed_at,
                    json.dumps(before.as_dict(), ensure_ascii=False, sort_keys=True),
                    json.dumps(after.as_dict(), ensure_ascii=False, sort_keys=True),
                ),
            )
        return ServiceChange(int(cursor.lastrowid), changed_at, update)

    def list_service_changes(self, service_id: str) -> tuple[ServiceChange, ...]:
        if self.get_service(service_id) is None:
            raise ValueError(f"service is not registered: {service_id}")
        if self._schema_version < 4:
            return ()
        rows = self._db.execute(
            "SELECT change_id, changed_at, actor, reason, before_json, after_json "
            "FROM service_changes WHERE service_id = ? ORDER BY change_id",
            (service_id,),
        ).fetchall()
        changes = []
        for change_id, changed_at, actor, reason, before_json, after_json in rows:
            before, after = json.loads(before_json), json.loads(after_json)
            before["criticality"] = BusinessCriticality(before["criticality"])
            after["criticality"] = BusinessCriticality(after["criticality"])
            changes.append(
                ServiceChange(
                    change_id,
                    changed_at,
                    ServiceUpdate(
                        RegisteredService(**before),
                        RegisteredService(**after),
                        actor,
                        reason,
                    ),
                )
            )
        return tuple(changes)

    def is_retired(self, service_id: str, deployable_id: str | None = None) -> bool:
        if self._schema_version < 5:
            return False
        return (
            self._db.execute(
                "SELECT 1 FROM asset_lifecycle_events WHERE service_id = ? AND "
                "(action = 'retire_service' OR (action = 'retire_deployable' "
                "AND deployable_id = ?)) LIMIT 1",
                (service_id, deployable_id),
            ).fetchone()
            is not None
        )

    def list_lifecycle_events(
        self, service_id: str | None = None
    ) -> tuple[dict[str, object], ...]:
        if self._schema_version < 5:
            return ()
        rows = self._db.execute(
            "SELECT event_id, action, service_id, deployable_id, project_uuid, actor, "
            "reason, changed_at, before_json, after_json FROM asset_lifecycle_events "
            + ("WHERE service_id = ? " if service_id is not None else "")
            + "ORDER BY event_id",
            (service_id,) if service_id is not None else (),
        ).fetchall()
        return tuple(
            {
                "event_id": row[0],
                "action": row[1],
                "service_id": row[2],
                "deployable_id": row[3],
                "project_uuid": row[4],
                "actor": row[5],
                "reason": row[6],
                "changed_at": row[7],
                "before": json.loads(row[8]),
                "after": json.loads(row[9]),
            }
            for row in rows
        )

    def lifecycle_state(self) -> dict[str, tuple]:
        events = self.list_lifecycle_events()
        active_uuids = {link.project_uuid for link in self.list_links()}
        return {
            "retired_services": tuple(
                sorted(
                    {
                        item["service_id"]
                        for item in events
                        if item["action"] == "retire_service"
                    }
                )
            ),
            "retired_deployables": tuple(
                sorted(
                    {
                        (item["service_id"], item["deployable_id"])
                        for item in events
                        if item["action"] == "retire_deployable"
                    }
                )
            ),
            "revoked_project_uuids": tuple(
                sorted(
                    {
                        item["project_uuid"]
                        for item in events
                        if item["action"] == "revoke_link"
                    }
                    - active_uuids
                )
            ),
        }

    def apply_lifecycle_change(self, change: LifecycleChange) -> dict[str, object]:
        if self._read_only:
            raise ValueError("cannot change a read-only asset DB")
        if self._schema_version < 5:
            raise ValueError(
                "lifecycle changes require an explicit backup and migration"
            )
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            if self.get_service(change.service_id) is None:
                raise ValueError("service is not registered")
            if (
                change.deployable_id is not None
                and self.get_deployable(change.service_id, change.deployable_id) is None
            ):
                raise ValueError("deployable is not registered")
            links = tuple(
                link
                for link in self.list_links()
                if link.service_id == change.service_id
                and (
                    change.deployable_id is None
                    or link.deployable_id == change.deployable_id
                )
                and (
                    change.project_uuid is None
                    or link.project_uuid == change.project_uuid
                )
            )
            if links != change.links:
                raise ValueError("Project links changed since review; review again")
            if change.action is not LifecycleAction.REVOKE_LINK and self.is_retired(
                change.service_id, change.deployable_id
            ):
                raise ValueError("asset is already retired")
            payload = change.as_dict()
            changed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            cursor = self._db.execute(
                "INSERT INTO asset_lifecycle_events "
                "(action, service_id, deployable_id, "
                "project_uuid, actor, reason, changed_at, before_json, after_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    change.action.value,
                    change.service_id,
                    change.deployable_id,
                    change.project_uuid,
                    change.actor,
                    change.reason,
                    changed_at,
                    json.dumps(payload["before"], ensure_ascii=False),
                    json.dumps(payload["after"], ensure_ascii=False),
                ),
            )
            if change.action is LifecycleAction.REVOKE_LINK:
                self._db.execute(
                    "DELETE FROM reviewed_project_links WHERE project_uuid = ?",
                    (change.project_uuid,),
                )
        return {**payload, "event_id": cursor.lastrowid, "changed_at": changed_at}
