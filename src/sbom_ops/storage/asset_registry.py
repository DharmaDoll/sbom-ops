from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from types import TracebackType

from sbom_ops.domain.asset_registry import (
    RegisteredDeployable,
    RegisteredService,
    ReviewedProjectLink,
)
from sbom_ops.domain.assets import BusinessCriticality


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

    def _initialize(self, *, create_if_missing: bool) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version == 1:
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
                PRAGMA user_version = 1;
                """)

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

    def register_deployable(self, deployable: RegisteredDeployable) -> None:
        try:
            with self._db:
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
