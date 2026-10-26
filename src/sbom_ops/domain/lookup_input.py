"""Sync envelope integrity checks; these do not prove portfolio completeness."""

import json
from collections import Counter
from datetime import datetime
from math import isfinite

from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.asset_registry import (
    RegistryDeploymentStatus,
    RegistryProjectStatus,
    RegistrySnapshotStatus,
)
from sbom_ops.domain.assets import DeploymentStatus
from sbom_ops.domain.lookup_evidence import validate_lookup_evidence
from sbom_ops.domain.models import AnalysisState, Priority, Severity

IDENTITY_FIELDS = (
    "finding_key",
    "project_uuid",
    "vulnerability_id",
    "vulnerability_source",
    "component_uuid",
    "component_purl",
    "component_name",
    "component_version",
)


def validate_lookup_envelope(document: object) -> dict[str, object]:
    if not isinstance(document, dict) or document.get("status") != "succeeded":
        raise ValueError("lookup_input_not_successful")
    run_id = document.get("run_id")
    if (
        not isinstance(run_id, str)
        or not run_id
        or len(run_id) > 256
        or run_id != run_id.strip()
        or not run_id.isprintable()
    ):
        raise ValueError("lookup_input_invalid_run")
    for field in ("findings_processed", "projects_processed"):
        count = document.get(field)
        if type(count) is not int or count < 0:
            raise ValueError("lookup_input_invalid_count")
    rows = document.get("review_queue")
    assessments = document.get("assessments")
    if not isinstance(rows, list) or not isinstance(assessments, list):
        raise ValueError("lookup_input_missing_rows")
    if len(rows) != document["findings_processed"] or len(rows) != len(assessments):
        raise ValueError("lookup_input_count_mismatch")
    if len(rows) > 10_000:
        raise ValueError("lookup_input_row_limit")

    def identity(row: object) -> tuple[str | None, ...]:
        if not isinstance(row, dict) or any(
            field not in row for field in IDENTITY_FIELDS
        ):
            raise ValueError("lookup_input_missing_identity")
        values = []
        for field in IDENTITY_FIELDS:
            value = row[field]
            required = field in ("finding_key", "project_uuid", "vulnerability_id")
            if value is None and not required:
                values.append(None)
                continue
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 8192
                or not value.isprintable()
            ):
                raise ValueError("lookup_input_invalid_identity")
            values.append(value)
        return tuple(values)

    reviews = Counter(identity(row) for row in rows)
    originals = Counter(identity(row) for row in assessments)
    if reviews != originals:
        raise ValueError("lookup_input_identity_mismatch")
    project_ids = {identity[1] for identity in reviews}
    if len(project_ids) > document["projects_processed"]:
        raise ValueError("lookup_input_project_count_mismatch")

    def evaluation(row: dict[str, object]) -> str:
        fields = (
            "priority",
            "severity",
            "analysis_state",
            "is_suppressed",
            "in_kev",
            "cvss_score",
            "epss_score",
            "rationale",
        )
        if any(field not in row for field in fields):
            raise ValueError("lookup_input_evaluation_missing")
        if (
            row["priority"] not in tuple(Priority)
            or row["severity"] not in tuple(Severity)
            or row["analysis_state"] not in tuple(AnalysisState)
        ):
            raise ValueError("lookup_input_evaluation_state")
        if any(type(row[field]) is not bool for field in ("is_suppressed", "in_kev")):
            raise ValueError("lookup_input_evaluation_boolean")
        for field, maximum in (("cvss_score", 10), ("epss_score", 1)):
            value = row[field]
            if value is not None and (
                type(value) not in (int, float)
                or not isfinite(value)
                or not 0 <= value <= maximum
            ):
                raise ValueError("lookup_input_evaluation_score")
        rationale = row["rationale"]
        if not isinstance(rationale, list) or any(
            not isinstance(value, str) for value in rationale
        ):
            raise ValueError("lookup_input_evaluation_rationale")
        return json.dumps(
            [identity(row), [row[field] for field in fields]], allow_nan=False
        )

    if Counter(evaluation(row) for row in rows) != Counter(
        evaluation(row) for row in assessments
    ):
        raise ValueError("lookup_input_evaluation_mismatch")
    _validate_context(document, rows)
    validate_lookup_evidence(document)
    return document


def _validate_context(document: dict[str, object], rows: list[object]) -> None:
    """Check saved projections against saved observations, not current runtime."""
    snapshot = document.get("registry_snapshot_status")
    if snapshot not in tuple(RegistrySnapshotStatus):
        raise ValueError("lookup_input_registry_status")
    projects = document.get("registry_projects")
    deployments = document.get("registry_deployments")
    if not isinstance(projects, list) or not isinstance(deployments, list):
        raise ValueError("lookup_input_registry_missing")
    by_project: dict[str, list[dict[str, object]]] = {}
    by_environment: dict[str, list[dict[str, object]]] = {}
    for project in projects:
        if not isinstance(project, dict) or project.get("status") not in tuple(
            RegistryProjectStatus
        ):
            raise ValueError("lookup_input_project_invalid")
        uuid = project.get("project_uuid")
        if not isinstance(uuid, str) or not uuid:
            raise ValueError("lookup_input_project_invalid")
        if project["status"] == "matched":
            for field in (
                "dt_name",
                "dt_version",
                "service_id",
                "deployable_id",
                "owner",
            ):
                value = project.get(field)
                if not isinstance(value, str) or not value or not value.isprintable():
                    raise ValueError("lookup_input_matched_asset_incomplete")
        by_project.setdefault(uuid, []).append(project)
    for deployment in deployments:
        if not isinstance(deployment, dict) or deployment.get("status") not in tuple(
            RegistryDeploymentStatus
        ):
            raise ValueError("lookup_input_deployment_invalid")
        uuid = deployment.get("project_uuid")
        if not isinstance(uuid, str) or not uuid:
            raise ValueError("lookup_input_deployment_invalid")
        candidates = by_project.get(uuid, [])
        if not candidates or any(
            deployment.get("artifact_id") != project.get("dt_version")
            for project in candidates
        ):
            raise ValueError("lookup_input_deployment_artifact")
        report_ids = deployment.get("report_ids")
        if not isinstance(report_ids, list) or any(
            type(value) is not int or value <= 0 for value in report_ids
        ):
            raise ValueError("lookup_input_report_ids")
        if deployment.get("source") != ("human_reported" if report_ids else None):
            raise ValueError("lookup_input_report_source")
        if deployment["status"] == "reported":
            if (
                not report_ids
                or deployment.get("deployment_status") not in tuple(DeploymentStatus)
                or deployment.get("exposure_status")
                not in (
                    ExposureStatus.CONFIRMED,
                    ExposureStatus.REJECTED,
                    ExposureStatus.UNKNOWN,
                )
            ):
                raise ValueError("lookup_input_reported_claim")
            for field in ("environment", "artifact_id", "reviewer"):
                value = deployment.get(field)
                if not isinstance(value, str) or not value or not value.isprintable():
                    raise ValueError("lookup_input_reported_claim")
            observed = _aware_time(deployment.get("observed_at"))
            expires = _aware_time(deployment.get("expires_at"))
            if expires <= observed:
                raise ValueError("lookup_input_reported_time")
        # Uncertain observations must not acquire a definitive deployment claim.
        if deployment["status"] != "reported" and any(
            deployment.get(field) is not None
            for field in (
                "deployment_status",
                "exposure_status",
                "reviewer",
                "observed_at",
                "expires_at",
            )
        ):
            raise ValueError("lookup_input_uncertain_deployment_claim")
        by_environment.setdefault(uuid, []).append(deployment)
    for row in rows:
        # Identity validation already establishes dictionary rows with Project IDs.
        candidates = by_project.get(row["project_uuid"], [])
        if snapshot == "not_requested":
            status = "not_requested"
        elif len(candidates) > 1:
            status = "ambiguous"
        elif not candidates:
            status = "unlinked"
        else:
            status = candidates[0]["status"]
        asset = candidates[0] if status == "matched" else None
        environments = by_environment.get(row["project_uuid"], []) if asset else []
        if (
            row.get("asset_status") != status
            or "asset" not in row
            or row["asset"] != asset
            or row.get("environments") != environments
        ):
            raise ValueError("lookup_input_context_mismatch")


def _aware_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("lookup_input_reported_time")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("lookup_input_reported_time") from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("lookup_input_reported_time")
    return result
