from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from sbom_ops.domain.advisory import (
    AdvisoryReference,
    AdvisorySnapshot,
    EvidenceFreshness,
    EvidenceOutcome,
    ExposureStatus,
    ProjectExposureObservation,
    VulnerabilityEvidenceObservation,
)

_MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024
_MAX_OBSERVATIONS = 10_000
_MAX_EXPOSURE_OBSERVATIONS = 10_000


def _required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _required_string(value, field)


def _timestamp(value: object, field: str) -> str:
    timestamp = _required_string(value, field)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return timestamp


def _enum(enum_type: type, value: object, field: str):
    try:
        return enum_type(value)
    except (ValueError, TypeError) as exc:
        choices = ", ".join(item.value for item in enum_type)
        raise ValueError(f"{field} must be one of: {choices}") from exc


def _mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def load_advisory_snapshot(path: str | Path) -> AdvisorySnapshot:
    """Load a bounded snapshot without fetching external URLs."""
    try:
        snapshot_path = Path(path)
        if snapshot_path.stat().st_size > _MAX_SNAPSHOT_BYTES:
            raise ValueError("advisory snapshot exceeds the 5 MiB size limit")
        raw_snapshot = snapshot_path.read_bytes()
        if len(raw_snapshot) > _MAX_SNAPSHOT_BYTES:
            raise ValueError("advisory snapshot exceeds the 5 MiB size limit")
        payload = json.loads(raw_snapshot)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid advisory snapshot JSON: {exc.msg}") from exc
    root = _mapping(payload, "snapshot")
    schema_version = root.get("schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise ValueError("schema_version must be 1")
    if schema_version != 1:
        raise ValueError("schema_version must be 1")
    snapshot_id = _required_string(root.get("snapshot_id"), "snapshot_id")
    generated_at = _timestamp(root.get("generated_at"), "generated_at")
    raw_observations = root.get("vulnerability_observations")
    raw_exposure = root.get("project_exposure")
    if not isinstance(raw_observations, list):
        raise ValueError("vulnerability_observations must be an array")
    if not isinstance(raw_exposure, list):
        raise ValueError("project_exposure must be an array")
    if len(raw_observations) > _MAX_OBSERVATIONS:
        raise ValueError("vulnerability_observations exceeds the 10,000 item limit")
    if len(raw_exposure) > _MAX_EXPOSURE_OBSERVATIONS:
        raise ValueError("project_exposure exceeds the 10,000 item limit")

    observations: list[VulnerabilityEvidenceObservation] = []
    observation_keys: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_observations):
        field = f"vulnerability_observations[{index}]"
        item = _mapping(raw, field)
        vulnerability_id = _required_string(
            item.get("vulnerability_id"), f"{field}.vulnerability_id"
        )
        source = _required_string(item.get("source"), f"{field}.source")
        signal = _required_string(item.get("signal"), f"{field}.signal")
        key = (vulnerability_id.upper(), source.casefold(), signal.casefold())
        if key in observation_keys:
            raise ValueError(f"duplicate observation: {field}")
        observation_keys.add(key)
        outcome = _enum(EvidenceOutcome, item.get("outcome"), f"{field}.outcome")
        freshness = _enum(
            EvidenceFreshness, item.get("freshness"), f"{field}.freshness"
        )
        observed_at = _timestamp(item.get("observed_at"), f"{field}.observed_at")
        source_revision = _optional_string(
            item.get("source_revision"), f"{field}.source_revision"
        )
        record_count = item.get("record_count")
        if record_count is not None and (
            isinstance(record_count, bool)
            or not isinstance(record_count, int)
            or record_count < 0
        ):
            raise ValueError(
                f"{field}.record_count must be a non-negative integer or null"
            )
        complete = item.get("complete")
        if not isinstance(complete, bool):
            raise ValueError(f"{field}.complete must be a boolean")
        raw_references = item.get("references", [])
        if not isinstance(raw_references, list) or len(raw_references) > 20:
            raise ValueError(f"{field}.references must be an array of at most 20 items")
        references: list[AdvisoryReference] = []
        for reference_index, raw_reference in enumerate(raw_references):
            ref_field = f"{field}.references[{reference_index}]"
            reference = _mapping(raw_reference, ref_field)
            url = _required_string(reference.get("url"), f"{ref_field}.url")
            parsed_url = urlparse(url)
            if parsed_url.scheme not in {"https", "http"} or not parsed_url.netloc:
                raise ValueError(f"{ref_field}.url must be an absolute HTTP(S) URL")
            assertions = reference.get("upstream_assertions", [])
            if not isinstance(assertions, list) or not all(
                isinstance(assertion, str) and assertion.strip()
                for assertion in assertions
            ):
                raise ValueError(
                    f"{ref_field}.upstream_assertions must be an array of "
                    "non-empty strings"
                )
            references.append(
                AdvisoryReference(
                    record_id=_optional_string(
                        reference.get("record_id"), f"{ref_field}.record_id"
                    ),
                    url=url,
                    provider=_optional_string(
                        reference.get("provider"), f"{ref_field}.provider"
                    ),
                    kind=_required_string(reference.get("kind"), f"{ref_field}.kind"),
                    upstream_type=_optional_string(
                        reference.get("upstream_type"), f"{ref_field}.upstream_type"
                    ),
                    upstream_assertions=tuple(
                        assertion.strip() for assertion in assertions
                    ),
                )
            )
        if record_count is not None and record_count < len(references):
            raise ValueError(
                f"{field}.record_count cannot be less than retained references"
            )
        if outcome is EvidenceOutcome.AVAILABLE and (
            record_count is None or record_count == 0
        ):
            raise ValueError(
                f"{field}: available outcome requires a positive record_count"
            )
        if outcome is EvidenceOutcome.NOT_OBSERVED and (
            not complete or record_count != 0 or references
        ):
            raise ValueError(
                f"{field}: not_observed requires complete=true, record_count=0, "
                "and no references"
            )
        observations.append(
            VulnerabilityEvidenceObservation(
                vulnerability_id=vulnerability_id,
                source=source,
                signal=signal,
                outcome=outcome,
                observed_at=observed_at,
                source_revision=source_revision,
                freshness=freshness,
                record_count=record_count,
                complete=complete,
                references=tuple(references),
            )
        )

    exposures: list[ProjectExposureObservation] = []
    for index, raw in enumerate(raw_exposure):
        field = f"project_exposure[{index}]"
        item = _mapping(raw, field)
        observed_at = _timestamp(item.get("observed_at"), f"{field}.observed_at")
        expires_at = _timestamp(item.get("expires_at"), f"{field}.expires_at")
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expires <= observed:
            raise ValueError(f"{field}.expires_at must be later than observed_at")
        exposures.append(
            ProjectExposureObservation(
                project_uuid=_required_string(
                    item.get("project_uuid"), f"{field}.project_uuid"
                ),
                environment=_required_string(
                    item.get("environment"), f"{field}.environment"
                ),
                status=_enum(ExposureStatus, item.get("status"), f"{field}.status"),
                source=_required_string(item.get("source"), f"{field}.source"),
                observed_at=observed_at,
                expires_at=expires_at,
                reviewer=_optional_string(item.get("reviewer"), f"{field}.reviewer"),
            )
        )

    return AdvisorySnapshot(
        snapshot_id=snapshot_id,
        generated_at=generated_at,
        vulnerability_observations=tuple(observations),
        project_exposure=tuple(exposures),
        sha256=hashlib.sha256(raw_snapshot).hexdigest(),
    )
