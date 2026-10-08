"""Version-coupled summaries of Dependency-Track OSV timestamp markers."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from math import isfinite
from pathlib import Path
from uuid import uuid4

_MAX_INPUT_BYTES = 64 * 1024
_MAX_ECOSYSTEMS = 32


def _parse_timestamp(value: str, location: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{location} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{location} must include a timezone")
    return parsed.astimezone(UTC)


def _validate_ecosystems(ecosystems: list[str]) -> tuple[str, ...]:
    if not ecosystems or len(ecosystems) > _MAX_ECOSYSTEMS:
        raise ValueError("between 1 and 32 expected ecosystems are required")
    if len(set(ecosystems)) != len(ecosystems):
        raise ValueError("expected ecosystems must be unique")
    for ecosystem in ecosystems:
        if not ecosystem or len(ecosystem) > 64:
            raise ValueError("invalid expected ecosystem")
        if any(
            character
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-"
            for character in ecosystem
        ):
            raise ValueError("invalid expected ecosystem")
    return tuple(sorted(ecosystems))


def summarize_osv_markers(
    raw: bytes,
    *,
    ecosystems: list[str],
    observed_at: str,
    max_age_hours: float,
) -> dict[str, object]:
    """Validate OSV marker pairs and return metadata without retaining raw input."""
    if len(raw) > _MAX_INPUT_BYTES:
        raise ValueError("OSV marker input exceeds 64 KiB")
    expected_ecosystems = _validate_ecosystems(ecosystems)
    observation_time = _parse_timestamp(observed_at, "observed_at")
    if not isfinite(max_age_hours) or max_age_hours <= 0 or max_age_hours > 8760:
        raise ValueError("max_age_hours must be greater than 0 and at most 8760")

    allowed_files: dict[str, tuple[str, str]] = {}
    for ecosystem in expected_ecosystems:
        allowed_files[f"google-osv-{ecosystem}.zip.ts"] = (ecosystem, "full")
        allowed_files[f"google-osv-{ecosystem}-modified.csv.ts"] = (
            ecosystem,
            "incremental",
        )

    markers: dict[tuple[str, str], datetime] = {}
    text = raw.decode("utf-8", errors="strict")
    for line_number, line in enumerate(text.splitlines(), start=1):
        parts = line.split("\t")
        if len(parts) != 2:
            raise ValueError(f"marker line {line_number} must contain one tab")
        filename = Path(parts[0]).name
        marker_identity = allowed_files.get(filename)
        if marker_identity is None:
            raise ValueError(f"unexpected marker file on line {line_number}")
        if marker_identity in markers:
            raise ValueError(f"duplicate marker file on line {line_number}")
        markers[marker_identity] = _parse_timestamp(
            parts[1], f"marker line {line_number}"
        )

    expected_count = len(expected_ecosystems) * 2
    if len(markers) != expected_count:
        raise ValueError("all expected full and incremental markers are required")

    threshold_seconds = max_age_hours * 60 * 60
    ecosystem_results: list[dict[str, object]] = []
    assessments: list[str] = []
    for ecosystem in expected_ecosystems:
        full = markers[(ecosystem, "full")]
        incremental = markers[(ecosystem, "incremental")]
        if incremental < full:
            raise ValueError("incremental marker cannot be older than full marker")
        latest = max(full, incremental)
        age_seconds = (observation_time - latest).total_seconds()
        if age_seconds < 0:
            assessment = "future"
        elif age_seconds > threshold_seconds:
            assessment = "older-than-threshold"
        else:
            assessment = "within-threshold"
        assessments.append(assessment)
        ecosystem_results.append(
            {
                "ecosystem": ecosystem,
                "full_success_started_at": full.isoformat(),
                "incremental_success_started_at": incremental.isoformat(),
                "latest_success_started_at": latest.isoformat(),
                "age_seconds": age_seconds,
                "age_assessment": assessment,
            }
        )

    if "future" in assessments:
        overall = "future"
    elif "older-than-threshold" in assessments:
        overall = "older-than-threshold"
    else:
        overall = "within-threshold"

    return {
        "schema_version": 1,
        "run_id": str(uuid4()),
        "target": "dependency-track-osv-internal-markers",
        "target_version": "4.14.3",
        "observed_at": observation_time.isoformat(),
        "configured_max_age_hours": max_age_hours,
        "input": {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "byte_count": len(raw),
            "raw_persisted": False,
        },
        "overall_age_assessment": overall,
        "ecosystems": ecosystem_results,
        "marker_semantics": (
            "In Dependency-Track 4.14.3 these internal files are written after "
            "successful OSV processing and contain the update operation start time."
        ),
        "interpretation_boundary": (
            "Marker age can establish the absence of a newer recorded successful "
            "OSV update on this datastore. It cannot distinguish a task that never "
            "ran from a failed task, prove upstream completeness, or replace a "
            "supported API or telemetry contract. Revalidate on every DT upgrade."
        ),
    }


def write_osv_marker_summary(
    raw: bytes,
    *,
    ecosystems: list[str],
    observed_at: str,
    max_age_hours: float,
    output_dir: str | Path,
) -> Path:
    result = summarize_osv_markers(
        raw,
        ecosystems=ecosystems,
        observed_at=observed_at,
        max_age_hours=max_age_hours,
    )
    run_dir = Path(output_dir) / str(result["run_id"])
    run_dir.mkdir(parents=True, exist_ok=False)
    output = run_dir / "osv-internal-markers.json"
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output
