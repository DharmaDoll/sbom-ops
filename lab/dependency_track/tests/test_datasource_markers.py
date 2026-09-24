from __future__ import annotations

import json

import pytest
from dt_lab.datasource_markers import (
    summarize_osv_markers,
    write_osv_marker_summary,
)

ECOSYSTEMS = ["Go", "npm"]
OBSERVED_AT = "2026-09-14T01:00:00Z"
MARKERS = b"\n".join(
    (
        b"/data/.dependency-track/osv/google-osv-Go.zip.ts\t" b"2026-09-13T00:00:00Z",
        b"/data/.dependency-track/osv/google-osv-Go-modified.csv.ts\t"
        b"2026-09-14T00:00:00Z",
        b"google-osv-npm.zip.ts\t2026-09-11T00:00:00Z",
        b"google-osv-npm-modified.csv.ts\t2026-09-11T00:00:00Z",
    )
)


def test_summary_reports_per_ecosystem_age_with_declared_threshold() -> None:
    result = summarize_osv_markers(
        MARKERS,
        ecosystems=ECOSYSTEMS,
        observed_at=OBSERVED_AT,
        max_age_hours=30,
    )

    assert result["overall_age_assessment"] == "older-than-threshold"
    assert result["input"]["raw_persisted"] is False
    assert result["ecosystems"] == [
        {
            "ecosystem": "Go",
            "full_success_started_at": "2026-09-13T00:00:00+00:00",
            "incremental_success_started_at": "2026-09-14T00:00:00+00:00",
            "latest_success_started_at": "2026-09-14T00:00:00+00:00",
            "age_seconds": 3600.0,
            "age_assessment": "within-threshold",
        },
        {
            "ecosystem": "npm",
            "full_success_started_at": "2026-09-11T00:00:00+00:00",
            "incremental_success_started_at": "2026-09-11T00:00:00+00:00",
            "latest_success_started_at": "2026-09-11T00:00:00+00:00",
            "age_seconds": 262800.0,
            "age_assessment": "older-than-threshold",
        },
    ]


def test_future_marker_is_not_reported_as_current() -> None:
    raw = MARKERS.replace(b"2026-09-14T00:00:00Z", b"2026-09-15T00:00:00Z")

    result = summarize_osv_markers(
        raw,
        ecosystems=ECOSYSTEMS,
        observed_at=OBSERVED_AT,
        max_age_hours=30,
    )

    assert result["overall_age_assessment"] == "future"
    assert result["ecosystems"][0]["age_assessment"] == "future"


@pytest.mark.parametrize(
    "raw",
    (
        MARKERS.replace(b"google-osv-npm.zip.ts", b"unexpected.ts"),
        MARKERS.replace(b"google-osv-npm.zip.ts\t2026-09-11T00:00:00Z\n", b""),
        MARKERS + b"\ngoogle-osv-npm.zip.ts\t2026-09-11T00:00:00Z",
        MARKERS.replace(b"\t2026-09-11T00:00:00Z", b" no-tab", 1),
    ),
)
def test_summary_rejects_unexpected_missing_duplicate_or_malformed_input(raw) -> None:
    with pytest.raises(ValueError):
        summarize_osv_markers(
            raw,
            ecosystems=ECOSYSTEMS,
            observed_at=OBSERVED_AT,
            max_age_hours=30,
        )


def test_summary_rejects_incremental_marker_older_than_full() -> None:
    raw = MARKERS.replace(b"2026-09-14T00:00:00Z", b"2026-09-12T00:00:00Z")

    with pytest.raises(ValueError, match="incremental marker"):
        summarize_osv_markers(
            raw,
            ecosystems=ECOSYSTEMS,
            observed_at=OBSERVED_AT,
            max_age_hours=30,
        )


@pytest.mark.parametrize(
    ("ecosystems", "observed_at", "max_age_hours"),
    (
        ([], OBSERVED_AT, 30),
        (["Go", "Go"], OBSERVED_AT, 30),
        (["bad/ecosystem"], OBSERVED_AT, 30),
        (ECOSYSTEMS, "not-a-time", 30),
        (ECOSYSTEMS, OBSERVED_AT, 0),
        (ECOSYSTEMS, OBSERVED_AT, float("nan")),
        (ECOSYSTEMS, OBSERVED_AT, 8761),
    ),
)
def test_summary_rejects_invalid_parameters(
    ecosystems, observed_at, max_age_hours
) -> None:
    with pytest.raises(ValueError):
        summarize_osv_markers(
            MARKERS,
            ecosystems=ecosystems,
            observed_at=observed_at,
            max_age_hours=max_age_hours,
        )


def test_writer_creates_run_scoped_sanitized_result(tmp_path) -> None:
    output = write_osv_marker_summary(
        MARKERS,
        ecosystems=ECOSYSTEMS,
        observed_at=OBSERVED_AT,
        max_age_hours=30,
        output_dir=tmp_path,
    )

    result = json.loads(output.read_text())
    assert output.name == "osv-internal-markers.json"
    assert result["input"]["raw_persisted"] is False
    assert "/data/" not in output.read_text()
