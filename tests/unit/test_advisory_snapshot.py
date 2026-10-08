from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sbom_ops.domain.advisory import (
    EvidenceFreshness,
    EvidenceOutcome,
    ExposureStatus,
    PocReportStatus,
    VulnerabilityEvidenceObservation,
    summarize_poc_reports,
)
from sbom_ops.services.advisory_snapshot import load_advisory_snapshot


def payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "snapshot_id": "capture-2026-10-03",
        "generated_at": "2026-10-03T00:00:00Z",
        "vulnerability_observations": [
            {
                "vulnerability_id": "CVE-2026-1234",
                "source": "vulnerability-lookup",
                "signal": "exploit_reference",
                "outcome": "available",
                "observed_at": "2026-10-03T00:00:00Z",
                "source_revision": "2026-10-02",
                "freshness": "fresh",
                "record_count": 3,
                "complete": True,
                "references": [
                    {
                        "record_id": "ref-1",
                        "url": "https://example.test/advisory/1",
                        "provider": "Example",
                        "kind": "poc_reference",
                        "upstream_type": "proof-of-concept",
                        "upstream_assertions": ["public"],
                    }
                ],
            },
            {
                "vulnerability_id": "CVE-2026-1234",
                "source": "scanner-x",
                "signal": "reachability",
                "outcome": "unknown",
                "observed_at": "2026-10-03T00:00:00Z",
                "source_revision": None,
                "freshness": "unknown",
                "record_count": None,
                "complete": False,
                "references": [],
            },
        ],
        "project_exposure": [
            {
                "project_uuid": "project-1",
                "environment": "production",
                "status": "confirmed",
                "source": "deployment-inventory",
                "observed_at": "2026-10-03T00:00:00Z",
                "expires_at": "2026-10-04T00:00:00Z",
                "reviewer": "security@example.test",
            }
        ],
    }


def write_payload(tmp_path, value: dict[str, object]):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_loads_advisory_and_project_exposure_observations(tmp_path) -> None:
    path = write_payload(tmp_path, payload())
    snapshot = load_advisory_snapshot(path)

    assert snapshot.snapshot_id == "capture-2026-10-03"
    assert snapshot.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(snapshot.vulnerability_observations) == 2
    assert snapshot.vulnerability_observations[0].references[0].kind == "poc_reference"
    assert snapshot.vulnerability_observations[1].outcome.value == "unknown"
    assert (
        snapshot.exposure_for_project("project-1")[0].status is ExposureStatus.CONFIRMED
    )
    assert snapshot.exposure_for_project("project-2") == ()


def test_documented_example_is_loadable() -> None:
    example_path = (
        Path(__file__).parents[2] / "examples" / "advisory-snapshot.example.json"
    )

    snapshot = load_advisory_snapshot(example_path)

    assert snapshot.snapshot_id == "reviewed-capture-2026-10-03"
    assert len(snapshot.vulnerability_observations) == 2
    assert (
        summarize_poc_reports(
            snapshot.vulnerability_observations,
            now=datetime(2026, 10, 7, tzinfo=UTC),
        ).status
        is PocReportStatus.REPORTED
    )


def test_incomplete_absence_cannot_be_claimed_as_not_observed(tmp_path) -> None:
    data = payload()
    observation = data["vulnerability_observations"][1]
    assert isinstance(observation, dict)
    observation.update(outcome="not_observed", complete=False, record_count=0)

    with pytest.raises(ValueError, match="not_observed requires"):
        load_advisory_snapshot(write_payload(tmp_path, data))


def test_rejects_non_http_reference_url(tmp_path) -> None:
    data = payload()
    observation = data["vulnerability_observations"][0]
    assert isinstance(observation, dict)
    reference = observation["references"][0]
    assert isinstance(reference, dict)
    reference["url"] = "file:///etc/passwd"

    with pytest.raises(ValueError, match=r"absolute HTTP\(S\) URL"):
        load_advisory_snapshot(write_payload(tmp_path, data))


def test_rejects_duplicate_source_signal_observation(tmp_path) -> None:
    data = payload()
    observations = data["vulnerability_observations"]
    assert isinstance(observations, list)
    observations.append(observations[0])

    with pytest.raises(ValueError, match="duplicate observation"):
        load_advisory_snapshot(write_payload(tmp_path, data))


def test_expired_exposure_is_effectively_unknown(tmp_path) -> None:
    snapshot = load_advisory_snapshot(write_payload(tmp_path, payload()))
    observation = snapshot.project_exposure[0]
    now = datetime.now(UTC) + timedelta(days=10)

    assert observation.effective_status(now=now) is ExposureStatus.UNKNOWN
    assert observation.as_dict(now=now)["reported_status"] == "confirmed"
    assert observation.as_dict(now=now)["effective_status"] == "unknown"


def poc_observation(
    source: str,
    outcome: EvidenceOutcome,
    count: int | None,
    *,
    signal: str = "published_poc",
    freshness: EvidenceFreshness = EvidenceFreshness.FRESH,
) -> VulnerabilityEvidenceObservation:
    return VulnerabilityEvidenceObservation(
        vulnerability_id="CVE-2026-1234",
        source=source,
        signal=signal,
        outcome=outcome,
        observed_at="2026-10-07T00:00:00Z",
        source_revision=None,
        freshness=freshness,
        record_count=count,
        complete=outcome is not EvidenceOutcome.UNKNOWN,
        expires_at="2099-01-01T00:00:00Z",
    )


def test_poc_summary_counts_only_explicit_provider_reports() -> None:
    summary = summarize_poc_reports(
        (
            poc_observation("source-a", EvidenceOutcome.AVAILABLE, 2),
            poc_observation("source-b", EvidenceOutcome.AVAILABLE, 3),
            poc_observation(
                "vuls.db", EvidenceOutcome.AVAILABLE, 149, signal="exploit-record"
            ),
        )
    )

    assert summary.status is PocReportStatus.REPORTED
    assert [source["record_count"] for source in summary.as_dict()["sources"]] == [
        2,
        3,
    ]
    assert all(
        source["vulnerability_id"] == "CVE-2026-1234"
        for source in summary.as_dict()["sources"]
    )
    assert "total_count" not in summary.as_dict()


def test_published_poc_requires_cve_identifier(tmp_path) -> None:
    data = payload()
    observation = data["vulnerability_observations"][0]
    assert isinstance(observation, dict)
    observation["signal"] = "published_poc"
    observation["vulnerability_id"] = "GHSA-abcd-efgh-ijkl"

    with pytest.raises(ValueError, match="must be a CVE for published_poc"):
        load_advisory_snapshot(write_payload(tmp_path, data))


def test_published_poc_requires_expiry(tmp_path) -> None:
    data = payload()
    observation = data["vulnerability_observations"][0]
    assert isinstance(observation, dict)
    observation["signal"] = "published_poc"

    with pytest.raises(ValueError, match="expires_at is required"):
        load_advisory_snapshot(write_payload(tmp_path, data))


def test_poc_summary_does_not_turn_missing_or_stale_data_into_absence() -> None:
    assert summarize_poc_reports(()).status is PocReportStatus.UNKNOWN
    assert (
        summarize_poc_reports(
            (poc_observation("source-a", EvidenceOutcome.NOT_OBSERVED, 0),)
        ).status
        is PocReportStatus.NOT_OBSERVED
    )
    assert (
        summarize_poc_reports(
            (
                poc_observation("source-a", EvidenceOutcome.NOT_OBSERVED, 0),
                poc_observation("source-b", EvidenceOutcome.UNKNOWN, None),
            )
        ).status
        is PocReportStatus.UNKNOWN
    )
    assert (
        summarize_poc_reports(
            (
                poc_observation(
                    "source-a",
                    EvidenceOutcome.AVAILABLE,
                    1,
                    freshness=EvidenceFreshness.STALE,
                ),
            )
        ).status
        is PocReportStatus.UNKNOWN
    )


def test_expired_poc_report_does_not_win_review_order() -> None:
    expired = replace(
        poc_observation("source-a", EvidenceOutcome.AVAILABLE, 1),
        expires_at="2026-10-08T00:00:00Z",
    )
    summary = summarize_poc_reports((expired,), now=datetime(2026, 10, 9, tzinfo=UTC))

    assert summary.status is PocReportStatus.UNKNOWN
