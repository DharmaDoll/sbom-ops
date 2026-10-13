"""Explicit, bounded PoC acquisition; independent of DT and remediation workflow."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from sbom_ops.domain.advisory import (
    EvidenceFreshness,
    EvidenceOutcome,
    VulnerabilityEvidenceObservation,
)
from sbom_ops.domain.poc import (
    PocFetchError,
    PocRecord,
    PocTargets,
    interpret_poc_sightings,
)


class PocSource(Protocol):
    source: str

    def get_poc_sightings(self, cve: str) -> object: ...


class PocRepository(Protocol):
    def get(self, cve: str, source: str) -> PocRecord | None: ...

    def save(self, record: PocRecord) -> None: ...


def collect_poc_snapshot(
    targets: PocTargets,
    client: PocSource,
    *,
    ttl_seconds: int = 21600,
    pacing_seconds: float = 3.1,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    sleep: Callable[[float], None] = time.sleep,
    repository: PocRepository | None = None,
    refresh_seconds: int = 3600,
) -> dict[str, object]:
    if not 1 <= ttl_seconds <= 604800:
        raise ValueError("ttl_seconds must be between 1 and 604800")
    if not 3.1 <= pacing_seconds <= 3600:
        raise ValueError("pacing_seconds must be between 3.1 and 3600")
    if not 1 <= refresh_seconds <= 604800:
        raise ValueError("refresh_seconds must be between 1 and 604800")
    ttl = timedelta(seconds=ttl_seconds)
    observations: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []
    stopped = False
    calls = 0
    for cve in targets.cves:
        previous = repository.get(cve, client.source) if repository else None
        if previous and not previous.needs_refresh(
            clock(), timedelta(seconds=refresh_seconds)
        ):
            observations.append(previous.observation().as_dict())
            diagnostics.append(
                {
                    "vulnerability_id": cve,
                    "attempted": False,
                    "cached": True,
                    "last_success_at": previous.success.observed_at,
                    "error": None,
                    "http_status": previous.http_status,
                }
            )
            continue
        error: str | None = None
        status: int | None = None
        attempted = not stopped
        if attempted and calls:
            sleep(pacing_seconds)
        observed_at = clock()
        try:
            if stopped:
                raise PocFetchError("not_attempted_after_transport_failure")
            calls += 1
            payload = client.get_poc_sightings(cve)
            observed_at = clock()
            observation = interpret_poc_sightings(
                payload, cve=cve, source=client.source, observed_at=observed_at, ttl=ttl
            )
        except (PocFetchError, ValueError) as exc:
            # Stop network calls on transport/HTTP failures, including 429. Never
            # retry earlier than Retry-After, or classify a 404 as a negative.
            if isinstance(exc, PocFetchError):
                error, status, stopped = exc.code, exc.status, True
            else:
                error = "invalid_response"
            observation = VulnerabilityEvidenceObservation(
                vulnerability_id=cve,
                source=client.source,
                signal="published_poc",
                outcome=EvidenceOutcome.UNKNOWN,
                observed_at=observed_at.isoformat(),
                source_revision=None,
                freshness=EvidenceFreshness.UNKNOWN,
                record_count=None,
                complete=False,
                expires_at=(observed_at + ttl).isoformat(),
            )
        success = (
            observation if error is None else previous.success if previous else None
        )
        if repository and attempted:
            record = PocRecord(
                cve, client.source, observed_at.isoformat(), success, error, status
            )
            repository.save(record)
            observation = record.observation()
        elif repository and previous:
            observation = previous.observation()
        observations.append(observation.as_dict())
        diagnostics.append(
            {
                "vulnerability_id": cve,
                "attempted": attempted,
                "cached": False,
                "last_success_at": success.observed_at if success else None,
                "error": error,
                "http_status": status,
            }
        )
    return {
        "schema_version": 1,
        "snapshot_id": f"poc-{uuid4()}",
        "generated_at": clock().isoformat(),
        "vulnerability_observations": observations,
        "project_exposure": [],
        "collection": {
            "status": (
                "partial"
                if targets.unresolved or any(row["error"] for row in diagnostics)
                else "succeeded"
            ),
            "unresolved_ids": list(targets.unresolved),
            "results": diagnostics,
        },
    }
