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
from sbom_ops.domain.poc_retry import PocRetryPolicy, PocSourceState


class PocSource(Protocol):
    source: str

    def get_poc_sightings(self, cve: str) -> object: ...


class PocRepository(Protocol):
    def get(self, cve: str, source: str) -> PocRecord | None: ...

    def save(self, record: PocRecord, state: PocSourceState | None = None) -> None: ...

    def source_state(self, source: str) -> PocSourceState: ...


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
    retry_policy: PocRetryPolicy | None = None,
    target_is_current: Callable[[str, datetime], bool] | None = None,
) -> dict[str, object]:
    retry_policy = retry_policy or PocRetryPolicy()
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
    state = (
        repository.source_state(client.source)
        if repository
        else PocSourceState(client.source)
    )
    cooling_down = state.blocked(clock())
    calls = 0

    def mapping_changed(cve: str) -> bool:
        if target_is_current is None or target_is_current(cve, clock()):
            return False
        diagnostics.append(
            {
                "vulnerability_id": cve,
                "attempted": False,
                "cached": False,
                "last_success_at": None,
                "error": "identifier_review_changed",
                "http_status": None,
            }
        )
        return True

    for cve in targets.cves:
        if mapping_changed(cve):
            continue
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
        attempted = not stopped and not cooling_down
        if attempted and calls:
            sleep(pacing_seconds)
        if attempted and mapping_changed(cve):
            continue
        observed_at = clock()
        try:
            if cooling_down:
                raise PocFetchError("source_cooldown")
            if stopped:
                raise PocFetchError("not_attempted_after_transport_failure")
            calls += 1
            payload = client.get_poc_sightings(cve)
            observed_at = clock()
            observation = interpret_poc_sightings(
                payload, cve=cve, source=client.source, observed_at=observed_at, ttl=ttl
            )
        except (PocFetchError, ValueError) as exc:
            observed_at = clock()
            if isinstance(exc, PocFetchError):
                error, status, stopped = exc.code, exc.status, True
            else:
                error, stopped = "invalid_response", True
            if attempted:
                state = retry_policy.failure(
                    state,
                    now=observed_at,
                    error=error,
                    status=status,
                    retry_after=(
                        exc.retry_after if isinstance(exc, PocFetchError) else None
                    ),
                )
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
        if attempted and error is None:
            state = PocSourceState(client.source)
        if repository and attempted:
            record = PocRecord(
                cve, client.source, observed_at.isoformat(), success, error, status
            )
            repository.save(record, state)
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
            "selection": targets.summary(),
            "source_state": state.as_dict(),
            "status": (
                "partial"
                if targets.unresolved or any(row["error"] for row in diagnostics)
                else "succeeded"
            ),
            "unresolved_ids": list(targets.unresolved),
            "results": diagnostics,
        },
    }
