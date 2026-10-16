"""Bounded manual acquisition; no DT mutation, PoC lookup or alias approval."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from sbom_ops.domain.identifier_candidates import (
    OSV_SOURCE,
    IdentifierFetchError,
    IdentifierObservation,
    IdentifierTarget,
    interpret_osv_candidates,
    osv_identifier,
)


class IdentifierSource(Protocol):
    def get_vulnerability(self, identifier: str) -> object: ...


class IdentifierRepository(Protocol):
    def save(self, observation: IdentifierObservation) -> None: ...


def collect_identifier_candidates(
    targets: tuple[IdentifierTarget, ...],
    client: IdentifierSource,
    repository: IdentifierRepository,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[dict[str, object]], tuple[str, ...]]:
    if len(targets) > 25:
        raise ValueError("at most 25 identifier lookups per execution")
    results = []
    for index, target in enumerate(targets):
        if index:
            sleep(3.1)
        requested = osv_identifier(target.original_id)
        try:
            payload = client.get_vulnerability(requested)
            observation = interpret_osv_candidates(target, payload, observed_at=clock())
        except (IdentifierFetchError, ValueError) as exc:
            observation = IdentifierObservation(
                target.original_id,
                target.dt_sources,
                requested,
                OSV_SOURCE,
                clock().isoformat(),
                None,
                (),
                "error",
                (
                    exc.code
                    if isinstance(exc, IdentifierFetchError)
                    else "invalid_response"
                ),
                exc.status if isinstance(exc, IdentifierFetchError) else None,
            )
        repository.save(observation)
        results.append(observation.as_dict())
        if observation.status == "error":
            return results, tuple(row.original_id for row in targets[index + 1 :])
    return results, ()
