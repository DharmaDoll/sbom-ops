"""Plan/recheck human-attributed decisions without contacting any external system."""

from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime

from sbom_ops.domain.identifier_candidates import OSV_SOURCE
from sbom_ops.domain.identifier_review import (
    effective_review_status,
    plan_identifier_decision,
)
from sbom_ops.storage.identifier_candidates import IdentifierStore


def review_identifier(
    store: IdentifierStore,
    *,
    observation_id: int,
    dt_source: str,
    cve: str,
    action: str,
    actor: str,
    reason: str,
    expires_at: str | None,
    max_age_hours: float = 24,
    execute: bool = False,
    now: datetime | None = None,
) -> dict[str, object]:
    store.require_reviews()
    with store.decision_transaction() if execute else nullcontext():
        observation = store.observation(observation_id)
        previous = store.latest_review(observation["original_id"], dt_source)
        decision = plan_identifier_decision(
            observation,
            latest_observation_id=store.latest_observation_id(
                observation["original_id"], OSV_SOURCE
            ),
            previous=previous,
            dt_source=dt_source,
            cve=cve,
            action=action,
            actor=actor,
            reason=reason,
            expires_at=expires_at,
            max_age_hours=max_age_hours,
            now=now or datetime.now(UTC),
        )
        review_id = store.append_decision(decision) if execute else None
        return {
            "status": "recorded" if execute else "preview",
            "review_id": review_id,
            **decision.as_dict(),
            "poc_connected": False,
        }


def list_identifier_reviews(
    store: IdentifierStore, *, limit: int = 100, now: datetime | None = None
) -> list[dict[str, object]]:
    rows = store.reviews(limit=limit)
    current = now or datetime.now(UTC)
    return [
        {
            **row,
            "effective_status": effective_review_status(
                row,
                latest_review_id=store.latest_review(
                    row["original_id"], row["dt_source"]
                )["review_id"],
                latest_observation_id=store.latest_observation_id(
                    row["original_id"], OSV_SOURCE
                ),
                now=current,
            ),
            "poc_connected": False,
        }
        for row in rows
    ]
