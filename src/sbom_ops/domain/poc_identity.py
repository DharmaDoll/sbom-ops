"""PoC-only identity projection; never a DT alias or a priority input."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime

from sbom_ops.domain.identifier_candidates import OSV_SOURCE
from sbom_ops.domain.identifier_review import effective_review_status


@dataclass(frozen=True)
class PocIdentity:
    original_id: str
    dt_source: str
    status: str
    cve: str | None = None
    review_id: int | None = None
    observation_id: int | None = None
    source: str | None = None
    observed_at: str | None = None
    decided_at: str | None = None
    expires_at: str | None = None
    actor: str | None = None
    reason: str | None = None

    def usable(self, now: datetime) -> bool:
        return (
            self.status == "active"
            and self.decided_at is not None
            and self.expires_at is not None
            and datetime.fromisoformat(self.decided_at)
            <= now
            < datetime.fromisoformat(self.expires_at)
        )

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def resolve_poc_identity(
    original_id: str,
    dt_source: str,
    decision: dict[str, object] | None,
    observation: dict[str, object] | None,
    *,
    latest_observation_id: int | None,
    now: datetime,
) -> PocIdentity:
    if now.tzinfo is None:
        raise ValueError("PoC identity clock requires a timezone")
    if decision is None:
        return PocIdentity(original_id, dt_source, "unreviewed")
    if (
        decision["original_id"] != original_id
        or decision["dt_source"] != dt_source
        or not observation
        or observation["original_id"] != original_id
        or observation["source"] != OSV_SOURCE
        or dt_source not in observation["dt_sources"]
        or observation["status"] not in ("candidate", "ambiguous")
        or decision["cve"] not in observation["cves"]
        or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", decision["cve"])
    ):
        raise ValueError("inconsistent PoC identity review")
    status = effective_review_status(
        decision,
        latest_review_id=decision["review_id"],
        latest_observation_id=latest_observation_id,
        now=now,
    )
    return PocIdentity(
        original_id,
        dt_source,
        status,
        decision["cve"],
        decision["review_id"],
        decision["observation_id"],
        observation["source"],
        observation["observed_at"],
        decision["decided_at"],
        decision["expires_at"],
        decision["actor"],
        decision["reason"],
    )
