"""Explicit, expiring identifier decisions; these are not security decisions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from sbom_ops.domain.identifier_candidates import OSV_SOURCE


@dataclass(frozen=True)
class IdentifierDecision:
    observation_id: int
    original_id: str
    dt_source: str
    cve: str
    action: str
    actor: str
    reason: str
    decided_at: str
    expires_at: str | None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def plan_identifier_decision(
    observation: dict[str, object],
    *,
    latest_observation_id: int,
    previous: dict[str, object] | None,
    dt_source: str,
    cve: str,
    action: str,
    actor: str,
    reason: str,
    expires_at: str | None,
    max_age_hours: float,
    now: datetime,
) -> IdentifierDecision:
    if now.tzinfo is None:
        raise ValueError("review clock requires a timezone")
    if not actor.strip() or not reason.strip():
        raise ValueError("actor and reason are required")
    if action not in ("approve", "revoke"):
        raise ValueError("unsupported review action")
    if (
        observation.get("source") != OSV_SOURCE
        or dt_source not in observation["dt_sources"]
    ):
        raise ValueError("DT source does not match the observed candidate")
    cve = cve.upper()
    if action == "approve":
        if not 0 < max_age_hours <= 8760:
            raise ValueError("max-age-hours must be positive and at most 8760")
        if observation["observation_id"] != latest_observation_id:
            raise ValueError("candidate was superseded; review the latest observation")
        if (
            observation["status"] not in ("candidate", "ambiguous")
            or cve not in observation["cves"]
        ):
            raise ValueError("CVE is not an explicit candidate")
        observed = datetime.fromisoformat(observation["observed_at"])
        if observed.tzinfo is None or not observed <= now < observed + timedelta(
            hours=max_age_hours
        ):
            raise ValueError("candidate observation is future or stale")
        if not expires_at:
            raise ValueError("approval requires expires-at")
        expires = datetime.fromisoformat(expires_at)
        if expires.tzinfo is None or not now < expires <= observed + timedelta(
            hours=max_age_hours
        ):
            raise ValueError(
                "expiry must be future and within the observation age limit"
            )
        expires_at = expires.isoformat()
    else:
        if expires_at is not None:
            raise ValueError("revocation must not set expires-at")
        if (
            not previous
            or previous["action"] != "approve"
            or previous["observation_id"] != observation["observation_id"]
            or previous["cve"] != cve
        ):
            raise ValueError("revocation must target the latest approval")
    return IdentifierDecision(
        observation["observation_id"],
        observation["original_id"],
        dt_source,
        cve,
        action,
        actor.strip(),
        reason.strip(),
        now.isoformat(),
        expires_at,
    )


def effective_review_status(
    decision: dict[str, object],
    *,
    latest_review_id: int,
    latest_observation_id: int,
    now: datetime,
) -> str:
    if decision["review_id"] != latest_review_id:
        return "superseded"
    if decision["action"] == "revoke":
        return "revoked"
    if datetime.fromisoformat(decision["decided_at"]) > now:
        return "future"
    if datetime.fromisoformat(decision["expires_at"]) <= now:
        return "expired"
    if decision["observation_id"] != latest_observation_id:
        return "observation_changed"
    return "active"
