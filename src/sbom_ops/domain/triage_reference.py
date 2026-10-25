"""Reference-only deadlines, never an adopted organizational SLA."""

import re
from dataclasses import dataclass
from datetime import date
from itertools import product

from sbom_ops.domain.triage_evidence import (
    TriageEvidenceContext,
    TriageEvidenceStatus,
    TriageFactor,
    TriageValue,
)

FACTORS = (
    TriageFactor.PUBLIC_EXPOSURE,
    TriageFactor.KEV,
    TriageFactor.AUTOMATABLE,
    TriageFactor.TECHNICAL_IMPACT,
)


@dataclass(frozen=True)
class ReferenceRule:
    conditions: tuple[str, ...]
    calendar_days: int | None
    forensic_triage: bool


@dataclass(frozen=True)
class ReferencePolicy:
    version: str
    source: str
    observed_on: str
    rules: tuple[ReferenceRule, ...]

    def __post_init__(self) -> None:
        for value in (self.version, self.source, self.observed_on):
            if (
                not isinstance(value, str)
                or not value
                or not value.isprintable()
                or value != value.strip()
                or len(value) > 2048
            ):
                raise ValueError("invalid reference policy metadata")
        if not self.source.startswith("https://"):
            raise ValueError("reference source must be an HTTPS citation")
        if date.fromisoformat(self.observed_on).isoformat() != self.observed_on:
            raise ValueError("reference observation must be an ISO date")
        if not isinstance(self.rules, tuple) or any(
            not isinstance(rule, ReferenceRule) for rule in self.rules
        ):
            raise ValueError("typed reference rules required")
        expected = set(
            product(("yes", "no"), ("yes", "no"), ("yes", "no"), ("total", "partial"))
        )
        actual = []
        for rule in self.rules:
            if not isinstance(rule.conditions, tuple) or any(
                not isinstance(value, str) for value in rule.conditions
            ):
                raise ValueError("invalid reference conditions")
            if rule.calendar_days is not None and (
                type(rule.calendar_days) is not int or rule.calendar_days <= 0
            ):
                raise ValueError("calendar days must be positive or null")
            if type(rule.forensic_triage) is not bool:
                raise ValueError("forensic triage must be boolean")
            actual.append(rule.conditions)
        if len(actual) != len(expected) or set(actual) != expected:
            raise ValueError(
                "reference rules must cover all 16 conditions exactly once"
            )

    @classmethod
    def from_dict(cls, payload: object) -> "ReferencePolicy":
        if not isinstance(payload, dict) or set(payload) != {
            "version",
            "source",
            "observed_on",
            "rules",
        }:
            raise ValueError("invalid reference policy structure")
        if not isinstance(payload["rules"], list):
            raise ValueError("reference rules must be a list")
        rules = []
        for row in payload["rules"]:
            if not isinstance(row, dict) or set(row) != {
                "conditions",
                "calendar_days",
                "forensic_triage",
            }:
                raise ValueError("invalid reference rule structure")
            if not isinstance(row["conditions"], list):
                raise ValueError("reference conditions must be a list")
            rules.append(
                ReferenceRule(
                    tuple(row["conditions"]),
                    row["calendar_days"],
                    row["forensic_triage"],
                )
            )
        return cls(
            payload["version"], payload["source"], payload["observed_on"], tuple(rules)
        )


@dataclass(frozen=True)
class ReferenceResult:
    policy: ReferencePolicy
    rule_id: str | None
    calendar_days: int | None
    forensic_triage: str
    missing: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "status": "pending" if self.missing else "matched",
            "policy_version": self.policy.version,
            "source": self.policy.source,
            "source_observed_on": self.policy.observed_on,
            "latest_verified": False,
            "rule_id": self.rule_id,
            "deadline_kind": (
                "pending"
                if self.missing
                else (
                    "calendar_days"
                    if self.calendar_days is not None
                    else "next_major_update_or_rebuild"
                )
            ),
            "calendar_days": self.calendar_days,
            "forensic_triage": self.forensic_triage,
            "missing": list(self.missing),
            "due_at": None,
            "organizational_sla_adopted": False,
        }


def evaluate_reference(
    context: TriageEvidenceContext | None, policy: ReferencePolicy
) -> ReferenceResult:
    if not isinstance(policy, ReferencePolicy):
        raise ValueError("validated reference policy required")
    if context is None:
        return ReferenceResult(policy, None, None, "pending", ("cve_unresolved",))
    if not isinstance(context, TriageEvidenceContext):
        raise ValueError("typed evidence context required")
    missing = []
    identity = context.subject.vulnerability
    if (
        identity.namespace != "CVE"
        or re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", identity.identifier) is None
    ):
        missing.append("cve_unresolved")
    if not context.subject.asset_link_verified:
        missing.append("asset_link_unverified")
    by_factor = {item.factor: item for item in context.factors}
    if len(by_factor) != len(context.factors):
        raise ValueError("duplicate reference input factor")
    values = []
    for factor in FACTORS:
        item = by_factor.get(factor)
        if item is None:
            missing.append(f"{factor.value}:missing")
        elif item.status is not TriageEvidenceStatus.KNOWN:
            missing.append(f"{factor.value}:{item.status.value}")
        else:
            allowed = (
                {TriageValue.TOTAL, TriageValue.PARTIAL}
                if factor is TriageFactor.TECHNICAL_IMPACT
                else {TriageValue.YES, TriageValue.NO}
            )
            if item.value not in allowed:
                raise ValueError("known reference factor has an invalid value")
            values.append(item.value.value)
    if missing:
        return ReferenceResult(policy, None, None, "pending", tuple(missing))
    conditions = tuple(values)
    rule = next(rule for rule in policy.rules if rule.conditions == conditions)
    return ReferenceResult(
        policy,
        "/".join(conditions),
        rule.calendar_days,
        (
            "specified_by_reference"
            if rule.forensic_triage
            else "not_specified_by_reference"
        ),
        (),
    )
