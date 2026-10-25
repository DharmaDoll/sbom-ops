from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from sbom_ops.domain.triage_evidence import (
    AssetEvidenceScope,
    TriageFactor,
    TriageObservation,
    TriageSubject,
    TriageValue,
    VulnerabilityIdentity,
    build_triage_evidence,
)
from sbom_ops.domain.triage_reference import ReferencePolicy, evaluate_reference
from sbom_ops.services.reference_policy import load_reference_policy

NOW = datetime(2026, 10, 24, tzinfo=UTC)
IDENTITY = VulnerabilityIdentity("CVE-2026-0001", "CVE")
ASSET = AssetEvidenceScope("shop", "api", "production", "build-1", "project-1")
SUBJECT = TriageSubject("finding-1", IDENTITY, ASSET, True)
FACTORS = (
    TriageFactor.PUBLIC_EXPOSURE,
    TriageFactor.KEV,
    TriageFactor.AUTOMATABLE,
    TriageFactor.TECHNICAL_IMPACT,
)


def observations(values: str) -> tuple[TriageObservation, ...]:
    return tuple(
        TriageObservation(
            evidence_id=factor.value,
            vulnerability=IDENTITY,
            factor=factor,
            value=TriageValue(value),
            source="synthetic",
            source_record="fixture",
            source_revision="fixture-v1",
            observed_at=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=1),
            asset=ASSET if factor is TriageFactor.PUBLIC_EXPOSURE else None,
        )
        for factor, value in zip(FACTORS, values.split("/"), strict=True)
    )


# Expected outcomes transcribed from the policy document, not the loaded JSON.
@pytest.mark.parametrize(
    ("values", "days", "forensic"),
    [
        ("yes/yes/yes/total", 3, True),
        ("yes/yes/yes/partial", 3, False),
        ("yes/yes/no/total", 3, True),
        ("yes/yes/no/partial", 14, False),
        ("yes/no/yes/total", 3, False),
        ("yes/no/yes/partial", 14, False),
        ("yes/no/no/total", 14, False),
        ("yes/no/no/partial", 60, False),
        ("no/yes/yes/total", 3, True),
        ("no/yes/yes/partial", 14, False),
        ("no/yes/no/total", 14, False),
        ("no/yes/no/partial", 14, False),
        ("no/no/yes/total", 60, False),
        ("no/no/yes/partial", 60, False),
        ("no/no/no/total", None, False),
        ("no/no/no/partial", None, False),
    ],
)
def test_all_reference_conditions(
    values: str, days: int | None, forensic: bool
) -> None:
    context = build_triage_evidence(SUBJECT, observations(values), now=NOW)
    result = evaluate_reference(context, load_reference_policy()).as_dict()
    assert result["status"] == "matched"
    assert result["rule_id"] == values
    assert result["calendar_days"] == days
    assert result["deadline_kind"] == (
        "calendar_days" if days is not None else "next_major_update_or_rebuild"
    )
    assert result["forensic_triage"] == (
        "specified_by_reference" if forensic else "not_specified_by_reference"
    )
    assert result["missing"] == []
    assert result["due_at"] is None
    assert result["organizational_sla_adopted"] is False
    assert result["latest_verified"] is False


@pytest.mark.parametrize("index", range(4))
@pytest.mark.parametrize(
    "state", ["unknown", "expired", "future", "conflict", "absent"]
)
def test_uncertain_factor_never_becomes_a_negative(index: int, state: str) -> None:
    reports = list(observations("yes/yes/yes/total"))
    report = reports[index]
    if state == "unknown":
        reports[index] = replace(report, value=TriageValue.UNKNOWN)
    elif state == "expired":
        reports[index] = replace(report, expires_at=NOW)
    elif state == "future":
        reports[index] = replace(report, observed_at=NOW + timedelta(seconds=1))
    elif state == "absent":
        reports.pop(index)
    else:
        reports.append(
            replace(
                report,
                evidence_id="contradiction",
                value=TriageValue.PARTIAL if index == 3 else TriageValue.NO,
            )
        )
    context = build_triage_evidence(SUBJECT, tuple(reports), now=NOW)
    result = evaluate_reference(context, load_reference_policy()).as_dict()
    assert result["status"] == "pending"
    assert result["calendar_days"] is None
    assert result["rule_id"] is None
    assert result["forensic_triage"] == "pending"
    expected = "unknown" if state == "absent" else state
    assert f"{FACTORS[index].value}:{expected}" in result["missing"]


def test_unverified_asset_prevents_reference_result() -> None:
    context = build_triage_evidence(
        replace(SUBJECT, asset_link_verified=False),
        observations("yes/yes/yes/total"),
        now=NOW,
    )
    result = evaluate_reference(context, load_reference_policy()).as_dict()
    assert result["status"] == "pending"
    assert "asset_link_unverified" in result["missing"]


@pytest.mark.parametrize(
    "value", [TriageValue.YES, TriageValue.NO, TriageValue.UNKNOWN]
)
def test_known_exploitation_is_not_a_substitute_for_the_four_factors(
    value: TriageValue,
) -> None:
    reports = observations("no/no/no/partial")
    exploitation = replace(
        reports[1],
        evidence_id="exploitation",
        factor=TriageFactor.KNOWN_EXPLOITATION,
        value=value,
    )
    baseline = build_triage_evidence(SUBJECT, reports, now=NOW)
    additional = build_triage_evidence(SUBJECT, (*reports, exploitation), now=NOW)
    policy = load_reference_policy()
    assert evaluate_reference(baseline, policy) == evaluate_reference(
        additional, policy
    )


@pytest.mark.parametrize("case", ["missing", "duplicate", "boolean_days", "zero_days"])
def test_invalid_reference_table_is_rejected(case: str) -> None:
    policy = load_reference_policy()
    rows = list(policy.rules)
    if case == "missing":
        rows.pop()
    elif case == "duplicate":
        rows[-1] = rows[0]
    else:
        rows[0] = replace(rows[0], calendar_days=True if case == "boolean_days" else 0)
    with pytest.raises(ValueError):
        replace(policy, rules=tuple(rows))


def test_unresolved_context_does_not_produce_a_deadline() -> None:
    result = evaluate_reference(None, load_reference_policy()).as_dict()
    assert result["status"] == "pending"
    assert result["due_at"] is None
    assert result["forensic_triage"] == "pending"
    assert "cve_unresolved" in result["missing"]


def test_non_cve_identity_cannot_match_even_with_all_known_factors() -> None:
    identity = VulnerabilityIdentity("GHSA-synthetic", "GITHUB")
    reports = tuple(
        replace(report, vulnerability=identity)
        for report in observations("yes/yes/yes/total")
    )
    context = build_triage_evidence(
        replace(SUBJECT, vulnerability=identity), reports, now=NOW
    )
    result = evaluate_reference(context, load_reference_policy()).as_dict()
    assert result["status"] == "pending"
    assert result["missing"] == ["cve_unresolved"]
    assert result["rule_id"] is None


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"version": "v1"},
        {
            "version": "v1",
            "source": "https://example.test/reference",
            "observed_on": "2026-10-22",
            "rules": [{}],
        },
    ],
)
def test_invalid_policy_structure_fails_explicitly(payload: object) -> None:
    with pytest.raises(ValueError):
        ReferencePolicy.from_dict(payload)


@pytest.mark.parametrize(
    "changes",
    [
        {"version": ""},
        {"version": "bad\nversion"},
        {"source": "file:///tmp/rules"},
        {"observed_on": "2026-02-30"},
    ],
)
def test_invalid_policy_metadata_is_rejected(changes: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        replace(load_reference_policy(), **changes)
