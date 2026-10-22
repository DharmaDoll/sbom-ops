"""CISA SSVC report interpretation, independent of transport and priority."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sbom_ops.domain.triage_evidence import (
    TriageFactor,
    TriageObservation,
    TriageValue,
    VulnerabilityIdentity,
)

CISA_ADP_ORG = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
VULNRICHMENT_SOURCE = "https://github.com/cisagov/vulnrichment"


class VulnrichmentError(ValueError):
    def __init__(self, code: str, *, status: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def validate_request(cve: str, revision: str) -> None:
    if not isinstance(cve, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve):
        raise VulnrichmentError("invalid_cve")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise VulnrichmentError("immutable_revision_required")


@dataclass(frozen=True)
class VulnrichmentReport:
    cve: str
    revision: str
    retrieved_at: datetime
    assessed_at: datetime | None
    exploitation: str | None
    observations: tuple[TriageObservation, ...]
    reasons: tuple[str, ...]


def interpret_vulnrichment(
    payload: object,
    *,
    cve: str,
    revision: str,
    retrieved_at: datetime,
    max_age: timedelta,
) -> VulnrichmentReport:
    """Read only a matching CISA ADP SSVC 2.0.3 assessment."""
    validate_request(cve, revision)
    if not isinstance(retrieved_at, datetime) or retrieved_at.utcoffset() is None:
        raise VulnrichmentError("invalid_retrieval_time")
    if not isinstance(max_age, timedelta) or max_age <= timedelta(0):
        raise VulnrichmentError("invalid_max_age")
    record = _object(payload)
    if record.get("dataType") != "CVE_RECORD" or record.get("dataVersion") != "5.1":
        raise VulnrichmentError("unsupported_record_format")
    metadata = _object(record.get("cveMetadata"))
    if metadata.get("cveId") != cve:
        raise VulnrichmentError("cve_mismatch")
    if metadata.get("state") != "PUBLISHED":
        raise VulnrichmentError("record_not_published")
    adps = _array(_object(record.get("containers")).get("adp", []))
    cisa = [
        (index, adp)
        for index, adp in enumerate(adps)
        if _object(adp.get("providerMetadata")).get("orgId") == CISA_ADP_ORG
    ]
    if len(cisa) > 1:
        raise VulnrichmentError("ambiguous_cisa_container")
    if not cisa:
        return VulnrichmentReport(
            cve, revision, retrieved_at, None, None, (), ("missing_cisa_ssvc",)
        )
    adp_index, container = cisa[0]
    metrics = _array(container.get("metrics", []))
    ssvc = [
        (index, _object(metric["other"].get("content")))
        for index, metric in enumerate(metrics)
        if "other" in metric and _object(metric["other"]).get("type") == "ssvc"
    ]
    if len(ssvc) > 1:
        raise VulnrichmentError("ambiguous_ssvc")
    if not ssvc:
        return VulnrichmentReport(
            cve, revision, retrieved_at, None, None, (), ("missing_cisa_ssvc",)
        )
    metric_index, content = ssvc[0]
    if content.get("id") != cve:
        raise VulnrichmentError("ssvc_cve_mismatch")
    if content.get("role") != "CISA Coordinator" or content.get("version") != "2.0.3":
        raise VulnrichmentError("unsupported_ssvc")
    assessed_at = _timestamp(content.get("timestamp"))
    if assessed_at > retrieved_at.astimezone(UTC):
        raise VulnrichmentError("future_assessment")
    try:
        expires_at = assessed_at + max_age
    except OverflowError:
        raise VulnrichmentError("invalid_max_age") from None

    allowed = {
        "Automatable": {"yes", "no"},
        "Technical Impact": {"total", "partial"},
        "Exploitation": {"none", "poc", "active"},
    }
    options: dict[str, str] = {}
    for option in _array(content.get("options", [])):
        if len(option) != 1:
            raise VulnrichmentError("invalid_ssvc_option")
        name, value = next(iter(option.items()))
        if (
            name not in allowed
            or not isinstance(value, str)
            or value not in allowed[name]
        ):
            raise VulnrichmentError("unsupported_ssvc_option")
        if name in options:
            raise VulnrichmentError("duplicate_ssvc_option")
        options[name] = value

    reasons = [f"missing_{name}" for name in allowed if name not in options]
    exploitation = options.get("Exploitation")
    # "none" and "poc" are not evidence that active exploitation is absent.
    if exploitation in {"none", "poc"}:
        reasons.append("no_active_exploitation_report")
    values = (
        (TriageFactor.AUTOMATABLE, TriageValue(options.get("Automatable", "unknown"))),
        (
            TriageFactor.TECHNICAL_IMPACT,
            TriageValue(options.get("Technical Impact", "unknown")),
        ),
        (
            TriageFactor.KNOWN_EXPLOITATION,
            TriageValue.YES if exploitation == "active" else TriageValue.UNKNOWN,
        ),
    )
    source_record = (
        f"{cve}#/containers/adp/{adp_index}/metrics/{metric_index}/other/content"
    )
    observations = tuple(
        TriageObservation(
            evidence_id=f"cisa-ssvc:{revision}:{cve}:{factor.value}",
            vulnerability=VulnerabilityIdentity(cve, "CVE"),
            factor=factor,
            value=value,
            source=VULNRICHMENT_SOURCE,
            source_record=source_record,
            source_revision=revision,
            observed_at=assessed_at,
            expires_at=expires_at,
        )
        for factor, value in values
    )
    return VulnrichmentReport(
        cve,
        revision,
        retrieved_at,
        assessed_at,
        exploitation,
        observations,
        tuple(sorted(reasons)),
    )


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise VulnrichmentError("invalid_record_structure")
    return value


def _array(value: object) -> list[dict]:
    if not isinstance(value, list) or len(value) > 1000:
        raise VulnrichmentError("invalid_record_structure")
    return [_object(item) for item in value]


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise VulnrichmentError("invalid_assessment_time")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        raise VulnrichmentError("invalid_assessment_time") from None
