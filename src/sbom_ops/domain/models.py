from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Priority(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class FindingState(StrEnum):
    ACTIVE = "ACTIVE"
    MISSING = "MISSING"
    RESOLVED = "RESOLVED"
    UNKNOWN = "UNKNOWN"


class AnalysisState(StrEnum):
    EXPLOITABLE = "EXPLOITABLE"
    IN_TRIAGE = "IN_TRIAGE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_AFFECTED = "NOT_AFFECTED"
    NOT_SET = "NOT_SET"
    UNKNOWN = "UNKNOWN"


class RemediationState(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class Finding:
    project_uuid: str
    project_name: str
    component_name: str
    component_version: str | None
    vulnerability_id: str
    severity: Severity
    cvss_score: float | None
    cwes: tuple[int, ...]
    description: str | None
    dependency_track_finding_id: str | None = None
    dependency_track_vulnerability_uuid: str | None = None
    vulnerability_source: str | None = None
    dependency_track_component_uuid: str | None = None
    component_purl: str | None = None

    def finding_key(self) -> str:
        """Return an opaque, versioned machine identity for the finding."""
        if (
            self.dependency_track_component_uuid
            and self.dependency_track_vulnerability_uuid
        ):
            identity = (
                "dependency-track",
                self.project_uuid,
                self.dependency_track_component_uuid,
                self.dependency_track_vulnerability_uuid,
            )
        elif self.component_purl:
            identity = (
                "purl",
                self.project_uuid,
                self.component_purl,
                (self.vulnerability_source or "").upper(),
                self.vulnerability_id.upper(),
            )
        else:
            identity = (
                "coordinates",
                self.project_uuid,
                self.component_name,
                self.component_version or "",
                (self.vulnerability_source or "").upper(),
                self.vulnerability_id.upper(),
            )
        serialized = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return f"v2:{self.project_uuid}:{digest}"

    def legacy_finding_key(self) -> str:
        """Return the v1 display-derived key for in-place issue migration."""
        component_version = self.component_version or ""
        return (
            f"{self.project_uuid}:{self.component_name}:"
            f"{component_version}:{self.vulnerability_id}"
        )


@dataclass(frozen=True)
class Enrichment:
    in_kev: bool
    epss_score: float | None
    has_known_active_exploitation: bool = False
    analysis_state: AnalysisState = AnalysisState.NOT_SET
    is_suppressed: bool = False
    analysis_detail: str | None = None


@dataclass(frozen=True)
class PrioritizedFinding:
    finding: Finding
    enrichment: Enrichment
    priority: Priority
    rationale: tuple[str, ...]


@dataclass(frozen=True)
class FindingAssessment:
    """Action-neutral assessment produced before any external workflow action."""

    project_uuid: str
    finding_key: str
    vulnerability_id: str
    priority: Priority
    analysis_state: AnalysisState
    rationale: tuple[str, ...]
