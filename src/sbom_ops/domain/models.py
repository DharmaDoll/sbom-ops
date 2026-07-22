from __future__ import annotations

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

    def finding_key(self) -> str:
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
    analysis_state: str | None = None
    is_suppressed: bool = False
    analysis_detail: str | None = None


@dataclass(frozen=True)
class PrioritizedFinding:
    finding: Finding
    enrichment: Enrichment
    priority: Priority
    rationale: tuple[str, ...]
