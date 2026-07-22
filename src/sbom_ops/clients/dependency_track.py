from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class DependencyTrackProject:
    uuid: str
    name: str


@dataclass(frozen=True)
class DependencyTrackFinding:
    project_uuid: str
    project_name: str
    component_name: str
    component_version: str | None
    vulnerability_id: str
    severity: str
    cvss_score: float | None
    cwes: tuple[int, ...]
    description: str | None
    epss_score: float | None
    analysis_state: str | None
    is_suppressed: bool
    analysis_detail: str | None
    finding_id: str | None
    vulnerability_uuid: str | None


class DependencyTrackApiError(RuntimeError):
    """Raised when Dependency-Track cannot serve an API request."""


def _number(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _cwes(value: Any) -> tuple[int, ...]:
    if isinstance(value, int):
        return (value,)
    if not isinstance(value, list):
        return ()
    result: list[int] = []
    for item in value:
        raw = item.get("cweId") if isinstance(item, dict) else item
        try:
            if raw is not None:
                result.append(int(raw))
        except (TypeError, ValueError):
            continue
    return tuple(result)


def _finding_from_payload(
    payload: dict[str, Any], project: DependencyTrackProject
) -> DependencyTrackFinding:
    component = payload.get("component") or {}
    vulnerability = payload.get("vulnerability") or {}
    analysis = payload.get("analysis") or {}
    aliases = vulnerability.get("aliases") or []
    vulnerability_id = vulnerability.get("vulnId") or vulnerability.get("id")
    if not vulnerability_id:
        for alias in aliases:
            if alias.get("cveId"):
                vulnerability_id = alias["cveId"]
                break
    if not vulnerability_id:
        raise DependencyTrackApiError("finding has no vulnerability identifier")

    return DependencyTrackFinding(
        project_uuid=project.uuid,
        project_name=project.name,
        component_name=str(component.get("name") or "unknown"),
        component_version=component.get("version"),
        vulnerability_id=str(vulnerability_id),
        severity=str(vulnerability.get("severity") or "UNKNOWN").upper(),
        cvss_score=_number(
            vulnerability.get("cvssV3BaseScore")
            or vulnerability.get("cvssV4BaseScore")
            or vulnerability.get("cvssV2BaseScore")
        ),
        cwes=_cwes(vulnerability.get("cwes") or vulnerability.get("cweId")),
        description=vulnerability.get("description"),
        epss_score=_number(vulnerability.get("epssScore") or payload.get("epssScore")),
        analysis_state=analysis.get("state"),
        is_suppressed=bool(analysis.get("isSuppressed", False)),
        analysis_detail=analysis.get("detail"),
        finding_id=payload.get("uuid") or payload.get("id"),
        vulnerability_uuid=vulnerability.get("uuid"),
    )


class DependencyTrackClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def _request_json(self, path: str, params: dict[str, str] | None = None) -> Any:
        query = f"?{urlencode(params)}" if params else ""
        request = Request(
            f"{self._base_url}{path}{query}",
            headers={"Accept": "application/json", "X-Api-Key": self._api_key},
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise DependencyTrackApiError(
                f"Dependency-Track request failed: {path}"
            ) from exc

    def list_projects(self) -> list[DependencyTrackProject]:
        payload = self._request_json("/api/v1/project")
        return [
            DependencyTrackProject(uuid=str(item["uuid"]), name=str(item["name"]))
            for item in payload
        ]

    def get_project_findings(self, project_uuid: str) -> list[DependencyTrackFinding]:
        project_payload = self._request_json(f"/api/v1/project/{project_uuid}")
        project = DependencyTrackProject(
            uuid=project_uuid,
            name=str(project_payload.get("name") or project_uuid),
        )
        payload = self._request_json(f"/api/v1/finding/project/{project_uuid}")
        if isinstance(payload, dict) and "findings" in payload:
            payload = payload["findings"]
        findings = [_finding_from_payload(item, project) for item in payload]

        # Dependency-Track exposes EPSS on the project vulnerability endpoint.
        # Use it as a fallback for finding responses that omit the field.
        vulnerability_payload = self._request_json(
            f"/api/v1/vulnerability/project/{project_uuid}"
        )
        if isinstance(vulnerability_payload, dict):
            vulnerability_payload = vulnerability_payload.get("vulnerabilities", [])
        epss_by_vulnerability = {
            str(item.get("vulnID") or item.get("vulnId")): _number(
                item.get("epssScore")
            )
            for item in vulnerability_payload
            if item.get("vulnID") or item.get("vulnId")
        }
        return [
            finding
            if finding.epss_score is not None
            else replace(
                finding,
                epss_score=epss_by_vulnerability.get(finding.vulnerability_id),
            )
            for finding in findings
        ]
