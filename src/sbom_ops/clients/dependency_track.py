from __future__ import annotations

import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request

from sbom_ops.clients.http import HttpApiError, collection_items, request_json


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
    vulnerability_source: str | None = None


class DependencyTrackApiError(RuntimeError):
    """Raised when Dependency-Track cannot serve an API request."""


@dataclass(frozen=True)
class BomUpload:
    token: str


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
        vulnerability_source=vulnerability.get("source"),
    )


class DependencyTrackClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 30.0,
        page_size: int = 100,
        max_retries: int = 3,
        retry_backoff_seconds: float = 1.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._page_size = page_size
        self._max_retries = max_retries
        self._retry_backoff_seconds = retry_backoff_seconds

    def _request_json(self, path: str, params: dict[str, str] | None = None) -> Any:
        query = f"?{urlencode(params)}" if params else ""
        request = Request(
            f"{self._base_url}{path}{query}",
            headers={"Accept": "application/json", "X-Api-Key": self._api_key},
        )
        try:
            return request_json(
                request,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._retry_backoff_seconds,
                error_message=f"Dependency-Track request failed: {path}",
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise DependencyTrackApiError(
                f"Dependency-Track request failed{detail}: {path}"
            ) from exc

    def upload_bom(self, project_uuid: str, bom_path: str | Path) -> BomUpload:
        """Upload a CycloneDX BOM and return DT's asynchronous processing token."""
        bom = Path(bom_path).read_bytes()
        boundary = "----sbom-ops-boundary"
        body = b"".join(
            [
                f"--{boundary}\r\n".encode(),
                b'Content-Disposition: form-data; name="project"\r\n\r\n',
                project_uuid.encode(),
                b"\r\n",
                (
                    f'--{boundary}\r\nContent-Disposition: form-data; name="bom"; '
                    f'filename="{Path(bom_path).name}"\r\n'
                    "Content-Type: application/octet-stream\r\n\r\n"
                ).encode(),
                bom,
                b"\r\n",
                f"--{boundary}--\r\n".encode(),
            ]
        )
        request = Request(
            f"{self._base_url}/api/v1/bom",
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "X-Api-Key": self._api_key,
            },
        )
        try:
            payload = request_json(
                request,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._retry_backoff_seconds,
                error_message="Dependency-Track BOM upload failed",
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise DependencyTrackApiError(
                f"Dependency-Track BOM upload failed{detail}"
            ) from exc
        token = payload.get("token") if isinstance(payload, dict) else None
        if not token:
            raise DependencyTrackApiError("Dependency-Track BOM response has no token")
        return BomUpload(token=str(token))

    def wait_for_bom_processing(
        self,
        token: str,
        *,
        timeout: float = 120.0,
        poll_interval: float = 5.0,
    ) -> None:
        """Wait for the asynchronous tasks created by a BOM upload to finish."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            payload = self._request_json(f"/api/v1/event/token/{token}")
            processing = (
                payload.get("processing") if isinstance(payload, dict) else payload
            )
            if processing is False:
                return
            time.sleep(
                min(
                    max(0.0, poll_interval),
                    max(0.0, deadline - time.monotonic()),
                )
            )
        raise DependencyTrackApiError(
            f"Dependency-Track BOM processing timed out: token {token}"
        )

    def _get_collection(
        self,
        path: str,
        keys: tuple[str, ...],
        *,
        paginated: bool = False,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        offset = 0
        seen: set[str] = set()
        while True:
            params = (
                {"offset": str(offset), "limit": str(self._page_size)}
                if paginated
                else None
            )
            payload = self._request_json(path, params)
            page = [dict(item) for item in collection_items(payload, keys)]
            if not page:
                break
            identifiers = [
                str(item.get("uuid") or item.get("id") or item) for item in page
            ]
            if seen.intersection(identifiers):
                raise DependencyTrackApiError(f"pagination did not advance: {path}")
            seen.update(identifiers)
            items.extend(page)
            if not paginated or len(page) < self._page_size:
                break
            offset += len(page)
        return items

    def list_projects(self) -> list[DependencyTrackProject]:
        payload = self._get_collection(
            "/api/v1/project", ("projects", "items"), paginated=True
        )
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
        payload = self._get_collection(
            f"/api/v1/finding/project/{project_uuid}", ("findings", "items")
        )
        findings = [_finding_from_payload(item, project) for item in payload]

        # Dependency-Track exposes EPSS on the project vulnerability endpoint.
        # Use it as a fallback for finding responses that omit the field.
        vulnerability_payload = self._get_collection(
            f"/api/v1/vulnerability/project/{project_uuid}",
            ("vulnerabilities", "items"),
        )
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

    def wait_for_analysis(
        self,
        project_uuid: str,
        *,
        timeout: float = 120.0,
        poll_interval: float = 5.0,
    ) -> list[DependencyTrackFinding]:
        """Wait until the findings response is stable across two polls.

        Dependency-Track BOM analysis is asynchronous. A stable response is the
        portable signal across supported DT versions; NOT_SET is a valid result.
        """
        deadline = time.monotonic() + timeout
        previous: tuple[tuple[Any, ...], ...] | None = None
        while time.monotonic() < deadline:
            findings = self.get_project_findings(project_uuid)
            fingerprint = tuple(
                sorted(
                    (
                        f.finding_id,
                        f.vulnerability_id,
                        f.component_name,
                        f.component_version,
                        f.analysis_state,
                        f.is_suppressed,
                    )
                    for f in findings
                )
            )
            if previous == fingerprint:
                return findings
            previous = fingerprint
            time.sleep(
                min(
                    max(0.0, poll_interval),
                    max(0.0, deadline - time.monotonic()),
                )
            )
        raise DependencyTrackApiError(
            f"Dependency-Track analysis did not stabilize: project {project_uuid}"
        )
