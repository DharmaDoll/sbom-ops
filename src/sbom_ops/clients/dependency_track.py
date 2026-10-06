from __future__ import annotations

import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request

from sbom_ops.clients.http import (
    HttpApiError,
    request_json,
)


@dataclass(frozen=True)
class DependencyTrackProject:
    uuid: str
    name: str
    version: str | None = None


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
    component_uuid: str | None = None
    component_purl: str | None = None
    vulnerability_aliases: tuple[str, ...] = ()
    cvss_version: str | None = None


class DependencyTrackApiError(RuntimeError):
    """Raised when Dependency-Track cannot serve an API request."""


@dataclass(frozen=True)
class BomUpload:
    token: str


def _number(value: Any) -> float | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _score(value: Any, *, maximum: float) -> float | None:
    number = _number(value)
    if number is None or not 0 <= number <= maximum:
        return None
    return number


def _first_score(*values: Any, maximum: float) -> float | None:
    for value in values:
        score = _score(value, maximum=maximum)
        if score is not None:
            return score
    return None


def _first_cvss_score(
    *values: tuple[str, Any],
) -> tuple[float | None, str | None]:
    for version, value in values:
        score = _score(value, maximum=10.0)
        if score is not None:
            return score, version
    return None, None


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


def _vulnerability_aliases(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    identifiers: list[str] = []
    for alias in value:
        if not isinstance(alias, dict):
            continue
        for field in ("cveId", "ghsaId"):
            identifier = alias.get(field)
            if isinstance(identifier, str) and identifier.strip():
                identifiers.append(identifier.strip())
    return tuple(dict.fromkeys(identifiers))


def _finding_from_payload(
    payload: dict[str, Any], project: DependencyTrackProject
) -> DependencyTrackFinding:
    component = payload.get("component")
    vulnerability = payload.get("vulnerability")
    analysis = payload.get("analysis")
    if not isinstance(component, Mapping) or not isinstance(vulnerability, Mapping):
        raise DependencyTrackApiError("finding has no component or vulnerability")
    if not isinstance(component.get("uuid"), str) or not component["uuid"].strip():
        raise DependencyTrackApiError("finding has no component UUID")
    if not isinstance(component.get("name"), str) or not component["name"].strip():
        raise DependencyTrackApiError("finding has no component name")
    if analysis is None:
        analysis = {}
    elif not isinstance(analysis, Mapping):
        raise DependencyTrackApiError("finding has malformed analysis")
    suppressed = analysis.get("isSuppressed", False)
    if not isinstance(suppressed, bool):
        raise DependencyTrackApiError("finding has malformed suppression state")
    aliases = vulnerability.get("aliases") or []
    vulnerability_id = vulnerability.get("vulnId") or vulnerability.get("id")
    if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
        raise DependencyTrackApiError("finding has no vulnerability identifier")
    cvss_score, cvss_version = _first_cvss_score(
        ("CVSSv3", vulnerability.get("cvssV3BaseScore")),
        ("CVSSv4", vulnerability.get("cvssV4Score")),
        ("CVSSv2", vulnerability.get("cvssV2BaseScore")),
    )

    return DependencyTrackFinding(
        project_uuid=project.uuid,
        project_name=project.name,
        component_name=str(component.get("name") or "unknown"),
        component_version=component.get("version"),
        vulnerability_id=str(vulnerability_id),
        severity=str(vulnerability.get("severity") or "UNKNOWN").upper(),
        cvss_score=cvss_score,
        cwes=_cwes(vulnerability.get("cwes") or vulnerability.get("cweId")),
        description=vulnerability.get("description"),
        epss_score=_first_score(
            vulnerability.get("epssScore"),
            payload.get("epssScore"),
            maximum=1.0,
        ),
        analysis_state=analysis.get("state"),
        is_suppressed=suppressed,
        analysis_detail=analysis.get("detail"),
        finding_id=payload.get("uuid") or payload.get("id"),
        vulnerability_uuid=vulnerability.get("uuid"),
        vulnerability_source=vulnerability.get("source"),
        component_uuid=component.get("uuid"),
        component_purl=component.get("purl") or component.get("purlCoordinates"),
        vulnerability_aliases=_vulnerability_aliases(aliases),
        cvss_version=cvss_version,
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

    def _request_json(
        self,
        path: str,
        params: dict[str, str] | None = None,
        *,
        include_headers: bool = False,
    ) -> Any:
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
                return_headers=include_headers,
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise DependencyTrackApiError(
                f"Dependency-Track request failed{detail}: {path}"
            ) from exc

    def _upload_bom(
        self, fields: tuple[tuple[str, str], ...], bom_path: str | Path
    ) -> BomUpload:
        bom = Path(bom_path).read_bytes()
        boundary = "----sbom-ops-boundary"
        parts: list[bytes] = []
        for name, value in fields:
            parts.extend(
                [
                    f"--{boundary}\r\n".encode(),
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                    value.encode(),
                    b"\r\n",
                ]
            )
        parts.extend(
            [
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
            data=b"".join(parts),
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

    def upload_bom(self, project_uuid: str, bom_path: str | Path) -> BomUpload:
        """Upload a CycloneDX BOM and return DT's asynchronous processing token."""
        return self._upload_bom((("project", project_uuid),), bom_path)

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
                payload.get("processing") if isinstance(payload, Mapping) else None
            )
            if not isinstance(processing, bool):
                raise DependencyTrackApiError(
                    "Dependency-Track BOM processing response is malformed"
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
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        offset = 0
        seen: set[str] = set()
        expected_total: int | None = None
        while True:
            request_params = dict(params or {})
            if paginated:
                request_params.update(
                    {"offset": str(offset), "limit": str(self._page_size)}
                )
            if paginated:
                payload, headers = self._request_json(
                    path, request_params or None, include_headers=True
                )
                raw_total = next(
                    (
                        value
                        for key, value in headers.items()
                        if key.lower() == "x-total-count"
                    ),
                    None,
                )
                if (
                    not isinstance(raw_total, str)
                    or not raw_total.isascii()
                    or not raw_total.isdigit()
                ):
                    raise DependencyTrackApiError(f"missing pagination total: {path}")
                page_total = int(raw_total)
                if expected_total is None:
                    expected_total = page_total
                elif page_total != expected_total:
                    raise DependencyTrackApiError(f"pagination total changed: {path}")
            else:
                payload = self._request_json(path, request_params or None)
            if isinstance(payload, list):
                raw_page = payload
            elif isinstance(payload, Mapping):
                present_keys = [key for key in keys if key in payload]
                if len(present_keys) != 1 or not isinstance(
                    payload[present_keys[0]], list
                ):
                    raise DependencyTrackApiError(f"malformed collection: {path}")
                raw_page = payload[present_keys[0]]
            else:
                raise DependencyTrackApiError(f"malformed collection: {path}")
            if any(not isinstance(item, Mapping) for item in raw_page):
                raise DependencyTrackApiError(f"malformed collection item: {path}")
            page = [dict(item) for item in raw_page]
            if not page and not paginated:
                break
            identifiers = [
                str(item.get("uuid") or item.get("id") or item) for item in page
            ]
            if seen.intersection(identifiers):
                raise DependencyTrackApiError(f"pagination did not advance: {path}")
            seen.update(identifiers)
            items.extend(page)
            if not paginated:
                break
            if expected_total is None or len(items) > expected_total:
                raise DependencyTrackApiError(f"pagination exceeds total: {path}")
            if len(items) == expected_total:
                break
            if len(page) < self._page_size:
                raise DependencyTrackApiError(f"pagination ended before total: {path}")
            offset += len(page)
        return items

    def list_projects(self) -> list[DependencyTrackProject]:
        payload = self._get_collection(
            "/api/v1/project", ("projects", "items"), paginated=True
        )
        if any(
            not isinstance(item.get("uuid"), str)
            or not item["uuid"].strip()
            or not isinstance(item.get("name"), str)
            or not item["name"].strip()
            for item in payload
        ):
            raise DependencyTrackApiError("project collection has incomplete identity")
        return [
            DependencyTrackProject(
                uuid=str(item["uuid"]),
                name=str(item["name"]),
                version=(
                    str(item["version"]) if item.get("version") is not None else None
                ),
            )
            for item in payload
        ]

    def get_project_findings(self, project_uuid: str) -> list[DependencyTrackFinding]:
        project_payload = self._request_json(f"/api/v1/project/{project_uuid}")
        if (
            not isinstance(project_payload, Mapping)
            or project_payload.get("uuid") != project_uuid
            or not isinstance(project_payload.get("name"), str)
            or not project_payload["name"].strip()
        ):
            raise DependencyTrackApiError("project response has incomplete identity")
        project = DependencyTrackProject(
            uuid=project_uuid,
            name=project_payload["name"],
        )
        payload = self._get_collection(
            f"/api/v1/finding/project/{project_uuid}",
            ("findings", "items"),
            params={"suppressed": "true"},
        )
        findings = [_finding_from_payload(item, project) for item in payload]

        # Dependency-Track exposes EPSS on the project vulnerability endpoint.
        # Use it as a fallback for finding responses that omit the field.
        vulnerability_payload = self._get_collection(
            f"/api/v1/vulnerability/project/{project_uuid}",
            ("vulnerabilities", "items"),
        )
        if any(
            not isinstance(item.get("vulnID") or item.get("vulnId"), str)
            or not (item.get("vulnID") or item.get("vulnId")).strip()
            for item in vulnerability_payload
        ):
            raise DependencyTrackApiError(
                "vulnerability collection has incomplete identity"
            )
        epss_by_vulnerability = {
            str(item.get("vulnID") or item.get("vulnId")): _score(
                item.get("epssScore"), maximum=1.0
            )
            for item in vulnerability_payload
            if item.get("vulnID") or item.get("vulnId")
        }
        return [
            (
                finding
                if finding.epss_score is not None
                else replace(
                    finding,
                    epss_score=epss_by_vulnerability.get(finding.vulnerability_id),
                )
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
                        (
                            f.project_uuid,
                            f.project_name,
                            f.finding_id,
                            f.vulnerability_uuid,
                            f.vulnerability_id,
                            f.vulnerability_aliases,
                            f.vulnerability_source,
                            f.component_uuid,
                            f.component_purl,
                            f.component_name,
                            f.component_version,
                            f.severity,
                            f.cvss_score,
                            f.cvss_version,
                            f.epss_score,
                            f.cwes,
                            f.description,
                            f.analysis_state,
                            f.is_suppressed,
                            f.analysis_detail,
                        )
                        for f in findings
                    ),
                    key=repr,
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
