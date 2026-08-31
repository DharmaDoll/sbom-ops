from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request

from dt_lab.domain import (
    AnalysisAction,
    BomUpload,
    DependencyTrackObservation,
    VexUpload,
)
from sbom_ops.clients.http import HttpApiError, HttpJsonResponse, request_json


class DependencyTrackLabApiError(RuntimeError):
    """Raised when Dependency-Track cannot serve a lab request."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class DependencyTrackLabClient:
    """Repository-only adapter for exploratory Dependency-Track observations."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_backoff_seconds: float = 1.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
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
                error_message=f"Dependency-Track lab request failed: {path}",
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise DependencyTrackLabApiError(
                f"Dependency-Track lab request failed{detail}: {path}",
                status=exc.status,
            ) from exc

    def _observe_json(
        self,
        path: str,
        params: dict[str, str] | None = None,
        *,
        accept: str = "application/json",
    ) -> DependencyTrackObservation:
        query = f"?{urlencode(params)}" if params else ""
        request = Request(
            f"{self._base_url}{path}{query}",
            headers={"Accept": accept, "X-Api-Key": self._api_key},
        )
        try:
            response = request_json(
                request,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._retry_backoff_seconds,
                error_message=f"Dependency-Track lab observation failed: {path}",
                return_response=True,
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise DependencyTrackLabApiError(
                f"Dependency-Track lab observation failed{detail}: {path}",
                status=exc.status,
            ) from exc
        if not isinstance(response, HttpJsonResponse):
            raise DependencyTrackLabApiError(
                "Dependency-Track lab observation returned no response metadata: "
                f"{path}"
            )
        safe_headers = {
            key: value
            for key, value in response.headers.items()
            if key.lower()
            in {
                "content-length",
                "content-type",
                "date",
                "etag",
                "last-modified",
                "retry-after",
                "x-total-count",
            }
        }
        return DependencyTrackObservation(
            method="GET",
            path=path,
            query=tuple(sorted((params or {}).items())),
            status=response.status,
            headers=tuple(sorted(safe_headers.items())),
            duration_seconds=response.duration_seconds,
            payload=response.payload,
        )

    def _observe_paginated_json(
        self,
        path: str,
        params: dict[str, str] | None = None,
        *,
        page_size: int = 100,
    ) -> DependencyTrackObservation:
        """Observe every page of a Dependency-Track list response.

        Dependency-Track's Component collection defaults to 100 items and
        communicates the complete collection size through ``X-Total-Count``.
        The lab retains one combined payload so large-corpus observations do
        not silently represent only the first page.
        """
        if page_size < 1:
            raise ValueError("page_size must be positive")

        base_params = dict(params or {})
        if "pageNumber" in base_params or "pageSize" in base_params:
            raise ValueError("pagination parameters are managed by the lab client")

        combined: list[Any] = []
        first: DependencyTrackObservation | None = None
        duration_seconds = 0.0
        total_count: int | None = None
        page_number = 1
        while True:
            page_params = {
                **base_params,
                "pageNumber": str(page_number),
                "pageSize": str(page_size),
            }
            page = self._observe_json(path, page_params)
            if not isinstance(page.payload, list):
                raise DependencyTrackLabApiError(
                    "Dependency-Track paginated observation returned a non-list "
                    f"payload: {path}"
                )
            if first is None:
                first = page
                raw_total_count = next(
                    (
                        value
                        for key, value in page.headers
                        if key.lower() == "x-total-count"
                    ),
                    None,
                )
                if raw_total_count is not None:
                    try:
                        total_count = int(raw_total_count)
                    except ValueError as exc:
                        raise DependencyTrackLabApiError(
                            "Dependency-Track returned an invalid X-Total-Count "
                            f"for {path}: {raw_total_count!r}"
                        ) from exc
                    if total_count < 0:
                        raise DependencyTrackLabApiError(
                            "Dependency-Track returned a negative X-Total-Count "
                            f"for {path}: {total_count}"
                        )
            duration_seconds += page.duration_seconds
            combined.extend(page.payload)

            if total_count is not None and len(combined) >= total_count:
                if len(combined) != total_count:
                    raise DependencyTrackLabApiError(
                        "Dependency-Track paginated observation exceeded "
                        f"X-Total-Count for {path}: expected {total_count}, "
                        f"observed {len(combined)}"
                    )
                break
            if len(page.payload) < page_size:
                if total_count is not None and len(combined) != total_count:
                    raise DependencyTrackLabApiError(
                        "Dependency-Track paginated observation ended before "
                        f"X-Total-Count for {path}: expected {total_count}, "
                        f"observed {len(combined)}"
                    )
                break
            page_number += 1
            if page_number > 10_000:
                raise DependencyTrackLabApiError(
                    "Dependency-Track paginated observation exceeded 10000 pages: "
                    f"{path}"
                )

        if first is None:  # pragma: no cover - loop always performs one request
            raise DependencyTrackLabApiError(
                f"Dependency-Track paginated observation returned no pages: {path}"
            )
        return DependencyTrackObservation(
            method=first.method,
            path=path,
            query=tuple(sorted({**base_params, "pageSize": str(page_size)}.items())),
            status=first.status,
            headers=first.headers,
            duration_seconds=duration_seconds,
            payload=combined,
        )

    def record_analysis_decision(
        self,
        *,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        action: AnalysisAction,
    ) -> DependencyTrackObservation:
        path = "/api/v1/analysis"
        payload = {
            "project": project_uuid,
            "component": component_uuid,
            "vulnerability": vulnerability_uuid,
            "analysisState": action.state.value,
            "analysisJustification": action.justification.value,
            "analysisResponse": action.response.value,
            "analysisDetails": action.detail,
            "comment": action.comment,
            "isSuppressed": action.suppressed,
        }
        request = Request(
            f"{self._base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            method="PUT",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Api-Key": self._api_key,
            },
        )
        try:
            response = request_json(
                request,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._retry_backoff_seconds,
                error_message="Dependency-Track lab analysis update failed",
                return_response=True,
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise DependencyTrackLabApiError(
                f"Dependency-Track lab analysis update failed{detail}",
                status=exc.status,
            ) from exc
        if not isinstance(response, HttpJsonResponse):
            raise DependencyTrackLabApiError(
                "Dependency-Track lab analysis update returned no response metadata"
            )
        return DependencyTrackObservation(
            method="PUT",
            path=path,
            query=(),
            status=response.status,
            headers=tuple(
                sorted(
                    (key, value)
                    for key, value in response.headers.items()
                    if key.lower()
                    in {
                        "content-length",
                        "content-type",
                        "date",
                        "etag",
                        "last-modified",
                        "retry-after",
                        "x-total-count",
                    }
                )
            ),
            duration_seconds=response.duration_seconds,
            payload=response.payload,
            request_payload=payload,
        )

    def upload_bom_by_project_coordinates(
        self, project_name: str, project_version: str, bom_path: str | Path
    ) -> BomUpload:
        bom = Path(bom_path).read_bytes()
        boundary = "----sbom-ops-dt-lab-boundary"
        fields = (
            ("autoCreate", "true"),
            ("projectName", project_name),
            ("projectVersion", project_version),
        )
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
                error_message="Dependency-Track lab BOM upload failed",
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise DependencyTrackLabApiError(
                f"Dependency-Track lab BOM upload failed{detail}",
                status=exc.status,
            ) from exc
        token = payload.get("token") if isinstance(payload, dict) else None
        if not token:
            raise DependencyTrackLabApiError(
                "Dependency-Track lab BOM response has no token"
            )
        return BomUpload(token=str(token))

    def upload_vex_for_project(
        self, project_uuid: str, vex_path: str | Path
    ) -> VexUpload:
        """Upload one CycloneDX VEX to an existing disposable lab Project."""
        vex = Path(vex_path).read_bytes()
        boundary = "----sbom-ops-dt-lab-vex-boundary"
        body = b"".join(
            [
                f"--{boundary}\r\n".encode(),
                b'Content-Disposition: form-data; name="project"\r\n\r\n',
                project_uuid.encode(),
                b"\r\n",
                f"--{boundary}\r\n".encode(),
                (
                    'Content-Disposition: form-data; name="vex"; '
                    f'filename="{Path(vex_path).name}"\r\n'
                    "Content-Type: application/vnd.cyclonedx+json\r\n\r\n"
                ).encode(),
                vex,
                b"\r\n",
                f"--{boundary}--\r\n".encode(),
            ]
        )
        request = Request(
            f"{self._base_url}/api/v1/vex",
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
                error_message="Dependency-Track lab VEX upload failed",
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise DependencyTrackLabApiError(
                f"Dependency-Track lab VEX upload failed{detail}",
                status=exc.status,
            ) from exc
        token = payload.get("token") if isinstance(payload, dict) else None
        if not token:
            raise DependencyTrackLabApiError(
                "Dependency-Track lab VEX response has no token"
            )
        return VexUpload(token=str(token))

    def wait_for_bom_processing(
        self,
        token: str,
        *,
        timeout: float = 120.0,
        poll_interval: float = 5.0,
    ) -> None:
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
        raise DependencyTrackLabApiError(
            f"Dependency-Track lab BOM processing timed out: token {token}"
        )

    def observe_project_lookup(
        self, project_name: str, project_version: str
    ) -> DependencyTrackObservation:
        return self._observe_json(
            "/api/v1/project/lookup",
            {"name": project_name, "version": project_version},
        )

    def observe_current_team(self) -> DependencyTrackObservation:
        return self._observe_json("/api/v1/team/self")

    def observe_project(self, project_uuid: str) -> DependencyTrackObservation:
        return self._observe_json(f"/api/v1/project/{project_uuid}")

    def observe_project_components(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observe_paginated_json(f"/api/v1/component/project/{project_uuid}")

    def observe_project_direct_components(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observe_paginated_json(
            f"/api/v1/component/project/{project_uuid}", {"onlyDirect": "true"}
        )

    def observe_project_services(self, project_uuid: str) -> DependencyTrackObservation:
        return self._observe_json(f"/api/v1/service/project/{project_uuid}")

    def observe_project_dependency_graph(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observe_json(
            f"/api/v1/dependencyGraph/project/{project_uuid}/directDependencies"
        )

    def observe_project_findings(
        self, project_uuid: str, *, suppressed: bool = False
    ) -> DependencyTrackObservation:
        return self._observe_json(
            f"/api/v1/finding/project/{project_uuid}",
            {"suppressed": "true"} if suppressed else None,
        )

    def observe_analysis_trail(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> DependencyTrackObservation:
        return self._observe_json(
            "/api/v1/analysis",
            {
                "project": project_uuid,
                "component": component_uuid,
                "vulnerability": vulnerability_uuid,
            },
        )

    def observe_analysis_trail_if_present(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> DependencyTrackObservation:
        """Observe an Analysis trail while preserving an expected absent row."""
        query = {
            "project": project_uuid,
            "component": component_uuid,
            "vulnerability": vulnerability_uuid,
        }
        try:
            return self._observe_json("/api/v1/analysis", query)
        except DependencyTrackLabApiError as exc:
            if exc.status != 404:
                raise
            return DependencyTrackObservation(
                method="GET",
                path="/api/v1/analysis",
                query=tuple(sorted(query.items())),
                status=404,
                headers=(),
                duration_seconds=0.0,
                payload=None,
            )

    def observe_project_vulnerabilities(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observe_json(f"/api/v1/vulnerability/project/{project_uuid}")

    def observe_project_metrics(self, project_uuid: str) -> DependencyTrackObservation:
        return self._observe_json(f"/api/v1/metrics/project/{project_uuid}/current")

    def observe_project_bom_export(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observe_json(
            f"/api/v1/bom/cyclonedx/project/{project_uuid}",
            {
                "format": "JSON",
                "variant": "inventory",
                "download": "false",
                "version": "1.5",
            },
            accept="application/vnd.cyclonedx+json",
        )

    def observe_project_vex_export(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        """Observe the CycloneDX VEX generated from a Project's audit state."""
        return self._observe_json(
            f"/api/v1/vex/cyclonedx/project/{project_uuid}",
            {"download": "false", "version": "1.5"},
            accept="application/vnd.cyclonedx+json",
        )

    def delete_project(self, project_uuid: str) -> None:
        """Delete one verified lab Project using DT's project API."""
        path = f"/api/v1/project/{project_uuid}"
        request = Request(
            f"{self._base_url}{path}",
            method="DELETE",
            headers={"Accept": "application/json", "X-Api-Key": self._api_key},
        )
        try:
            response = request_json(
                request,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._retry_backoff_seconds,
                error_message=f"Dependency-Track lab Project deletion failed: {path}",
                return_response=True,
                allow_empty=True,
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise DependencyTrackLabApiError(
                f"Dependency-Track lab Project deletion failed{detail}: {path}",
                status=exc.status,
            ) from exc
        if not isinstance(response, HttpJsonResponse) or response.status != 204:
            status = response.status if isinstance(response, HttpJsonResponse) else None
            raise DependencyTrackLabApiError(
                "Dependency-Track lab Project deletion returned an unexpected "
                f"response: {path}",
                status=status,
            )
