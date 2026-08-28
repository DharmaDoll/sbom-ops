from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request

from dt_lab.domain import BomUpload, DependencyTrackObservation
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

    def observe_project(self, project_uuid: str) -> DependencyTrackObservation:
        return self._observe_json(f"/api/v1/project/{project_uuid}")

    def observe_project_components(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observe_json(f"/api/v1/component/project/{project_uuid}")

    def observe_project_direct_components(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observe_json(
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

    def observe_project_findings(self, project_uuid: str) -> DependencyTrackObservation:
        return self._observe_json(f"/api/v1/finding/project/{project_uuid}")

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
