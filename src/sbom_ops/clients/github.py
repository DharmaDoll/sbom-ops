from __future__ import annotations

import json
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from sbom_ops.clients.http import request_json


class GitHubApiError(RuntimeError):
    """Raised when GitHub cannot serve an API request."""


class GitHubIssuesClient:
    def __init__(
        self,
        token: str,
        owner: str,
        repo: str,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_backoff_seconds: float = 1.0,
    ) -> None:
        self._token = token
        self._owner = owner
        self._repo = repo
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_backoff_seconds = retry_backoff_seconds
        self._base_url = "https://api.github.com"

    def _request_json(
        self, method: str, path: str, payload: dict | None = None
    ) -> dict | list:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            f"{self._base_url}{path}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            return request_json(
                request,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._retry_backoff_seconds,
                error_message=f"GitHub request failed: {method} {path}",
                opener=urlopen,
            )
        except RuntimeError as exc:
            raise GitHubApiError(str(exc)) from exc

    @property
    def _repo_path(self) -> str:
        return f"/repos/{quote(self._owner)}/{quote(self._repo)}"

    def find_open_issue_by_finding_key(self, finding_key: str) -> dict | None:
        query = urlencode(
            {"q": f'repo:{self._owner}/{self._repo} is:issue is:open "{finding_key}"'}
        )
        result = self._request_json("GET", f"/search/issues?{query}")
        items = result.get("items", [])
        return items[0] if items else None

    def list_open_issues(self, label: str) -> list[dict]:
        issues: list[dict] = []
        for page in range(1, 11):
            query = urlencode(
                {
                    "state": "open",
                    "labels": label,
                    "per_page": "100",
                    "page": str(page),
                }
            )
            result = self._request_json("GET", f"{self._repo_path}/issues?{query}")
            if not isinstance(result, list):
                raise GitHubApiError("GitHub issues response was not a list")
            page_items = [item for item in result if "pull_request" not in item]
            issues.extend(page_items)
            if len(result) < 100:
                break
        return issues

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        return self._request_json(
            "POST",
            f"{self._repo_path}/issues",
            {"title": title, "body": body, "labels": labels},
        )

    def update_issue(self, issue_number: int, title: str, body: str) -> dict:
        return self._request_json(
            "PATCH",
            f"{self._repo_path}/issues/{issue_number}",
            {"title": title, "body": body},
        )

    def close_issue(self, issue_number: int) -> dict:
        return self._request_json(
            "PATCH", f"{self._repo_path}/issues/{issue_number}", {"state": "closed"}
        )
