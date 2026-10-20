from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from sbom_ops.clients.http import HttpApiError, request_json


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
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        *,
        include_headers: bool = False,
    ) -> dict | list | tuple:
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
                # Replaying an old body after a response loss can overwrite a
                # newer human edit. Let orchestration re-read before retrying.
                max_retries=self._max_retries if method == "GET" else 0,
                backoff_seconds=self._retry_backoff_seconds,
                error_message=f"GitHub request failed: {method} {path}",
                opener=urlopen,
                return_headers=include_headers,
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise GitHubApiError(
                f"GitHub request failed{detail}: {method} {path}"
            ) from exc

    @property
    def _repo_path(self) -> str:
        return f"/repos/{quote(self._owner)}/{quote(self._repo)}"

    def list_issues(self) -> list[dict]:
        """Read open AND closed issues without label or search-index filtering.

        The bounded reader fails rather than returning a truncated collection.
        Link URLs are never used as credential-bearing request destinations.
        """
        issues: list[dict] = []
        numbers: set[int] = set()
        for page in range(1, 11):
            query = urlencode(
                {
                    "state": "all",
                    "sort": "created",
                    "direction": "asc",
                    "per_page": "100",
                    "page": str(page),
                }
            )
            result, headers = self._request_json(
                "GET", f"{self._repo_path}/issues?{query}", include_headers=True
            )
            if not isinstance(result, list) or len(result) > 100:
                raise GitHubApiError("GitHub issues response was not a list")
            for item in result:
                if (
                    not isinstance(item, dict)
                    or type(item.get("number")) is not int
                    or item["number"] <= 0
                    or item["number"] in numbers
                    or not isinstance(item.get("repository_url"), str)
                    or item.get("repository_url", "").lower()
                    != f"{self._base_url}{self._repo_path}".lower()
                ):
                    raise GitHubApiError("invalid or repeated repository issue")
                numbers.add(item["number"])
                if "pull_request" not in item:
                    issues.append(item)
            link = next((v for k, v in headers.items() if k.lower() == "link"), "")
            if not self._has_next_page(link, page):
                return issues
            if not result:
                raise GitHubApiError("empty GitHub page has a continuation")
        raise GitHubApiError("GitHub issue page limit reached; inventory is incomplete")

    @staticmethod
    def _has_next_page(link: str, page: int) -> bool:
        if not link:
            return False
        parts = link.split(",")
        next_pages: list[str] = []
        for part in parts:
            match = re.fullmatch(r'\s*<([^<>]+)>;\s*rel="([^"]+)"\s*', part)
            if match is None:
                raise GitHubApiError("invalid GitHub pagination header")
            if "next" in match[2].split():
                next_pages.append(match[1])
        if len(next_pages) > 1:
            raise GitHubApiError("duplicate GitHub next page")
        if not next_pages:
            return False
        try:
            target = urlsplit(next_pages[0])
        except ValueError as exc:
            raise GitHubApiError("invalid GitHub next page URL") from exc
        query = parse_qs(target.query)
        if (
            target.scheme != "https"
            or target.netloc != "api.github.com"
            or query.get("page") != [str(page + 1)]
            or query.get("state") != ["all"]
            or query.get("sort") != ["created"]
            or query.get("direction") != ["asc"]
            or query.get("per_page") != ["100"]
        ):
            raise GitHubApiError("unexpected GitHub next page")
        return True

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        return self._request_json(
            "POST",
            f"{self._repo_path}/issues",
            {"title": title, "body": body, "labels": labels},
        )

    def get_issue(self, issue_number: int) -> dict:
        if type(issue_number) is not int or issue_number <= 0:
            raise ValueError("issue number must be a positive integer")
        result = self._request_json("GET", f"{self._repo_path}/issues/{issue_number}")
        if not isinstance(result, dict):
            raise GitHubApiError("GitHub issue response was not an object")
        return result

    def update_issue(self, issue_number: int, title: str | None, body: str) -> dict:
        payload = {"body": body}
        if title is not None:
            payload["title"] = title
        return self._request_json(
            "PATCH",
            f"{self._repo_path}/issues/{issue_number}",
            payload,
        )

    def close_issue(self, issue_number: int) -> dict:
        return self._request_json(
            "PATCH", f"{self._repo_path}/issues/{issue_number}", {"state": "closed"}
        )
