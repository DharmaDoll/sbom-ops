from __future__ import annotations


class GitHubIssuesClient:
    def find_open_issue_by_finding_key(self, finding_key: str) -> dict | None:
        raise NotImplementedError

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        raise NotImplementedError

    def update_issue(self, issue_number: int, title: str, body: str) -> dict:
        raise NotImplementedError

    def close_issue(self, issue_number: int) -> dict:
        raise NotImplementedError
