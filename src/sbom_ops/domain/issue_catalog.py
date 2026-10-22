"""Exact finding identity matching over a fully read repository issue list."""

from __future__ import annotations

from dataclasses import dataclass

from sbom_ops.domain.issue_body import IssueBodyError, parse_issue_body
from sbom_ops.domain.repair_issue import parse_repair_record


class IssueIdentityError(ValueError):
    """Issue identity is ambiguous; no create/update decision is safe."""


@dataclass(frozen=True)
class ManagedIssue:
    number: int
    state: str
    body: str
    key: str
    aliases: tuple[str, ...] = ()


class IssueCatalog:
    def __init__(self, issues: list[dict]) -> None:
        self._issues: dict[int, ManagedIssue] = {}
        numbers: set[int] = set()
        for issue in issues:
            if not isinstance(issue, dict):
                raise IssueIdentityError("issue response must be an object")
            number = issue.get("number")
            if type(number) is not int or number <= 0 or number in numbers:
                raise IssueIdentityError("invalid or repeated issue number")
            numbers.add(number)
            if "pull_request" in issue:
                continue
            if not isinstance(issue.get("state"), str) or issue["state"] not in {
                "open",
                "closed",
            }:
                raise IssueIdentityError("invalid issue state")
            body = issue.get("body")
            if body is None:
                body = ""
            try:
                key = parse_issue_body(body).finding_key
                repair = parse_repair_record(body)
            except IssueBodyError as exc:
                raise IssueIdentityError(
                    f"invalid managed body in issue #{number}"
                ) from exc
            if key is not None:
                self._issues[number] = ManagedIssue(
                    number, issue["state"], body, key, repair.keys if repair else ()
                )

    def find(self, key: str, legacy_key: str) -> ManagedIssue | None:
        return self.find_any((key, legacy_key))

    def individual_issues(self) -> tuple[ManagedIssue, ...]:
        return tuple(item for item in self._issues.values() if not item.aliases)

    def find_any(self, keys: tuple[str, ...]) -> ManagedIssue | None:
        matches = [
            item
            for item in self._issues.values()
            if set(keys).intersection((item.key, *item.aliases))
        ]
        if len(matches) > 1:
            raise IssueIdentityError(
                "multiple issues match the current or legacy finding key"
            )
        return matches[0] if matches else None

    def record(
        self, number: int, state: str, body: str, *, previous_key: str | None = None
    ) -> None:
        """Reflect a confirmed write so duplicate rows in a run cannot recreate it."""
        parsed = IssueCatalog([{"number": number, "state": state, "body": body}])
        if number not in parsed._issues:
            raise IssueIdentityError("confirmed issue has no finding key")
        if (
            number in self._issues
            and self._issues[number].key != parsed._issues[number].key
        ):
            # Only an explicit legacy migration may change an existing key.
            if self._issues[number].key != previous_key:
                raise IssueIdentityError("issue number was reused for another finding")
        self._issues.update(parsed._issues)
