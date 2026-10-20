"""Durable evidence of an attempted GitHub create, not remediation state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


class IssueIntentError(ValueError):
    """A previous create must be reconciled before another write."""


class IssueJournalBusy(IssueIntentError):
    """Another process owns the local workflow journal."""


@dataclass(frozen=True)
class IssueCreateIntent:
    intent_id: str
    repository: str
    finding_key: str
    run_id: str
    state: str
    created_at: str
    issue_number: int | None = None
    confirmed_at: str | None = None
    confirmed_run_id: str | None = None

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.intent_id,
                self.repository,
                self.finding_key,
                self.run_id,
            )
        ):
            raise IssueIntentError("invalid create intent identity")
        if (
            self.repository != self.repository.lower()
            or self.repository.count("/") != 1
            or any(
                not part or part.strip() != part for part in self.repository.split("/")
            )
        ):
            raise IssueIntentError("invalid intent repository")
        if not isinstance(self.state, str) or self.state not in {
            "pending",
            "confirmed",
        }:
            raise IssueIntentError("invalid create intent state")
        if not _aware_timestamp(self.created_at):
            raise IssueIntentError("intent timestamp needs a timezone")
        if self.state == "pending":
            if any(
                value is not None
                for value in (
                    self.issue_number,
                    self.confirmed_at,
                    self.confirmed_run_id,
                )
            ):
                raise IssueIntentError("pending intent has confirmation data")
        elif (
            type(self.issue_number) is not int
            or self.issue_number <= 0
            or not isinstance(self.confirmed_run_id, str)
            or not self.confirmed_run_id.strip()
            or not _aware_timestamp(self.confirmed_at)
        ):
            raise IssueIntentError("invalid intent confirmation")


def _aware_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False
