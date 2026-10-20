from __future__ import annotations

import pytest

from sbom_ops.domain.issue_body import new_issue_body
from sbom_ops.domain.issue_catalog import IssueCatalog, IssueIdentityError


def issue(number: int, key: str, state: str = "open") -> dict:
    return {"number": number, "state": state, "body": new_issue_body(key, "details")}


def test_exact_match_ignores_mentions_and_uses_managed_key_not_saved_history() -> None:
    catalog = IssueCatalog(
        [
            {"number": 1, "state": "open", "body": "text mentioning wanted"},
            issue(2, "wanted-extra"),
            {
                **issue(3, "wanted"),
                "body": new_issue_body("wanted", "data")
                + "\n<!-- sbom-ops:finding-key=old -->",
            },
        ]
    )
    assert catalog.find("wanted", "old").number == 3
    assert catalog.find("old", "missing") is None


@pytest.mark.parametrize(
    "states", [("open", "open"), ("open", "closed"), ("closed", "closed")]
)
def test_duplicate_new_or_legacy_key_is_ambiguous(states: tuple[str, str]) -> None:
    catalog = IssueCatalog([issue(1, "new", states[0]), issue(2, "old", states[1])])
    with pytest.raises(IssueIdentityError, match="multiple"):
        catalog.find("new", "old")


def test_closed_issue_is_returned_for_human_review_not_treated_as_absent() -> None:
    result = IssueCatalog([issue(1, "key", "closed")]).find("key", "old")
    assert result.state == "closed"


@pytest.mark.parametrize(
    "rows",
    [
        [None],
        [{"number": True}],
        [issue(1, "key"), issue(1, "key")],
        [{**issue(1, "key"), "state": "unknown"}],
        [{**issue(1, "key"), "body": "<!-- sbom-ops:managed:start -->"}],
    ],
)
def test_incomplete_or_invalid_metadata_cannot_authorize_creation(rows: list) -> None:
    with pytest.raises(IssueIdentityError):
        IssueCatalog(rows)


def test_record_requires_an_explicit_identity_migration() -> None:
    catalog = IssueCatalog([issue(1, "old")])
    with pytest.raises(IssueIdentityError, match="reused"):
        catalog.record(1, "open", new_issue_body("new", "details"))
    catalog.record(1, "open", new_issue_body("new", "details"), previous_key="old")
    assert catalog.find("new", "old").number == 1
    assert catalog.find("old", "missing") is None


def test_pull_requests_and_unmanaged_issues_are_not_matches() -> None:
    catalog = IssueCatalog(
        [
            {**issue(1, "key"), "pull_request": {}},
            {"number": 2, "state": "open", "body": None},
        ]
    )
    assert catalog.find("key", "old") is None
