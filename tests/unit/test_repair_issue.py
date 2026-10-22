import base64
import json
from dataclasses import asdict, replace

import pytest

from sbom_ops.domain.issue_body import END, IssueBodyError, new_issue_body
from sbom_ops.domain.issue_catalog import IssueCatalog, IssueIdentityError
from sbom_ops.domain.models import Priority
from sbom_ops.domain.repair_issue import (
    MAX_REPAIR_BODY,
    RepairMember,
    RepairRecord,
    merge_repair_record,
    parse_repair_record,
    repair_issue_body,
)


def record() -> RepairRecord:
    return RepairRecord(
        "repair-v1:" + "a" * 64,
        "acme/repo",
        "sbom",
        (
            RepairMember(
                "v2:p1:" + "b" * 64,
                "p1:lib:1:CVE-2026-1000",
                "p1",
                "P1",
                False,
                "details",
            ),
        ),
    )


def test_record_roundtrip_keeps_external_comments_as_text_not_control_data() -> None:
    original = record()
    injected = replace(
        original.members[0], content="<!-- sbom-ops:managed:start -->\n<script>"
    )
    original = replace(original, members=(injected,))
    body = repair_issue_body(original)
    assert parse_repair_record(body) == original
    assert body.count("<!-- sbom-ops:managed:start -->") == 1
    assert "&lt;script&gt;" in body


@pytest.mark.parametrize("legacy", [True, False])
def test_migration_preserves_human_notes_and_both_old_keys(legacy: bool) -> None:
    current = record()
    member = current.members[0]
    old = (
        f"<!-- sbom-ops:finding-key={member.legacy_key} -->\nold human notes"
        if legacy
        else "before\n" + new_issue_body(member.finding_key, "old") + "\nafter"
    )
    body = repair_issue_body(current, existing=old)
    if legacy:
        assert old in body
    else:
        assert body.startswith("before\n") and body.endswith("\nafter")
    catalog = IssueCatalog([{"number": 1, "state": "open", "body": body}])
    for key in current.keys:
        assert catalog.find(key, key).number == 1
    # No old key is read out of the saved human-history area.
    assert catalog.find("unrelated", "missing") is None


def test_unobserved_members_are_kept_with_last_priority_until_observed_again() -> None:
    original = record()
    member2 = replace(
        original.members[0],
        finding_key="v2:p2:" + "c" * 64,
        legacy_key="p2:lib:1:CVE-2026-1000",
        project_uuid="p2",
        priority="P3",
    )
    merged = merge_repair_record(replace(original, members=(member2,)), original)
    assert len(merged.members) == 2
    assert merged.members[0].observed is False
    assert merged.priority is Priority.P1
    body = repair_issue_body(merged)
    assert "今回未確認" in body
    again = merge_repair_record(original, parse_repair_record(body))
    assert again.members[0].observed is True
    assert again.members[1].observed is False
    assert merged.keys == again.keys


@pytest.mark.parametrize(
    "field,value",
    [
        ("group_key", "repair-v1:" + "d" * 64),
        ("repository", "acme/other"),
        ("label_prefix", "security"),
    ],
)
def test_changed_record_scope_is_not_silently_migrated(field: str, value: str) -> None:
    with pytest.raises(IssueBodyError, match="route changed"):
        merge_repair_record(record(), replace(record(), **{field: value}))


@pytest.mark.parametrize(
    "extra",
    [
        "<!-- sbom-ops:repair-record=not-base64 -->",
        "<!-- sbom-ops:repair-record=e30= -->",  # empty JSON object
    ],
)
def test_malformed_or_duplicate_records_are_rejected(extra: str) -> None:
    valid = repair_issue_body(record())
    with pytest.raises(IssueBodyError):
        parse_repair_record(valid.replace(END, extra + "\n" + END))
    with pytest.raises(IssueBodyError):
        parse_repair_record(new_issue_body(record().group_key, "missing record"))


def test_group_and_individual_issue_matches_are_ambiguous_even_when_closed() -> None:
    original = record()
    catalog = IssueCatalog(
        [
            {"number": 1, "state": "open", "body": repair_issue_body(original)},
            {
                "number": 2,
                "state": "closed",
                "body": new_issue_body(original.members[0].finding_key, "old"),
            },
        ]
    )
    with pytest.raises(IssueIdentityError, match="multiple"):
        catalog.find_any(original.keys)


def test_large_body_is_rejected_without_losing_members_or_human_notes() -> None:
    current = record()
    huge = replace(current.members[0], content="x" * MAX_REPAIR_BODY)
    with pytest.raises(IssueBodyError, match="no truncation"):
        repair_issue_body(replace(current, members=(huge,)))
    with pytest.raises(IssueBodyError, match="no truncation"):
        repair_issue_body(
            current,
            existing=new_issue_body(current.members[0].finding_key, "old")
            + "x" * MAX_REPAIR_BODY,
        )


def test_excluded_member_never_selects_the_group_priority() -> None:
    current = record()
    assert (
        replace(current, members=(replace(current.members[0], excluded=True),)).priority
        is None
    )


@pytest.mark.parametrize(
    "change", ["duplicate", "version", "missing", "wrong_type", "unknown"]
)
def test_record_schema_rejects_ambiguous_or_incomplete_payloads(change: str) -> None:
    raw = {"version": 1, **asdict(record())}
    if change == "version":
        raw["version"] = True
    elif change == "missing":
        del raw["members"][0]["observed"]
    elif change == "wrong_type":
        raw["members"][0]["excluded"] = "false"
    elif change == "unknown":
        raw["members"][0]["other"] = "unexpected"
    serialized = json.dumps(raw)
    if change == "duplicate":
        serialized = serialized.replace('"version": 1', '"version": 1, "version": 1')
    encoded = base64.b64encode(serialized.encode()).decode()
    body = new_issue_body(record().group_key, "details").replace(
        END, f"<!-- sbom-ops:repair-record={encoded} -->\n{END}"
    )
    with pytest.raises(IssueBodyError):
        parse_repair_record(body)
