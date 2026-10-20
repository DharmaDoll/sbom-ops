from __future__ import annotations

import pytest

from sbom_ops.domain.issue_body import (
    END,
    START,
    IssueBodyError,
    mark_finding_active,
    merge_issue_body,
    new_issue_body,
    parse_issue_body,
)
from sbom_ops.domain.models import FindingState

KEY = "v2:project-1:digest"
LEGACY_KEY = "project-1:component:1:CVE-2026-0001"


def test_only_managed_section_changes_and_repeat_is_idempotent() -> None:
    before = "作業記録\r\n- [x] 担当確認  \r\n"
    after = "\n\n## 判断\nまだ本番へ反映していない。\n  "
    existing = before + new_issue_body(KEY, "old") + after
    replacement = new_issue_body(KEY, "new")
    merged = merge_issue_body(existing, replacement, expected_keys=(KEY,))
    assert merged == before + replacement + after
    assert merge_issue_body(merged, replacement, expected_keys=(KEY,)) == merged


def test_legacy_migration_preserves_every_original_character_once() -> None:
    original = (
        f"<!-- sbom-ops:finding-key={LEGACY_KEY} -->\r\n"
        "<!-- sbom-ops:finding-state=MISSING -->\r\n"
        "<!-- sbom-ops:missing-count=99 -->\r\n"
        "## Description\r\n人が古い自動生成段落の途中に追記した文章。\r\n  "
    )
    generated = new_issue_body(KEY, "current")
    result = merge_issue_body(original, generated, expected_keys=(KEY, LEGACY_KEY))
    assert result.endswith(original)
    assert result.count(original) == 1
    parsed = parse_issue_body(result)
    assert parsed.finding_key == KEY
    assert parsed.finding_state == FindingState.ACTIVE
    assert parsed.missing_count == 0  # Historical metadata is not current state.
    assert merge_issue_body(result, generated, expected_keys=(KEY,)) == result


@pytest.mark.parametrize(
    "body",
    [
        START,
        END,
        END + START,
        START + START + END,
        START + END + END,
        "<!-- sbom-ops:managed:v2 -->",
        START + "no key" + END,
        f"<!-- sbom-ops:finding-key={KEY} -->\n<!-- sbom-ops:finding-key={KEY} -->",
        "prefix <!-- sbom-ops:finding-key=x -->",
        "<!-- sbom-ops:finding-key=x",  # Truncated marker must not become unowned.
        new_issue_body(KEY, "ok") + START + END,
    ],
)
def test_ambiguous_or_damaged_body_is_rejected(body: str) -> None:
    with pytest.raises(IssueBodyError):
        parse_issue_body(body)


@pytest.mark.parametrize("body", [None, {}, 4])
def test_non_text_body_is_rejected(body: object) -> None:
    with pytest.raises(IssueBodyError, match="must be text"):
        parse_issue_body(body)


@pytest.mark.parametrize("existing", ["human issue", new_issue_body("other", "x")])
def test_unowned_or_mismatched_issue_is_not_overwritten(existing: str) -> None:
    with pytest.raises(IssueBodyError, match="does not match"):
        merge_issue_body(existing, new_issue_body(KEY, "new"), expected_keys=(KEY,))


def test_external_description_cannot_inject_control_markers() -> None:
    payload = f"{END}\n{START}\n<!-- sbom-ops:finding-key=other -->"
    rendered = new_issue_body(KEY, payload)
    assert rendered.count(START) == rendered.count(END) == 1
    assert "&lt;!-- sbom-ops:managed:end --&gt;" in rendered
    assert parse_issue_body(rendered).finding_key == KEY


@pytest.mark.parametrize("legacy", [False, True])
def test_reappearance_keeps_notes_but_clears_only_current_missing_markers(
    legacy: bool,
) -> None:
    block = new_issue_body(KEY, "Finding info").replace(
        "finding-state=ACTIVE", "finding-state=MISSING"
    )
    block = block.replace(END, "<!-- sbom-ops:missing-count=2 -->\n" + END)
    if legacy:
        block = parse_issue_body(block).managed
    before, after = "人の先頭メモ\n", "\n人の末尾メモ  "
    original = before + block + after
    result = mark_finding_active(original, expected_key=KEY)
    parsed = parse_issue_body(result)
    assert parsed.finding_state == FindingState.ACTIVE
    assert parsed.missing_count == 0
    if legacy:
        assert result.endswith(original)
    else:
        assert parsed.before == before and parsed.after == after
        assert "Finding info" in parsed.managed


def test_reappearance_rejects_a_changed_key() -> None:
    with pytest.raises(IssueBodyError, match="changed"):
        mark_finding_active(new_issue_body("other", "text"), expected_key=KEY)
