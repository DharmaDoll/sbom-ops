"""Own only the delimited part of an issue; retain all other text verbatim."""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape

from sbom_ops.domain.models import FindingState

START = "<!-- sbom-ops:managed:start -->"
END = "<!-- sbom-ops:managed:end -->"
_KEY = re.compile(r"^<!-- sbom-ops:finding-key=([^<>\r\n]+) -->\r?$", re.MULTILINE)
_STATE = re.compile(r"^<!-- sbom-ops:finding-state=([^<>\r\n]*) -->\r?$", re.MULTILINE)
_COUNT = re.compile(r"^<!-- sbom-ops:missing-count=([^<>\r\n]*) -->\r?$", re.MULTILINE)


class IssueBodyError(ValueError):
    """The issue's ownership boundary or finding identity is ambiguous."""


@dataclass(frozen=True)
class IssueBody:
    before: str
    managed: str
    after: str
    legacy: bool
    finding_key: str | None

    @property
    def finding_state(self) -> FindingState | None:
        values = _STATE.findall(self.managed)
        if len(values) != 1:
            return None
        try:
            return FindingState(values[0])
        except ValueError:
            return None

    @property
    def missing_count(self) -> int:
        values = _COUNT.findall(self.managed)
        if len(values) != 1 or re.fullmatch(r"[0-9]{1,9}", values[0]) is None:
            return 0
        return int(values[0])


def parse_issue_body(body: str) -> IssueBody:
    if not isinstance(body, str):
        raise IssueBodyError("issue body must be text")
    legacy = "<!-- sbom-ops:managed" not in body
    before = after = ""
    managed = body
    if not legacy:
        if (
            body.count("<!-- sbom-ops:managed") != 2
            or body.count(START) != 1
            or body.count(END) != 1
            or body.index(START) >= body.index(END)
        ):
            raise IssueBodyError("invalid or duplicate issue managed boundaries")
        before, rest = body.split(START)
        managed, after = rest.split(END)
    keys = _KEY.findall(managed)
    if len(keys) > 1 or managed.count("<!-- sbom-ops:finding-key") != len(keys):
        raise IssueBodyError("invalid or duplicate issue finding key")
    if not legacy and len(keys) != 1:
        raise IssueBodyError("managed issue body needs exactly one finding key")
    return IssueBody(before, managed, after, legacy, keys[0] if keys else None)


def new_issue_body(finding_key: str, content: str) -> str:
    # Render external descriptions as text, never as ownership-control comments.
    block = (
        f"{START}\n<!-- sbom-ops:finding-key={finding_key} -->\n"
        f"<!-- sbom-ops:finding-state=ACTIVE -->\n\n"
        f"{escape(content, quote=False)}\n{END}"
    )
    parse_issue_body(block)  # Also validate keys produced by fallback identities.
    return block


def merge_issue_body(
    existing: str, generated: str, *, expected_keys: tuple[str, ...]
) -> str:
    current = parse_issue_body(existing)
    replacement = parse_issue_body(generated)
    if (
        current.finding_key not in expected_keys
        or replacement.finding_key not in expected_keys
        or replacement.legacy
    ):
        raise IssueBodyError("issue finding key does not match the current finding")
    block = START + replacement.managed + END
    if current.legacy:
        # Never guess which lines in a pre-boundary issue were added by humans.
        return block + "\n\n## 移行前の本文（保存・自動更新対象外）\n\n" + existing
    return current.before + block + current.after


def mark_finding_active(body: str, *, expected_key: str) -> str:
    current = parse_issue_body(body)
    if current.finding_key != expected_key:
        raise IssueBodyError("issue finding key changed before reappearance update")
    if current.legacy:
        generated = new_issue_body(expected_key, "Findingを再確認しました。")
    else:
        content = _STATE.sub("", current.managed)
        content = _COUNT.sub("", content)
        generated = START + content + "\n<!-- sbom-ops:finding-state=ACTIVE -->\n" + END
    return merge_issue_body(body, generated, expected_keys=(expected_key,))
