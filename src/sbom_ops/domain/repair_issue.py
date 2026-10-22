"""Versioned group membership in the managed Issue body, never workflow decisions."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import asdict, dataclass, replace

from sbom_ops.domain.issue_body import (
    END,
    IssueBodyError,
    merge_issue_body,
    new_issue_body,
    parse_issue_body,
)
from sbom_ops.domain.models import Priority

_MARKER = "<!-- sbom-ops:repair-record="
_RECORD = re.compile(
    r"^<!-- sbom-ops:repair-record=([A-Za-z0-9+/=]+) -->$", re.MULTILINE
)
_KEY = re.compile(r"repair-v1:[0-9a-f]{64}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
# Bound our own representation, including human notes. Never silently truncate
# members or split a group into extra Issues when it outgrows this format.
MAX_REPAIR_BODY = 60000


def _text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and all(char.isprintable() for char in value)
    )


@dataclass(frozen=True)
class RepairMember:
    finding_key: str
    legacy_key: str
    project_uuid: str
    priority: str
    excluded: bool
    content: str
    observed: bool = True

    def __post_init__(self) -> None:
        if (
            not all(
                _text(value)
                for value in (
                    self.finding_key,
                    self.legacy_key,
                    self.project_uuid,
                )
            )
            or self.priority not in {p.value for p in Priority}
            or type(self.excluded) is not bool
            or type(self.observed) is not bool
            or not isinstance(self.content, str)
        ):
            raise IssueBodyError("invalid repair member")
        prefix = f"v2:{self.project_uuid}:"
        if not self.finding_key.startswith(prefix) or not _DIGEST.fullmatch(
            self.finding_key[len(prefix) :]
        ):
            raise IssueBodyError("repair member needs its original v2 finding key")


@dataclass(frozen=True)
class RepairRecord:
    group_key: str
    repository: str
    label_prefix: str
    members: tuple[RepairMember, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.group_key, str)
            or _KEY.fullmatch(self.group_key) is None
            or not _text(self.repository)
            or self.repository != self.repository.lower()
            or self.repository.count("/") != 1
            or not all(self.repository.split("/"))
            or not _text(self.label_prefix)
            or not self.members
            or len({m.finding_key for m in self.members}) != len(self.members)
        ):
            raise IssueBodyError("invalid repair record identity or members")

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    self.group_key,
                    *(
                        key
                        for member in self.members
                        for key in (member.finding_key, member.legacy_key)
                    ),
                }
            )
        )

    @property
    def priority(self) -> Priority | None:
        # Unobserved members remain unresolved and keep their last known priority.
        return min(
            (Priority(m.priority) for m in self.members if not m.excluded),
            default=None,
        )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate repair field")
        result[key] = value
    return result


def parse_repair_record(body: str) -> RepairRecord | None:
    parsed = parse_issue_body(body)
    values = _RECORD.findall(parsed.managed)
    if not values and _MARKER not in parsed.managed:
        if parsed.finding_key and parsed.finding_key.startswith("repair-v1:"):
            raise IssueBodyError("repair issue is missing its membership record")
        return None
    if parsed.legacy or len(values) != 1 or parsed.managed.count(_MARKER) != 1:
        raise IssueBodyError("invalid repair membership marker")
    if len(body) > MAX_REPAIR_BODY:
        raise IssueBodyError("repair issue exceeds the supported body size")
    try:
        raw = json.loads(
            base64.b64decode(values[0], validate=True), object_pairs_hook=_unique_object
        )
        if set(raw) != {
            "version",
            "group_key",
            "repository",
            "label_prefix",
            "members",
        }:
            raise ValueError("unexpected repair fields")
        if type(raw["version"]) is not int or raw["version"] != 1:
            raise ValueError("unsupported repair record version")
        if not isinstance(raw["members"], list):
            raise ValueError("invalid repair members")
        for member in raw["members"]:
            if not isinstance(member, dict) or set(member) != {
                "finding_key",
                "legacy_key",
                "project_uuid",
                "priority",
                "excluded",
                "content",
                "observed",
            }:
                raise ValueError("unexpected repair member fields")
        record = RepairRecord(
            raw["group_key"],
            raw["repository"],
            raw["label_prefix"],
            tuple(RepairMember(**item) for item in raw["members"]),
        )
    except (
        ValueError,
        TypeError,
        KeyError,
        binascii.Error,
        UnicodeError,
        RecursionError,
    ) as exc:
        raise IssueBodyError("invalid repair membership record") from exc
    if parsed.finding_key != record.group_key:
        raise IssueBodyError("repair record and managed key disagree")
    return record


def merge_repair_record(
    current: RepairRecord, previous: RepairRecord | None
) -> RepairRecord:
    if previous is None:
        return current
    if (current.group_key, current.repository, current.label_prefix) != (
        previous.group_key,
        previous.repository,
        previous.label_prefix,
    ):
        raise IssueBodyError("repair identity or route changed; review before writing")
    members = {m.finding_key: replace(m, observed=False) for m in previous.members}
    for member in current.members:
        old = members.get(member.finding_key)
        if old is not None and (old.legacy_key, old.project_uuid) != (
            member.legacy_key,
            member.project_uuid,
        ):
            raise IssueBodyError("repair member identity changed")
        members[member.finding_key] = member
    return replace(current, members=tuple(members[key] for key in sorted(members)))


def repair_issue_body(record: RepairRecord, *, existing: str | None = None) -> str:
    sections = [
        "## 修正作業のまとまり",
        "同じサービス・配布単位・部品・脆弱性のFindingをまとめています。",
        "今回未確認は解決を意味しません。DT分析・抑制はFindingごとに判断します。",
        "Issue優先度: "
        + (record.priority.value if record.priority else "分析除外のみ")
        + "（分析除外を除く最優先値。今回未確認の最後の値も保持）",
    ]
    for member in record.members:
        sections.extend(
            [
                f"### Finding {member.finding_key}",
                (
                    "今回観測"
                    if member.observed
                    else "今回未確認（前回の情報を保持・解決未確認）"
                ),
                f"Issue同期の分析除外={member.excluded}",
                member.content,
            ]
        )
    body = new_issue_body(record.group_key, "\n\n".join(sections))
    payload = {"version": 1, **asdict(record)}
    encoded = base64.b64encode(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode()
    ).decode("ascii")
    body = body.replace(END, f"{_MARKER}{encoded} -->\n{END}")
    if existing is not None:
        body = merge_issue_body(existing, body, expected_keys=record.keys)
    if len(body) > MAX_REPAIR_BODY:
        raise IssueBodyError(
            "repair issue exceeds the supported body size; no truncation"
        )
    return body
