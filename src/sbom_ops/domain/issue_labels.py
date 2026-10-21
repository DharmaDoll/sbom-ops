"""Plan changes only to the configured, explicitly reserved label names."""

from __future__ import annotations

from dataclasses import dataclass

from sbom_ops.domain.models import Priority


class IssueLabelError(ValueError):
    """Invalid or unconfirmed labels must not be treated as an empty set."""


def label_names(payload: object) -> tuple[str, ...]:
    if not isinstance(payload, list):
        raise IssueLabelError("issue labels must be a list")
    names: list[str] = []
    seen: set[str] = set()
    for row in payload:
        name = row.get("name") if isinstance(row, dict) else row
        if (
            not isinstance(name, str)
            or not name.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or name.casefold() in seen
        ):
            raise IssueLabelError("invalid or duplicate issue label")
        seen.add(name.casefold())
        names.append(name)
    return tuple(names)


@dataclass(frozen=True)
class IssueLabelPlan:
    desired: tuple[str, ...]
    add: tuple[str, ...]
    remove: tuple[str, ...]


def plan_issue_labels(
    current: tuple[str, ...],
    prefix: str,
    priority: Priority,
) -> IssueLabelPlan:
    label_names(list(current))
    label_names([prefix])
    desired = (prefix, f"{prefix}-{priority.value}")
    wanted = {name.casefold() for name in desired}
    present = {name.casefold() for name in current}
    reserved = {f"{prefix}-{level.value}".casefold() for level in Priority}
    return IssueLabelPlan(
        desired=desired,
        add=tuple(name for name in desired if name.casefold() not in present),
        remove=tuple(name for name in current if name.casefold() in reserved - wanted),
    )
