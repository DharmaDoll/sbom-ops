"""Sanitized summaries of Dependency-Track datasource task logs."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

_MAX_INPUT_BYTES = 20 * 1024 * 1024
_MAX_RETAINED_EVENTS = 500
_TIMESTAMP = re.compile(r"^(?P<value>\d{4}-\d{2}-\d{2}T\S+Z)\s")
_DATASOURCE_TASK_NAMES = (
    "OsvDownloadTask",
    "NistMirrorTask",
    "EpssMirrorTask",
    "GitHubAdvisoryMirrorTask",
)
_SCHEDULER_CONTROL_NAMES = (
    "PortfolioMetricsUpdateTask",
    "InternalComponentIdentificationTask",
)
_TASK_NAMES = _DATASOURCE_TASK_NAMES + _SCHEDULER_CONTROL_NAMES
_TASK = re.compile(
    r"\[(?P<name>OsvDownloadTask|NistMirrorTask|EpssMirrorTask|"
    r"GitHubAdvisoryMirrorTask|PortfolioMetricsUpdateTask|"
    r"InternalComponentIdentificationTask)\]"
)
_OSV_ECOSYSTEM = re.compile(r"\[osvEcosystem=(?P<name>[A-Za-z0-9._+-]{1,64})\]")


def _parse_timestamp(value: str, location: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{location} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{location} must include a timezone")
    return parsed.astimezone(UTC)


def _classify_event(line: str, task: str) -> str | None:
    lowered = line.lower()
    if " error " in lowered:
        return "failed"
    if task == "PortfolioMetricsUpdateTask":
        if "executing portfolio metrics update" in lowered:
            return "started"
        if "completed portfolio metrics update" in lowered:
            return "completed"
        return None
    if task == "InternalComponentIdentificationTask":
        if "starting internal component identification" in lowered:
            return "started"
        if "internal component identification completed" in lowered:
            return "completed"
        return None
    if task == "GitHubAdvisoryMirrorTask":
        if (
            "mirroring ghsas that were modified since" in lowered
            or "ghsas were not incrementally mirrored before" in lowered
        ):
            return "started"
        if (
            "successfully mirrored" in lowered
            or "no modified ghsas available; mirror is already up-to-date" in lowered
        ):
            return "completed"
        return None
    if "incremental update - initiating" in lowered:
        return "incremental-download-started"
    if "incremental update completed for" in lowered:
        return "incremental-completed"
    if "full mirror - initiating" in lowered:
        return "full-download-started"
    if "full mirror completed for" in lowered:
        return "ecosystem-completed"
    if "retrieval of" in lowered and "not necessary" in lowered:
        return "upstream-unchanged"
    if "no new or modified advisories since" in lowered:
        return "upstream-unchanged"
    if "mirroring complete" in lowered or "mirror completed" in lowered:
        return "completed"
    if "starting " in lowered or "initializing " in lowered:
        return "started"
    return None


def summarize_datasource_logs(
    raw: bytes,
    *,
    window_start: str,
    window_end: str,
) -> dict[str, object]:
    """Return bounded task metadata without retaining raw log messages."""
    if len(raw) > _MAX_INPUT_BYTES:
        raise ValueError("datasource log input exceeds 20 MiB")
    start = _parse_timestamp(window_start, "window_start")
    end = _parse_timestamp(window_end, "window_end")
    if start >= end:
        raise ValueError("window_start must be before window_end")
    text = raw.decode("utf-8", errors="replace")

    parseable_timestamps: list[datetime] = []
    out_of_window_log_line_count = 0
    task_counts = {name: Counter() for name in _TASK_NAMES}
    events: list[dict[str, str]] = []
    truncated_events = 0
    for line in text.splitlines():
        timestamp_match = _TIMESTAMP.match(line)
        if timestamp_match is None:
            continue
        timestamp = _parse_timestamp(timestamp_match.group("value"), "log timestamp")
        if timestamp < start or timestamp > end:
            out_of_window_log_line_count += 1
            continue
        parseable_timestamps.append(timestamp)
        task_match = _TASK.search(line)
        if task_match is None:
            continue
        task = task_match.group("name")
        event = _classify_event(line, task)
        if event is None:
            continue
        task_counts[task][event] += 1
        retained = {
            "at": timestamp.isoformat(),
            "task": task,
            "event": event,
        }
        ecosystem_match = _OSV_ECOSYSTEM.search(line)
        if ecosystem_match is not None:
            retained["ecosystem"] = ecosystem_match.group("name")
        if len(events) < _MAX_RETAINED_EVENTS:
            events.append(retained)
        else:
            truncated_events += 1

    def task_summary(task_names: tuple[str, ...]) -> dict[str, object]:
        result: dict[str, object] = {}
        for task in task_names:
            counts = task_counts[task]
            if counts["failed"]:
                observation = "failed"
            elif counts["completed"]:
                observation = "completed"
            elif (
                counts["started"]
                or counts["full-download-started"]
                or counts["incremental-download-started"]
                or counts["ecosystem-completed"]
                or counts["incremental-completed"]
            ):
                observation = "incomplete"
            else:
                observation = "not-observed"
            result[task] = {
                "observation": observation,
                "event_counts": dict(sorted(counts.items())),
            }
        return result

    tasks = task_summary(_DATASOURCE_TASK_NAMES)
    scheduler_controls = task_summary(_SCHEDULER_CONTROL_NAMES)

    return {
        "schema_version": 2,
        "run_id": str(uuid4()),
        "target": "dependency-track-datasource-log-window",
        "observed_at": datetime.now(UTC).isoformat(),
        "input": {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "byte_count": len(raw),
            "raw_persisted": False,
        },
        "window": {
            "requested_start": start.isoformat(),
            "requested_end": end.isoformat(),
            "first_log_timestamp": (
                min(parseable_timestamps).isoformat() if parseable_timestamps else None
            ),
            "last_log_timestamp": (
                max(parseable_timestamps).isoformat() if parseable_timestamps else None
            ),
            "parseable_log_line_count": len(parseable_timestamps),
            "out_of_window_log_line_count": out_of_window_log_line_count,
        },
        "tasks": tasks,
        "scheduler_controls": scheduler_controls,
        "events": events,
        "retained_event_limit": _MAX_RETAINED_EVENTS,
        "truncated_event_count": truncated_events,
        "interpretation_boundary": (
            "not-observed means no matching task event appeared in the supplied "
            "log window. It does not prove that upstream data was current, that a "
            "task never ran, or that retained vulnerability data was complete. "
            "Control-task activity proves only that those independent timers ran; "
            "it does not prove health or elapsed cadence for each mirror timer."
        ),
    }


def write_datasource_log_summary(
    raw: bytes,
    *,
    window_start: str,
    window_end: str,
    output_dir: str | Path,
) -> Path:
    result = summarize_datasource_logs(
        raw, window_start=window_start, window_end=window_end
    )
    run_dir = Path(output_dir) / str(result["run_id"])
    run_dir.mkdir(parents=True, exist_ok=False)
    output = run_dir / "datasource-log-window.json"
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output
