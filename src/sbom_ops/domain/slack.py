"""Action-neutral notification models and selection rules."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=True).encode()
    ).hexdigest()


def safe_text(value: object, limit: int = 240) -> str:
    text = str(value if value is not None else "不明")
    # Literal text only: never Slack user/channel syntax or external URLs.
    text = re.sub(r"https?://\S+", "[参照省略]", text)
    text = re.sub(r"xox[baprs]-\S+", "[secret]", text)
    text = "".join(c if c.isprintable() else " " for c in text)
    return (
        text[:limit]
        .replace("&", "＆")
        .replace("<", "＜")
        .replace(">", "＞")
        .replace("@", "＠")
    )


def reference(value: str) -> str:
    if not isinstance(value, str) or len(value) > 500:
        raise ValueError("invalid notification reference")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(c.isspace() or c in "<>@\\" for c in value)
        or "hooks.slack.com" in parsed.netloc
        or re.search(r"xox[baprs]-", value)
        or any(not c.isprintable() for c in value)
    ):
        raise ValueError(
            "notification references require HTTPS without credentials/query/fragment"
        )
    return value


@dataclass(frozen=True)
class SlackPolicy:
    channel: str = "C00000000"
    enabled: bool = False
    token_env: str = "SBOM_OPS_SLACK_BOT_TOKEN"
    priorities: tuple[str, ...] = ("P0", "P1")
    grouping: str = "repair"
    change_fields: tuple[str, ...] = ("priority", "owners", "context", "rationale")
    min_interval_seconds: int = 3600
    reminder_seconds: int = 0
    pacing_seconds: int = 1
    max_messages: int = 20
    max_attempts: int = 3
    max_input_age_seconds: int = 86400
    dt_url: str = "https://dt.example.invalid"
    report_url: str = "https://reports.example.invalid"
    record_url: str = "https://work.example.invalid"

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or not re.fullmatch(
            r"[CG][A-Z0-9]{8,30}", self.channel
        ):
            raise ValueError("invalid Slack destination/enabled")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", self.token_env):
            raise ValueError("invalid token environment name")
        if (
            self.grouping not in ("repair", "finding")
            or not self.priorities
            or set(self.priorities) - {"P0", "P1", "P2", "P3"}
            or set(self.change_fields) - {"priority", "owners", "context", "rationale"}
        ):
            raise ValueError("invalid notification selection policy")
        for name in (
            "min_interval_seconds",
            "reminder_seconds",
            "pacing_seconds",
            "max_messages",
            "max_attempts",
            "max_input_age_seconds",
        ):
            value = getattr(self, name)
            lower = 0 if name in ("min_interval_seconds", "reminder_seconds") else 1
            upper = 100 if name in ("max_messages", "max_attempts") else 31_536_000
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("invalid notification limit")
        for value in (self.dt_url, self.report_url, self.record_url):
            reference(value)


@dataclass(frozen=True)
class Notification:
    key: str
    fingerprint: str
    priority: str
    text: str
    observed_at: str
    source_run_id: str
    kind: str = "candidate"


@dataclass(frozen=True)
class Delivery:
    intent_id: str
    channel: str
    notification_key: str
    fingerprint: str
    event: str
    run_id: str
    state: str
    created_at: float
    updated_at: float
    attempts: int
    retry_at: float
    ts: str | None
    thread_ts: str | None
    body_hash: str
    error: str | None = None


def selection(
    notification: Notification,
    history: tuple[Delivery, ...],
    policy: SlackPolicy,
    now: float,
    *,
    retry_failed: bool = False,
) -> str:
    if notification.priority not in policy.priorities:
        return "excluded_priority"
    if any(r.state in ("pending", "unknown") for r in history):
        return "blocked_unknown"
    if history:
        last = history[-1]
        if last.state != "confirmed":
            if not retry_failed:
                return "retry_requires_opt_in"
            if last.attempts >= policy.max_attempts:
                return "attempt_limit"
            if now < last.retry_at:
                return "retry_after"
            if last.fingerprint != notification.fingerprint:
                return "blocked_changed_failed_input"
            return "retry"
        if now < last.updated_at + policy.min_interval_seconds:
            return "interval"
        if last.fingerprint != notification.fingerprint:
            return "changed"
        if policy.reminder_seconds and now >= last.updated_at + policy.reminder_seconds:
            return "reminder"
        return "duplicate"
    return "new"


def aware_time(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset() is None:
        raise ValueError("notification observation needs timezone")
    return result
