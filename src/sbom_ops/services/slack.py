"""Notification orchestration; independent of inventory and Issue mutation."""

from collections.abc import Callable
from dataclasses import asdict
from time import sleep, time
from typing import Protocol
from uuid import uuid4

from sbom_ops.clients.slack import SlackOutcome
from sbom_ops.domain.slack import Delivery, Notification, SlackPolicy, digest, selection
from sbom_ops.storage.slack import SlackJournal


class Sender(Protocol):
    def post(
        self, channel: str, text: str, *, thread_ts: str | None = None
    ) -> SlackOutcome: ...


def deliver(
    notifications: tuple[Notification, ...],
    policy: SlackPolicy,
    *,
    journal: SlackJournal | None = None,
    sender: Sender | None = None,
    execute: bool = False,
    dry_run: bool = False,
    retry_failed: bool = False,
    clock: Callable[[], float] = time,
    pause: Callable[[float], None] = sleep,
    run_id: str | None = None,
) -> dict[str, object]:
    run_id = run_id or str(uuid4())
    writing = execute and policy.enabled and not dry_run
    if writing and (journal is None or sender is None):
        raise ValueError("enabled execution needs initialized journal and sender")
    records = journal.records() if journal else ()
    destination = tuple(r for r in records if r.channel == policy.channel)
    blocked = any(r.state in ("pending", "unknown") for r in destination)
    cooldown = max((r.retry_at for r in destination), default=0)
    latest = {r.notification_key: r for r in destination}
    failed = {
        key: row
        for key, row in latest.items()
        if row.state in ("rejected", "rate_limited")
    }
    by_key = {n.key: n for n in notifications}
    recovery_block = None
    if failed:
        if not retry_failed:
            recovery_block = "retry_requires_opt_in"
        elif any(key not in by_key for key in failed):
            recovery_block = "blocked_failed_input"
        else:
            for key, row in failed.items():
                decision = selection(
                    by_key[key], (row,), policy, clock(), retry_failed=True
                )
                if decision != "retry":
                    recovery_block = decision
                    break
        # Confirm recovery before allowing any new work on this destination.
        notifications = tuple(sorted(notifications, key=lambda n: n.key not in failed))
    output = []
    attempted = 0
    stopped = False
    for notification in notifications:
        history = tuple(
            r for r in destination if r.notification_key == notification.key
        )
        reason = selection(
            notification, history, policy, clock(), retry_failed=retry_failed
        )
        if blocked:
            reason = "blocked_unknown"
        elif recovery_block:
            reason = recovery_block
        elif clock() < cooldown:
            reason = "retry_after"
        eligible = reason in ("new", "changed", "reminder", "retry")
        confirmed = [r for r in history if r.state == "confirmed"]
        thread_ts = (confirmed[0].thread_ts or confirmed[0].ts) if confirmed else None
        text = f"通知種別: {reason}\n{notification.text}\n送信相関ID: {run_id}"
        row = {
            "key": notification.key,
            "reason": reason,
            "channel": policy.channel,
            "thread_ts": thread_ts,
            "text": text,
            "state": "preview",
        }
        output.append(row)
        if not writing or not eligible:
            continue
        if stopped or attempted >= policy.max_messages:
            row["state"] = "not_attempted"
            row["reason"] = "stopped" if stopped else "run_limit"
            continue
        # Pacing also survives separate invocations sharing the journal.
        last_attempt = max((r.created_at for r in destination), default=0)
        delay = last_attempt + policy.pacing_seconds - clock()
        if delay > 60:
            row["state"] = "not_attempted"
            row["reason"] = "pacing_wait"
            continue
        if delay > 0:
            pause(delay)
        attempts = history[-1].attempts + 1 if reason == "retry" else 1
        intent = Delivery(
            str(uuid4()),
            policy.channel,
            notification.key,
            notification.fingerprint,
            reason,
            run_id,
            "pending",
            clock(),
            clock(),
            attempts,
            0,
            None,
            thread_ts,
            digest(text),
        )
        journal.reserve(intent)  # Durable before POST. Any error stops the whole run.
        attempted += 1
        outcome = sender.post(policy.channel, text, thread_ts=thread_ts)
        journal.finish(
            intent.intent_id,
            state=outcome.state,
            now=clock(),
            ts=outcome.ts,
            error=outcome.error,
            retry_at=clock() + outcome.retry_seconds,
        )
        row.update(
            {
                "state": outcome.state,
                "intent_id": intent.intent_id,
                "ts": outcome.ts,
                "error": outcome.error,
            }
        )
        destination = tuple(r for r in journal.records() if r.channel == policy.channel)
        stopped = outcome.state != "confirmed"
    return {
        "status": "stopped" if stopped or blocked or recovery_block else "succeeded",
        "mode": "execute" if writing else "preview",
        "run_id": run_id,
        "attempted": attempted,
        "notifications": output,
    }


def journal_report(journal: SlackJournal) -> dict[str, object]:
    return {
        "deliveries": [asdict(r) for r in journal.records()],
        "audit": journal.audit(),
    }
