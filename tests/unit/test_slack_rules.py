from dataclasses import replace

from sbom_ops.domain.slack import (
    Delivery,
    Notification,
    SlackPolicy,
    safe_text,
    selection,
)


def test_selection_survives_restart_and_requires_retry_opt_in() -> None:
    policy = SlackPolicy(min_interval_seconds=10)
    message = Notification("key", "a", "P1", "body", "2026-10-29T00:00:00Z", "run")
    sent = Delivery(
        "id",
        policy.channel,
        "key",
        "a",
        "new",
        "run",
        "confirmed",
        100,
        100,
        1,
        0,
        "100.001",
        None,
        "hash",
    )
    assert selection(message, (), policy, 200) == "new"
    assert selection(message, (sent,), policy, 200) == "duplicate"
    assert (
        selection(replace(message, fingerprint="b"), (sent,), policy, 200) == "changed"
    )
    assert (
        selection(
            message, (replace(sent, state="unknown"),), policy, 200, retry_failed=True
        )
        == "blocked_unknown"
    )
    limited = replace(sent, state="rate_limited", retry_at=300)
    assert selection(message, (limited,), policy, 200) == "retry_requires_opt_in"
    assert (
        selection(message, (limited,), policy, 200, retry_failed=True) == "retry_after"
    )
    assert selection(message, (limited,), policy, 300, retry_failed=True) == "retry"
    assert (
        selection(message, (sent,), replace(policy, reminder_seconds=100), 200)
        == "reminder"
    )


def test_external_text_is_literal_and_secrets_are_not_rendered() -> None:
    text = safe_text(
        "<!channel> <@U123> @here https://hooks.slack.com/services/fake xoxb-synthetic"
    )
    assert "<" not in text and "@" not in text
    assert "https://" not in text and "xoxb-" not in text


def test_policy_rejects_credential_urls_and_unbounded_settings() -> None:
    import pytest

    for values in (
        {"dt_url": "http://example.test"},
        {"report_url": "https://user:password@example.test"},
        {"record_url": "https://example.test/?token=secret"},
        {"dt_url": "https://hooks.slack.com/services/synthetic"},
        {"dt_url": "https://example.test/<@U123>"},
        {"pacing_seconds": 0},
        {"max_attempts": 0},
        {"max_messages": True},
        {"enabled": "true"},
        {"grouping": "guess"},
        {"priorities": ("P9",)},
    ):
        with pytest.raises(ValueError):
            SlackPolicy(**values)
