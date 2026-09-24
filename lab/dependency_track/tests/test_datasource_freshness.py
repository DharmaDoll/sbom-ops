from __future__ import annotations

import json

import pytest
from dt_lab.datasource_freshness import (
    summarize_datasource_logs,
    write_datasource_log_summary,
)

START = "2026-09-12T00:00:00Z"
END = "2026-09-13T00:00:00Z"


def test_summary_retains_only_bounded_task_metadata() -> None:
    raw = b"\n".join(
        (
            b"2026-09-12T01:00:00.000000000Z INFO unrelated projectUuid=secret",
            b"2026-09-12T01:01:00.000000000Z INFO [OsvDownloadTask] "
            b"Starting Google OSV mirroring for: [Go]",
            b"2026-09-12T01:01:01.000000000Z INFO [OsvDownloadTask] "
            b"Full mirror - Initiating download [osvEcosystem=Go]",
            b"2026-09-12T01:02:00.000000000Z INFO [OsvDownloadTask] "
            b"Full mirror completed for Go [osvEcosystem=Go]",
            b"2026-09-12T01:03:00.000000000Z INFO [OsvDownloadTask] "
            b"Google OSV mirroring complete",
            b"2026-09-12T02:00:00.000000000Z INFO [EpssMirrorTask] "
            b"Starting EPSS mirroring task",
            b"2026-09-12T02:00:01.000000000Z INFO [EpssMirrorTask] "
            b"Retrieval of scores not necessary.",
            b"2026-09-12T02:00:02.000000000Z INFO [EpssMirrorTask] "
            b"EPSS mirroring complete",
        )
    )

    result = summarize_datasource_logs(raw, window_start=START, window_end=END)

    assert result["input"]["raw_persisted"] is False
    assert result["window"]["parseable_log_line_count"] == 8
    assert result["tasks"]["OsvDownloadTask"] == {
        "observation": "completed",
        "event_counts": {
            "completed": 1,
            "ecosystem-completed": 1,
            "full-download-started": 1,
            "started": 1,
        },
    }
    assert result["tasks"]["EpssMirrorTask"]["observation"] == "completed"
    assert result["tasks"]["NistMirrorTask"]["observation"] == "not-observed"
    serialized = json.dumps(result)
    assert "projectUuid" not in serialized
    assert "secret" not in serialized
    assert result["events"][1]["ecosystem"] == "Go"


def test_summary_does_not_retain_unbounded_ecosystem_text() -> None:
    raw = (
        b"2026-09-12T01:01:01Z INFO [OsvDownloadTask] "
        b"Full mirror - Initiating download [osvEcosystem=secret=value]"
    )

    result = summarize_datasource_logs(raw, window_start=START, window_end=END)

    assert result["events"] == [
        {
            "at": "2026-09-12T01:01:01+00:00",
            "task": "OsvDownloadTask",
            "event": "full-download-started",
        }
    ]
    assert "secret=value" not in json.dumps(result)


def test_failed_and_started_only_tasks_remain_distinct() -> None:
    raw = b"\n".join(
        (
            b"2026-09-12T03:00:00Z INFO [NistMirrorTask] Starting NIST mirroring task",
            b"2026-09-12T03:01:00Z ERROR [NistMirrorTask] upstream failed details",
            b"2026-09-12T04:00:00Z INFO [GitHubAdvisoryMirrorTask] "
            b"GHSAs were not incrementally mirrored before; Mirroring all GHSAs",
        )
    )

    result = summarize_datasource_logs(raw, window_start=START, window_end=END)

    assert result["tasks"]["NistMirrorTask"]["observation"] == "failed"
    assert result["tasks"]["GitHubAdvisoryMirrorTask"]["observation"] == "incomplete"


def test_ecosystem_completion_without_task_completion_is_incomplete() -> None:
    raw = (
        b"2026-09-12T03:00:00Z INFO [OsvDownloadTask] "
        b"Full mirror completed for Go [osvEcosystem=Go]\n"
    )

    result = summarize_datasource_logs(raw, window_start=START, window_end=END)

    assert result["tasks"]["OsvDownloadTask"]["observation"] == "incomplete"


def test_incremental_osv_events_are_classified_without_raw_urls() -> None:
    raw = b"\n".join(
        (
            b"2026-09-12T03:00:00Z INFO [OsvDownloadTask] "
            b"Incremental update - Initiating download of https://secret.example "
            b"[osvEcosystem=Go]",
            b"2026-09-12T03:01:00Z INFO [OsvDownloadTask] "
            b"No new or modified advisories since the last update, skipping "
            b"[osvEcosystem=Go]",
            b"2026-09-12T03:02:00Z INFO [OsvDownloadTask] "
            b"Incremental update completed for Go [osvEcosystem=Go]",
            b"2026-09-12T03:03:00Z INFO [OsvDownloadTask] "
            b"Google OSV mirroring complete",
        )
    )

    result = summarize_datasource_logs(raw, window_start=START, window_end=END)

    assert result["tasks"]["OsvDownloadTask"] == {
        "observation": "completed",
        "event_counts": {
            "completed": 1,
            "incremental-completed": 1,
            "incremental-download-started": 1,
            "upstream-unchanged": 1,
        },
    }
    assert "secret.example" not in json.dumps(result)


def test_scheduler_controls_are_separate_from_datasource_tasks() -> None:
    raw = b"\n".join(
        (
            b"2026-09-12T05:00:00Z INFO [PortfolioMetricsUpdateTask] "
            b"Executing portfolio metrics update",
            b"2026-09-12T05:00:10Z INFO [PortfolioMetricsUpdateTask] "
            b"Completed portfolio metrics update in 00:00:010",
            b"2026-09-12T06:00:00Z INFO [InternalComponentIdentificationTask] "
            b"Starting internal component identification",
            b"2026-09-12T06:00:01Z INFO [InternalComponentIdentificationTask] "
            b"Internal component identification completed in 00:00:001",
        )
    )

    result = summarize_datasource_logs(raw, window_start=START, window_end=END)

    assert all(
        task["observation"] == "not-observed" for task in result["tasks"].values()
    )
    assert result["scheduler_controls"] == {
        "PortfolioMetricsUpdateTask": {
            "observation": "completed",
            "event_counts": {"completed": 1, "started": 1},
        },
        "InternalComponentIdentificationTask": {
            "observation": "completed",
            "event_counts": {"completed": 1, "started": 1},
        },
    }


@pytest.mark.parametrize(
    ("start_message", "completion_message"),
    (
        (
            "GHSAs were not incrementally mirrored before; Mirroring all GHSAs",
            "Successfully mirrored 42 GHSAs in PT1S",
        ),
        (
            "Mirroring GHSAs that were modified since 2026-09-01T00:00Z",
            "No modified GHSAs available; Mirror is already up-to-date",
        ),
    ),
)
def test_ghsa_4143_log_contract_is_classified(
    start_message: str, completion_message: str
) -> None:
    raw = (
        f"2026-09-12T05:00:00Z INFO [GitHubAdvisoryMirrorTask] "
        f"{start_message}\n"
        f"2026-09-12T05:01:00Z INFO [GitHubAdvisoryMirrorTask] "
        f"{completion_message}"
    ).encode()

    result = summarize_datasource_logs(raw, window_start=START, window_end=END)

    assert result["tasks"]["GitHubAdvisoryMirrorTask"] == {
        "observation": "completed",
        "event_counts": {"completed": 1, "started": 1},
    }


def test_summary_excludes_events_outside_declared_window() -> None:
    raw = b"2026-09-11T23:59:59Z INFO [EpssMirrorTask] EPSS mirroring complete\n"

    result = summarize_datasource_logs(raw, window_start=START, window_end=END)

    assert result["window"]["parseable_log_line_count"] == 0
    assert result["window"]["out_of_window_log_line_count"] == 1
    assert result["tasks"]["EpssMirrorTask"]["observation"] == "not-observed"


def test_summary_caps_retained_events_without_losing_counts() -> None:
    raw = b"\n".join(
        b"2026-09-12T03:00:00Z INFO [NistMirrorTask] NIST mirroring complete"
        for _ in range(501)
    )

    result = summarize_datasource_logs(raw, window_start=START, window_end=END)

    assert len(result["events"]) == 500
    assert result["truncated_event_count"] == 1
    assert result["tasks"]["NistMirrorTask"]["event_counts"] == {"completed": 501}


def test_writer_creates_run_scoped_sanitized_result(tmp_path) -> None:
    output = write_datasource_log_summary(
        b"2026-09-12T05:00:00Z INFO unrelated\n",
        window_start=START,
        window_end=END,
        output_dir=tmp_path,
    )

    assert output.name == "datasource-log-window.json"
    assert (
        json.loads(output.read_text())["tasks"]["OsvDownloadTask"]["observation"]
        == "not-observed"
    )


@pytest.mark.parametrize(
    ("start", "end"),
    ((END, START), ("not-a-time", END), (START, "2026-09-12T00:00:00")),
)
def test_summary_rejects_invalid_windows(start, end) -> None:
    with pytest.raises(ValueError):
        summarize_datasource_logs(b"", window_start=start, window_end=end)
