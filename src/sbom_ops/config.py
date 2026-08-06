from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DependencyTrackConfig:
    base_url: str
    api_key: str
    page_size: int = 100
    timeout_seconds: float = 30.0
    max_retries: int = 3
    retry_backoff_seconds: float = 1.0
    analysis_wait_timeout_seconds: float = 120.0
    analysis_poll_interval_seconds: float = 5.0


@dataclass(frozen=True)
class GitHubConfig:
    token: str
    owner: str
    repo: str
    issue_label_prefix: str = "sbom"
    timeout_seconds: float = 30.0
    max_retries: int = 3
    retry_backoff_seconds: float = 1.0


@dataclass(frozen=True)
class IntelligenceConfig:
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    timeout_seconds: float = 30.0
    max_retries: int = 3
    retry_backoff_seconds: float = 1.0


@dataclass(frozen=True)
class PriorityConfig:
    p1_epss_threshold: float = 0.7
    p2_cvss_threshold: float = 7.0
    create_issues_for: tuple[str, ...] = ("P0", "P1")


@dataclass(frozen=True)
class RuntimeConfig:
    dry_run: bool = False
    project_uuids: tuple[str, ...] = field(default_factory=tuple)
    log_level: str = "INFO"
    wait_for_analysis: bool = False


@dataclass(frozen=True)
class AppConfig:
    dependency_track: DependencyTrackConfig
    github: GitHubConfig
    intelligence: IntelligenceConfig
    priority: PriorityConfig
    runtime: RuntimeConfig


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ValueError(f"missing required environment variable: {name}")
    return value


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_project_uuids(cli_project: str | None) -> tuple[str, ...]:
    if cli_project:
        return (cli_project,)
    raw = os.getenv("SBOM_OPS_PROJECT_UUIDS", "")
    if not raw.strip():
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _parse_priorities() -> tuple[str, ...]:
    raw = os.getenv("SBOM_OPS_CREATE_ISSUES_FOR", "P0,P1")
    return tuple(item.strip().upper() for item in raw.split(",") if item.strip())


def _validate(config: AppConfig) -> AppConfig:
    dt = config.dependency_track
    github = config.github
    intelligence = config.intelligence
    if dt.page_size < 1:
        raise ValueError("SBOM_OPS_DT_PAGE_SIZE must be greater than zero")
    if dt.timeout_seconds <= 0 or github.timeout_seconds <= 0:
        raise ValueError("API timeout values must be greater than zero")
    if (
        dt.max_retries < 0
        or github.max_retries < 0
        or intelligence.max_retries < 0
    ):
        raise ValueError("API retry counts must not be negative")
    if dt.analysis_wait_timeout_seconds <= 0:
        raise ValueError("SBOM_OPS_DT_ANALYSIS_WAIT_TIMEOUT_SECONDS must be positive")
    if dt.analysis_poll_interval_seconds < 0:
        raise ValueError(
            "SBOM_OPS_DT_ANALYSIS_POLL_INTERVAL_SECONDS must not be negative"
        )
    if not 0 <= config.priority.p1_epss_threshold <= 1:
        raise ValueError("SBOM_OPS_PRIORITY_P1_EPSS_THRESHOLD must be between 0 and 1")
    if config.priority.p2_cvss_threshold < 0:
        raise ValueError("SBOM_OPS_PRIORITY_P2_CVSS_THRESHOLD must not be negative")
    return config


def load_config(args: Any) -> AppConfig:
    dependency_track = DependencyTrackConfig(
        base_url=_require_env("SBOM_OPS_DT_BASE_URL"),
        api_key=_require_env("SBOM_OPS_DT_API_KEY"),
        page_size=int(os.getenv("SBOM_OPS_DT_PAGE_SIZE", "100")),
        timeout_seconds=float(os.getenv("SBOM_OPS_DT_TIMEOUT_SECONDS", "30")),
        max_retries=int(os.getenv("SBOM_OPS_DT_MAX_RETRIES", "3")),
        retry_backoff_seconds=float(
            os.getenv("SBOM_OPS_DT_RETRY_BACKOFF_SECONDS", "1")
        ),
        analysis_wait_timeout_seconds=float(
            os.getenv("SBOM_OPS_DT_ANALYSIS_WAIT_TIMEOUT_SECONDS", "120")
        ),
        analysis_poll_interval_seconds=float(
            os.getenv("SBOM_OPS_DT_ANALYSIS_POLL_INTERVAL_SECONDS", "5")
        ),
    )
    github = GitHubConfig(
        token=_require_env("SBOM_OPS_GITHUB_TOKEN"),
        owner=_require_env("SBOM_OPS_GITHUB_OWNER"),
        repo=_require_env("SBOM_OPS_GITHUB_REPO"),
        issue_label_prefix=os.getenv("SBOM_OPS_ISSUE_LABEL_PREFIX", "sbom"),
        timeout_seconds=float(os.getenv("SBOM_OPS_GITHUB_TIMEOUT_SECONDS", "30")),
        max_retries=int(os.getenv("SBOM_OPS_GITHUB_MAX_RETRIES", "3")),
        retry_backoff_seconds=float(
            os.getenv("SBOM_OPS_GITHUB_RETRY_BACKOFF_SECONDS", "1")
        ),
    )
    intelligence = IntelligenceConfig(
        kev_feed_url=os.getenv(
            "SBOM_OPS_KEV_FEED_URL",
            IntelligenceConfig.kev_feed_url,
        ),
        epss_api_url=os.getenv(
            "SBOM_OPS_EPSS_API_URL",
            IntelligenceConfig.epss_api_url,
        ),
        timeout_seconds=float(os.getenv("SBOM_OPS_INTEL_TIMEOUT_SECONDS", "30")),
        max_retries=int(os.getenv("SBOM_OPS_INTEL_MAX_RETRIES", "3")),
        retry_backoff_seconds=float(
            os.getenv("SBOM_OPS_INTEL_RETRY_BACKOFF_SECONDS", "1")
        ),
    )
    priority = PriorityConfig(
        p1_epss_threshold=float(
            os.getenv("SBOM_OPS_PRIORITY_P1_EPSS_THRESHOLD", "0.7")
        ),
        p2_cvss_threshold=float(
            os.getenv("SBOM_OPS_PRIORITY_P2_CVSS_THRESHOLD", "7.0")
        ),
        create_issues_for=_parse_priorities(),
    )
    runtime = RuntimeConfig(
        dry_run=bool(getattr(args, "dry_run", False))
        or _parse_bool(os.getenv("SBOM_OPS_DRY_RUN"), False),
        project_uuids=_parse_project_uuids(getattr(args, "project_uuid", None)),
        log_level=getattr(args, "log_level", None)
        or os.getenv("SBOM_OPS_LOG_LEVEL", "INFO"),
        wait_for_analysis=bool(getattr(args, "wait_for_analysis", False))
        or _parse_bool(os.getenv("SBOM_OPS_WAIT_FOR_ANALYSIS"), False),
    )
    return _validate(AppConfig(
        dependency_track=dependency_track,
        github=github,
        intelligence=intelligence,
        priority=priority,
        runtime=runtime,
    ))
