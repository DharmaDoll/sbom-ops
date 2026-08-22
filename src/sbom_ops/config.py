from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sbom_ops.domain.routing import ProjectRoute


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
    enabled: bool = True


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
    kev_cache_file: str | None = None
    kev_cache_ttl_seconds: float = 18_000.0
    kev_cache_allow_stale: bool = False


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
    sync_log_file: str | None = None


@dataclass(frozen=True)
class WorkflowConfig:
    close_missing_findings: bool = False
    missing_confirmation_runs: int = 2


@dataclass(frozen=True)
class RoutingConfig:
    routes: tuple[ProjectRoute, ...] = ()


@dataclass(frozen=True)
class AppConfig:
    dependency_track: DependencyTrackConfig
    github: GitHubConfig
    intelligence: IntelligenceConfig
    priority: PriorityConfig
    runtime: RuntimeConfig
    workflow: WorkflowConfig = field(default_factory=WorkflowConfig)
    routing: RoutingConfig = field(default_factory=RoutingConfig)


_MISSING = object()
_SECTIONS = {
    "dependency_track",
    "github",
    "intelligence",
    "priority",
    "runtime",
    "workflow",
    "routing",
}
_SECTION_KEYS = {
    "dependency_track": {
        "base_url",
        "api_key",
        "page_size",
        "timeout_seconds",
        "max_retries",
        "retry_backoff_seconds",
        "kev_cache_file",
        "kev_cache_ttl_seconds",
        "kev_cache_allow_stale",
        "analysis_wait_timeout_seconds",
        "analysis_poll_interval_seconds",
    },
    "github": {
        "enabled",
        "token",
        "owner",
        "repo",
        "issue_label_prefix",
        "timeout_seconds",
        "max_retries",
        "retry_backoff_seconds",
    },
    "intelligence": {
        "kev_feed_url",
        "epss_api_url",
        "timeout_seconds",
        "max_retries",
        "retry_backoff_seconds",
    },
    "priority": {"p1_epss_threshold", "p2_cvss_threshold", "create_issues_for"},
    "runtime": {
        "dry_run",
        "project_uuids",
        "log_level",
        "wait_for_analysis",
        "sync_log_file",
    },
    "workflow": {"close_missing_findings", "missing_confirmation_runs"},
    "routing": {"projects"},
}


def _resolve_env_references(value: Any, path: str) -> Any:
    if isinstance(value, str) and value.startswith("env:"):
        name = value[4:].strip()
        if not name:
            raise ValueError(f"{path} contains an empty environment reference")
        resolved = os.getenv(name)
        if not resolved:
            raise ValueError(
                f"missing environment variable {name} referenced by {path}"
            )
        return resolved
    if isinstance(value, Mapping):
        return {
            key: _resolve_env_references(item, f"{path}.{key}")
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _resolve_env_references(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    return value


def _load_yaml_config(path_value: str | None) -> dict[str, Any]:
    if not path_value:
        return {}
    path = Path(path_value)
    try:
        with path.open(encoding="utf-8") as config_file:
            loaded = yaml.safe_load(config_file)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML config {path}: {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, Mapping):
        raise ValueError("YAML config root must be a mapping")

    unknown_sections = set(loaded) - _SECTIONS
    if unknown_sections:
        names = ", ".join(sorted(str(item) for item in unknown_sections))
        raise ValueError(f"unknown config section(s): {names}")
    for section, values in loaded.items():
        if not isinstance(values, Mapping):
            raise ValueError(f"config section {section} must be a mapping")
        unknown_keys = set(values) - _SECTION_KEYS[section]
        if unknown_keys:
            names = ", ".join(sorted(str(item) for item in unknown_keys))
            raise ValueError(f"unknown config key(s) in {section}: {names}")
    return _resolve_env_references(dict(loaded), "config")


def _config_value(
    config: Mapping[str, Any],
    section: str,
    key: str,
    env_name: str | None = None,
    default: Any = _MISSING,
) -> Any:
    if env_name:
        environment_value = os.getenv(env_name)
        if environment_value is not None:
            return environment_value
    section_values = config.get(section, {})
    if key in section_values:
        return section_values[key]
    if default is not _MISSING:
        return default
    raise ValueError(f"missing required setting: {section}.{key}")


def _as_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _as_int(value: Any, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _as_float(value: Any, name: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc


def _as_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ValueError(f"{name} must be a boolean")


def _as_string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        values = value.split(",")
    elif isinstance(value, list | tuple):
        values = value
    else:
        raise ValueError(f"{name} must be a list or comma-separated string")
    return tuple(_as_string(item, name) for item in values if str(item).strip())


def _parse_project_uuids(
    config: Mapping[str, Any], cli_project: str | None
) -> tuple[str, ...]:
    if cli_project:
        return (cli_project,)
    value = _config_value(
        config,
        "runtime",
        "project_uuids",
        "SBOM_OPS_PROJECT_UUIDS",
        default=(),
    )
    return _as_string_tuple(value, "runtime.project_uuids") if value else ()


def _parse_priorities(config: Mapping[str, Any]) -> tuple[str, ...]:
    value = _config_value(
        config,
        "priority",
        "create_issues_for",
        "SBOM_OPS_CREATE_ISSUES_FOR",
        default=("P0", "P1"),
    )
    priorities = tuple(
        item.upper() for item in _as_string_tuple(value, "priority.create_issues_for")
    )
    invalid = set(priorities) - {"P0", "P1", "P2", "P3"}
    if invalid:
        names = ", ".join(sorted(invalid))
        raise ValueError(
            f"priority.create_issues_for contains invalid priority: {names}"
        )
    return priorities


def _parse_routes(config: Mapping[str, Any]) -> tuple[ProjectRoute, ...]:
    raw_routes = _config_value(config, "routing", "projects", default=())
    if not raw_routes:
        return ()
    if not isinstance(raw_routes, list):
        raise ValueError("routing.projects must be a list")

    routes: list[ProjectRoute] = []
    allowed_keys = {"project_uuid", "owner", "repo", "issue_label_prefix"}
    for index, raw_route in enumerate(raw_routes):
        if not isinstance(raw_route, Mapping):
            raise ValueError(f"routing.projects[{index}] must be a mapping")
        unknown_keys = set(raw_route) - allowed_keys
        if unknown_keys:
            names = ", ".join(sorted(str(item) for item in unknown_keys))
            raise ValueError(
                f"unknown config key(s) in routing.projects[{index}]: {names}"
            )
        routes.append(
            ProjectRoute(
                project_uuid=_as_string(
                    raw_route.get("project_uuid"),
                    f"routing.projects[{index}].project_uuid",
                ),
                owner=_as_string(
                    raw_route.get("owner"), f"routing.projects[{index}].owner"
                ),
                repo=_as_string(
                    raw_route.get("repo"), f"routing.projects[{index}].repo"
                ),
                issue_label_prefix=(
                    _as_string(
                        raw_route["issue_label_prefix"],
                        f"routing.projects[{index}].issue_label_prefix",
                    )
                    if raw_route.get("issue_label_prefix") is not None
                    else None
                ),
            )
        )
    return tuple(routes)


def _validate(config: AppConfig) -> AppConfig:
    dt = config.dependency_track
    github = config.github
    intelligence = config.intelligence
    if dt.page_size < 1:
        raise ValueError("dependency_track.page_size must be greater than zero")
    if dt.timeout_seconds <= 0 or github.timeout_seconds <= 0:
        raise ValueError("API timeout values must be greater than zero")
    if intelligence.timeout_seconds <= 0:
        raise ValueError("intelligence.timeout_seconds must be greater than zero")
    if intelligence.kev_cache_ttl_seconds < 0:
        raise ValueError("intelligence.kev_cache_ttl_seconds must not be negative")
    if dt.max_retries < 0 or github.max_retries < 0 or intelligence.max_retries < 0:
        raise ValueError("API retry counts must not be negative")
    if (
        dt.retry_backoff_seconds < 0
        or github.retry_backoff_seconds < 0
        or intelligence.retry_backoff_seconds < 0
    ):
        raise ValueError("API retry backoff values must not be negative")
    if dt.analysis_wait_timeout_seconds <= 0:
        raise ValueError(
            "dependency_track.analysis_wait_timeout_seconds must be positive"
        )
    if dt.analysis_poll_interval_seconds < 0:
        raise ValueError(
            "dependency_track.analysis_poll_interval_seconds must not be negative"
        )
    if not 0 <= config.priority.p1_epss_threshold <= 1:
        raise ValueError("priority.p1_epss_threshold must be between 0 and 1")
    if config.priority.p2_cvss_threshold < 0:
        raise ValueError("priority.p2_cvss_threshold must not be negative")
    if config.workflow.missing_confirmation_runs < 2:
        raise ValueError("workflow.missing_confirmation_runs must be at least 2")
    return config


def load_config(args: Any) -> AppConfig:
    config_path = getattr(args, "config", None) or os.getenv("SBOM_OPS_CONFIG_FILE")
    config = _load_yaml_config(config_path)
    dependency_track = DependencyTrackConfig(
        base_url=_as_string(
            _config_value(
                config, "dependency_track", "base_url", "SBOM_OPS_DT_BASE_URL"
            ),
            "dependency_track.base_url",
        ),
        api_key=_as_string(
            _config_value(config, "dependency_track", "api_key", "SBOM_OPS_DT_API_KEY"),
            "dependency_track.api_key",
        ),
        page_size=_as_int(
            _config_value(
                config, "dependency_track", "page_size", "SBOM_OPS_DT_PAGE_SIZE", 100
            ),
            "dependency_track.page_size",
        ),
        timeout_seconds=_as_float(
            _config_value(
                config,
                "dependency_track",
                "timeout_seconds",
                "SBOM_OPS_DT_TIMEOUT_SECONDS",
                30,
            ),
            "dependency_track.timeout_seconds",
        ),
        max_retries=_as_int(
            _config_value(
                config,
                "dependency_track",
                "max_retries",
                "SBOM_OPS_DT_MAX_RETRIES",
                3,
            ),
            "dependency_track.max_retries",
        ),
        retry_backoff_seconds=_as_float(
            _config_value(
                config,
                "dependency_track",
                "retry_backoff_seconds",
                "SBOM_OPS_DT_RETRY_BACKOFF_SECONDS",
                1,
            ),
            "dependency_track.retry_backoff_seconds",
        ),
        analysis_wait_timeout_seconds=_as_float(
            _config_value(
                config,
                "dependency_track",
                "analysis_wait_timeout_seconds",
                "SBOM_OPS_DT_ANALYSIS_WAIT_TIMEOUT_SECONDS",
                120,
            ),
            "dependency_track.analysis_wait_timeout_seconds",
        ),
        analysis_poll_interval_seconds=_as_float(
            _config_value(
                config,
                "dependency_track",
                "analysis_poll_interval_seconds",
                "SBOM_OPS_DT_ANALYSIS_POLL_INTERVAL_SECONDS",
                5,
            ),
            "dependency_track.analysis_poll_interval_seconds",
        ),
    )
    github_enabled = _as_bool(
        _config_value(
            config,
            "github",
            "enabled",
            "SBOM_OPS_GITHUB_ENABLED",
            True,
        ),
        "github.enabled",
    ) and not bool(getattr(args, "no_github", False))
    github = GitHubConfig(
        token=_as_string(
            _config_value(
                config,
                "github",
                "token",
                "SBOM_OPS_GITHUB_TOKEN",
                default=os.getenv("GH_TOKEN")
                or ("disabled" if not github_enabled else _MISSING),
            ),
            "github.token",
        ),
        owner=_as_string(
            _config_value(
                config,
                "github",
                "owner",
                "SBOM_OPS_GITHUB_OWNER",
                "disabled" if not github_enabled else _MISSING,
            ),
            "github.owner",
        ),
        repo=_as_string(
            _config_value(
                config,
                "github",
                "repo",
                "SBOM_OPS_GITHUB_REPO",
                "disabled" if not github_enabled else _MISSING,
            ),
            "github.repo",
        ),
        issue_label_prefix=_as_string(
            _config_value(
                config,
                "github",
                "issue_label_prefix",
                "SBOM_OPS_ISSUE_LABEL_PREFIX",
                "sbom",
            ),
            "github.issue_label_prefix",
        ),
        timeout_seconds=_as_float(
            _config_value(
                config,
                "github",
                "timeout_seconds",
                "SBOM_OPS_GITHUB_TIMEOUT_SECONDS",
                30,
            ),
            "github.timeout_seconds",
        ),
        max_retries=_as_int(
            _config_value(
                config, "github", "max_retries", "SBOM_OPS_GITHUB_MAX_RETRIES", 3
            ),
            "github.max_retries",
        ),
        retry_backoff_seconds=_as_float(
            _config_value(
                config,
                "github",
                "retry_backoff_seconds",
                "SBOM_OPS_GITHUB_RETRY_BACKOFF_SECONDS",
                1,
            ),
            "github.retry_backoff_seconds",
        ),
        enabled=github_enabled,
    )
    kev_cache_file_value = _config_value(
        config,
        "intelligence",
        "kev_cache_file",
        "SBOM_OPS_KEV_CACHE_FILE",
        None,
    )
    intelligence = IntelligenceConfig(
        kev_feed_url=_as_string(
            _config_value(
                config,
                "intelligence",
                "kev_feed_url",
                "SBOM_OPS_KEV_FEED_URL",
                IntelligenceConfig.kev_feed_url,
            ),
            "intelligence.kev_feed_url",
        ),
        epss_api_url=_as_string(
            _config_value(
                config,
                "intelligence",
                "epss_api_url",
                "SBOM_OPS_EPSS_API_URL",
                IntelligenceConfig.epss_api_url,
            ),
            "intelligence.epss_api_url",
        ),
        timeout_seconds=_as_float(
            _config_value(
                config,
                "intelligence",
                "timeout_seconds",
                "SBOM_OPS_INTEL_TIMEOUT_SECONDS",
                30,
            ),
            "intelligence.timeout_seconds",
        ),
        max_retries=_as_int(
            _config_value(
                config, "intelligence", "max_retries", "SBOM_OPS_INTEL_MAX_RETRIES", 3
            ),
            "intelligence.max_retries",
        ),
        retry_backoff_seconds=_as_float(
            _config_value(
                config,
                "intelligence",
                "retry_backoff_seconds",
                "SBOM_OPS_INTEL_RETRY_BACKOFF_SECONDS",
                1,
            ),
            "intelligence.retry_backoff_seconds",
        ),
        kev_cache_file=(
            _as_string(
                kev_cache_file_value,
                "intelligence.kev_cache_file",
            )
            if kev_cache_file_value is not None
            else None
        ),
        kev_cache_ttl_seconds=_as_float(
            _config_value(
                config,
                "intelligence",
                "kev_cache_ttl_seconds",
                "SBOM_OPS_KEV_CACHE_TTL_SECONDS",
                18_000,
            ),
            "intelligence.kev_cache_ttl_seconds",
        ),
        kev_cache_allow_stale=_as_bool(
            _config_value(
                config,
                "intelligence",
                "kev_cache_allow_stale",
                "SBOM_OPS_KEV_CACHE_ALLOW_STALE",
                False,
            ),
            "intelligence.kev_cache_allow_stale",
        ),
    )
    priority = PriorityConfig(
        p1_epss_threshold=_as_float(
            _config_value(
                config,
                "priority",
                "p1_epss_threshold",
                "SBOM_OPS_PRIORITY_P1_EPSS_THRESHOLD",
                0.7,
            ),
            "priority.p1_epss_threshold",
        ),
        p2_cvss_threshold=_as_float(
            _config_value(
                config,
                "priority",
                "p2_cvss_threshold",
                "SBOM_OPS_PRIORITY_P2_CVSS_THRESHOLD",
                7.0,
            ),
            "priority.p2_cvss_threshold",
        ),
        create_issues_for=_parse_priorities(config),
    )
    runtime_dry_run = _as_bool(
        _config_value(config, "runtime", "dry_run", "SBOM_OPS_DRY_RUN", False),
        "runtime.dry_run",
    )
    runtime_wait_for_analysis = _as_bool(
        _config_value(
            config,
            "runtime",
            "wait_for_analysis",
            "SBOM_OPS_WAIT_FOR_ANALYSIS",
            False,
        ),
        "runtime.wait_for_analysis",
    )
    runtime_sync_log_file_value = _config_value(
        config,
        "runtime",
        "sync_log_file",
        "SBOM_OPS_SYNC_LOG_FILE",
        None,
    )
    runtime_sync_log_file = (
        _as_string(runtime_sync_log_file_value, "runtime.sync_log_file")
        if runtime_sync_log_file_value is not None
        else None
    )
    runtime = RuntimeConfig(
        dry_run=bool(getattr(args, "dry_run", False)) or runtime_dry_run,
        project_uuids=_parse_project_uuids(config, getattr(args, "project_uuid", None)),
        log_level=_as_string(
            getattr(args, "log_level", None)
            or _config_value(
                config, "runtime", "log_level", "SBOM_OPS_LOG_LEVEL", "INFO"
            ),
            "runtime.log_level",
        ),
        wait_for_analysis=bool(getattr(args, "wait_for_analysis", False))
        or runtime_wait_for_analysis,
        sync_log_file=(
            _as_string(
                getattr(args, "sync_log_file", None),
                "runtime.sync_log_file",
            )
            if getattr(args, "sync_log_file", None)
            else runtime_sync_log_file
        ),
    )
    workflow = WorkflowConfig(
        close_missing_findings=_as_bool(
            _config_value(
                config,
                "workflow",
                "close_missing_findings",
                "SBOM_OPS_CLOSE_MISSING_FINDINGS",
                False,
            ),
            "workflow.close_missing_findings",
        ),
        missing_confirmation_runs=_as_int(
            _config_value(
                config,
                "workflow",
                "missing_confirmation_runs",
                "SBOM_OPS_MISSING_CONFIRMATION_RUNS",
                2,
            ),
            "workflow.missing_confirmation_runs",
        ),
    )
    routing = RoutingConfig(routes=_parse_routes(config))
    return _validate(
        AppConfig(
            dependency_track=dependency_track,
            github=github,
            intelligence=intelligence,
            priority=priority,
            runtime=runtime,
            workflow=workflow,
            routing=routing,
        )
    )
