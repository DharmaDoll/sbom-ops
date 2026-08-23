from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import pytest

from sbom_ops.config import load_config


def test_load_config_reads_required_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example.com")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_TOKEN", "gh-token")
    monkeypatch.setenv("SBOM_OPS_GITHUB_OWNER", "acme")
    monkeypatch.setenv("SBOM_OPS_GITHUB_REPO", "svc")

    config = load_config(Namespace(dry_run=False, project_uuid=None, log_level=None))

    assert config.dependency_track.base_url == "https://dtrack.example.com"
    assert config.github.owner == "acme"
    assert config.runtime.dry_run is False
    assert config.workflow.close_missing_findings is False
    assert config.workflow.missing_confirmation_runs == 2


def test_cli_project_overrides_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example.com")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_TOKEN", "gh-token")
    monkeypatch.setenv("SBOM_OPS_GITHUB_OWNER", "acme")
    monkeypatch.setenv("SBOM_OPS_GITHUB_REPO", "svc")
    monkeypatch.setenv("SBOM_OPS_PROJECT_UUIDS", "one,two")

    config = load_config(
        Namespace(dry_run=False, project_uuid="cli-project", log_level=None)
    )

    assert config.runtime.project_uuids == ("cli-project",)


def test_issue_priority_filter_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example.com")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_TOKEN", "gh-token")
    monkeypatch.setenv("SBOM_OPS_GITHUB_OWNER", "acme")
    monkeypatch.setenv("SBOM_OPS_GITHUB_REPO", "svc")
    monkeypatch.setenv("SBOM_OPS_CREATE_ISSUES_FOR", "P0, p2")

    config = load_config(Namespace(dry_run=False, project_uuid=None, log_level=None))

    assert config.priority.create_issues_for == ("P0", "P2")


def test_invalid_timeout_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example.com")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_TOKEN", "gh-token")
    monkeypatch.setenv("SBOM_OPS_GITHUB_OWNER", "acme")
    monkeypatch.setenv("SBOM_OPS_GITHUB_REPO", "svc")
    monkeypatch.setenv("SBOM_OPS_DT_TIMEOUT_SECONDS", "0")

    with pytest.raises(ValueError, match="timeout"):
        load_config(Namespace(dry_run=False, project_uuid=None, log_level=None))


def test_gh_token_is_fallback_for_github_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example.com")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key")
    monkeypatch.delenv("SBOM_OPS_GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", "gh-token-from-auth")
    monkeypatch.setenv("SBOM_OPS_GITHUB_OWNER", "acme")
    monkeypatch.setenv("SBOM_OPS_GITHUB_REPO", "svc")

    config = load_config(Namespace(dry_run=False, project_uuid=None, log_level=None))

    assert config.github.token == "gh-token-from-auth"


def test_github_issue_sync_can_be_disabled_by_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example.com")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_TOKEN", "gh-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_OWNER", "acme")
    monkeypatch.setenv("SBOM_OPS_GITHUB_REPO", "service-a")

    config = load_config(
        Namespace(
            dry_run=False,
            no_github=True,
            project_uuid=None,
            log_level=None,
        )
    )

    assert config.github.enabled is False


def test_sync_log_file_is_loaded_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example.com")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_TOKEN", "gh-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_OWNER", "acme")
    monkeypatch.setenv("SBOM_OPS_GITHUB_REPO", "service-a")
    monkeypatch.setenv("SBOM_OPS_SYNC_LOG_FILE", "var/sync.jsonl")

    config = load_config(Namespace(dry_run=False, project_uuid=None, log_level=None))

    assert config.runtime.sync_log_file == "var/sync.jsonl"


def test_safe_closure_policy_is_configurable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example.com")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_TOKEN", "gh-token")
    monkeypatch.setenv("SBOM_OPS_GITHUB_OWNER", "acme")
    monkeypatch.setenv("SBOM_OPS_GITHUB_REPO", "svc")
    monkeypatch.setenv("SBOM_OPS_CLOSE_MISSING_FINDINGS", "true")
    monkeypatch.setenv("SBOM_OPS_MISSING_CONFIRMATION_RUNS", "3")

    config = load_config(Namespace(dry_run=False, project_uuid=None, log_level=None))

    assert config.workflow.close_missing_findings is True
    assert config.workflow.missing_confirmation_runs == 3


def test_single_missing_confirmation_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example.com")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key")
    monkeypatch.setenv("SBOM_OPS_GITHUB_TOKEN", "gh-token")
    monkeypatch.setenv("SBOM_OPS_GITHUB_OWNER", "acme")
    monkeypatch.setenv("SBOM_OPS_GITHUB_REPO", "svc")
    monkeypatch.setenv("SBOM_OPS_MISSING_CONFIRMATION_RUNS", "1")

    with pytest.raises(ValueError, match="at least 2"):
        load_config(Namespace(dry_run=False, project_uuid=None, log_level=None))


def test_load_config_from_yaml_and_env_references(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "dt-key-from-env")
    monkeypatch.setenv("SBOM_OPS_GITHUB_TOKEN", "gh-key-from-env")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
dependency_track:
  base_url: https://yaml-dtrack.example.com
  api_key: env:SBOM_OPS_DT_API_KEY
  page_size: 25
github:
  token: env:SBOM_OPS_GITHUB_TOKEN
  owner: yaml-owner
  repo: yaml-repo
intelligence:
  kev_feed_url: https://kev.example.com/feed.json
priority:
  p1_epss_threshold: 0.8
  create_issues_for: [P0, P2]
runtime:
  project_uuids: [project-a, project-b]
  wait_for_analysis: true
workflow:
  close_missing_findings: true
  missing_confirmation_runs: 3
routing:
  projects:
    - project_uuid: project-a
      owner: team-a
      repo: service-a
      issue_label_prefix: security
""",
        encoding="utf-8",
    )

    config = load_config(
        Namespace(
            config=str(config_path),
            dry_run=False,
            project_uuid=None,
            log_level=None,
            wait_for_analysis=False,
        )
    )

    assert config.dependency_track.api_key == "dt-key-from-env"
    assert config.dependency_track.page_size == 25
    assert config.github.token == "gh-key-from-env"
    assert config.priority.create_issues_for == ("P0", "P2")
    assert config.runtime.project_uuids == ("project-a", "project-b")
    assert config.runtime.wait_for_analysis is True
    assert config.workflow.close_missing_findings is True
    assert config.routing.routes[0].repository == "team-a/service-a"
    assert config.routing.routes[0].issue_label_prefix == "security"


def test_environment_overrides_yaml_and_cli_overrides_projects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_TIMEOUT_SECONDS", "22")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
dependency_track:
  base_url: https://dtrack.example.com
  api_key: dt-key
  timeout_seconds: 11
github:
  token: gh-key
  owner: acme
  repo: service
runtime:
  project_uuids: [yaml-project]
""",
        encoding="utf-8",
    )

    config = load_config(
        Namespace(
            config=str(config_path),
            dry_run=False,
            project_uuid="cli-project",
            log_level=None,
            wait_for_analysis=False,
        )
    )

    assert config.dependency_track.timeout_seconds == 22
    assert config.runtime.project_uuids == ("cli-project",)


def test_unknown_yaml_key_is_rejected(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
dependency_track:
  base_url: https://dtrack.example.com
  api_key: dt-key
  typo_page_size: 10
github:
  token: gh-key
  owner: acme
  repo: service
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown config key"):
        load_config(
            Namespace(
                config=str(config_path),
                dry_run=False,
                project_uuid=None,
                log_level=None,
                wait_for_analysis=False,
            )
        )


def test_missing_yaml_env_reference_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("MISSING_DT_KEY", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
dependency_track:
  base_url: https://dtrack.example.com
  api_key: env:MISSING_DT_KEY
github:
  token: gh-key
  owner: acme
  repo: service
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="MISSING_DT_KEY"):
        load_config(
            Namespace(
                config=str(config_path),
                dry_run=False,
                project_uuid=None,
                log_level=None,
                wait_for_analysis=False,
            )
        )
