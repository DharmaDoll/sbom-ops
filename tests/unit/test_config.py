from __future__ import annotations

from argparse import Namespace

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
