from __future__ import annotations

import pytest

from sbom_ops.domain.routing import ProjectRoute, ProjectRouter, ProjectRoutingError


def test_project_router_resolves_project_route() -> None:
    router = ProjectRouter(
        (
            ProjectRoute("project-a", "team-a", "service-a"),
            ProjectRoute("project-b", "team-b", "service-b", "vuln"),
        )
    )

    assert router.is_configured is True
    assert router.resolve("project-a").repository == "team-a/service-a"
    assert router.resolve("project-b").issue_label_prefix == "vuln"


def test_project_router_rejects_unconfigured_project() -> None:
    router = ProjectRouter((ProjectRoute("project-a", "team-a", "service-a"),))

    with pytest.raises(ProjectRoutingError, match="project-b"):
        router.resolve("project-b")


def test_project_router_rejects_duplicate_project_routes() -> None:
    with pytest.raises(ProjectRoutingError, match="duplicate"):
        ProjectRouter(
            (
                ProjectRoute("project-a", "team-a", "service-a"),
                ProjectRoute("project-a", "team-b", "service-b"),
            )
        )
