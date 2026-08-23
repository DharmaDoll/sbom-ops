from __future__ import annotations

from dataclasses import dataclass


class ProjectRoutingError(ValueError):
    """Raised when a Dependency-Track project has no safe workflow route."""


@dataclass(frozen=True)
class ProjectRoute:
    project_uuid: str
    owner: str
    repo: str
    issue_label_prefix: str | None = None

    @property
    def repository(self) -> str:
        return f"{self.owner}/{self.repo}"


class ProjectRouter:
    def __init__(self, routes: tuple[ProjectRoute, ...] = ()) -> None:
        by_project: dict[str, ProjectRoute] = {}
        for route in routes:
            if route.project_uuid in by_project:
                raise ProjectRoutingError(
                    f"duplicate route for Dependency-Track project {route.project_uuid}"
                )
            by_project[route.project_uuid] = route
        self._routes = by_project

    @property
    def is_configured(self) -> bool:
        return bool(self._routes)

    def resolve(self, project_uuid: str) -> ProjectRoute | None:
        if not self._routes:
            return None
        route = self._routes.get(project_uuid)
        if route is None:
            raise ProjectRoutingError(
                f"no GitHub repository route configured for project {project_uuid}"
            )
        return route
