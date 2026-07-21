from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DependencyTrackProject:
    uuid: str
    name: str


class DependencyTrackClient:
    def list_projects(self) -> list[DependencyTrackProject]:
        raise NotImplementedError

    def get_project_findings(self, project_uuid: str) -> list[dict]:
        raise NotImplementedError
