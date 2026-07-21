from __future__ import annotations


class EpssClient:
    def get_scores(self, cve_ids: list[str]) -> dict[str, float]:
        raise NotImplementedError
