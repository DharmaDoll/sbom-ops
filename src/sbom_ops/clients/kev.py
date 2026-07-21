from __future__ import annotations


class KevClient:
    def get_known_exploited_vulnerabilities(self) -> set[str]:
        raise NotImplementedError
