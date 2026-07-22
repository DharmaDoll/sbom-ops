from __future__ import annotations

import json
from urllib.request import Request, urlopen


class KevClient:
    def __init__(self, feed_url: str, timeout: float = 30.0) -> None:
        self._feed_url = feed_url
        self._timeout = timeout

    def get_known_exploited_vulnerabilities(self) -> set[str]:
        request = Request(self._feed_url, headers={"Accept": "application/json"})
        with urlopen(request, timeout=self._timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return {
            str(item["cveID"])
            for item in payload.get("vulnerabilities", [])
            if item.get("cveID")
        }
