from __future__ import annotations

import json

from sbom_ops.clients import github as github_module
from sbom_ops.clients import kev as kev_module
from sbom_ops.clients.github import GitHubIssuesClient
from sbom_ops.clients.kev import KevClient


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self._payload = json.dumps(payload).encode()

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._payload


def test_kev_client_reads_cve_ids(monkeypatch) -> None:
    monkeypatch.setattr(
        kev_module,
        "urlopen",
        lambda request, timeout: FakeResponse(
            {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
        ),
    )

    result = KevClient(
        "https://cisa.example/feed"
    ).get_known_exploited_vulnerabilities()
    assert result == {"CVE-2026-0001"}


def test_github_client_sends_issue_create_request(monkeypatch) -> None:
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        return FakeResponse({"number": 42})

    monkeypatch.setattr(github_module, "urlopen", fake_urlopen)

    result = GitHubIssuesClient("token", "acme", "service-a").create_issue(
        "title", "body", ["sbom"]
    )

    request = captured["request"]
    assert result["number"] == 42
    assert request.get_method() == "POST"
    assert request.full_url.endswith("/repos/acme/service-a/issues")
    assert json.loads(request.data) == {
        "title": "title",
        "body": "body",
        "labels": ["sbom"],
    }
