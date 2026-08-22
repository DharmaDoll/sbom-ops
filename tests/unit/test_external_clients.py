from __future__ import annotations

import json

from sbom_ops.clients import github as github_module
from sbom_ops.clients import kev as kev_module
from sbom_ops.clients.github import GitHubIssuesClient
from sbom_ops.clients.http import HttpApiError
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


def test_kev_client_uses_fresh_cache_without_fetching(monkeypatch, tmp_path) -> None:
    cache = tmp_path / "kev.json"
    cache.write_text(
        json.dumps({"fetched_at": 4_000_000_000, "cve_ids": ["CVE-CACHED"]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(kev_module.time, "time", lambda: 4_000_000_001)
    monkeypatch.setattr(
        kev_module,
        "urlopen",
        lambda request, timeout: (_ for _ in ()).throw(AssertionError("fetched")),
    )

    result = KevClient(
        "https://cisa.example/feed",
        cache_path=str(cache),
        cache_ttl_seconds=60,
    ).get_known_exploited_vulnerabilities()

    assert result == {"CVE-CACHED"}


def test_kev_client_can_use_stale_cache_only_when_enabled(
    monkeypatch, tmp_path
) -> None:
    cache = tmp_path / "kev.json"
    cache.write_text(
        json.dumps({"fetched_at": 1, "cve_ids": ["CVE-STALE"]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(kev_module.time, "time", lambda: 10_000)
    monkeypatch.setattr(
        kev_module,
        "request_json",
        lambda *args, **kwargs: (_ for _ in ()).throw(HttpApiError("down")),
    )

    client = KevClient(
        "https://cisa.example/feed",
        cache_path=str(cache),
        cache_ttl_seconds=60,
        allow_stale_cache=True,
    )

    assert client.get_known_exploited_vulnerabilities() == {"CVE-STALE"}
    assert client.used_stale_cache is True


def test_kev_client_reuses_cache_on_not_modified(monkeypatch, tmp_path) -> None:
    cache = tmp_path / "kev.json"
    cache.write_text(
        json.dumps(
            {
                "fetched_at": 1,
                "cve_ids": ["CVE-UNCHANGED"],
                "metadata": {"etag": "abc"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(kev_module.time, "time", lambda: 10_000)
    monkeypatch.setattr(
        kev_module,
        "request_json",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            HttpApiError("not modified", status=304)
        ),
    )

    result = KevClient(
        "https://cisa.example/feed",
        cache_path=str(cache),
        cache_ttl_seconds=60,
    ).get_known_exploited_vulnerabilities()

    assert result == {"CVE-UNCHANGED"}


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


def test_github_issue_listing_filters_pull_requests_and_paginates(monkeypatch) -> None:
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request.full_url)
        if request.full_url.endswith("page=1"):
            page = [
                {"number": 10, "title": "issue"},
                {"number": 11, "title": "pull request", "pull_request": {}},
            ]
            page.extend(
                {"number": number, "title": "additional issue"}
                for number in range(12, 110)
            )
            return FakeResponse(page)
        return FakeResponse([])

    monkeypatch.setattr(github_module, "urlopen", fake_urlopen)

    issues = GitHubIssuesClient("token", "acme", "service-a").list_open_issues("sbom")

    assert issues[0]["number"] == 10
    assert 11 not in {issue["number"] for issue in issues}
    assert len(issues) == 99
    assert len(requests) == 2
    assert "page=1" in requests[0]
    assert "page=2" in requests[1]
