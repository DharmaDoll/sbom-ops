from __future__ import annotations

import json

import pytest
from dt_lab import client as client_module
from dt_lab.client import DependencyTrackLabClient
from dt_lab.datasources import configure_osv


class FakeClient:
    def __init__(self):
        self.value = None
        self.writes = 0
        self.alias = "false"
        self.ignore_write = False

    def read_config_properties(self):
        return [
            {
                "groupName": "vuln-source",
                "propertyName": name,
                "propertyValue": value,
                "propertyType": kind,
            }
            for name, value, kind in (
                ("google.osv.enabled", self.value, "STRING"),
                ("google.osv.alias.sync.enabled", self.alias, "BOOLEAN"),
                ("github.advisories.enabled", "false", "BOOLEAN"),
                ("github.advisories.access.token", "secret-do-not-log", "STRING"),
            )
        ]

    def update_config_property(self, group, name, value, property_type):
        self.writes += 1
        if not self.ignore_write:
            self.value = value


def test_dry_run_no_mutation_and_no_secret(tmp_path):
    client = FakeClient()
    path = tmp_path / "audit.jsonl"
    configure_osv(client, audit_path=path)
    assert client.writes == 0
    assert "secret-do-not-log" not in path.read_text()
    assert json.loads(path.read_text().splitlines()[-1])["event"] == "dry_run"


def test_execute_verifies_and_repeat_is_noop(tmp_path):
    client = FakeClient()
    evidence = tmp_path / "recovery.md"
    evidence.write_text("operator-reviewed restore evidence")
    for n in range(2):
        path = tmp_path / f"audit-{n}.jsonl"
        configure_osv(client, audit_path=path, execute=True, recovery_evidence=evidence)
        assert (
            json.loads(path.read_text().splitlines()[-1])["event"]
            == "configuration_verified"
        )
    assert client.writes == 1


@pytest.mark.parametrize("problem", ["alias", "baseline", "readback"])
def test_fail_closed(tmp_path, problem):
    client = FakeClient()
    if problem == "alias":
        client.alias = "true"
    if problem == "baseline":
        client.value = "Debian"
    if problem == "readback":
        client.ignore_write = True
    evidence = tmp_path / "recovery.md"
    evidence.write_text("reviewed")
    path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError):
        configure_osv(client, audit_path=path, execute=True, recovery_evidence=evidence)
    assert client.writes == (1 if problem == "readback" else 0)
    assert json.loads(path.read_text().splitlines()[-1])["event"] == "failed"


def test_requires_evidence_and_exclusive_audit(tmp_path):
    client = FakeClient()
    path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError):
        configure_osv(client, audit_path=path, execute=True)
    path.write_text("existing")
    with pytest.raises(FileExistsError):
        configure_osv(client, audit_path=path)
    assert path.read_text() == "existing"
    assert client.writes == 0


def test_server_reordering_is_verified_without_rewrite(tmp_path):
    client = FakeClient()
    client.value = "RubyGems;PyPI;Go;npm"
    evidence = tmp_path / "recovery.md"
    evidence.write_text("reviewed")
    configure_osv(
        client,
        audit_path=tmp_path / "audit.jsonl",
        execute=True,
        recovery_evidence=evidence,
    )
    assert client.writes == 0


def test_configuration_post_contract_no_retry(monkeypatch):
    def request(req, **kwargs):
        assert req.method == "POST"
        assert req.full_url == "https://dt.example/api/v1/configProperty"
        assert kwargs["max_retries"] == 0
        assert json.loads(req.data) == {
            "groupName": "vuln-source",
            "propertyName": "google.osv.enabled",
            "propertyValue": "Go;npm;PyPI;RubyGems",
            "propertyType": "STRING",
        }
        return {}

    monkeypatch.setattr(client_module, "request_json", request)
    DependencyTrackLabClient("https://dt.example", "key").update_config_property(
        "vuln-source", "google.osv.enabled", "Go;npm;PyPI;RubyGems", "STRING"
    )
