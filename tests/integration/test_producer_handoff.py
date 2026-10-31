"""Safety boundaries of the optional example workflow, without network or secrets."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from sbom_ops.clients.dependency_track import (
    BomUpload,
    DependencyTrackApiError,
    DependencyTrackProject,
)

SCRIPT = Path(__file__).parents[2] / "examples/sbom-producers/handoff.py"
spec = importlib.util.spec_from_file_location("producer_handoff", SCRIPT)
assert spec and spec.loader
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)
IMAGE = "ghcr.io/example/checkout@sha256:" + "a" * 64
UUID = "00000000-0000-4000-8000-000000000001"


@pytest.fixture
def build(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    bom = tmp_path / "build.cdx.json"
    bom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {"component": {"type": "container", "name": IMAGE}},
                "components": [
                    {
                        "name": "libc6",
                        "purl": "pkg:deb/debian/libc6@2.36?distro=debian-12",
                    },
                    {"name": "picocolors", "purl": "pkg:npm/picocolors@1.1.1"},
                ],
            }
        )
    )
    return bom, handoff.prepare(
        bom, IMAGE, "npm", "b" * 40, "https://example.invalid/1"
    )


class FakeDT:
    def __init__(self, failure: str = "", wrong_identity: bool = False) -> None:
        self.failure = failure
        self.wrong_identity = wrong_identity
        self.uploads = 0

    def list_projects(self) -> list[DependencyTrackProject]:
        return [
            DependencyTrackProject(
                UUID,
                "wrong" if self.wrong_identity else "checkout-api/npm",
                "sha256:" + "a" * 64,
            )
        ]

    def upload_bom(self, project_uuid: str, bom: Path) -> BomUpload:
        self.uploads += 1
        if self.failure == "upload":
            raise DependencyTrackApiError("sensitive response must not reach artifacts")
        return BomUpload("00000000-0000-4000-8000-000000000002")

    def wait_for_bom_processing(self, token: str, *, timeout: float) -> None:
        if self.failure == "wait":
            raise DependencyTrackApiError("timeout")

    def get_project_findings(self, project_uuid: str) -> list[Any]:
        if self.failure == "findings":
            raise DependencyTrackApiError("403")
        return []


def test_empty_findings_never_proves_analysis_or_remediation_complete(
    build: tuple[Path, dict[str, Any]], tmp_path: Path
) -> None:
    bom, data = build
    client = FakeDT()
    path = tmp_path / "result.json"
    assert handoff.upload(data, bom, UUID, client, path) == 0
    result = json.loads(path.read_text())
    assert result["acceptance"] == "accepted"
    assert result["bom_processing"] == "token_idle"
    assert result["findings"] == "read"
    assert result["finding_count"] == 0
    assert result["analysis_complete"] == "unverified"
    assert client.uploads == 1
    with pytest.raises(FileExistsError):
        handoff.upload(data, bom, UUID, client, path)
    assert client.uploads == 1


@pytest.mark.parametrize(
    "failure,acceptance,processing,findings",
    [
        ("upload", "unknown", "not_checked", "not_read"),
        ("wait", "accepted", "unknown", "not_read"),
        ("findings", "accepted", "token_idle", "unknown"),
    ],
)
def test_failure_preserves_stages_without_resending(
    build: tuple[Path, dict[str, Any]],
    tmp_path: Path,
    failure: str,
    acceptance: str,
    processing: str,
    findings: str,
) -> None:
    bom, data = build
    client = FakeDT(failure)
    path = tmp_path / "result.json"
    assert handoff.upload(data, bom, UUID, client, path) == 2
    result = json.loads(path.read_text())
    assert (result["acceptance"], result["bom_processing"], result["findings"]) == (
        acceptance,
        processing,
        findings,
    )
    assert "finding_count" not in result
    assert client.uploads == 1
    assert "sensitive response" not in path.read_text()


def test_mismatched_project_prevents_mutation(
    build: tuple[Path, dict[str, Any]], tmp_path: Path
) -> None:
    bom, data = build
    client = FakeDT(wrong_identity=True)
    assert handoff.upload(data, bom, UUID, client, tmp_path / "result.json") == 2
    assert client.uploads == 0


def test_modified_bom_prevents_connection(
    build: tuple[Path, dict[str, Any]], tmp_path: Path
) -> None:
    bom, data = build
    bom.write_text(bom.read_text() + "\n")
    with pytest.raises(ValueError, match="sbom_digest"):
        handoff.upload(data, bom, UUID, object(), tmp_path / "result.json")
    assert not (tmp_path / "result.json").exists()


def test_source_bom_and_wrong_image_are_rejected(
    build: tuple[Path, dict[str, Any]],
) -> None:
    bom, _ = build
    source = json.loads(bom.read_text())
    source["metadata"]["component"]["type"] = "application"
    bom.write_text(json.dumps(source))
    with pytest.raises(ValueError, match="not a Source"):
        handoff.prepare(bom, IMAGE, "npm", "b" * 40, "run")
    with pytest.raises(ValueError, match="repository@"):
        handoff.prepare(bom, "ghcr.io/example/checkout:latest", "npm", "b" * 40, "run")


def test_missing_os_or_app_dependency_fails(build: tuple[Path, dict[str, Any]]) -> None:
    bom, _ = build
    data = json.loads(bom.read_text())
    data["components"] = data["components"][:1]
    bom.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="application"):
        handoff.prepare(bom, IMAGE, "npm", "b" * 40, "run")


def test_upload_and_read_credentials_are_separate(
    build: tuple[Path, dict[str, Any]], tmp_path: Path
) -> None:
    bom, data = build

    class UploadOnly(FakeDT):
        def list_projects(self) -> list[DependencyTrackProject]:
            raise AssertionError("upload key must not read projects")

        def get_project_findings(self, project_uuid: str) -> list[Any]:
            raise AssertionError("upload key must not read findings")

    class ReadOnly(FakeDT):
        def upload_bom(self, project_uuid: str, bom: Path) -> BomUpload:
            raise AssertionError("read key must not upload")

    writer, reader = UploadOnly(), ReadOnly()
    assert (
        handoff.upload(
            data, bom, UUID, writer, tmp_path / "result.json", read_client=reader
        )
        == 0
    )
    assert writer.uploads == 1 and reader.uploads == 0


@pytest.mark.parametrize("field", ["artifact_digest", "platform", "project_name"])
def test_handoff_identity_mismatch_stops_before_connection(
    build: tuple[Path, dict[str, Any]], tmp_path: Path, field: str
) -> None:
    bom, data = build
    data[field] = "different"
    with pytest.raises(ValueError, match=field):
        handoff.upload(data, bom, UUID, object(), tmp_path / "result.json")
    assert not (tmp_path / "result.json").exists()
