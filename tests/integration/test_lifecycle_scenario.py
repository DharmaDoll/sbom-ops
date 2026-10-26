"""Saved lifecycle teaching data must exercise the real local product paths."""

import importlib.util
import socket
from pathlib import Path

import pytest

from sbom_ops.services.lifecycle_evidence import load_evidence


def test_saved_evidence_separates_rebuild_from_document_correction() -> None:
    samples = Path(__file__).parents[2] / "examples/lifecycle"
    source, a, b, corrected = (
        load_evidence(samples / f"{name}.json")
        for name in ("source", "build-a", "build-b", "build-a-corrected")
    )
    assert source.source_revision == a.source_revision == b.source_revision
    assert source.kind == "source" and source.artifact_id is None
    assert a.artifact_id != b.artifact_id
    assert a.artifact_digest != b.artifact_digest
    assert a.build_ref != b.build_ref
    assert corrected.artifact_id == a.artifact_id
    assert corrected.artifact_digest == a.artifact_digest
    assert corrected.build_ref == a.build_ref
    assert corrected.sbom_digest != a.sbom_digest
    assert corrected.supersedes_id == 2 and corrected.reason
    assert len({item.sbom_ref for item in (source, a, b, corrected)}) == 4


def test_lifecycle_scenario_preserves_parallel_deployments_and_history(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline scenario attempted network access")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    path = Path(__file__).parents[2] / "examples/lifecycle_scenario.py"
    assert path.is_file(), "the runnable lifecycle teaching scenario is missing"
    spec = importlib.util.spec_from_file_location("lifecycle_example", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.run_scenario()
    stages = {stage["name"]: stage for stage in result["stages"]}
    assert len(stages) == 7
    assert len(stages["unapproved"]["deployments"]) == 2

    def placements(name: str) -> dict[tuple[str, str | None], tuple[str, str | None]]:
        return {
            (row["artifact_id"], row["environment"]): (
                row["status"],
                row["deployment_status"],
            )
            for row in stages[name]["deployments"]
        }

    assert placements("parallel")[("build-a", "production")] == ("reported", "deployed")
    assert placements("parallel")[("build-b", "production")] == ("reported", "deployed")
    assert placements("stopped")[("build-a", "production")] == (
        "reported",
        "not_deployed",
    )
    assert placements("stopped")[("build-b", "production")] == ("reported", "deployed")
    assert placements("stopped")[("build-a", "staging")] == ("reported", "deployed")
    assert placements("conflict")[("build-b", "production")] == ("conflict", None)
    # B was never reported in staging; it is unreported, not an expired claim.
    assert placements("expired") == {
        ("build-a", "production"): ("expired", None),
        ("build-a", "staging"): ("expired", None),
        ("build-b", "production"): ("expired", None),
        ("build-b", "staging"): ("unreported", None),
    }
    assert all(
        row["status"] == "unverified_link"
        for row in stages["unapproved"]["deployments"]
    )
    assert result["preview_unchanged"] is True
    assert result["history_count"] == 4
    assert result["temporary_db_removed"] is True
    assert {
        record["status"] for record in stages["stopped"]["evidence"][0]["records"]
    } == {"matched", "superseded", "not_build", "different_artifact"}
    assert capsys.readouterr().out == ""
