"""Synthetic reviewed mapping -> PoC tests; no live API or DT mutation."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from sbom_ops import cli
from sbom_ops.domain import advisory, models
from sbom_ops.domain.advisory import AdvisorySnapshot, PocReportStatus
from sbom_ops.domain.identifier_candidates import (
    IdentifierTarget,
    interpret_osv_candidates,
)
from sbom_ops.domain.models import AnalysisState, FindingAssessment, Priority, Severity
from sbom_ops.domain.poc import PocTargets, interpret_poc_sightings, select_poc_targets
from sbom_ops.services.identifier_review import review_identifier
from sbom_ops.services.orchestrator import RunResult
from sbom_ops.services.poc_identity import (
    attach_reviewed_poc,
    reviewed_target_is_current,
    select_reviewed_poc_targets,
)
from sbom_ops.services.poc_refresh import collect_poc_snapshot
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.identifier_candidates import IdentifierStore
from sbom_ops.storage.poc import PocStore

NOW = datetime(2026, 10, 18, tzinfo=UTC)
ID = "GO-2026-10001"
CVE = "CVE-2026-10001"


def payload(source="OSV", aliases=()):
    return {
        "status": "succeeded",
        "assessments": [
            {
                "vulnerability_id": ID,
                "vulnerability_source": source,
                "vulnerability_aliases": list(aliases),
            }
        ],
    }


def candidate():
    return interpret_osv_candidates(
        IdentifierTarget(ID, ("OSV",)),
        {"id": ID, "modified": NOW.isoformat(), "aliases": [CVE]},
        observed_at=NOW,
    )


def decide(store, **changes):
    options = dict(
        observation_id=1,
        dt_source="OSV",
        cve=CVE,
        action="approve",
        actor="fictional-operator",
        reason="synthetic identity check",
        expires_at=(NOW + timedelta(hours=1)).isoformat(),
        now=NOW,
        execute=True,
    )
    options.update(changes)
    return review_identifier(store, **options)


@pytest.fixture
def clock(monkeypatch):
    current = [NOW]

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return current[0]

    monkeypatch.setattr(models, "datetime", FixedClock)
    monkeypatch.setattr(advisory, "datetime", FixedClock)
    monkeypatch.setattr(cli, "datetime", FixedClock)
    return current


@pytest.fixture
def path(tmp_path, clock):
    path = tmp_path / "assets.sqlite3"
    with AssetRegistry(path, create_if_missing=True):
        pass
    with IdentifierStore(path) as store:
        store.save(candidate())
    return path


def assessment():
    return FindingAssessment(
        "project",
        "finding",
        ID,
        "OSV",
        Severity.HIGH,
        8.0,
        None,
        Priority.P2,
        AnalysisState.NOT_AFFECTED,
        True,
        ("unchanged rationale",),
    )


def response(cve=CVE, count=2):
    return {
        "metadata": {"count": count, "page": 1, "per_page": 1},
        "data": (
            [
                {
                    "vulnerability": cve,
                    "type": "published-proof-of-concept",
                    "creation_timestamp": NOW.isoformat(),
                }
            ]
            if count
            else []
        ),
    }


def snapshot(count=2):
    observation = interpret_poc_sightings(
        response(count=count),
        cve=CVE,
        source="fictional-provider",
        observed_at=NOW,
        ttl=timedelta(hours=6),
    )
    return AdvisorySnapshot("fictional", NOW.isoformat(), (observation,), ())


def test_unreviewed_candidate_and_input_projection_never_authorize_fetch(path):
    forged = payload()
    forged["assessments"][0]["poc_identity"] = {"status": "active", "cve": CVE}
    with IdentifierStore(path, read_only=True) as store:
        targets, mappings = select_reviewed_poc_targets(
            forged, store, max_cves=25, now=NOW
        )
    assert targets == PocTargets((), (ID,))
    assert mappings[0].status == "unreviewed"


def test_review_selection_scoped_to_exact_id_and_source_and_deduplicated(path):
    with IdentifierStore(path) as store:
        decide(store)
    before = path.read_bytes()
    with IdentifierStore(path, read_only=True) as store:
        combined = payload()
        combined["assessments"] += (
            payload()["assessments"] + payload("GITHUB")["assessments"]
        )
        targets, mappings = select_reviewed_poc_targets(
            combined, store, max_cves=1, now=NOW
        )
        assert targets == PocTargets((CVE,), (ID,))
        assert [m.status for m in mappings] == ["active", "unreviewed"]
        assert mappings[0].actor == "fictional-operator"
        assert mappings[0].observation_id == 1
        explicit, direct = select_reviewed_poc_targets(
            payload(aliases=("CVE-2026-10002",)), store, max_cves=1, now=NOW
        )
        assert explicit.cves == ("CVE-2026-10002",)
        assert direct == ()
        combined["assessments"] += [{"vulnerability_id": "CVE-2026-10002"}]
        with pytest.raises(ValueError, match="exceeds"):
            select_reviewed_poc_targets(combined, store, max_cves=1, now=NOW)
    assert path.read_bytes() == before
    assert select_poc_targets(payload(), max_cves=25).cves == ()


@pytest.mark.parametrize(
    "change,status",
    [
        ("expire", "expired"),
        ("future", "future"),
        ("revoke", "revoked"),
        ("new", "observation_changed"),
        ("withdrawn", "observation_changed"),
        ("error", "observation_changed"),
    ],
)
def test_invalidated_mapping_never_fetches_or_attaches_saved_poc(
    path, clock, change, status
):
    with IdentifierStore(path) as store:
        decide(store)
        if change == "expire":
            clock[0] += timedelta(hours=1)
        elif change == "future":
            clock[0] -= timedelta(seconds=1)
        elif change == "revoke":
            decide(store, action="revoke", expires_at=None)
        else:
            store.save(
                replace(candidate(), status="candidate" if change == "new" else change)
            )
    with IdentifierStore(path, read_only=True) as store:
        targets, mappings = select_reviewed_poc_targets(
            payload(), store, max_cves=25, now=clock[0]
        )
        result = attach_reviewed_poc((assessment(),), snapshot(), store, now=clock[0])[
            0
        ]
    assert targets.cves == ()
    assert mappings[0].status == status
    assert result.poc_reports.status is PocReportStatus.UNKNOWN
    assert result.reviewed_poc_observations == ()


@pytest.mark.parametrize("count,expected", [(2, "reported"), (0, "not_observed")])
def test_only_poc_is_attached_without_changing_risk_or_aliases(
    path, clock, count, expected
):
    with IdentifierStore(path) as store:
        decide(store)
    original = assessment()
    with IdentifierStore(path, read_only=True) as store:
        result = attach_reviewed_poc((original,), snapshot(count), store, now=NOW)[0]
    assert result.poc_reports.status.value == expected
    assert result.poc_reports.sources[0].vulnerability_id == CVE
    assert replace(result, poc_identity=None, reviewed_poc_observations=()) == original
    clock[0] += timedelta(hours=1)
    assert result.poc_reports.status is PocReportStatus.UNKNOWN


@pytest.mark.parametrize("when", ["before_cache", "during_pacing"])
def test_recheck_does_not_reuse_or_request_revoked_mapping(path, when):
    with IdentifierStore(path) as store:
        decide(store)
        targets, mappings = select_reviewed_poc_targets(
            payload(), store, max_cves=25, now=NOW
        )
    calls = []
    source = SimpleNamespace(
        source="fictional-provider",
        get_poc_sightings=lambda cve: calls.append(cve) or response(cve),
    )

    def revoke(_delay=0):
        with IdentifierStore(path) as writer:
            decide(writer, action="revoke", expires_at=None)

    with PocStore(path) as pocs:
        collect_poc_snapshot(targets, source, repository=pocs, clock=lambda: NOW)
    calls.clear()
    direct = ()
    if when == "before_cache":
        revoke()
    else:
        direct = ("CVE-2026-00001",)
        targets = PocTargets(direct + targets.cves, ())
    with IdentifierStore(path, read_only=True) as store, PocStore(path) as pocs:
        result = collect_poc_snapshot(
            targets,
            source,
            repository=pocs,
            clock=lambda: NOW + timedelta(minutes=2),
            refresh_seconds=3600 if when == "before_cache" else 1,
            sleep=revoke,
            target_is_current=lambda cve, now: reviewed_target_is_current(
                store, cve, direct, mappings, now=now
            ),
        )
        assert pocs.get(CVE, source.source).success.observed_at == NOW.isoformat()
        assert pocs.source_state(source.source).failures == 0
    assert calls == list(direct)
    assert result["collection"]["results"][-1]["error"] == "identifier_review_changed"
    assert result["collection"]["status"] == "partial"


def test_cli_preview_execute_display_revoke_and_no_default_connection(
    path, tmp_path, monkeypatch, capsys
):
    with IdentifierStore(path) as store:
        decide(store)
    input_path = tmp_path / "sync.json"
    input_path.write_text(json.dumps(payload()))
    calls = []
    monkeypatch.setattr(
        cli,
        "VulnerabilityLookupClient",
        lambda *a, **k: SimpleNamespace(
            source="fictional-provider",
            get_poc_sightings=lambda cve: calls.append(cve) or response(cve),
        ),
    )
    # Acquisition clock must match the deterministic identity review clock.
    original_collect = cli.collect_poc_snapshot
    monkeypatch.setattr(
        cli,
        "collect_poc_snapshot",
        lambda *a, **k: original_collect(*a, clock=lambda: NOW, **k),
    )
    args = ["poc-fetch", "--findings", str(input_path), "--db", str(path)]
    assert cli.run_poc_fetch(cli.build_parser().parse_args(args)) == 0
    assert json.loads(capsys.readouterr().out)["cves"] == []
    before = path.read_bytes()
    args += ["--use-reviewed-identifiers"]
    assert cli.run_poc_fetch(cli.build_parser().parse_args(args)) == 0
    assert json.loads(capsys.readouterr().out)["cves"] == [CVE]
    assert path.read_bytes() == before and calls == []
    assert cli.run_poc_fetch(cli.build_parser().parse_args(args + ["--execute"])) == 0
    assert (
        json.loads(capsys.readouterr().out)["identifier_selection"][0]["review_id"] == 1
    )
    assert calls == [CVE]
    base = RunResult("run", 0, False, 1, 1, 0, 0, 0, True, assessments=(assessment(),))
    captured = []

    def orchestrator(**kwargs):
        captured.append(kwargs)
        return SimpleNamespace(run=lambda: base)

    monkeypatch.setattr(cli, "Orchestrator", orchestrator)
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    before = path.read_bytes()
    assert (
        cli.run_sync(
            config, "json", poc_db_path=str(path), use_reviewed_identifiers=True
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["assessments"][0]["poc_reports"]["status"] == "reported"
    assert output["review_queue"][0]["poc_identity"]["original_id"] == ID
    assert output["assessments"][0]["priority"] == "P2"
    assert output["assessments"][0]["vulnerability_aliases"] == []
    assert output["issues_created"] == 0
    assert set(captured[0]) == {"config", "force_refresh_kev", "advisory_snapshot"}
    assert path.read_bytes() == before
    with IdentifierStore(path) as store:
        decide(store, action="revoke", expires_at=None)
    assert (
        cli.run_sync(
            config, "review", poc_db_path=str(path), use_reviewed_identifiers=True
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "PoC用CVE対応=revoked" in output
    assert "PoC=不明" in output
    assert cli.run_poc_fetch(cli.build_parser().parse_args(args + ["--execute"])) == 1
    capsys.readouterr()
    assert calls == [CVE]


def test_old_schema_or_missing_db_does_not_create_or_migrate(
    path, tmp_path, monkeypatch, capsys
):
    missing = tmp_path / "missing.sqlite3"
    input_path = tmp_path / "sync.json"
    input_path.write_text(json.dumps(payload()))
    args = cli.build_parser().parse_args(
        [
            "poc-fetch",
            "--findings",
            str(input_path),
            "--db",
            str(missing),
            "--use-reviewed-identifiers",
        ]
    )
    import sqlite3

    with pytest.raises(sqlite3.Error):
        cli.run_poc_fetch(args)
    assert not missing.exists()
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE advisory_feed_revisions")
        db.execute("DROP TABLE advisory_poll_state")
        db.execute("DROP TABLE lifecycle_evidence")
        db.execute("DROP TABLE vulnrichment_snapshots")
        db.execute("DROP TABLE identifier_reviews")
        db.execute("PRAGMA user_version=8")
    before = path.read_bytes()
    with (
        IdentifierStore(path, read_only=True) as store,
        pytest.raises(ValueError, match="v9"),
    ):
        select_reviewed_poc_targets(payload(), store, max_cves=25, now=NOW)
    base = RunResult("run", 0, False, 1, 1, 0, 0, 0, True, assessments=(assessment(),))
    monkeypatch.setattr(
        cli, "Orchestrator", lambda **k: SimpleNamespace(run=lambda: base)
    )
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    assert (
        cli.run_sync(
            config, "json", poc_db_path=str(path), use_reviewed_identifiers=True
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["poc_identity_status"] == "invalid"
    assert output["findings_processed"] == 1
    assert output["assessments"][0]["poc_reports"]["status"] == "unknown"
    assert path.read_bytes() == before
    with pytest.raises(ValueError, match="PoC DB"):
        cli.run_sync(config, use_reviewed_identifiers=True)


def test_mapping_does_not_import_other_signals_and_requires_fresh_poc(path):
    with IdentifierStore(path) as store:
        decide(store)
    original = snapshot()
    poc = original.vulnerability_observations[0]
    intelligence = replace(
        original,
        vulnerability_observations=(
            replace(poc, expires_at=NOW.isoformat()),
            replace(poc, signal="known_active_exploitation"),
        ),
    )
    with IdentifierStore(path, read_only=True) as store:
        projected = attach_reviewed_poc((assessment(),), intelligence, store, now=NOW)[
            0
        ]
        other_source = attach_reviewed_poc(
            (replace(assessment(), vulnerability_source="GITHUB"),),
            original,
            store,
            now=NOW,
        )[0]
    assert projected.poc_reports.status is PocReportStatus.UNKNOWN
    assert len(projected.reviewed_poc_observations) == 1
    assert projected.reviewed_poc_observations[0].signal == "published_poc"
    assert projected.advisory_observations == ()
    assert other_source.poc_reports.status is PocReportStatus.UNKNOWN
    assert other_source.reviewed_poc_observations == ()


def test_expiry_during_pacing_stops_only_mapped_target(path):
    with IdentifierStore(path) as store:
        decide(store)
        _, mappings = select_reviewed_poc_targets(
            payload(), store, max_cves=25, now=NOW
        )
    current = [NOW]
    calls = []
    direct = ("CVE-2026-00001",)
    source = SimpleNamespace(
        source="fictional-provider",
        get_poc_sightings=lambda cve: calls.append(cve) or response(cve),
    )

    def delay(_seconds):
        current[0] += timedelta(hours=1)

    with IdentifierStore(path, read_only=True) as store:
        result = collect_poc_snapshot(
            PocTargets(direct + (CVE,), ()),
            source,
            sleep=delay,
            clock=lambda: current[0],
            target_is_current=lambda cve, now: reviewed_target_is_current(
                store, cve, direct, mappings, now=now
            ),
        )
    assert calls == list(direct)
    assert result["collection"]["results"][-1]["error"] == "identifier_review_changed"


def test_cancellation_in_flight_keeps_cve_observation_but_not_mapping(path):
    with IdentifierStore(path) as store:
        decide(store)
        targets, mappings = select_reviewed_poc_targets(
            payload(), store, max_cves=25, now=NOW
        )

    def fetch(cve):
        with IdentifierStore(path) as writer:
            decide(writer, action="revoke", expires_at=None)
        return response(cve)

    source = SimpleNamespace(source="fictional-provider", get_poc_sightings=fetch)
    with IdentifierStore(path, read_only=True) as store, PocStore(path) as pocs:
        collect_poc_snapshot(
            targets,
            source,
            repository=pocs,
            clock=lambda: NOW,
            target_is_current=lambda cve, now: reviewed_target_is_current(
                store, cve, (), mappings, now=now
            ),
        )
        assert pocs.get(CVE, source.source).success.record_count == 2
        projected = attach_reviewed_poc(
            (assessment(),), pocs.snapshot(), store, now=NOW
        )[0]
    assert projected.poc_identity.status == "revoked"
    assert projected.poc_reports.status is PocReportStatus.UNKNOWN


def test_reapproval_different_cve_does_not_reuse_old_poc(path):
    with IdentifierStore(path) as store:
        decide(store)
        store.save(replace(candidate(), cves=("CVE-2026-10002",)))
        decide(store, observation_id=2, cve="CVE-2026-10002")
    with IdentifierStore(path, read_only=True) as store:
        projected = attach_reviewed_poc((assessment(),), snapshot(), store, now=NOW)[0]
        targets, _ = select_reviewed_poc_targets(payload(), store, max_cves=25, now=NOW)
    assert targets.cves == ("CVE-2026-10002",)
    assert projected.poc_identity.review_id == 2
    assert projected.poc_reports.status is PocReportStatus.UNKNOWN
