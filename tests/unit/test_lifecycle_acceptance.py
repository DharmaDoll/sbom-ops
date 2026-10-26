"""Lifecycle acceptance: shared source does not merge artifact/deployment identity."""

from dataclasses import replace
from datetime import UTC, datetime

from sbom_ops.clients.dependency_track import DependencyTrackProject
from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegisteredService,
    ReportedDeployment,
    ReviewedProjectLink,
)
from sbom_ops.domain.assets import BusinessCriticality, DeploymentStatus
from sbom_ops.domain.lifecycle_evidence import (
    LifecycleEvidence,
    RecordedEvidence,
    match_lifecycle_evidence,
)
from sbom_ops.services.asset_registry import (
    observe_registry_deployments,
    observe_registry_projects,
)

NOW = datetime(2026, 10, 25, tzinfo=UTC)


def test_shared_source_parallel_artifacts_redeployment_and_stop() -> None:
    projects = tuple(
        DependencyTrackProject(f"uuid-{v}", "shop/api", v) for v in ("a", "b")
    )
    links = tuple(
        ReviewedProjectLink(
            p.uuid, p.name, p.version, "shop", "api", "reviewer", "2026-10-01T00:00:00Z"
        )
        for p in projects
    )
    first = ReportedDeployment(
        "shop",
        "api",
        "production",
        "a",
        DeploymentStatus.DEPLOYED,
        ExposureStatus.UNKNOWN,
        "operator",
        "deployment record",
        "2026-10-20T00:00:00Z",
        "2026-11-01T00:00:00Z",
        1,
    )
    parallel = replace(first, artifact_id="b", report_id=2)
    redeployed = replace(first, environment="staging", report_id=3)
    snapshot = AssetRegistrySnapshot(
        (RegisteredService("shop", "team", BusinessCriticality.HIGH, "sales"),),
        links,
        (first, parallel, redeployed),
    )
    observed = observe_registry_projects(snapshot, projects, projects)
    item = LifecycleEvidence(
        "shop",
        "api",
        "build",
        "boms/a.json",
        "operator",
        artifact_id="a",
        source_repository="https://example.test/repo",
        source_revision="a" * 40,
        observed_at=NOW,
    )
    records = (
        RecordedEvidence(1, NOW, item),
        RecordedEvidence(
            2, NOW, replace(item, artifact_id="b", sbom_ref="boms/b.json")
        ),
    )
    assert match_lifecycle_evidence(snapshot, observed[0], records, now=NOW) == {
        1: "matched",
        2: "different_artifact",
    }
    assert match_lifecycle_evidence(snapshot, observed[1], records, now=NOW) == {
        1: "different_artifact",
        2: "matched",
    }
    placements = observe_registry_deployments(snapshot, observed, now=NOW)
    assert {
        (r.project_uuid, r.environment)
        for r in placements
        if r.deployment_status is DeploymentStatus.DEPLOYED
    } == {("uuid-a", "production"), ("uuid-b", "production"), ("uuid-a", "staging")}
    stopped = replace(
        first,
        report_id=4,
        supersedes_report_id=1,
        observed_at="2026-10-21T00:00:00Z",
        deployment_status=DeploymentStatus.NOT_DEPLOYED,
    )
    after = replace(
        snapshot, deployment_reports=(*snapshot.deployment_reports, stopped)
    )
    placements = observe_registry_deployments(after, observed, now=NOW)
    statuses = {
        (r.project_uuid, r.environment): r.deployment_status for r in placements
    }
    assert statuses[("uuid-a", "production")] is DeploymentStatus.NOT_DEPLOYED
    assert statuses[("uuid-b", "production")] is DeploymentStatus.DEPLOYED
    assert statuses[("uuid-a", "staging")] is DeploymentStatus.DEPLOYED
    assert (
        match_lifecycle_evidence(after, observed[0], records, now=NOW)[1] == "matched"
    )
    assert len(records) == 2  # Redeployment/stop does not manufacture another SBOM.


def test_source_build_and_corrected_document_remain_distinct() -> None:
    project = DependencyTrackProject("uuid", "shop/api", "a")
    snapshot = AssetRegistrySnapshot(
        (),
        (
            ReviewedProjectLink(
                "uuid",
                "shop/api",
                "a",
                "shop",
                "api",
                "reviewer",
                "2026-10-01T00:00:00Z",
            ),
        ),
    )
    # Use a registered owner so the existing Project observation can match.
    snapshot = replace(
        snapshot,
        services=(
            RegisteredService("shop", "team", BusinessCriticality.HIGH, "sales"),
        ),
    )
    observed = observe_registry_projects(snapshot, (project,), (project,))[0]
    build = LifecycleEvidence(
        "shop",
        "api",
        "build",
        "boms/build.json",
        "operator",
        artifact_id="a",
        source_repository="https://example.test/repo",
        source_revision="a" * 40,
        sbom_digest="sha256:" + "b" * 64,
        observed_at=NOW,
    )
    source = replace(
        build,
        kind="source",
        artifact_id=None,
        sbom_ref="boms/source.json",
        sbom_digest="sha256:" + "c" * 64,
    )
    corrected = replace(
        build,
        supersedes_id=1,
        reason="document correction",
        sbom_ref="boms/corrected.json",
        sbom_digest="sha256:" + "d" * 64,
    )
    records = tuple(
        RecordedEvidence(i, NOW, item)
        for i, item in enumerate((build, source, corrected), 1)
    )
    assert match_lifecycle_evidence(snapshot, observed, records, now=NOW) == {
        1: "superseded",
        2: "not_build",
        3: "matched",
    }
    assert len({r.evidence.sbom_digest for r in records}) == 3
    assert records[0].evidence.artifact_id == records[2].evidence.artifact_id
