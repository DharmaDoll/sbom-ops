from dataclasses import replace

from sbom_ops.domain.models import Finding, Severity


def test_finding_key_is_stable() -> None:
    finding = Finding(
        project_uuid="project-1",
        project_name="service-a",
        component_name="openssl",
        component_version="1.0.0",
        vulnerability_id="CVE-2026-0001",
        severity=Severity.HIGH,
        cvss_score=8.0,
        cwes=(79,),
        description=None,
    )

    assert finding.finding_key().startswith("v2:project-1:")
    assert len(finding.finding_key().split(":", 2)[2]) == 64
    assert finding.legacy_finding_key() == "project-1:openssl:1.0.0:CVE-2026-0001"


def test_finding_key_prefers_dependency_track_uuids() -> None:
    base = Finding(
        project_uuid="project-1",
        project_name="service-a",
        component_name="openssl",
        component_version="1.0.0",
        vulnerability_id="CVE-2026-0001",
        severity=Severity.HIGH,
        cvss_score=8.0,
        cwes=(),
        description=None,
        dependency_track_vulnerability_uuid="vulnerability-1",
        dependency_track_component_uuid="component-1",
        component_purl="pkg:generic/openssl@1.0.0",
    )
    renamed = replace(
        base,
        component_name="renamed-for-display",
        component_version="display-version",
        component_purl="pkg:generic/renamed@2",
    )

    assert base.finding_key() == renamed.finding_key()
    assert base.legacy_finding_key() != renamed.legacy_finding_key()


def test_finding_key_uses_purl_when_dependency_track_uuids_are_unavailable() -> None:
    base = Finding(
        project_uuid="project-1",
        project_name="service-a",
        component_name="shared-display-name",
        component_version="1.0.0",
        vulnerability_id="GHSA-1111-2222-3333",
        severity=Severity.HIGH,
        cvss_score=8.0,
        cwes=(),
        description=None,
        vulnerability_source="GITHUB",
        component_purl="pkg:npm/package-a@1.0.0",
    )
    other_component = replace(base, component_purl="pkg:npm/package-b@1.0.0")

    assert base.legacy_finding_key() == other_component.legacy_finding_key()
    assert base.finding_key() != other_component.finding_key()
