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

    assert finding.finding_key() == "project-1:openssl:1.0.0:CVE-2026-0001"
