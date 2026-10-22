from dataclasses import asdict, replace

import pytest

from sbom_ops.domain.models import Finding, Severity
from sbom_ops.domain.triage_identity import resolve_triage_cve


def finding(identifier: str, aliases: tuple[str, ...] = ()) -> Finding:
    return Finding(
        project_uuid="project-1",
        project_name="synthetic",
        component_name="app",
        component_version="1",
        vulnerability_id=identifier,
        severity=Severity.HIGH,
        cvss_score=8.0,
        cwes=(),
        description=None,
        vulnerability_source="GITHUB",
        vulnerability_aliases=aliases,
    )


def test_multiple_cves_are_not_arbitrarily_selected() -> None:
    source = finding("GHSA-synthetic", ("CVE-2026-0002", "CVE-2026-0001"))
    result = resolve_triage_cve(source)
    assert result.cve is None
    assert result.candidates == ("CVE-2026-0001", "CVE-2026-0002")
    assert result.reasons == ("multiple_cve_candidates",)
    assert result.original_id == source.vulnerability_id
    assert result.finding_key == source.finding_key()


@pytest.mark.parametrize(
    "identifier,aliases,expected",
    [
        ("CVE-2026-0001", (), "CVE-2026-0001"),
        ("GHSA-synthetic", ("CVE-2026-0001",), "CVE-2026-0001"),
        ("OSV-synthetic", (" cve-2026-0001 ", "CVE-2026-0001"), "CVE-2026-0001"),
        ("CVE-2026-0001", ("GHSA-synthetic", "CVE-2026-0001"), "CVE-2026-0001"),
        ("GHSA-synthetic", (), None),
        ("CVE-2026-0001", ("CVE-2026-0002",), None),
        ("CVE-2026-0001", ("CVE-２０２６-0002",), None),
        ("CVE-malformed", ("CVE-2026-0001",), None),
        ("", ("CVE-2026-0001",), None),
    ],
)
def test_link_preserves_native_finding(identifier, aliases, expected) -> None:
    source = finding(identifier, aliases)
    before = asdict(source)
    result = resolve_triage_cve(source)
    assert result.cve == expected
    assert asdict(source) == before
    assert result.original_id == identifier
    assert result.original_source == "GITHUB"
    assert result.aliases == aliases
    assert result.finding_key == source.finding_key()
    assert bool(result.reasons) == (expected is None)


def test_free_text_and_poc_fields_do_not_supply_an_identity() -> None:
    source = replace(finding("GHSA-synthetic"), description="PoC CVE-2026-0001")
    result = resolve_triage_cve(source)
    assert result.candidates == ()
    assert result.cve is None
    assert result.reasons == ("no_cve_candidate",)


def test_alias_order_does_not_resolve_conflict() -> None:
    first = resolve_triage_cve(
        finding("CVE-2026-0001", ("CVE-2026-0003", "CVE-2026-0002"))
    )
    second = resolve_triage_cve(
        finding("CVE-2026-0001", ("CVE-2026-0002", "CVE-2026-0003"))
    )
    assert first.candidates == second.candidates
    assert first.cve is second.cve is None
    assert first.reasons == second.reasons


@pytest.mark.parametrize("aliases", [["CVE-2026-0001"], (None,), "CVE-2026-0001"])
def test_malformed_alias_container_is_rejected(aliases) -> None:
    with pytest.raises(ValueError):
        resolve_triage_cve(finding("GHSA-synthetic", aliases))
