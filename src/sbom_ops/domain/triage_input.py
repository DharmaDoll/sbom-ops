"""Explicit, immutable choices for a read-only reference evaluation."""

from dataclasses import dataclass

from sbom_ops.domain.vulnrichment_snapshot import VulnrichmentSnapshot


@dataclass(frozen=True)
class SelectedCisaSnapshot:
    snapshot_id: int
    snapshot: VulnrichmentSnapshot

    def __post_init__(self) -> None:
        if type(self.snapshot_id) is not int or not 1 <= self.snapshot_id < 2**63:
            raise ValueError("invalid CISA snapshot ID")
        if not isinstance(self.snapshot, VulnrichmentSnapshot):
            raise ValueError("validated CISA snapshot required")


@dataclass(frozen=True)
class TriageInput:
    environment: str
    cisa: tuple[SelectedCisaSnapshot, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.environment, str)
            or not self.environment
            or self.environment != self.environment.strip()
            or not self.environment.isprintable()
            or len(self.environment) > 2048
        ):
            raise ValueError("invalid triage environment")
        if not isinstance(self.cisa, tuple) or any(
            not isinstance(item, SelectedCisaSnapshot) for item in self.cisa
        ):
            raise ValueError("explicit CISA selections required")
        if len({item.snapshot.cve for item in self.cisa}) != len(self.cisa):
            raise ValueError("choose only one CISA snapshot per CVE")
