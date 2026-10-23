"""Explicit single-CVE retrieval; no inventory, alias or workflow changes."""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Protocol

from sbom_ops.domain.vulnrichment import (
    VulnrichmentError,
    VulnrichmentReport,
    interpret_vulnrichment,
    validate_request,
)
from sbom_ops.domain.vulnrichment_snapshot import VulnrichmentSnapshot


class VulnrichmentReader(Protocol):
    def get_record(self, cve: str, revision: str) -> object: ...


class VulnrichmentWriter(Protocol):
    def save(self, snapshot: VulnrichmentSnapshot) -> int: ...


def collect_vulnrichment(
    client: VulnrichmentReader,
    repository: VulnrichmentWriter,
    *,
    cve: str,
    revision: str,
    max_age: timedelta,
    clock: Callable[[], datetime],
) -> tuple[int, VulnrichmentSnapshot]:
    """Fetch one explicit version; failures never return an older success."""
    validate_request(cve, revision)
    if not isinstance(max_age, timedelta) or max_age <= timedelta(0):
        raise VulnrichmentError("invalid_max_age")
    payload = client.get_record(cve, revision)
    snapshot = VulnrichmentSnapshot.capture(
        payload, cve=cve, revision=revision, max_age=max_age, retrieved_at=clock()
    )
    return repository.save(snapshot), snapshot


def fetch_vulnrichment(
    client: VulnrichmentReader,
    *,
    cve: str,
    revision: str,
    max_age: timedelta,
    clock: Callable[[], datetime],
) -> VulnrichmentReport:
    validate_request(cve, revision)
    if not isinstance(max_age, timedelta) or max_age <= timedelta(0):
        raise VulnrichmentError("invalid_max_age")
    payload = client.get_record(cve, revision)
    return interpret_vulnrichment(
        payload, cve=cve, revision=revision, max_age=max_age, retrieved_at=clock()
    )
