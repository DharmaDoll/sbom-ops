"""Source-reported identity candidates, never approved aliases or risk decisions."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime

from sbom_ops.domain.poc import select_poc_targets

OSV_SOURCE = "osv:https://api.osv.dev"
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.IGNORECASE)


class IdentifierFetchError(Exception):
    def __init__(self, code: str, *, status: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def osv_identifier(identifier: str) -> str:
    if re.fullmatch(
        r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}",
        identifier,
        re.IGNORECASE,
    ):
        return "GHSA-" + identifier[5:].lower()
    if re.fullmatch(r"(?:GO|PYSEC)-[0-9]{4}-[0-9]+", identifier, re.IGNORECASE):
        return identifier.upper()
    raise ValueError("only GHSA, GO and PYSEC identifiers are supported")


@dataclass(frozen=True)
class IdentifierTarget:
    original_id: str
    dt_sources: tuple[str, ...]


@dataclass(frozen=True)
class IdentifierObservation:
    original_id: str
    dt_sources: tuple[str, ...]
    requested_id: str
    source: str
    observed_at: str
    source_modified_at: str | None
    cves: tuple[str, ...]
    status: str
    error: str | None = None
    http_status: int | None = None

    def as_dict(self) -> dict[str, object]:
        return {**asdict(self), "approved": False}


def select_identifier_targets(
    payload: object, *, max_ids: int, only_ids: tuple[str, ...] = ()
) -> tuple[tuple[IdentifierTarget, ...], tuple[str, ...]]:
    if not 1 <= max_ids <= 25:
        raise ValueError("max-ids must be between 1 and 25")
    # Share successful-input validation and its safety limit for resolved CVEs.
    unresolved = select_poc_targets(payload, max_cves=1000).unresolved
    if only_ids:
        if not set(only_ids).issubset(unresolved):
            raise ValueError("selected ID is not unresolved in the sync input")
        unresolved = tuple(sorted(set(only_ids)))
    targets = []
    unsupported = []
    sources: dict[str, set[str]] = {}
    for row in payload["assessments"]:
        identifier = row["vulnerability_id"].strip()
        source = row.get("vulnerability_source") or "UNKNOWN"
        if not isinstance(source, str) or len(source) > 128:
            raise ValueError("invalid vulnerability source")
        sources.setdefault(identifier, set()).add(source)
    for identifier in unresolved:
        try:
            osv_identifier(identifier)
        except ValueError:
            unsupported.append(identifier)
        else:
            targets.append(
                IdentifierTarget(identifier, tuple(sorted(sources[identifier])))
            )
    if len(targets) > max_ids:
        raise ValueError("unresolved supported IDs exceed max-ids; narrow the input")
    return tuple(targets), tuple(unsupported)


def interpret_osv_candidates(
    target: IdentifierTarget, payload: object, *, observed_at: datetime
) -> IdentifierObservation:
    requested = osv_identifier(target.original_id)
    if observed_at.tzinfo is None:
        raise ValueError("observation time requires a timezone")
    if not isinstance(payload, dict) or payload.get("id") != requested:
        raise ValueError("OSV response identity mismatch")
    modified = payload.get("modified")
    if not isinstance(modified, str):
        raise ValueError("OSV modified time missing")
    timestamp = datetime.fromisoformat(modified)
    if timestamp.tzinfo is None or timestamp > observed_at:
        raise ValueError("invalid OSV modified time")
    aliases = payload.get("aliases", [])
    if (
        not isinstance(aliases, list)
        or len(aliases) > 1000
        or any(not isinstance(value, str) for value in aliases)
    ):
        raise ValueError("invalid OSV aliases")
    cves = tuple(sorted({value.upper() for value in aliases if _CVE.fullmatch(value)}))
    # Withdrawn records must not be presented as current mapping candidates.
    withdrawn = payload.get("withdrawn") is not None
    if withdrawn:
        status = "withdrawn"
    elif len(cves) > 1:
        status = "ambiguous"
    elif cves:
        status = "candidate"
    else:
        status = "unresolved"
    return IdentifierObservation(
        target.original_id,
        target.dt_sources,
        requested,
        OSV_SOURCE,
        observed_at.isoformat(),
        modified,
        () if withdrawn else cves,
        status,
    )
