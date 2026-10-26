"""Explicit lifecycle evidence, independent of storage and external systems."""

import json
import re
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegistryProjectObservation,
    RegistryProjectStatus,
    validate_identifier,
)

MAX_INPUT_BYTES = 65536


def _text(value: object, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > limit
        or not value.isprintable()
    ):
        raise ValueError("invalid evidence text")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid evidence text") from None
    return value


def _reference(value: object) -> None:
    text = _text(value, 2048)
    if any(char in text for char in "\\%?#"):
        raise ValueError("invalid evidence reference")
    parsed = urlsplit(text)
    if parsed.scheme:
        if (
            any(char.isspace() for char in text)
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("invalid evidence reference")
        _ = parsed.port  # Reject malformed ports even though no request is made.
    elif parsed.netloc or text.startswith("/") or ":" in text:
        raise ValueError("invalid evidence reference")
    if ".." in parsed.path.split("/"):
        raise ValueError("invalid evidence reference")


@dataclass(frozen=True)
class LifecycleEvidence:
    service_id: str
    deployable_id: str
    kind: str
    sbom_ref: str
    actor: str
    artifact_id: str | None = None
    source_repository: str | None = None
    source_revision: str | None = None
    artifact_digest: str | None = None
    sbom_digest: str | None = None
    build_ref: str | None = None
    observed_at: datetime | None = None
    supersedes_id: int | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        for value in (self.service_id, self.deployable_id):
            validate_identifier(_text(value, 128), label="asset ID")
        if self.kind not in ("source", "build", "unknown"):
            raise ValueError("invalid evidence kind")
        _reference(self.sbom_ref)
        _text(self.actor, 128)
        for value in (self.source_repository, self.build_ref):
            if value is not None:
                _reference(value)
        if self.artifact_id is not None:
            _text(self.artifact_id, 512)
        if self.kind == "build" and self.artifact_id is None:
            raise ValueError("build requires artifact ID")
        if (self.source_repository is None) != (self.source_revision is None):
            raise ValueError("source repository and revision must be paired")
        if self.kind == "source" and self.source_repository is None:
            raise ValueError("source requires repository and revision")
        if self.source_revision is not None and not re.fullmatch(
            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", _text(self.source_revision, 64)
        ):
            raise ValueError("invalid source revision")
        for value in (self.artifact_digest, self.sbom_digest):
            if value is not None and not re.fullmatch(
                r"sha256:[0-9a-fA-F]{64}", _text(value, 71)
            ):
                raise ValueError("invalid evidence digest")
        if (self.supersedes_id is None) != (self.reason is None):
            raise ValueError("correction requires record ID and reason")
        if self.supersedes_id is not None:
            if (
                type(self.supersedes_id) is not int
                or not 1 <= self.supersedes_id <= 2**63 - 1
                or self.kind == "unknown"
            ):
                raise ValueError("invalid correction target")
            _text(self.reason, 1000)
        if self.observed_at is not None:
            if (
                not isinstance(self.observed_at, datetime)
                or self.observed_at.utcoffset() is None
            ):
                raise ValueError("evidence observation must include timezone")
            object.__setattr__(self, "observed_at", self.observed_at.astimezone(UTC))


def validate_correction(
    previous: LifecycleEvidence, successor: LifecycleEvidence, *, previous_id: int
) -> None:
    """Validate identity only; storage must also reject missing/forked records."""
    if type(previous_id) is not int or not 1 <= previous_id <= 2**63 - 1:
        raise ValueError("invalid previous record ID")
    if successor.supersedes_id != previous_id or previous.kind == "unknown":
        raise ValueError("invalid correction relationship")
    old_target = (previous.service_id, previous.deployable_id, previous.kind)
    new_target = (successor.service_id, successor.deployable_id, successor.kind)
    if old_target != new_target:
        raise ValueError("correction cannot change scope or kind")
    if previous.kind == "build":
        same = previous.artifact_id == successor.artifact_id
    else:
        same = (previous.source_repository, previous.source_revision) == (
            successor.source_repository,
            successor.source_revision,
        )
    if not same:
        raise ValueError("correction cannot change target")


@dataclass(frozen=True)
class RecordedEvidence:
    record_id: int
    recorded_at: datetime
    evidence: LifecycleEvidence


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate evidence key")
        result[key] = value
    return result


def _invalid_constant(_: str) -> None:
    raise ValueError("invalid evidence JSON constant")


def parse_evidence(raw: str) -> LifecycleEvidence:
    try:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
            raise ValueError("invalid evidence input size or type")
        payload = json.loads(
            raw, object_pairs_hook=_unique, parse_constant=_invalid_constant
        )
        allowed = {field.name for field in fields(LifecycleEvidence)} | {
            "schema_version"
        }
        required = {
            "schema_version",
            "service_id",
            "deployable_id",
            "kind",
            "sbom_ref",
            "actor",
        }
        if (
            not isinstance(payload, dict)
            or not required <= payload.keys()
            or payload.keys() - allowed
        ):
            raise ValueError("invalid evidence fields")
        version = payload.pop("schema_version")
        if type(version) is not int or version != 1:
            raise ValueError("invalid evidence schema version")
        observed = payload.get("observed_at")
        if observed is not None:
            payload["observed_at"] = datetime.fromisoformat(_text(observed, 64))
        return LifecycleEvidence(**payload)
    except (UnicodeError, RecursionError, OverflowError):
        raise ValueError("invalid evidence input") from None


def serialize_evidence(evidence: LifecycleEvidence) -> str:
    """Encode the input contract, without storage-owned identity or timestamps."""
    if not isinstance(evidence, LifecycleEvidence):
        raise ValueError("invalid evidence model")
    payload = asdict(evidence)
    payload["schema_version"] = 1
    if evidence.observed_at is not None:
        payload["observed_at"] = evidence.observed_at.isoformat()
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    parse_evidence(raw)  # Apply the same size/type rules at the persistence boundary.
    return raw


def match_lifecycle_evidence(
    snapshot: AssetRegistrySnapshot,
    project: RegistryProjectObservation,
    records: tuple[RecordedEvidence, ...],
    *,
    now: datetime,
) -> dict[int, str]:
    """Match inventory evidence, never runtime exposure or remediation status."""
    if now.utcoffset() is None:
        raise ValueError("evaluation time must include timezone")
    by_id: dict[int, RecordedEvidence] = {}
    corrected: set[int] = set()
    for record in sorted(records, key=lambda item: item.record_id):
        if (
            type(record.record_id) is not int
            or record.record_id < 1
            or record.record_id in by_id
            or record.recorded_at.utcoffset() is None
        ):
            raise ValueError("invalid evidence history")
        previous_id = record.evidence.supersedes_id
        if previous_id is not None:
            if previous_id not in by_id or previous_id in corrected:
                raise ValueError("invalid evidence correction history")
            validate_correction(
                by_id[previous_id].evidence, record.evidence, previous_id=previous_id
            )
            corrected.add(previous_id)
        by_id[record.record_id] = record
    rejected = dict.fromkeys(by_id, "asset_link_unverified")
    links = [
        link for link in snapshot.links if link.project_uuid == project.project_uuid
    ]
    if (
        project.status is not RegistryProjectStatus.MATCHED
        or len(links) != 1
        or project.project_uuid in snapshot.revoked_project_uuids
        or project.service_id in snapshot.retired_services
        or (project.service_id, project.deployable_id) in snapshot.retired_deployables
    ):
        return rejected
    link = links[0]
    if (
        link.project_name,
        link.project_version,
        link.service_id,
        link.deployable_id,
    ) != (
        project.dt_name,
        project.dt_version,
        project.service_id,
        project.deployable_id,
    ):
        return rejected
    reviewed = datetime.fromisoformat(link.reviewed_at)
    if reviewed.utcoffset() is None or reviewed > now:
        return rejected
    result: dict[int, str] = {}
    for record in records:
        item = record.evidence
        if (item.service_id, item.deployable_id) != (
            link.service_id,
            link.deployable_id,
        ):
            state = "different_asset"
        elif item.kind != "build":
            state = "not_build"
        elif item.artifact_id != link.project_version:
            state = "different_artifact"
        elif record.recorded_at > now or (
            item.observed_at is not None and item.observed_at > now
        ):
            state = "future"
        elif item.observed_at is None:
            state = "observation_unknown"
        else:
            state = "matched"
        result[record.record_id] = state
    eligible = {key for key, state in result.items() if state == "matched"}
    for record in records:
        previous_id = record.evidence.supersedes_id
        if previous_id is not None and record.record_id in eligible:
            result[previous_id] = "superseded"
    candidates = [key for key, state in result.items() if state == "matched"]
    if len(candidates) > 1:
        result.update(dict.fromkeys(candidates, "multiple_candidates"))
    return result
