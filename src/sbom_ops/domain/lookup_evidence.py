"""Validate saved lifecycle evidence without fetching references or re-evaluating it."""

import json
from collections import Counter
from datetime import datetime

from sbom_ops.domain.lifecycle_evidence import parse_evidence, validate_correction

RECORD_STATES = frozenset(
    (
        "matched",
        "asset_link_unverified",
        "different_asset",
        "not_build",
        "different_artifact",
        "future",
        "observation_unknown",
        "superseded",
        "multiple_candidates",
    )
)


def validate_lookup_evidence(document: dict[str, object]) -> None:
    state = document.get("lifecycle_evidence_status")
    views = document.get("lifecycle_evidence")
    if state not in (
        "not_requested",
        "migration_required",
        "loaded",
        "invalid",
    ) or not isinstance(views, list):
        raise ValueError("lookup_input_evidence_state")
    if state != "loaded":
        if views:
            raise ValueError("lookup_input_unavailable_evidence")
        return
    projects = document["registry_projects"]
    if len(views) != len(projects):
        raise ValueError("lookup_input_evidence_project_count")
    observed = []
    for view in views:
        if not isinstance(view, dict) or not isinstance(view.get("records"), list):
            raise ValueError("lookup_input_evidence_view")
        identity = (view.get("project_uuid"), view.get("project_status"))
        if not all(isinstance(value, str) for value in identity):
            raise ValueError("lookup_input_evidence_identity")
        observed.append(identity)
        previous = {}
        corrected = set()
        for record in view["records"]:
            if not isinstance(record, dict):
                raise ValueError("lookup_input_evidence_record")
            record_id = record.get("record_id")
            if (
                type(record_id) is not int
                or not 0 < record_id < 2**63
                or record_id in previous
            ):
                raise ValueError("lookup_input_evidence_record_id")
            if record.get("status") not in RECORD_STATES:
                raise ValueError("lookup_input_evidence_record_state")
            timestamp = record.get("recorded_at")
            if not isinstance(timestamp, str):
                raise ValueError("lookup_input_evidence_time")
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("lookup_input_evidence_time")
            item = parse_evidence(
                json.dumps(record.get("evidence"), ensure_ascii=False)
            )
            if item.supersedes_id is not None:
                target = item.supersedes_id
                if target not in previous or target in corrected or target >= record_id:
                    raise ValueError("lookup_input_evidence_correction")
                validate_correction(previous[target], item, previous_id=target)
                corrected.add(target)
            if record["status"] in ("matched", "multiple_candidates"):
                candidates = [p for p in projects if p["project_uuid"] == identity[0]]
                if len(candidates) != 1:
                    raise ValueError("lookup_input_evidence_matched_identity")
                project = candidates[0]
                if (
                    identity[1] != "matched"
                    or item.kind != "build"
                    or item.service_id != project.get("service_id")
                    or item.deployable_id != project.get("deployable_id")
                    or item.artifact_id != project.get("dt_version")
                    or item.observed_at is None
                ):
                    raise ValueError("lookup_input_evidence_matched_identity")
            previous[record_id] = item
    expected = Counter((p["project_uuid"], p["status"]) for p in projects)
    if Counter(observed) != expected:
        raise ValueError("lookup_input_evidence_project_mismatch")
