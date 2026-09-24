"""Bounded, explicitly authorized instance-wide OSV configuration experiment."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class OsvPlan:
    before: str | None
    after: str = "Go;npm;PyPI;RubyGems"


def plan_osv(rows: Any) -> OsvPlan:
    """Reject unexpected baselines and expose only the selected safe setting."""
    if not isinstance(rows, list):
        raise ValueError("configuration response must be a list")
    selected: dict[str, Any] = {}
    names = {
        "google.osv.enabled": "STRING",
        "google.osv.alias.sync.enabled": "BOOLEAN",
        "github.advisories.enabled": "BOOLEAN",
    }
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid configuration entry")
        name = row.get("propertyName")
        if row.get("groupName") != "vuln-source" or name not in names:
            continue
        if name in selected or row.get("propertyType") != names[name]:
            raise ValueError("duplicate or mistyped source setting")
        selected[name] = row.get("propertyValue")
    if set(selected) != set(names):
        raise ValueError("required source settings missing")
    if any(selected[n] != "false" for n in names if n != "google.osv.enabled"):
        raise ValueError("OSV alias sync and GHSA must remain disabled")
    before = selected["google.osv.enabled"]
    if isinstance(before, str) and before:
        ecosystems = before.split(";")
        desired = OsvPlan(None).after.split(";")
        if len(ecosystems) == len(desired) and set(ecosystems) == set(desired):
            before = OsvPlan(None).after
    if before not in (None, "", OsvPlan(None).after):
        raise ValueError("unexpected OSV baseline; review existing ecosystems")
    return OsvPlan(before)


class SourceClient(Protocol):
    def read_config_properties(self) -> Any: ...

    def update_config_property(
        self, group: str, name: str, value: str, property_type: str
    ) -> Any: ...


def configure_osv(
    client: SourceClient,
    *,
    audit_path: Path,
    execute: bool = False,
    recovery_evidence: Path | None = None,
) -> OsvPlan:
    """Write intent durably before a non-retried POST, then verify readback.

    Recovery evidence is an operator attestation, not automatic proof of restore.
    Calls must be serialized operationally: the DT endpoint has no CAS contract.
    """
    evidence_hash = None
    if execute:
        if recovery_evidence is None:
            raise ValueError("execution requires reviewed recovery evidence")
        evidence = recovery_evidence.read_bytes()
        if not evidence.strip():
            raise ValueError("recovery evidence is empty")
        evidence_hash = hashlib.sha256(evidence).hexdigest()
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidental overwriting of an earlier audit.
    with audit_path.open("x", encoding="utf-8") as audit:

        def record(event: str, **fields: Any) -> None:
            audit.write(
                json.dumps(
                    {
                        "event": event,
                        "at": datetime.now(UTC).isoformat(),
                        **fields,
                    },
                    sort_keys=True,
                )
                + "\n"
            )
            audit.flush()
            os.fsync(audit.fileno())

        record("started", execute=execute, recovery_sha256=evidence_hash)
        try:
            plan = plan_osv(client.read_config_properties())
            record("plan", **asdict(plan))
            if not execute:
                record("dry_run")
                return plan
            if plan_osv(client.read_config_properties()) != plan:
                raise ValueError("configuration changed during preflight")
            if plan.before != plan.after:
                record("write_intent", **asdict(plan))
                client.update_config_property(
                    "vuln-source", "google.osv.enabled", plan.after, "STRING"
                )
            after = plan_osv(client.read_config_properties())
            if after.before != plan.after:
                raise ValueError("OSV readback mismatch; inspect instance")
            record("configuration_verified", synchronization="not_verified")
            return plan
        except Exception as exc:
            # Do not persist server payloads or arbitrary exception strings.
            record("failed", error_type=type(exc).__name__)
            raise
