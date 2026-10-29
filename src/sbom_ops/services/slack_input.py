"""Adapt validated sync projections to existing repair candidates, offline."""

from dataclasses import fields
from datetime import datetime

from sbom_ops.domain.asset_registry import (
    RegistryProjectObservation,
    RegistryProjectStatus,
)
from sbom_ops.domain.assets import BusinessCriticality
from sbom_ops.domain.lookup_input import validate_lookup_envelope
from sbom_ops.domain.models import AnalysisState, FindingAssessment, Priority, Severity
from sbom_ops.domain.remediation import build_remediation_groups
from sbom_ops.domain.review import FindingReview
from sbom_ops.domain.slack import (
    Notification,
    SlackPolicy,
    aware_time,
    digest,
    safe_text,
)


def notifications(
    document: dict[str, object], policy: SlackPolicy, *, observed_at: str, now: datetime
) -> tuple[Notification, ...]:
    validate_lookup_envelope(document)
    observed_at = aware_time(observed_at).isoformat()
    age = (now - aware_time(observed_at)).total_seconds()
    if not 0 <= age <= policy.max_input_age_seconds:
        raise ValueError("notification input is stale or future-dated")
    rows = []
    originals = {}
    identities = [raw["finding_key"] for raw in document["review_queue"]]
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate notification Finding identity")
    for raw in document["review_queue"]:
        values = {
            f.name: raw[f.name]
            for f in fields(FindingAssessment)
            if f.name in raw and f.name not in ("poc_identity", "analysis_detail")
        }
        for name, enum in (
            ("priority", Priority),
            ("severity", Severity),
            ("analysis_state", AnalysisState),
        ):
            values[name] = enum(values[name])
        values["rationale"] = tuple(values["rationale"])
        values["vulnerability_aliases"] = ()
        item = FindingAssessment(**values)
        # Respect analysis exclusions without making a new security decision.
        if item.is_suppressed or item.analysis_state in (
            AnalysisState.NOT_AFFECTED,
            AnalysisState.FALSE_POSITIVE,
        ):
            continue
        asset = raw["asset"]
        if asset:
            asset = RegistryProjectObservation(
                **{
                    **asset,
                    "status": RegistryProjectStatus(asset["status"]),
                    "criticality": (
                        BusinessCriticality(asset["criticality"])
                        if asset.get("criticality")
                        else None
                    ),
                }
            )
        row = FindingReview(item, raw["asset_status"], asset, ())
        originals[item.finding_key] = raw
        rows.append(row)
    groups = (
        build_remediation_groups(rows)
        if policy.grouping == "repair"
        else tuple(g for row in rows for g in build_remediation_groups((row,)))
    )
    result = []
    for group in groups:
        first = group.members[0].assessment
        # Individual fallback groups can still have a verified asset; do not
        # discard its display identity just because package identity is missing.
        asset = group.members[0].asset
        service_id = group.service_id or (asset.service_id if asset else None)
        deployable_id = group.deployable_id or (asset.deployable_id if asset else None)
        owners = sorted(
            {r.asset.owner for r in group.members if r.asset and r.asset.owner}
        )
        context = sorted(
            {
                f"{e['environment'] or '環境不明'}: {e['status']} / "
                f"{e.get('deployment_status') or '稼働不明'}"
                for r in group.members
                for e in originals[r.assessment.finding_key]["environments"]
            }
        )
        rationale = sorted({v for r in group.members for v in r.assessment.rationale})
        missing = []
        if not owners:
            missing.append("担当未割当・資産対応未確認")
        if not context:
            missing.append("稼働・影響範囲未確認")
        elif any(
            e["status"] != "reported"
            for r in group.members
            for e in originals[r.assessment.finding_key]["environments"]
        ):
            missing.append("配置申告の不足・期限切れ等を確認")
        if first.epss_score is None:
            missing.append("EPSS未取得")
        priority = group.highest_observed_priority.value
        key = (
            group.key
            if policy.grouping == "repair"
            else "finding:" + digest(group.finding_keys)
        )
        parts = {
            "priority": priority,
            "owners": owners,
            "context": context,
            "rationale": rationale,
        }
        fingerprint = digest({name: parts[name] for name in policy.change_fields})
        lines = [
            f"対応候補 {'緊急' if priority == 'P0' else '通常'} {priority}",
            f"サービス/配布単位: {safe_text(service_id)} / "
            f"{safe_text(deployable_id)}",
            f"担当: {safe_text(', '.join(owners) or '未割当')}",
            f"脆弱性/部品: {safe_text(first.vulnerability_id)} / "
            f"{safe_text(first.component_name)} {safe_text(first.component_version)}",
            f"根拠: {safe_text('; '.join(rationale), 400)}",
            f"影響候補: {len(group.finding_keys)} Finding / "
            f"{safe_text('; '.join(context) or '未確認', 400)}",
            f"不足情報: {safe_text('; '.join(missing) or '追加調査で確認')}",
            "次の行動: セキュリティ担当がDTと配置・担当を確認し、"
            "対応要否を判断して作業管理先に記録。参照をスレッドへ共有。",
            f"DT: {policy.dt_url}",
            "Project参照: "
            + safe_text(
                ", ".join(sorted({r.assessment.project_uuid for r in group.members})),
                400,
            ),
            f"詳細: {policy.report_url}",
            f"判断記録先: {policy.record_url}",
            f"観測: {observed_at} / 入力相関ID: {safe_text(document['run_id'])}",
            f"候補key: {key}",
            "投稿・反応は担当確定、例外承認、修正完了を意味しません。",
        ]
        result.append(
            Notification(
                key,
                fingerprint,
                priority,
                "\n".join(lines),
                observed_at,
                document["run_id"],
            )
        )
    return tuple(sorted(result, key=lambda n: (n.priority, n.key)))
