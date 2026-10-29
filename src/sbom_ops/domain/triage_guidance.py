"""Human follow-up suggestions; no execution, priority changes or SLA adoption."""

from dataclasses import asdict, dataclass

from sbom_ops.domain.triage_reference import ReferenceResult


@dataclass(frozen=True)
class TriageAction:
    code: str
    reason: str
    role: str
    assignee: str | None
    instruction: str


_CONFIRM = {
    "cve_unresolved": (
        "security",
        "元の脆弱性IDと出典を確認し、対象CVEとの対応を確認してください。",
    ),
    "asset_link_unverified": (
        "asset",
        "Projectとサービス・成果物の対応を確認し、台帳で承認してください。",
    ),
    "public_exposure": (
        "asset",
        "対象環境・成果物の稼働と外部公開範囲を確認し、有効な申告を登録してください。",
    ),
    "kev": (
        "security",
        "対象CVEのKEV掲載状況と、取得の成功・完全性・鮮度を確認してください。",
    ),
    "automatable": (
        "security",
        "対象CVEの自動化可能性について、CISA評価の版・根拠・有効期限を確認してください。"
        "PoC有無で代用しないでください。",
    ),
    "technical_impact": (
        "security",
        "対象CVEの部分制御・完全制御について、CISA評価の版・根拠・有効期限を確認してください。",
    ),
}


def suggest_triage_actions(
    reference: ReferenceResult, *, asset_owner: str | None
) -> tuple[TriageAction, ...]:
    """Only asset-role actions may use the verified asset's registered owner."""
    actions = []
    if asset_owner is None:
        actions.append(
            TriageAction(
                "identify_asset_owner",
                "owner_unassigned",
                "asset",
                None,
                "対象資産の担当を確認してください。別資産の担当を流用しないでください。",
            )
        )
    for missing in reference.missing:
        factor, _, status = missing.partition(":")
        role, instruction = _CONFIRM.get(
            factor, ("security", "参照判定の不足理由と元の根拠を確認してください。")
        )
        actions.append(
            TriageAction(
                "confirm_" + factor,
                status or missing,
                role,
                asset_owner if role == "asset" else None,
                instruction,
            )
        )
    if not reference.missing:
        actions.append(
            TriageAction(
                "review_remediation",
                "reference_matched",
                "asset",
                asset_owner,
                "参照期限区分と対象環境を踏まえ、セキュリティ担当と修正・緩和の対応計画を"
                "確認してください。実期限の決定ではありません。",
            )
        )
        if reference.forensic_triage == "specified_by_reference":
            actions.append(
                TriageAction(
                    "plan_forensic_triage",
                    "specified_by_reference",
                    "security",
                    None,
                    "修正・緩和に加え、侵害確認の担当と調査計画を確認してください。自動調査や侵害判定は行いません。",
                )
            )
    return tuple(actions)


def actions_as_dict(actions: tuple[TriageAction, ...]) -> list[dict[str, object]]:
    return [asdict(action) for action in actions]
