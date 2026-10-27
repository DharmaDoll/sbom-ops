"""Read recorded revisions; never infer changes to discarded article bodies."""

from pathlib import Path

from sbom_ops.domain.advisory_feed import revision_change
from sbom_ops.storage.advisory_feed import AdvisoryFeedStore


def advisory_history(db: Path, *, source_id: str, item_key: str) -> dict[str, object]:
    with AdvisoryFeedStore(db, read_only=True) as store:
        rows = store.history(source_id, item_key)
    revisions = []
    previous = None
    for row in rows:
        revisions.append({**row, "change": revision_change(previous, row)})
        previous = row
    return {
        "status": "recorded_history" if rows else "no_saved_history",
        "source_id": source_id,
        "item_key": item_key,
        "revisions": revisions,
        "warnings": [
            "保存した観測履歴であり、配信元のすべての訂正を網羅しません。",
            "本文は保存しないため本文差分は表示できません。指紋だけが変わる場合もあります。",
            "履歴なしは記事不存在・影響なし・解決済みを意味しません。",
        ],
    }
