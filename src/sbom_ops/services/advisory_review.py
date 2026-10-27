"""Join feed mentions to one validated saved sync snapshot, without writes."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sbom_ops.domain.advisory_feed import AdvisoryFeedItem
from sbom_ops.domain.advisory_poll import poll_view
from sbom_ops.domain.lookup import LookupQuery
from sbom_ops.services.lookup import lookup_validated_document
from sbom_ops.services.lookup_input import read_lookup_document
from sbom_ops.storage.advisory_feed import AdvisoryFeedStore


def review_saved_advisories(
    db: Path,
    findings: Path,
    *,
    source_id: str,
    after_id: int = 0,
    limit: int = 100,
    max_age: timedelta = timedelta(hours=1),
) -> dict[str, object]:
    with AdvisoryFeedStore(db, read_only=True) as store:
        rows, state = store.latest_with_state(source_id, after_id=after_id, limit=limit)
    result = _review_metadata(tuple(row["metadata"] for row in rows), findings)
    result["poll"] = poll_view(state, now=datetime.now(UTC), max_age=max_age)
    for article, row in zip(result["articles"], rows, strict=True):
        for key in ("record_id", "first_seen_at", "last_seen_at"):
            article[key] = row[key]
    result["next_after_id"] = rows[-1]["record_id"] if len(rows) == limit else None
    result["warnings"].append(
        "保存済み記事の最新の版だけを照合します。ページ間の更新は固定しません。"
    )
    return result


def review_advisories(
    items: tuple[AdvisoryFeedItem, ...], findings: Path
) -> dict[str, object]:
    if not isinstance(items, tuple) or len(items) > 500:
        raise ValueError("advisory_review_item_limit")
    if any(not isinstance(item, AdvisoryFeedItem) for item in items):
        raise ValueError("advisory_review_invalid_item")
    if len({item.identity for item in items}) != len(items):
        raise ValueError("advisory_review_duplicate_item")
    return _review_metadata(tuple(item.metadata for item in items), findings)


def _review_metadata(
    metadata: tuple[dict[str, object], ...], findings: Path
) -> dict[str, object]:
    """Internal input comes only from validated items or validated stored records."""
    cves = sorted({cve for item in metadata for cve, _ in item["cve_mentions"]})
    if len(cves) > 1000:
        raise ValueError("advisory_review_cve_limit")
    # Read once: all article queries must refer to the same validated snapshot.
    document = read_lookup_document(findings)
    lookups = {
        cve: lookup_validated_document(document, LookupQuery("cve", cve))
        for cve in cves
    }
    articles = []
    for item in metadata:
        mentioned = sorted({cve for cve, _ in item["cve_mentions"]})
        articles.append(
            {
                "article": item,
                "status": "cve_observed" if mentioned else "cve_not_observed",
                "cves": mentioned,
            }
        )
    return {
        "scope": "saved_sync_only",
        "source_run_id": document["run_id"],
        "articles": articles,
        "lookups": lookups,
        "warnings": [
            "速報のCVE言及は、自社資産への影響や実悪用を証明しません。",
            "CVE未取得は未採番とは限りません。原文を確認してください。",
            "検索は保存済みrunの範囲だけです。一致なしは影響なしではありません。",
        ],
    }
