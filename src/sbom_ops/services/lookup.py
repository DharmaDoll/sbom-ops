"""Read a saved sync result and select rows, without any write or refresh."""

from dataclasses import asdict
from pathlib import Path

from sbom_ops.domain.lookup import LookupQuery
from sbom_ops.services.lookup_input import read_lookup_document


def lookup_file(path: Path, query: LookupQuery) -> dict[str, object]:
    document = read_lookup_document(path)
    return lookup_validated_document(document, query)


def lookup_validated_document(
    document: dict[str, object], query: LookupQuery
) -> dict[str, object]:
    """Select from a document already checked by read_lookup_document."""
    selected = [
        row
        for row in document["review_queue"]
        if query.matches_identity(
            row["vulnerability_id"], row["vulnerability_source"], row["component_purl"]
        )
    ]
    results = []
    for row in selected:
        results.append(
            {
                "finding": row,
                "lifecycle_evidence_status": document["lifecycle_evidence_status"],
                "lifecycle_evidence": [
                    view
                    for view in document["lifecycle_evidence"]
                    if view["project_uuid"] == row["project_uuid"]
                ],
            }
        )
    return {
        "status": "matched" if results else "no_match_in_input",
        "scope": "saved_sync_only",
        "source_run_id": document["run_id"],
        "query": asdict(query),
        "input_finding_count": document["findings_processed"],
        "input_project_count": document["projects_processed"],
        "matched_finding_count": len(results),
        "warnings": [
            "保存時点の入力だけを検索しています。現在の配置やDT全体の網羅性を保証しません。",
            "一致なしは影響なし・修正済みの意味ではありません。",
            "CVEは主IDだけを検索し、alias候補やPoC用対応を含めません。",
        ],
        "results": results,
    }
