"""Exact read-only selection of existing Finding review rows."""

import re
from collections.abc import Sequence
from dataclasses import dataclass

from sbom_ops.domain.review import FindingReview


@dataclass(frozen=True)
class LookupQuery:
    kind: str
    value: str
    source: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in ("cve", "vulnerability", "purl"):
            raise ValueError("unsupported lookup kind")
        _validate_text(self.value, 2048)
        if self.kind == "vulnerability":
            _validate_text(self.source, 128)
        elif self.source is not None:
            raise ValueError("source is only valid for vulnerability lookup")
        if self.kind == "cve" and not re.fullmatch(
            r"CVE-[0-9]{4}-[0-9]{4,19}", self.value
        ):
            raise ValueError("invalid CVE query")
        # Only an exact key is compared: no decoding or canonicalization of PURLs.
        if self.kind == "purl" and (
            not re.fullmatch(r"pkg:[a-z][a-z0-9.+-]*/\S+", self.value)
        ):
            raise ValueError("invalid PURL query")

    def matches_identity(
        self, identifier: str, source: str | None, purl: str | None
    ) -> bool:
        if self.kind == "purl":
            return purl == self.value
        return identifier == self.value and (
            self.kind == "cve" or source == self.source
        )


def _validate_text(value: object, limit: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or value != value.strip()
        or not value.isprintable()
    ):
        raise ValueError("invalid lookup text")


def lookup_reviews(
    rows: Sequence[FindingReview], query: LookupQuery
) -> tuple[FindingReview, ...]:
    def matches(row: FindingReview) -> bool:
        item = row.assessment
        return query.matches_identity(
            item.vulnerability_id, item.vulnerability_source, item.component_purl
        )

    return tuple(row for row in rows if matches(row))
