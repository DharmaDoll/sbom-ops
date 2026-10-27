"""Immutable feed item identity and revision fingerprint; no I/O."""

import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_FIELDS = frozenset(
    ("dc:identifier", "dc:date", "pubDate", "guid", "description", "content:encoded")
)
_CVE = re.compile(r"(?<![A-Za-z0-9_-])CVE-[0-9]{4}-[0-9]{4,19}(?![A-Za-z0-9_-])")


def revision_change(
    previous: dict[str, object] | None, current: dict[str, object]
) -> dict[str, object]:
    """Compare metadata from validated stored records; never reconstruct bodies."""
    if previous is None:
        return {
            "kind": "first_observation",
            "previous_record_id": None,
            "changed_fields": [],
            "fingerprint_changed": False,
        }
    before, after = previous["metadata"], current["metadata"]
    fields = [
        key
        for key in ("title", "url", "source_fields", "cve_mentions")
        if before[key] != after[key]
    ]
    return {
        "kind": "revision",
        "previous_record_id": previous["record_id"],
        "changed_fields": fields,
        "fingerprint_changed": before["fingerprint"] != after["fingerprint"],
    }


def _text(value: object, limit: int, *, multiline: bool = False) -> None:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("advisory_invalid_text")
    if any(
        not char.isprintable() and not (multiline and char in "\n\r\t")
        for char in value
    ):
        raise ValueError("advisory_invalid_text")
    if len(value.encode("utf-8")) > limit:
        raise ValueError("advisory_text_limit")


@dataclass(frozen=True)
class AdvisoryFeedItem:
    source_id: str
    item_key: str
    url: str
    title: str
    # Transient extraction input: never automatically log or persist article bodies.
    source_fields: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        _text(self.source_id, 64)
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", self.source_id):
            raise ValueError("advisory_invalid_source")
        for value, limit in (
            (self.item_key, 4096),
            (self.url, 4096),
            (self.title, 4096),
        ):
            _text(value, limit)
            if not value or value != value.strip():
                raise ValueError("advisory_empty_or_padded_text")
        url = urlsplit(self.url)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.port not in (None, 443)
            or "\\" in self.url
            or any(char.isspace() for char in self.url)
        ):
            raise ValueError("advisory_invalid_url")
        # This validates a reference, not permission to fetch it. Adapters must
        # independently restrict network destinations and redirects.
        if not isinstance(self.source_fields, tuple) or len(self.source_fields) > len(
            _FIELDS
        ):
            raise ValueError("advisory_invalid_fields")
        seen: set[str] = set()
        for pair in self.source_fields:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError("advisory_invalid_field")
            name, value = pair
            if not isinstance(name, str) or name not in _FIELDS or name in seen:
                raise ValueError("advisory_duplicate_or_unknown_field")
            _text(value, 65536, multiline=True)
            seen.add(name)

    @property
    def metadata(self) -> dict[str, object]:
        """Persistence projection: retain provenance but not full article bodies."""
        return {
            "source_id": self.source_id,
            "item_key": self.item_key,
            "url": self.url,
            "title": self.title,
            "fingerprint": self.fingerprint,
            "source_fields": [
                list(pair)
                for pair in self.source_fields
                if pair[0] not in ("description", "content:encoded")
            ],
            "cve_mentions": [list(pair) for pair in self.cve_mentions],
        }

    @property
    def cve_mentions(self) -> tuple[tuple[str, str], ...]:
        """CVE and source field, not a claim of applicability or exploitation."""
        fields = (("title", self.title), *self.source_fields)
        return tuple(
            sorted(
                {
                    (match.group(), name)
                    for name, value in fields
                    if name in ("title", "description", "content:encoded")
                    for match in _CVE.finditer(value)
                }
            )
        )

    @property
    def identity(self) -> tuple[str, str]:
        return (self.source_id, self.item_key)

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(
            [
                1,
                self.source_id,
                self.item_key,
                self.url,
                self.title,
                sorted(self.source_fields),
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        # Change detection only; this is not a signature or authenticity proof.
        return hashlib.sha256(payload).hexdigest()
