"""Synthetic items distinguish source, fragment and article corrections."""

from dataclasses import replace

import pytest

from sbom_ops.domain.advisory_feed import AdvisoryFeedItem


def item(fragment: str = "1") -> AdvisoryFeedItem:
    url = f"https://example.test/wr/example.html#{fragment}"
    return AdvisoryFeedItem(
        source_id="jpcert",
        item_key=url,
        url=url,
        title="架空の注意喚起",
        source_fields=(
            ("dc:identifier", "wr-example"),
            ("description", "CVE-2026-1000"),
        ),
    )


def test_identity_keeps_source_and_fragment() -> None:
    first, second = item("1"), item("2")
    assert first.identity == ("jpcert", first.url)
    assert first.identity != second.identity
    assert first.identity != replace(first, source_id="other").identity
    assert len({first.identity, second.identity, item("1").identity}) == 2


def test_fingerprint_is_stable_but_detects_changes_without_new_date() -> None:
    first = item()
    assert len(first.fingerprint) == 64
    assert first.fingerprint == item().fingerprint
    assert (
        first.fingerprint
        == replace(
            first, source_fields=tuple(reversed(first.source_fields))
        ).fingerprint
    )
    for changed in (
        replace(first, title="訂正"),
        replace(first, source_fields=(("description", "訂正された内容"),)),
        replace(
            first,
            source_fields=(*first.source_fields, ("dc:date", "2026-10-01T00:00:00Z")),
        ),
    ):
        assert changed.identity == first.identity
        assert changed.fingerprint != first.fingerprint


@pytest.mark.parametrize(
    "changes",
    [
        {"source_id": ""},
        {"item_key": "bad\nkey"},
        {"title": "bad\x1btitle"},
        {"url": "javascript:alert(1)"},
        {"url": "https://user:secret@example.test/a"},
        {"source_fields": (("description", "a"), ("description", "b"))},
        {"source_fields": (("fetched_at", "2026-10-27"),)},
        {"source_fields": (("description", "x" * 65537),)},
    ],
)
def test_invalid_or_observation_fields_are_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        replace(item(), **changes)


def test_utf8_limit_and_multiline_body_without_body_repr() -> None:
    boundary = replace(item(), source_fields=(("description", "x" * 65536),))
    assert len(boundary.fingerprint) == 64
    body = "架空の本文\n次の行\tCVE-2026-1000"
    multiline = replace(item(), source_fields=(("description", body),))
    assert "架空の本文" not in repr(multiline)
    assert multiline.fingerprint != item().fingerprint
    with pytest.raises(ValueError):
        replace(item(), source_fields=(("description", "あ" * 21846),))


@pytest.mark.parametrize(
    "fields",
    [
        [("description", "mutable")],
        (["description", "mutable"],),
        (("description", None),),
        (("channel:lastBuildDate", "2026-10-27"),),
    ],
)
def test_field_structure_is_immutable_and_article_scoped(fields: object) -> None:
    with pytest.raises(ValueError):
        replace(item(), source_fields=fields)


def test_opaque_item_key_is_not_assumed_to_be_a_url() -> None:
    notice = replace(item(), source_id="vendor", item_key="urn:example:notice:42")
    assert notice.identity == ("vendor", "urn:example:notice:42")
    assert notice.url == item().url


def test_cve_mentions_keep_field_provenance_and_ignore_identifier_fields() -> None:
    notice = replace(
        item(),
        title="CVE-2026-1000",
        source_fields=(
            ("description", "CVE-2026-1000 / CVE-2026-2000 / CVE-2026-2000"),
            ("guid", "CVE-2026-9999"),
        ),
    )
    assert notice.cve_mentions == (
        ("CVE-2026-1000", "description"),
        ("CVE-2026-1000", "title"),
        ("CVE-2026-2000", "description"),
    )
    assert replace(notice, title="No identifier", source_fields=()).cve_mentions == ()


def test_cve_extraction_does_not_truncate_invalid_tokens() -> None:
    notice = replace(
        item(),
        title="（CVE-2026-1234）",
        source_fields=(
            (
                "description",
                "XCVE-2026-5555 CVE-2026-6666suffix CVE-2026-123 "
                "CVE-2026-12345678901234567890 cve-2026-7777",
            ),
        ),
    )
    assert notice.cve_mentions == (("CVE-2026-1234", "title"),)
