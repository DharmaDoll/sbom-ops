"""Synthetic RSS only: no live articles, networking or database writes."""

import pytest

from sbom_ops.services.advisory_feed_parser import parse_advisory_feed

RDF = b"""<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>Example</title></channel>
<item rdf:about="https://example.test/wr#1"><title>CVE-2026-1000</title>
<link>https://example.test/wr#1</link><dc:identifier>same</dc:identifier>
<dc:date>2026-10-27T10:00+09:00</dc:date></item>
<item rdf:about="https://example.test/wr#2"><title>No CVE supplied</title>
<link>https://example.test/wr#2</link><dc:identifier>same</dc:identifier></item>
</rdf:RDF>"""

RSS = b"""<rss version="2.0"><channel><title>Example</title>
<item><title>Example notice</title><link>https://example.test/notice</link>
<guid isPermaLink="false">urn:notice:1</guid>
<pubDate>Tue, 27 Oct 2026 01:00:00 +0000</pubDate>
<description>CVE-2026-1000 and CVE-2026-2000</description></item>
</channel></rss>"""


def test_rdf_keeps_fragment_items_and_missing_date() -> None:
    result = parse_advisory_feed(RDF, source_id="jpcert")
    assert len(result) == 2
    assert result[0].item_key == "https://example.test/wr#1"
    assert result[1].item_key == "https://example.test/wr#2"
    assert "dc:date" not in dict(result[1].source_fields)
    assert result[0].cve_mentions == (("CVE-2026-1000", "title"),)
    assert result[1].cve_mentions == ()


def test_rss_keeps_opaque_guid_and_original_date() -> None:
    result = parse_advisory_feed(RSS, source_id="ubuntu")
    assert len(result) == 1
    assert result[0].item_key == "urn:notice:1"
    assert dict(result[0].source_fields)["pubDate"] == "Tue, 27 Oct 2026 01:00:00 +0000"
    assert result[0].cve_mentions == (
        ("CVE-2026-1000", "description"),
        ("CVE-2026-2000", "description"),
    )


@pytest.mark.parametrize(
    "raw,source",
    [
        (b'<!DOCTYPE rss [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss/>', "ubuntu"),
        (b"<rss><channel>&unknown;</channel></rss>", "ubuntu"),
        (b"<html/>", "ubuntu"),
        (b'<rss version="2.0"/>', "ubuntu"),
        (
            RSS.replace(
                b"<title>Example notice</title>", b"<title>A</title><title>B</title>"
            ),
            "ubuntu",
        ),
        (
            RDF.replace(
                b"<link>https://example.test/wr#1</link>",
                b"<link>https://example.test/wr#9</link>",
            ),
            "jpcert",
        ),
        (RSS.replace(b"urn:notice:1", b""), "ubuntu"),
        (RDF.replace(b"2026-10-27T10:00+09:00", b"2026-10-27"), "jpcert"),
        (RSS, "unknown"),
        (b"x" * (1048576 + 1), "ubuntu"),
        (b"<a>" * 33 + b"</a>" * 33, "ubuntu"),
    ],
    ids=[
        "dtd",
        "entity",
        "html",
        "channel",
        "duplicate-title",
        "identity",
        "guid",
        "date",
        "source",
        "size",
        "depth",
    ],
)
def test_invalid_feed_is_not_empty_success(raw: bytes, source: str) -> None:
    with pytest.raises(ValueError):
        parse_advisory_feed(raw, source_id=source)


def test_duplicate_items_are_rejected_instead_of_overwritten() -> None:
    raw = RDF.replace(b"wr#2", b"wr#1")
    with pytest.raises(ValueError, match="duplicate_item"):
        parse_advisory_feed(raw, source_id="jpcert")


def test_no_network_and_no_cdata_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    raw = RSS.replace(
        b"CVE-2026-1000 and CVE-2026-2000",
        b'<![CDATA[<a href="https://untrusted.example">CVE-2026-1000</a>]]>',
    )
    result = parse_advisory_feed(raw, source_id="ubuntu")
    assert result[0].cve_mentions == (("CVE-2026-1000", "description"),)


def test_utf16_dtd_is_rejected_before_entity_processing() -> None:
    raw = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<!DOCTYPE rss [<!ENTITY x "expanded">]><rss/>'
    ).encode("utf-16")
    with pytest.raises(ValueError, match="dtd_or_entity"):
        parse_advisory_feed(raw, source_id="ubuntu")
