"""Bounded offline feed parsing, never link retrieval."""

from datetime import datetime
from email.utils import parsedate_to_datetime
from xml.etree.ElementTree import Element, TreeBuilder
from xml.parsers import expat

from sbom_ops.domain.advisory_feed import AdvisoryFeedItem

_RDF = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"
_RSS = "{http://purl.org/rss/1.0/}"
_DC = "{http://purl.org/dc/elements/1.1/}"
_CONTENT = "{http://purl.org/rss/1.0/modules/content/}"


def _tree(raw: bytes) -> Element:
    if not isinstance(raw, bytes) or not raw or len(raw) > 1048576:
        raise ValueError("advisory_feed_size")
    builder = TreeBuilder()
    parser = expat.ParserCreate(namespace_separator="}")
    depth = count = 0

    def expanded(name: str) -> str:
        return "{" + name if "}" in name else name

    def start(name: str, attrs: dict[str, str]) -> None:
        nonlocal depth, count
        depth += 1
        count += 1
        if depth > 32 or count > 20000:
            raise ValueError("advisory_feed_structure_limit")
        builder.start(expanded(name), {expanded(k): v for k, v in attrs.items()})

    def end(name: str) -> None:
        nonlocal depth
        builder.end(expanded(name))
        depth -= 1

    def forbidden(*args: object) -> None:
        raise ValueError("advisory_feed_dtd_or_entity")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = builder.data
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(raw, True)
        return builder.close()
    except expat.ExpatError:
        raise ValueError("advisory_feed_invalid_xml") from None


def _value(node: Element, tag: str, *, required: bool = False) -> str | None:
    children = node.findall(tag)
    if len(children) > 1 or (required and not children):
        raise ValueError("advisory_feed_missing_or_duplicate_field")
    if not children:
        return None
    child = children[0]
    if len(child):
        raise ValueError("advisory_feed_nested_field")
    value = child.text or ""
    if required and not value.strip():
        raise ValueError("advisory_feed_empty_field")
    return value


def parse_advisory_feed(raw: bytes, *, source_id: str) -> tuple[AdvisoryFeedItem, ...]:
    if source_id not in ("jpcert", "ubuntu"):
        raise ValueError("advisory_feed_unknown_source")
    root = _tree(raw)
    ns = _RSS if source_id == "jpcert" else ""
    expected = _RDF + "RDF" if ns else "rss"
    if root.tag != expected or (not ns and root.get("version") != "2.0"):
        raise ValueError("advisory_feed_wrong_format")
    channels = root.findall(ns + "channel")
    if len(channels) != 1:
        raise ValueError("advisory_feed_channel")
    nodes = (root if ns else channels[0]).findall(ns + "item")
    if len(nodes) > 500 or len(list(root.iter(ns + "item"))) != len(nodes):
        raise ValueError("advisory_feed_item_structure")
    results = []
    seen = set()
    for node in nodes:
        title = _value(node, ns + "title", required=True)
        link = _value(node, ns + "link", required=True)
        key = node.get(_RDF + "about") if ns else _value(node, "guid", required=True)
        if not key or (ns and key != link):
            raise ValueError("advisory_feed_identity")
        fields = []
        for name, tag in (
            ("dc:identifier", _DC + "identifier"),
            ("dc:date", _DC + "date"),
            ("pubDate", "pubDate"),
            ("guid", "guid"),
            ("description", ns + "description"),
            ("content:encoded", _CONTENT + "encoded"),
        ):
            value = _value(node, tag)
            if value is not None:
                if name in ("dc:date", "pubDate"):
                    try:
                        date = (
                            datetime.fromisoformat(value)
                            if name == "dc:date"
                            else parsedate_to_datetime(value)
                        )
                        if date.tzinfo is None or date.utcoffset() is None:
                            raise ValueError("missing timezone")
                    except (ValueError, TypeError, OverflowError):
                        raise ValueError("advisory_feed_invalid_date") from None
                fields.append((name, value))
        item = AdvisoryFeedItem(source_id, key, link, title, tuple(fields))
        if item.identity in seen:
            raise ValueError("advisory_feed_duplicate_item")
        seen.add(item.identity)
        results.append(item)
    return tuple(results)
