"""Bounded offline loading of a successful sync document, never API access."""

from pathlib import Path

from sbom_ops.domain.lookup_input import validate_lookup_envelope
from sbom_ops.services.sbom_quality_input import read_quality_json


def read_lookup_document(path: Path) -> dict[str, object]:
    document, _ = read_quality_json(path, max_bytes=8 * 1024 * 1024, max_depth=64)
    return validate_lookup_envelope(document)
