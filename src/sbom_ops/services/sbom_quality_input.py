"""Read an original local BOM without upload, URL resolution, or mutation."""

import hashlib
import json
import os
import stat
from pathlib import Path

from sbom_ops.domain.sbom_quality_input import (
    QualityInput,
    QualityInputError,
    QualityInputLimits,
    inspect_document,
)

DEFAULT_LIMITS = QualityInputLimits()


def read_quality_input(
    path: Path, *, limits: QualityInputLimits = DEFAULT_LIMITS
) -> QualityInput:
    if not isinstance(limits, QualityInputLimits):
        raise QualityInputError("invalid_limits")
    document, raw = read_quality_json(
        path, max_bytes=limits.max_bytes, max_depth=limits.max_depth
    )
    subjects = inspect_document(document, limits)
    return QualityInput(
        document=document,
        sha256=hashlib.sha256(raw).hexdigest(),
        byte_count=len(raw),
        component_subjects=subjects,
        limits=limits,
    )


def read_quality_json(
    path: Path, *, max_bytes: int, max_depth: int
) -> tuple[object, bytes]:
    """Shared bounded decoding for quality BOMs and explicit policy files."""
    if any(type(value) is not int or value <= 0 for value in (max_bytes, max_depth)):
        raise QualityInputError("invalid_limits")
    raw = _read_file(path, max_bytes)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise QualityInputError("invalid_utf8") from None
    _check_depth(text, max_depth)
    try:
        document = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except QualityInputError:
        raise
    except (ValueError, RecursionError):
        raise QualityInputError("invalid_json") from None
    return document, raw


def _read_file(path: Path, max_bytes: int) -> bytes:
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise QualityInputError("not_regular_file")
        # Recheck the opened descriptor. Nonblocking open prevents a FIFO swap
        # between stat and open from waiting for a writer on POSIX platforms.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise QualityInputError("not_regular_file")
            if info.st_size > max_bytes:
                raise QualityInputError("byte_limit_exceeded")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(max_bytes + 1)
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        if isinstance(exc, QualityInputError):
            raise
        raise QualityInputError("read_failed") from None
    if len(raw) > max_bytes:
        raise QualityInputError("byte_limit_exceeded")
    return raw


def _check_depth(text: str, maximum: int) -> None:
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > maximum:
                raise QualityInputError("depth_limit_exceeded")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise QualityInputError("invalid_json")
    # Syntax and matching delimiters are still checked by the JSON decoder.


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise QualityInputError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise QualityInputError("invalid_json")
