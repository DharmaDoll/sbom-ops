import hashlib
import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from sbom_ops.domain.sbom_quality_input import QualityInputError, QualityInputLimits
from sbom_ops.services.sbom_quality_input import read_quality_input


def test_reads_original_bytes_and_nested_component_locations(tmp_path: Path) -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {"name": "app", "components": [{"name": "embedded"}]},
            "tools": {"components": [{"name": "generator"}]},
        },
        "components": [{"name": "日本語", "components": [{"name": "nested"}]}],
    }
    raw = json.dumps(document, ensure_ascii=False, indent=2).encode() + b"\n"
    path = tmp_path / "original.json"
    path.write_bytes(raw)

    result = read_quality_input(path)

    assert result.document == document
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert result.byte_count == len(raw)
    assert result.component_subjects == (
        "/components/0",
        "/components/0/components/0",
        "/metadata/component",
        "/metadata/component/components/0",
    )
    assert result.limits == QualityInputLimits()
    assert path.read_bytes() == raw
    assert "日本語" not in repr(result)


def _file(tmp_path: Path, raw: bytes) -> Path:
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    return path


BASE = b'{"bomFormat":"CycloneDX","specVersion":"1.5"}'


@pytest.mark.parametrize("version", ["1.5", "1.6"])
def test_accepts_supported_versions_without_inventing_components(
    tmp_path: Path, version: str
) -> None:
    raw = BASE.replace(b"1.5", version.encode())
    result = read_quality_input(_file(tmp_path, raw))
    assert result.document["specVersion"] == version
    assert result.component_subjects == ()


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"", "invalid_json"),
        (b'{"private":', "invalid_json"),
        (b'{"x":1,"x":2}', "duplicate_json_key"),
        (b'{"x":{"private":1,"priva\\u0074e":2}}', "duplicate_json_key"),
        (b'{"x":NaN}', "invalid_json"),
        (b'{"x":Infinity}', "invalid_json"),
        (b'{"x":-Infinity}', "invalid_json"),
        (b'{"x":1e999}', "invalid_json"),
        (b'{"x":"\xff"}', "invalid_utf8"),
        (b'{"x":"\\ud800"}', "invalid_unicode"),
        (b'{"\\udfff":1}', "invalid_unicode"),
        (b"[]", "invalid_document_structure"),
        (b"null", "invalid_document_structure"),
        (b"{}", "unsupported_format"),
        (BASE.replace(b"1.5", b"1.7"), "unsupported_format"),
        (BASE.replace(b'"1.5"', b"1.5"), "unsupported_format"),
        (BASE.replace(b'"1.5"', b"[]"), "unsupported_format"),
        (BASE.replace(b"CycloneDX", b"SPDX"), "unsupported_format"),
    ],
)
def test_rejects_bad_input_without_echoing_data(
    tmp_path: Path, raw: bytes, code: str
) -> None:
    path = _file(tmp_path, raw)
    with pytest.raises(QualityInputError) as caught:
        read_quality_input(path)
    assert caught.value.code == code
    assert str(caught.value) == code
    assert path.read_bytes() == raw


@pytest.mark.parametrize(
    "name", ["max_bytes", "max_depth", "max_nodes", "max_components"]
)
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "64", None])
def test_limits_require_positive_integers(name: str, value: object) -> None:
    with pytest.raises(QualityInputError, match="^invalid_limits$"):
        QualityInputLimits(**{name: value})


def test_byte_boundary(tmp_path: Path) -> None:
    path = _file(tmp_path, BASE)
    assert read_quality_input(path, limits=QualityInputLimits(max_bytes=len(BASE)))
    with pytest.raises(QualityInputError, match="^byte_limit_exceeded$"):
        read_quality_input(path, limits=QualityInputLimits(max_bytes=len(BASE) - 1))


def test_node_boundary_includes_values_but_not_keys(tmp_path: Path) -> None:
    path = _file(tmp_path, BASE)
    assert read_quality_input(path, limits=QualityInputLimits(max_nodes=3))
    with pytest.raises(QualityInputError, match="^node_limit_exceeded$"):
        read_quality_input(path, limits=QualityInputLimits(max_nodes=2))


def test_depth_boundary_and_quoted_delimiters(tmp_path: Path) -> None:
    document = json.loads(BASE)
    document["custom"] = [{"value": '{[\\"\\\\]}'}]
    path = _file(tmp_path, json.dumps(document).encode())
    assert read_quality_input(path, limits=QualityInputLimits(max_depth=3))
    with pytest.raises(QualityInputError, match="^depth_limit_exceeded$"):
        read_quality_input(path, limits=QualityInputLimits(max_depth=2))


def test_depth_guard_runs_before_json_decoder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*args: object, **kwargs: object) -> None:
        pytest.fail("decoder must not see excessive nesting")

    path = _file(tmp_path, b"[" * 5000 + b"]" * 5000)
    monkeypatch.setattr("sbom_ops.services.sbom_quality_input.json.loads", unexpected)
    with pytest.raises(QualityInputError, match="^depth_limit_exceeded$"):
        read_quality_input(path)


def test_component_boundary_counts_metadata_and_nested_but_not_tools(
    tmp_path: Path,
) -> None:
    document = json.loads(BASE)
    document["metadata"] = {"component": {"components": [{}]}, "tools": [{"name": "x"}]}
    document["components"] = [{}]
    path = _file(tmp_path, json.dumps(document).encode())
    assert (
        len(
            read_quality_input(
                path, limits=QualityInputLimits(max_components=3)
            ).component_subjects
        )
        == 3
    )
    with pytest.raises(QualityInputError, match="^component_limit_exceeded$"):
        read_quality_input(path, limits=QualityInputLimits(max_components=2))


@pytest.mark.parametrize(
    ("extra", "code"),
    [
        ({"metadata": None}, "invalid_document_structure"),
        ({"metadata": {"component": None}}, "invalid_component_structure"),
        ({"components": None}, "invalid_component_structure"),
        ({"components": [False]}, "invalid_component_structure"),
        ({"components": [{"components": {}}]}, "invalid_component_structure"),
    ],
)
def test_rejects_unwalkable_structure(
    tmp_path: Path, extra: dict[str, object], code: str
) -> None:
    path = _file(tmp_path, json.dumps(json.loads(BASE) | extra).encode())
    with pytest.raises(QualityInputError, match=f"^{code}$"):
        read_quality_input(path)


def test_read_failure_hides_path(tmp_path: Path) -> None:
    with pytest.raises(QualityInputError, match="^read_failed$"):
        read_quality_input(tmp_path / "private-missing-file")


def test_directory_and_fifo_rejected_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    def unexpected(*args: object, **kwargs: object) -> None:
        pytest.fail("special files must not be opened")

    monkeypatch.setattr("sbom_ops.services.sbom_quality_input.os.open", unexpected)
    for path in (tmp_path, fifo, Path("/dev/null")):
        with pytest.raises(QualityInputError, match="^not_regular_file$"):
            read_quality_input(path)


def test_bom_urls_never_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*args: object, **kwargs: object) -> None:
        pytest.fail("network use is prohibited")

    monkeypatch.setattr(socket, "socket", unexpected)
    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    document = json.loads(BASE) | {"$schema": "https://example.invalid/schema"}
    path = _file(tmp_path, json.dumps(document).encode())
    assert read_quality_input(path).document == document


def test_original_whitespace_changes_identity_not_decoded_document(
    tmp_path: Path,
) -> None:
    path = _file(tmp_path, BASE)
    first = read_quality_input(path)
    path.write_bytes(BASE + b"\n")
    second = read_quality_input(path)
    assert first.document == second.document
    assert first.sha256 != second.sha256
    assert first.byte_count + 1 == second.byte_count


def test_opened_descriptor_rechecked_and_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _file(tmp_path, BASE)
    fifo = tmp_path / "swapped-pipe"
    os.mkfifo(fifo)
    original_open = os.open
    descriptors = []

    def swapped_open(path: Path, flags: int) -> int:
        assert flags & os.O_NONBLOCK
        fd = original_open(fifo, flags)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr("sbom_ops.services.sbom_quality_input.os.open", swapped_open)
    with pytest.raises(QualityInputError, match="^not_regular_file$"):
        read_quality_input(path)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_growth_after_stat_cannot_bypass_byte_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _file(tmp_path, BASE + b" " * 100)
    original_fstat = os.fstat

    def smaller_stat(fd: int) -> SimpleNamespace:
        return SimpleNamespace(st_mode=original_fstat(fd).st_mode, st_size=1)

    monkeypatch.setattr("sbom_ops.services.sbom_quality_input.os.fstat", smaller_stat)
    with pytest.raises(QualityInputError, match="^byte_limit_exceeded$"):
        read_quality_input(path, limits=QualityInputLimits(max_bytes=len(BASE)))


def test_fixture_can_be_read_without_claiming_compliance() -> None:
    path = Path("examples/sboms/vulnerable-demo.cdx.json")
    before = path.read_bytes()
    result = read_quality_input(path)
    assert len(result.component_subjects) == 5
    assert result.sha256 == hashlib.sha256(before).hexdigest()
    assert path.read_bytes() == before
