import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from sbom_ops import cli


@pytest.mark.parametrize("required,expected", [(False, 0), (True, 1)])
def test_quality_cli_reports_demo_without_loading_runtime_config(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    required: bool,
    expected: int,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("quality evaluation must not load DT/GitHub configuration")

    monkeypatch.setattr(cli, "load_config", forbidden)
    args = ["sbom-ops", "sbom-quality", "examples/sboms/vulnerable-demo.cdx.json"]
    if required:
        args += ["--require", "component_hash"]
    monkeypatch.setattr(sys, "argv", args)
    assert cli.main() == expected
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert captured.err == ""
    assert result["status"] == "evaluated"
    assert result["exit_code"] == expected
    assert len(result["checks"]) == 49
    assert len(result["policy"]["violations"]) == (5 if required else 0)


@pytest.mark.parametrize(
    "extra,code",
    [
        (["--max-bytes", "2"], "byte_limit_exceeded"),
        (["--max-depth", "1"], "depth_limit_exceeded"),
        (["--max-nodes", "2"], "node_limit_exceeded"),
        (["--max-components", "1"], "component_limit_exceeded"),
        (["--max-bytes", "0"], "invalid_limits"),
        (["--max-depth", "-1"], "invalid_limits"),
        (["--policy-version", "unused"], "invalid_policy"),
        (["--require", "component_hash", "--policy-version", ""], "invalid_policy"),
        (
            ["--require", "component_hash", "--require", "component_hash"],
            "invalid_policy",
        ),
    ],
)
def test_configuration_and_limit_errors_are_one_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
    code: str,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["sbom-ops", "sbom-quality", "examples/sboms/vulnerable-demo.cdx.json", *extra],
    )
    assert cli.main() == 2
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert captured.err == ""
    assert result["error"] == {"code": code}
    assert result["status"] == "error"
    assert result["exit_code"] == 2
    assert "checks" not in result
    assert "summary" not in result


@pytest.mark.parametrize(
    "raw,code",
    [
        (b'{"private-input":', "invalid_json"),
        (b'{"private-input":1,"private-input":2}', "duplicate_json_key"),
        (b'{"bomFormat":"CycloneDX","specVersion":"9.0"}', "unsupported_format"),
        (None, "read_failed"),
    ],
)
def test_file_errors_do_not_disclose_input_or_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    raw: bytes | None,
    code: str,
) -> None:
    path = tmp_path / "private-input-file.json"
    if raw is not None:
        path.write_bytes(raw)
    monkeypatch.setattr(sys, "argv", ["sbom-ops", "sbom-quality", str(path)])
    assert cli.main() == 2
    captured = capsys.readouterr()
    assert "private-input" not in captured.out + captured.err
    assert str(tmp_path) not in captured.out + captured.err
    assert json.loads(captured.out)["error"] == {"code": code}


def test_selected_present_fields_succeed_without_network(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("network use is prohibited")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "sbom-quality",
            "examples/sboms/vulnerable-demo.cdx.json",
            "--require",
            "component_name",
            "--require",
            "component_version",
            "--policy-version",
            "company-v2",
        ],
    )
    assert cli.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["policy_version"] == "company-v2"
    assert result["policy"]["mode"] == "enforce"
    assert result["policy"]["violations"] == []


def test_interrupt_has_distinct_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def interrupted(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("sbom_ops.sbom_quality_cli.evaluate_sbom_file", interrupted)
    monkeypatch.setattr(sys, "argv", ["sbom-ops", "sbom-quality", "unused.json"])
    assert cli.main() == 130
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == {"code": "interrupted"}
    assert "checks" not in result


@pytest.mark.parametrize(
    "extra,expected",
    [([], 0), (["--require", "component_hash"], 1), (["--max-bytes", "1"], 2)],
)
def test_real_process_returns_documented_exit_codes(
    extra: list[str], expected: int
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sbom_ops.cli",
            "sbom-quality",
            "examples/sboms/vulnerable-demo.cdx.json",
            *extra,
        ],
        env=os.environ | {"PYTHONPATH": str(Path("src").resolve())},
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == expected
    assert result.stderr == ""
    assert json.loads(result.stdout)["exit_code"] == expected
