from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_offline_poc_scenario() -> None:
    scenario = Path(__file__).parents[2] / "examples" / "poc_scenario.py"
    completed = subprocess.run(
        [sys.executable, str(scenario)], check=True, capture_output=True, text=True
    )
    assert completed.stderr == ""
    for expected in (
        "外部通信なし",
        "取得時=reported 件数=2 6時間後=unknown",
        "取得時=not_observed 件数=0 6時間後=unknown",
        "取得時=unknown 件数=None 6時間後=unknown",
        "未解決ID: GHSA-unresolved",
        "SQLiteから再読込済み。再実行で成功済み2件の取得を省略。",
    ):
        assert expected in completed.stdout
