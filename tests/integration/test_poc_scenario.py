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
        "架空の対応を期限付き採用→PoC報告2件を表示→期限切れ・取消後は不明。優先度は不変。",
        "架空のCVE候補をSQLiteへ保存。未採用のためPoC紐付け・優先度は変更しません。",
        "CVE対応なし: 脆弱性は1件、取得対象CVEは0件。PoCなしとは判断しません。",
        "取得時=reported 件数=2 6時間後=unknown",
        "取得時=not_observed 件数=0 6時間後=unknown",
        "取得時=unknown 件数=None 6時間後=unknown",
        "未解決ID: GHSA-unresolved",
        "SQLiteから再読込済み。再実行で成功済み2件の取得を省略。",
        "再試行の待機中は通信なし。次回可能時刻:",
    ):
        assert expected in completed.stdout
