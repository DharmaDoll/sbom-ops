# 文書配置表

操作の入口は[運用ガイド](operations.md)。この表は、説明を追加・修正するときの配置先を定める。
最初の分割は[#26](https://github.com/DharmaDoll/sbom-ops/issues/26)、
入口と短い手順の再統合は[#28](https://github.com/DharmaDoll/sbom-ops/issues/28)を参照。
進捗・公開・検証記録は各Issueで管理する。

## 文書の役割

| 文書 | ここに集約する内容 | 他ページへ委ねる内容 |
| --- | --- | --- |
| [README](../README.md) | 製品概要・導入コマンド・最初の入口 | 担当別フロー、日常運用の詳細 |
| [operations](operations.md) | 作業選択・5つの利用シーン・担当・日常確認・ログ・台帳復旧 | 長い初回教材、資産・調査・任意連携の詳細 |
| [getting-started](getting-started.md) | 架空例と一件のDT Findingを追う初回演習 | 日常運用の正本 |
| [assets](assets.md) | 資産登録・成果物根拠・配備申告・変更・廃止 | CIでの生成器設定 |
| [sbom-producers](sbom-producers.md) | 生成・投入順序と引渡し、npm・uv・Trivy／Actions例、投入失敗時の再開 | 品質評価CLIの詳しい説明 |
| [sbom-input](sbom-input.md) | 元SBOMの記載品質、方針・終了コード、品質結果の保存 | 生成・DT投入の手順 |
| [investigation](investigation.md) | 速報・CVE逆引き、PoC・CISA・VEX受領時の確認 | 自動的な対応判断 |
| [slack-notifications](slack-notifications.md)／[github-sync](github-sync.md) | 各連携の明示送信・監査・復旧と有効化条件 | 通常運用の必須手順 |
| [DT setup](dependency-track/setup.md) | DT構築・キー・接続確認・保守責任・cleanup・本番前チェック | sbom-opsの日常確認 |
| [DT api](dependency-track/api.md) | API・権限・クライアント実装の参照 | 操作教材 |
| [data-sources](data-sources.md)／[priority-policy](priority-policy.md) | 情報源の選定根拠・優先度方針 | CLI操作の繰返し |
| [vex](vex.md)／[ADR](adr/README.md) | 設計案・設計判断と制約 | 未実装機能の利用手順 |
| [SPEC](../SPEC.md) | 状態・識別・判定・失敗時動作の契約 | 初見向けの操作教材 |
| [ROADMAP](../ROADMAP.md)／[plan](../plan.md) | 成果の方向性・実装順序／着手時の設計案 | 現在の操作、進捗・完了条件の二重管理 |
| [DT実験台帳](../lab/dependency_track/EXPERIMENTS.md)／[速報実験台帳](../lab/exploit_intelligence/EXPERIMENTS.md) | 実験の観測事実と解釈 | 通常運用の手順 |

長い手順を一冊へ戻すと、初回演習・日常確認・任意の外部書込みが混ざる。
これらは分離し、利用シーンと短い日常手順だけを運用ガイドへまとめる。
SBOM生成と品質評価も、担当・入力・成功条件が異なるので正本を分ける。

## operationsの全節と移動先

現在の構成と移動先は[運用ガイドの目次](operations.md#目次)を正本とする。
初回分割以前の見出しには[旧リンクからの案内](operations.md#旧リンクからの案内)を残す。
同じ見出し・移動先の全件表はここで再管理しない。
日常確認・ログ・復旧は本文をoperationsへ戻し、旧アンカーから直接読める。

## use-casesの全節と整理先

5つの場面と役割表は[運用ガイドの利用者の作業一覧](operations.md#利用者の作業一覧いつどこで何をするか)へ統合した。
`use-cases.md`は旧見出しごとの移動案内だけを保持する。
`daily-operations.md`と`dependency-track/operations.md`も同じ方針で旧リンクを維持する。
READMEと現在の操作ページからは統合先へ直接リンクする。

## 現行仕様との照合で直す記載

仕様との不一致は、[SPEC](../SPEC.md)と現行CLIを確認して操作の正本だけを直す。
過去の修正項目・完了記録は[#26](https://github.com/DharmaDoll/sbom-ops/issues/26)に残す。
実装済み・未提供・導入者が設定する内容を区別し、移動だけで機能の提供範囲を変えない。

## 参照の維持方針

旧ページと明示アンカーは、既存Issue・外部ブックマークのための移動案内として残す。
ファイル数を減らすために削除してリンクを切らず、本文の重複をなくす。
固定コミットへの参照は当時の検証根拠なので変更しない。
リンクの検査では、通常リンクだけでなく変更前の全見出し・明示アンカーの保持も確認する。

## 後続の文書拡張

追加内容はまず上表の正本へ入れる。既存ページと同じ担当・入力・作業目的なら節を追加し、
別ページにするのは独立した長い手順や設計判断が必要な場合に限る。
概要には結論と正本へのリンクを置き、コマンド列・担当表・失敗時手順を複製しない。
SPECには動作契約、操作ページには利用者が行うこと、Issueには進捗を記録する。
