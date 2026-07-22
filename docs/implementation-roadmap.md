# 今後の実装予定

この文書は、現在の実装状況と今後の実装予定を一つの一覧にまとめたもの。
優先度は次の意味で使用する。

- P0: 実運用開始の前提
- P1: 運用安定化・Security teamの実務に必要
- P2: 高度化・効率化
- P3: 将来拡張

## 現在できていること

| 項目 | 状態 | 備考 |
| --- | --- | --- |
| Domain model | 完了 | Finding、Severity、Priority、Enrichment |
| Priority Engine | 完了 | KEV、Critical、EPSS、CVSSによるP0〜P3 |
| Dependency-Track API client | MVP完了 | Project、Finding、EPSS、Analysis state読取 |
| KEV client | MVP完了 | CISA JSON feed取得 |
| GitHub Issues client | MVP完了 | 作成、更新、重複検索、クローズ |
| Orchestrator | MVP完了 | Finding取得からIssue同期まで |
| VEX/Analysis state除外 | MVP完了 | `NOT_AFFECTED`、`FALSE_POSITIVE`、抑制済み |
| Dry-run / plan | MVP完了 | 設定と書き込み予定の確認 |
| Mock fixtures / tests | MVP完了 | 14 tests、外部クライアントと同期処理 |
| 業務フロー・責務文書 | 完了 | 情報源、トリアージ、VEX運用を文書化 |

## Phase 0: 実運用接続とMVPハードニング（P0）

| タスク | 目的 | 完了条件 |
| --- | --- | --- |
| 実Dependency-Track接続検証 | APIレスポンスと権限を確認 | 実環境でProject/Finding/EPSS/Analysisを取得できる |
| 実GitHub接続検証 | Issue権限とラベルを確認 | Issue作成・更新・クローズをDry-run後に実行できる |
| APIリトライ・タイムアウト | 一時障害への耐性 | リトライ回数・待機・失敗ログが設定可能 |
| APIページネーション | 大規模Portfolio対応 | Project/Finding/Issueの全ページを処理できる |
| 非同期分析待機 | SBOM登録直後の欠損防止 | 分析完了確認または再試行ができる |
| YAML設定 | 環境変数以外の運用設定 | `SPEC.md`の設定例を読み込める |
| GitHub Actions実行例 | 定期同期を自動化 | 定期実行・Dry-run・Secrets設定例がある |
| 権限分離ドキュメント | API keyの最小権限化 | DT read用、SBOM upload用、GitHub用を分離できる |

## Phase 1: 運用ログ・監査・キャッシュ（P1）

| タスク | 目的 | 完了条件 |
| --- | --- | --- |
| 構造化同期ログ | 実行結果を追跡 | `run_id`、件数、時間、失敗を出力・保存できる |
| 監査ストア | FindingとIssueの変化を追跡 | state、priority、Issue操作の履歴を検索できる |
| KEV永続キャッシュ | CISA feed取得を効率化 | 5時間TTL、取得時刻、ハッシュを保存できる |
| 条件付きKEV更新 | 不要な取得を削減 | ETag / Last-Modifiedを利用できる |
| stale fallback | CISA障害時の継続運用 | 古いキャッシュ利用を明示して処理できる |
| KEV強制更新 | 緊急対応 | `kev-refresh --force`相当の操作ができる |
| キャッシュロック | 同時実行競合を防止 | 並列同期でキャッシュが破損しない |
| 同期失敗アラート | 運用停止を検知 | 連続失敗・キャッシュ期限切れを通知できる |

## Phase 2: VEX作成・レビュー・公開（P1）

| タスク | 目的 | 完了条件 |
| --- | --- | --- |
| VEX候補キュー | Security teamの作業対象を集約 | KEV、EPSS、影響範囲、期限で並べ替えられる |
| VEXコンテキスト表示 | 判断材料を一元化 | Finding、SBOM、Analysis、Issueを確認できる |
| VEX根拠テンプレート | 判断品質を標準化 | `not_affected`理由・`affected`対応方法が必須になる |
| VEX Draft/Review/Approve | 承認プロセスを管理 | 承認前にDTへ公開できない |
| CycloneDX検証 | 不正VEXを防止 | スキーマ・識別子・必須項目を検証できる |
| VEX差分プレビュー | 公開影響を確認 | Issue除外・優先度変更・対象件数を表示できる |
| Dependency-Track VEX publish | 承認済みVEXを反映 | Dry-run後に権限付きで投入できる |
| VEX版管理 | 製品・バージョンとの対応を追跡 | 承認者、時刻、対象SBOMを保存できる |
| VEX期限・再評価 | 古い判断を放置しない | KEV、EPSS、SBOM更新で再評価キューに入る |

## Phase 3: LLMトリアージ支援（P2）

| タスク | 目的 | 完了条件 |
| --- | --- | --- |
| Finding要約 | Security teamの調査時間を短縮 | 根拠付き要約を生成できる |
| 影響説明 | 開発者への説明を支援 | CVSS、EPSS、コンポーネント情報を反映できる |
| 修正案提示 | 対応方針を支援 | 更新、回避策、追加調査を提案できる |
| VEX下書き支援 | VEX作成を効率化 | 根拠付きDraftを生成できる |
| 構造化出力 | 自動処理可能にする | summary、impact、remediation、evidence、confidenceを持つ |
| Human review | 誤判定を防止 | Security team承認なしに公開できない |
| 安全制約 | 最終判断を人に残す | Priority、VEX、抑制、例外、Issue closeを変更できない |
| LLM監査ログ | 提案の説明責任 | prompt version、model、入力、出力、承認者を記録できる |

## Phase 4: リスク判定の高度化（P2）

| タスク | 目的 |
| --- | --- |
| Reachability | 実際にコードパスへ到達可能か判断 |
| `govulncheck`連携 | Go依存関係の到達性補完 |
| `pip-audit`連携 | Python依存関係の補完検証 |
| `osv-scanner`連携 | OSV情報との補完照合 |
| 影響範囲集約 | CVE単位で全Projectを横断表示 |
| Asset criticality | システム重要度を優先度に反映 |

## Phase 5: 外部連携と可視化（P3）

| タスク | 目的 |
| --- | --- |
| Jira adapter | GitHub以外の対応管理へ対応 |
| Slack / Teams通知 | P0や同期失敗を通知 |
| Dashboard | Security team向けPortfolio可視化 |
| Metrics | SLA、滞留、MTTR、再発率を集計 |
| SARIF / Dependency Graph | CI・開発ツールへ結果を連携 |
| Multi-tenancy | 組織・チーム単位の分離 |

## 実装順序の依存関係

```text
Phase 0: 実接続・ハードニング
    ↓
Phase 1: ログ・監査・KEVキャッシュ
    ↓
Phase 2: VEX作成・承認・公開
    ↓
Phase 3: LLMトリアージ支援
    ↓
Phase 4: 到達性・高度なリスク判定
    ↓
Phase 5: Jira・通知・Dashboard・Metrics
```

## 設計上の不変条件

- Dependency-TrackはInventory、Finding、EPSS、VEX/Analysisの正本とする。
- GitHub IssuesはRemediation workflowの正本とする。
- 監査ストアは履歴・キャッシュ・運用メトリクスの補助に限定する。
- LLMは要約・説明・提案に限定し、Security判断を自動確定しない。
- VEX、抑制、例外、リスク受容はSecurity teamの承認を必要とする。
