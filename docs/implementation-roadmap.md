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
| Domain model | 完了 | Finding、Severity、Priority、Enrichment、3種類のstate型 |
| Priority Engine | 完了 | KEV、Critical、EPSS、CVSSによるP0〜P3 |
| Dependency-Track API client | MVP完了 | Project、SBOM upload token、Finding、EPSS、Analysis state読取 |
| KEV client | MVP完了 | CISA JSON feed取得 |
| GitHub Issues client | MVP完了 | 作成、更新、重複検索、クローズ |
| Orchestrator | MVP完了 | Finding取得からIssue同期まで |
| VEX/Analysis state除外 | MVP完了 | `NOT_AFFECTED`、`FALSE_POSITIVE`、抑制済み |
| Dry-run / plan | MVP完了 | 設定、Finding単位のIssue予定操作、書き込み予定の確認 |
| Safe closure | MVP完了 | 既定無効、分析待機、最低2回の連続不在確認 |
| Finding identity v2 | MVP完了 | UUID/PURLベース、旧keyからの移行 |
| API retry / timeout | MVP完了 | 設定可能。実障害・rate limitでの検証待ち |
| Project pagination | MVP完了 | DT Projectのoffset/limit処理。大規模Portfolio検証待ち |
| 非同期分析待機 | MVP完了 | BOM processing完了待機。実環境の分析時間検証待ち |
| GitHub Actions sync例 | MVP完了 | repository-localな同期例。WIF SBOM upload workflowとは別物 |
| Mock fixtures / tests | MVP完了 | 外部クライアントと同期処理 |
| 業務フロー・責務文書 | 完了 | 情報源、トリアージ、VEX運用を文書化 |

## Phase 0: 実運用接続とMVPハードニング（P0）

| タスク | 目的 | 完了条件 |
| --- | --- | --- |
| 実Dependency-Track接続検証 | APIレスポンスと権限を確認 | 実環境でProject/Finding/EPSS/Analysisを取得できる（資格情報待ち） |
| 実GitHub接続検証 | Issue権限とラベルを確認 | Issue作成・更新・クローズをDry-run後に実行できる（資格情報待ち） |
| APIリトライ・タイムアウト実環境検証 | 一時障害への耐性 | 実装済み設定を使い、timeout、429、5xx、`Retry-After`、最大試行到達時の動作を実環境相当で確認できる |
| APIページネーション実環境検証 | 大規模Portfolio対応 | 実装済みProject paginationとGitHub Issue全ページ処理を大規模fixtureまたは実環境で確認できる。Finding/VulnerabilityはDT v4の非ページング仕様に従う |
| 非同期分析待機実環境検証 | SBOM登録直後の欠損防止 | 実装済みBOM upload token待機で`processing=false`を確認し、timeout時にcloseへ進まない |
| 実環境での安全なClose検証 | 誤クローズ防止 | timeout、部分取得、分析中、filter変更でcloseされない |
| Finding identity実レスポンス検証 | 重複・衝突防止 | component UUID/PURLとvulnerability UUID/sourceを確認 |
| YAML設定 | 環境変数以外の運用設定 | `SPEC.md`の設定例を読み込める |
| GitHub Actions sync例のhardening | 定期同期を安全に自動化 | 既存例のactionをcommit SHAで固定し、timeout、concurrency、Dry-run、権限を検証できる。WIF upload workflowとは明確に分離する |
| 権限分離ドキュメント | API keyの最小権限化 | DT read用、SBOM upload用、GitHub用を分離できる |

### 直近のPR単位

1. YAML config loader、schema validation、unit tests、`SPEC.md`整合
2. Project/repository routingのdomain model、resolver、config、unit tests
3. Dependency-Track/GitHub contract fixturesと失敗系integration tests
4. 既存sync workflowのhardeningと運用手順更新

## Phase 0.5: GCPゼロトラスト配信基盤（P0/P1）

`Additional.txt`の提案は、GitHub Actionsに長期秘密情報を置かない方針と
Identityベースのアクセス制御を採用する。一方、Cloud Run、認証プロキシ、IAPを
確定アーキテクチャとはせず、公式仕様に基づくADRと本番相当PoCを通過してから
Terraform実装へ進む。

| タスク | 目的 | 完了条件 |
| --- | --- | --- |
| 実行基盤ADR / PoC | Cloud Runへの先行固定を避ける | Cloud RunとGKE/Helmを、DTの推奨リソース、常駐バックグラウンド処理、起動時間、可用性、費用、運用負荷で比較し選定できる |
| DTサービス分離 | 公式配布形態に合わせる | API server、browser-facing frontend、外部PostgreSQLを分離し、接続、migration、upgradeを再現できる |
| データ保護 | Inventoryの正本を保護 | PostgreSQLの暗号化、backup/restore、PITR、DR演習、RPO/RTOを定義し復旧試験に合格する |
| GitHub OIDC / WIF | GitHubに長期GCP鍵を置かない | 固定的なorganization/repository ID、ref/environment、承認済み`job_workflow_ref`で信頼を制限し、想定外repo/workflowのtoken exchangeが拒否される |
| SBOM upload gateway | DT API keyをCIへ渡さない | gatewayだけがSecret Managerのupload専用keyを参照し、rotationと監査ができる |
| Repository/project認可 | 他ProjectへのSBOM上書きを防ぐ | 検証済みOIDC callerからDT project UUIDをサーバー側で解決し、不一致・未知repo・caller指定UUIDを拒否する |
| Gateway面の縮小 | 汎用proxy化を防ぐ | 許可するmethod/path/content type/body sizeをBOM uploadに限定し、issuer、audience、期限、caller identityを検証する |
| Service-to-service認証 | 内部経路を最小権限化 | gateway固有service accountだけがbackendをinvokeでき、ID token audienceとegress/ingress制約を統合試験で確認する |
| 人間向け認証PoC | Entra ID利用者の画面アクセスを保護 | IAP/Identity PlatformまたはDT native OIDCを比較し、SPAからAPIへの認証、CORS、group認可、logout、break-glassをE2E確認する |
| Reusable workflow | 各repoへ安全な共通送信経路を提供 | `id-token: write`と`contents: read`だけを付与し、actionをcommit SHAで固定し、timeout/retry/concurrencyを設定する |
| 失敗ポリシー | SBOM欠落を見逃さない | upload失敗は既定でjobを失敗させ、明示的な非blockingモードでも監視可能なwarning、metric、alertを必須とする |
| 本番化ゲートの可観測性 | 問題を検知できない状態で公開しない | 公開前に構造化ログ、認証・認可audit event、WIF拒否、gateway 4xx/5xx、upload token、分析遅延を相関できるmetricと連続失敗alertを利用できる |
| IaC検証 | 権限逸脱と設定差分を防ぐ | Terraform format/validate/plan、policy check、権限negative test、環境別変数、rollback手順をCIで検証する |

### 採用しない前提

- `repository_owner`名だけでは認可しない。再利用されない数値IDとrepo/workflow単位の条件を使う。
- callerが渡した`project_uuid`を無条件に転送しない。
- Nginx等へ全Dependency-Track APIを透過させない。
- SBOM upload errorを無条件に握りつぶさない。既定はfail-closedとする。
- API serverだけをデプロイして人間向けUIが成立すると仮定しない。

### 設計時に参照する公式仕様

- [Dependency-Track: Deploying Docker Container](https://docs.dependencytrack.org/getting-started/deploy-docker/)
- [Dependency-Track: REST API](https://docs.dependencytrack.org/integrations/rest-api/)
- [Dependency-Track: Continuous Integration & Delivery](https://docs.dependencytrack.org/usage/cicd/)
- [Google Cloud: Workload Identity Federation with deployment pipelines](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
- [Google Cloud: Authenticating service-to-service](https://cloud.google.com/run/docs/authenticating/service-to-service)
- [Google Cloud: Configure IAP for Cloud Run](https://cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run)
- [Google Cloud: IAP external identities](https://cloud.google.com/iap/docs/external-identities)
- [GitHub: Configuring OIDC in Google Cloud Platform](https://docs.github.com/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-google-cloud-platform)
- [GitHub: OIDC with reusable workflows](https://docs.github.com/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows)

## Phase 1: 運用基盤の拡張・キャッシュ（P1）

| タスク | 目的 | 完了条件 |
| --- | --- | --- |
| 構造化同期ログの永続化 | 実行結果を長期追跡 | Phase 0.5の最低限ログを拡張し、`run_id`、件数、時間、失敗を保存・検索できる |
| 監査ストア | FindingとIssueの変化を追跡 | Phase 0.5の認証・upload監査に加え、state、priority、Issue操作の履歴を検索できる |
| KEV永続キャッシュ | CISA feed取得を効率化 | 5時間TTL、取得時刻、ハッシュを保存できる |
| 条件付きKEV更新 | 不要な取得を削減 | ETag / Last-Modifiedを利用できる |
| stale fallback | CISA障害時の継続運用 | 古いキャッシュ利用を明示して処理できる |
| KEV強制更新 | 緊急対応 | `kev-refresh --force`相当の操作ができる |
| キャッシュロック | 同時実行競合を防止 | 並列同期でキャッシュが破損しない |
| 同期失敗アラート | 運用停止を検知 | 連続失敗・キャッシュ期限切れを通知できる |
| 3状態のライフサイクル | 状態混同を防止 | Finding、Analysis、Remediationを独立遷移として扱える |
| Multi-repository routing | Projectごとの作業場所へ連携 | DT ProjectからGitHub repositoryを設定で解決できる |

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

## Phase 3: リスク判定・Reachability（P2）

| タスク | 目的 | 完了条件 |
| --- | --- | --- |
| Reachability evidence | 実際のコードパス到達性を補助判断 | Findingを自動抑制せず、tool version、入力、出力、時刻、confidenceを保存できる |
| `govulncheck` adapter | Go依存関係の到達性補完 | 外部実行をadapterへ分離し、mock fixtureと失敗時fallbackを持つ |
| `pip-audit` adapter | Python依存関係の補完検証 | 外部実行をadapterへ分離し、mock fixtureと失敗時fallbackを持つ |
| `osv-scanner` adapter | OSV情報との補完照合 | 外部実行をadapterへ分離し、mock fixtureと失敗時fallbackを持つ |
| VEX evidence連携 | 人間のVEX判断を支援 | Reachability結果を根拠として表示するが、自動publish・自動not_affectedを行わない |
| 影響範囲集約 | CVE単位で全Projectを横断表示 | FindingとProjectの対応を一覧化できる |
| PriorityContext | 追加リスク要因を分離 | Asset criticality、Exposure、Reachability、Controlを拡張可能な入力として保持する |
| Remediation policy | Priorityと期限を分離 | Priorityを変更せず、SLA、期限、escalationを別モデルで管理する |

## Phase 4: LLMトリアージ支援（P2）

| タスク | 目的 | 完了条件 |
| --- | --- | --- |
| Finding要約 | Security teamの調査時間を短縮 | VEX、Reachabilityを含む根拠付き要約を生成できる |
| 影響説明 | 開発者への説明を支援 | CVSS、EPSS、コンポーネント、Reachability情報を反映できる |
| 修正案提示 | 対応方針を支援 | 更新、回避策、追加調査を提案できる |
| VEX下書き支援 | VEX作成を効率化 | 根拠付きDraftを生成できるが承認・publishはできない |
| 構造化出力 | 自動処理可能にする | summary、impact、remediation、evidence、confidenceを持つ |
| Human review | 誤判定を防止 | Security team承認なしに公開できない |
| 安全制約 | 最終判断を人に残す | Priority、VEX、抑制、例外、Issue closeを変更できない |
| LLM監査ログ | 提案の説明責任 | prompt version、model、入力、出力、承認者を記録できる |

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
Phase 0.5: GCP基盤ADR・PoC・安全なSBOM upload
           ＋ 本番化に必要な最小ログ・監査・通知
    ↓
Phase 1: 運用ログ・監査の拡張・KEVキャッシュ
    ↓
Phase 2: VEX作成・承認・公開
    ↓
Phase 3: Reachability・高度なリスク判定
    ↓
Phase 4: LLMトリアージ支援
    ↓
Phase 5: Jira・通知・Dashboard・Metrics
```

## 設計上の不変条件

- Dependency-TrackはInventory、Finding、EPSS、VEX/Analysisの正本とする。
- GitHub IssuesはRemediation workflowの正本とする。
- 監査ストアは履歴・キャッシュ・運用メトリクスの補助に限定する。
- LLMは要約・説明・提案に限定し、Security判断を自動確定しない。
- VEX、抑制、例外、リスク受容はSecurity teamの承認を必要とする。
