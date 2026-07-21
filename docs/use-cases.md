# 業務フローと利用シーン

この文書は、sbom-opsを実際のセキュリティ運用へ組み込むための代表的な
業務フローを定義する。各フローでは、Dependency-Trackをインベントリと
脆弱性分析の一次情報源、GitHub Issuesを remediation workflow の一次情報源
として扱う。

## システム間の責務

| システム | 担当 |
| --- | --- |
| CI/CD | SBOM生成、SBOM更新、修正版の検証 |
| Dependency-Track | SBOM、コンポーネント、脆弱性、EPSS、VEX/分析状態の管理 |
| sbom-ops | Finding取得、KEV補完、優先度計算、Issue同期 |
| GitHub Issues | 開発タスク、担当者、対応状況、クローズ状態の管理 |
| Security team | 優先度ポリシー、VEX/分析判断、例外承認 |
| Developer | 修正、依存関係更新、CI通過 |

## Security担当による一元管理

Security teamは、各開発チームが個別に脆弱性を判断するのではなく、
Dependency-Trackを横断してリスクを把握し、GitHub Issuesを対応状況の
統一された窓口として管理する。

一元管理の対象は以下とする。

- 全プロジェクト・全バージョンのFinding
- EPSS、KEV、CVSS、VEX/分析状態
- P0〜P3の優先度ポリシーと閾値
- GitHub Issueの作成条件、担当チーム、SLA
- 例外、リスク受容、再評価の判断記録
- 未対応、対応中、検証待ち、解決済みの件数と滞留状況

Dependency-Trackは技術的なインベントリとFindingの一元管理を担い、
sbom-opsは複数プロジェクトのFindingを同じルールで処理する。GitHubは
Security teamと開発チームが対応を追跡するための作業管理面とする。

## フロー1: 通常の定期同期

### 起点

日次または数時間ごとのスケジュール実行。

### 手順

1. CI/CDが最新SBOMをDependency-Trackへアップロードする。
2. Dependency-Trackがコンポーネントと脆弱性を分析する。
3. sbom-opsが対象プロジェクトのFindingを取得する。
4. sbom-opsがDependency-TrackのEPSS、VEX/分析状態、抑制状態を読む。
5. sbom-opsがKEV情報を補完し、P0〜P3を計算する。
6. `NOT_AFFECTED`、`FALSE_POSITIVE`、抑制済みを除外する。
7. 設定された優先度（MVPではP0/P1）のFindingについてIssueを作成・更新する。
8. 同じFinding keyの既存Issueがあれば重複作成しない。
9. Dependency-Trackから消えたFindingに対応するIssueをクローズする。

### 結果

- 新規脆弱性はGitHub Issueになる。
- 既存Issueには最新のEPSS、分析状態、優先度、根拠が反映される。
- 解消済みFindingのIssueはクローズされる。

## フロー2: KEV登録による緊急対応

### 起点

CVEがCISA KEVへ追加され、次回同期が実行される。

### 手順

1. sbom-opsがKEV feedを取得する。
2. Dependency-TrackのFindingとCVEを照合する。
3. KEV該当FindingをP0にする。
4. GitHub Issueを緊急対応として作成または更新する。
5. IssueにKEV該当、CVE、対象コンポーネント、修正方針を記載する。
6. Security teamと開発チームが対応期限と担当者を確認する。

### 制約

sbom-opsはKEV該当を理由にDependency-Trackの分析状態を自動変更しない。
Issueの優先度は業務上の対応優先度であり、Dependency-Trackの監査判断を
置き換えない。

## フロー3: Security担当によるトリアージ

### 起点

新規Finding、既存Findingの重大度変更、KEV/EPSS変更、VEX取り込み、または
開発チームからの再評価依頼。

### 手順

1. sbom-opsがFindingをプロジェクト横断で収集し、同じ優先度ルールを適用する。
2. Security teamがP0/P1と、滞留期間を確認する。
3. Security teamがDependency-Track上の分析状態を確認する。
4. 誤検知、対象外、抑制、VEXの妥当性を判断する。
5. 判断が必要なFindingは`IN_TRIAGE`とし、根拠と再評価条件を記録する。
6. 対応が必要なFindingのみGitHub Issueを作成または更新する。
7. Issueには優先度、根拠、対象プロジェクト、Finding key、担当チーム、SLAを記載する。
8. 例外やリスク受容はSecurity teamの承認記録として管理し、自動承認しない。

### トリアージの判断

| 判断 | Dependency-Track | GitHub Issues |
| --- | --- | --- |
| 対応が必要 | `EXPLOITABLE` または未判断 | Issue作成・更新 |
| 調査中 | `IN_TRIAGE` | 調査中として記録 |
| 対象外 | `NOT_AFFECTED` | 新規Issueを作成しない |
| 誤検知 | `FALSE_POSITIVE` | 新規Issueを作成しない |
| 抑制 | Suppressed | ポリシーに従いIssue対象外 |

Security teamの判断結果とDependency-Trackの監査履歴を一次記録とし、
GitHub Issueには対応に必要な要約と参照先を記載する。

## フロー4: サプライヤーVEXの取り込み

### 起点

サプライヤーまたは製品チームからCycloneDX VEXを受領する。

### 手順

1. Security teamがVEXの出所と対象プロジェクトを確認する。
2. CIまたは運用担当がVEXをDependency-Trackへ投入する。
3. Dependency-TrackがVEXを分析状態へ反映する。
4. 次回のsbom-ops同期で分析状態と抑制状態を読み取る。
5. `NOT_AFFECTED`、`FALSE_POSITIVE`等は新規Issue対象から除外する。
6. 既存Issueがある場合は、VEXの状態と根拠をIssueへ反映する。

### 制約

sbom-opsはVEXを独自解釈して「安全」と決定しない。VEXの取り込みと
分析判断はDependency-TrackおよびSecurity teamの管理下に置く。

## フロー5: 開発者による脆弱性修正

### 起点

GitHub Issueが作成または更新される。

### 手順

1. 開発者がIssueの対象コンポーネントと脆弱性を確認する。
2. 依存関係更新またはコード修正を行う。
3. CIでテストとSBOM生成を実行する。
4. 修正版SBOMをDependency-Trackへアップロードする。
5. Dependency-TrackでFindingが消滅または状態変化する。
6. 次回同期でsbom-opsが差分を確認する。
7. Findingが消えた場合、対応するGitHub Issueをクローズする。

## フロー6: Dry-runによる導入・ポリシー検証

### 起点

新規プロジェクトを登録する前、または優先度設定を変更する前。

### 手順

1. `sbom-ops plan` または `sync --dry-run` を実行する。
2. 実際のIssue作成・更新・クローズは行わない。
3. 対象Finding、EPSS、KEV、VEX状態、計算された優先度を確認する。
4. Security teamがIssue作成対象と閾値を承認する。
5. 承認後に通常の同期を有効化する。

## 共通ルール

- Finding keyは `project_uuid:component_name:component_version:vulnerability_id` とする。
- Dependency-TrackのEPSS値がある場合、外部EPSS値で上書きしない。
- Dependency-Trackの分析状態・VEX状態をsbom-opsが自動変更しない。
- GitHub Issueのクローズは、Finding消滅または明示された業務ルールに基づく。
- AIを導入する場合も、説明・要約・修正案の提示に限定する。
- 優先度変更、例外承認、VEX判断は人または明示的な業務ルールが行う。

## MVPで確認する受入条件

- 定期同期でP0/P1の新規Issueが作成される。
- 同一Findingの同期を繰り返してもIssueが重複しない。
- KEV登録FindingがP0として扱われる。
- Dependency-TrackのEPSS値が優先度計算に利用される。
- VEXで`NOT_AFFECTED`となったFindingから新規Issueが作成されない。
- Finding消滅後の同期でIssueがクローズされる。
- Dry-runではGitHubに書き込みが発生しない。
