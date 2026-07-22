# VEX運用とSecurity team支援

VEXは、製品またはコンポーネントが特定の脆弱性に対して影響を受けるかを
機械可読な形式で伝えるセキュリティアドバイザリである。VEXの判断は
Dependency-TrackのFindingと関連付け、Security teamの承認を経て公開する。

Dependency-TrackはCycloneDX VEXの取り込みと生成を担当する。sbom-opsは
VEXの最終判断を自動化せず、Security teamの作業を支援し、承認済み結果を
Dependency-Trackへ反映する境界を提供する。

## 想定するVEXステータス

- `affected`: 製品が脆弱性の影響を受ける
- `not_affected`: 製品は影響を受けない
- `fixed`: 修正版で解消済み
- `under_investigation`: 調査中

`not_affected`には理由、`affected`には対応方法を必須とする。VEXの状態と
理由は、製品・バージョン・脆弱性・コンポーネントの組み合わせに対する判断
として管理する。

## Security team向けVEX作成フロー

```text
Dependency-Track Finding
        ↓
VEX候補キューへ登録
        ↓
証拠・コンテキスト収集
        ↓
VEX下書き作成
        ↓
Security reviewerレビュー
        ↓
CycloneDX検証・差分確認
        ↓
承認・公開
        ↓
Dependency-Trackへ投入
        ↓
Analysis stateとGitHub Issueを同期
```

### VEX候補になるFinding

- 同じCVEが多数のプロジェクトに影響する
- サプライヤーVEXと自社分析が一致しない
- `NOT_AFFECTED`または`FALSE_POSITIVE`の判断が必要
- KEVやEPSSの変化により再評価が必要
- 既存VEXの有効期限が近い
- SBOM更新でコンポーネントやバージョンが変わった

## Security teamを支援する機能

### 1. VEX候補キュー

全プロジェクトから候補Findingを集約し、次の条件で並べ替える。

- KEV該当
- EPSS降順
- CVSS降順
- 影響プロジェクト数
- `IN_TRIAGE`の経過時間
- VEX未作成・期限切れ

### 2. 判断コンテキストの一括表示

VEX作成画面またはCLIで、次の情報を一画面にまとめる。

- Dependency-TrackのFinding情報
- Vulnerability source
- CVSS、EPSS、KEV
- 対象プロジェクトとバージョン
- コンポーネントのPURL
- 現在のAnalysis stateと監査メモ
- 既存VEXの状態と最終更新日
- GitHub Issueの対応状況
- 関連するSBOMのコミット・リリース

### 3. 根拠テンプレート

`not_affected`や`affected`を選択したとき、根拠と対応方法を構造化して入力
できるようにする。

例：

- 脆弱なコードパスを使用していない
- 脆弱な機能を設定で無効化している
- ビルド時に該当コードを除外している
- コンパイル条件により影響を受けない
- 実行環境の防御制御で悪用できない
- 修正版へ更新済み
- 回避策を適用済み

自由記述だけにせず、選択式の理由と補足説明を組み合わせる。

### 4. 下書き・レビュー・承認

VEXは次の状態を持つ。

```text
DRAFT
  ↓
IN_REVIEW
  ↓
APPROVED
  ↓
PUBLISHED
```

`APPROVED`になるまでDependency-Trackへ反映しない。P0、KEV該当、広範囲に
影響するFindingでは、Security reviewerによる二者承認を要求できるようにする。

### 5. 差分プレビュー

公開前に、VEX反映によって何が変わるかを表示する。

- 新たに除外されるFinding
- 新たにIssue化されるFinding
- 既存Issueが更新・クローズ候補になるもの
- 優先度が変わるFinding
- 影響するプロジェクト数

### 6. 検証と公開

- CycloneDXスキーマ検証
- 製品・バージョン・脆弱性識別子の存在確認
- `not_affected`の理由必須チェック
- `affected`の対応方法必須チェック
- VEXと対象SBOMのバージョン整合性確認
- 署名または生成者・承認者・時刻の記録
- Dependency-Track投入後のAnalysis state確認

### 7. 再評価と期限

VEXには再評価日または有効期限を持たせる。次のイベントで再評価キューへ戻す。

- KEV登録
- EPSSの大幅上昇
- 新しいSBOMリリース
- コンポーネント更新
- 実行経路や設定の変更
- サプライヤーVEXの更新
- VEXの有効期限到来

## LLMの利用範囲

LLMはVEX下書きの作成支援に使える。ただし、出力は必ず提案として扱う。

LLMに許可する処理：

- Findingと証拠の要約
- 脆弱性の影響説明
- `not_affected`理由の候補提示
- `affected`時の修正案・回避策の候補提示
- 追加で確認すべき証拠の提示
- VEX本文の下書き生成

LLMに許可しない処理：

- VEXステータスの最終決定
- `not_affected`の自動承認
- Dependency-TrackのAnalysis state変更
- 抑制・例外・リスク受容
- GitHub Issueのクローズ

LLM出力には、参照したFinding、EPSS、KEV、Analysis detail、コード・設定等の
根拠を添付し、根拠がない推測を事実として出力しない。

## 保存と責務

```text
VEXリポジトリ／リリース成果物
  └─ 承認済みVEXの版管理

Dependency-Track
  └─ VEX取り込み後のAnalysis stateと監査履歴

sbom-ops監査ストア
  └─ 下書き、レビュー、公開、同期結果、差分履歴
```

Dependency-TrackはFindingとAnalysisの正本、GitHub Issuesは対応状況の正本と
する。sbom-opsの監査ストアは履歴と作業状態の補助であり、分析判断を置き換えない。

## 将来CLI案

```text
sbom-ops vex candidates --project PROJECT_UUID
sbom-ops vex draft --finding-key FINDING_KEY
sbom-ops vex validate path/to/vex.json
sbom-ops vex plan path/to/vex.json
sbom-ops vex publish path/to/vex.json --require-approval
sbom-ops vex review --finding-key FINDING_KEY
```

`publish`はデフォルトでDry-runとし、承認情報がないVEXの投入を拒否する。
