# 運用ガイド

## 目次

- [作業から手順を選ぶ](#作業から手順を選ぶ)
- [利用者の作業一覧：いつ・どこで・何をするか](#利用者の作業一覧いつどこで何をするか)
  - [役割と判断の記録先](#役割と判断の記録先)
  - [初回導入・サービス登録](#1-初回導入サービス登録)
  - [イメージ更新・SBOM訂正](#2-イメージ更新sbom訂正)
  - [配備・切替・停止](#3-配備切替停止)
  - [日常確認・脆弱性通知への対応](#4-日常確認脆弱性通知への対応)
  - [調査・修正・完了確認](#5-調査修正完了確認)
  - [調達・共通基盤と確認範囲](#調達共通基盤と確認範囲)
- [日常の運用とログ](#日常の運用とログ)
  - [日常の流れ](#日常の流れ)
  - [バックアップと復旧](#バックアップと復旧)
  - [障害時の確認](#障害時の確認)
  - [更新・担当変更・停止の通し演習](#同じサービスで更新担当変更停止を通す)
- [YAML configuration](#yaml-configuration)
- [旧リンクからの案内](#旧リンクからの案内)

初めての方は[最短の初回確認](getting-started.md#最短の初回確認外部通信なし)から始める。
担当・作業のタイミングと日常の確認はこのページ、長い個別手順は下の表から開く。
コマンドはリポジトリのルートで実行し、通常運用は`--no-github`を指定する。

## 作業から手順を選ぶ

| したいこと | 開く手順 |
| --- | --- |
| まず出力を見る・DTで一件追う | [初回確認とDT演習](getting-started.md) |
| npm・uvからCI供給を始める | [担当別の導入手順・Actions例](sbom-producers.md) |
| サービス・担当を登録する | [資産登録](assets.md#登録単位と新規サービスの開始順序) |
| 新しいイメージのSBOMを送る | [生成・投入](sbom-producers.md#コンテナのsbomを生成してdtへ送るタイミング) |
| 配備・更新・停止を記録する | [稼働申告](assets.md#配備変更と稼働申告) |
| 日常の結果・不足情報を見る | [日常確認](#日常の流れ) |
| Slack通知の予定本文を見る | [通知preview・送信台帳・復旧](slack-notifications.md) |
| 速報・CVEから担当を探す | [調査・任意の補助情報](investigation.md) |
| 台帳を検査・復元する | [バックアップと復旧](#バックアップと復旧) |
| GitHub連携の条件を調べる | [任意のGitHub同期](github-sync.md)（有効化保留） |

## 利用者の作業一覧：いつ・どこで・何をするか

初回は導入準備 → Build SBOM投入 → 配備先との対応確認 → 日常確認の順に進める。
以下の5場面で担当・行動・結果を確認する。

### 役割と判断の記録先

| 担当・システム | 責任 |
| --- | --- |
| サービス担当 | サービス・配布単位・担当・事業影響を決める |
| 開発／CI担当 | 配布成果物からSBOMを生成し、元文書・digest・CI記録を残してDTへ送る |
| 運用担当・資産台帳 | DT Projectとの対応を確認し、成果物根拠・期限付き稼働申告・訂正履歴を保存する |
| Dependency-Track | SBOM構成・Finding・分析状態を管理する |
| セキュリティ担当 | 対応要否・分析判断・例外を決め、開発担当へ引き渡す |
| sbom-ops | 読取・優先度計算・資産照合・確認用一覧を提供する |

分析判断はDTとセキュリティ担当の記録、対応作業は組織で合意した作業管理先に残す。
GitHub Issuesを使う場合も自動起票は前提にせず、製品の同期は既定無効・有効化保留。
Slack通知は[予定本文を標準出力で確認](slack-notifications.md)できる。
通常のsyncでSlackへ送信されるわけではない。CI組込み・定期起動の設定は導入者が行う。

### 1. 初回導入・サービス登録

**起点:** 新しいサービスを管理対象にする。
**担当:** サービス担当・運用担当（CI担当へ命名と送信先を引き渡す）。

1. 架空教材で、Finding・担当・未確認事項の見方を確認する。
2. サービス・配布単位・担当・事業影響を決め、登録入力をpreviewしてから保存する。
3. 最初のSBOM投入後にCI記録とDTの名・版・UUIDを照合し、人が対応を承認する。

**結果:** 資産とDT Projectの対応が追跡できる。承認は稼働・影響有無の証明ではない。
**次の手順:** [初回確認とDT演習](getting-started.md)。

### 2. イメージ更新・SBOM訂正

**起点:** 新しい配布成果物ができた、またはSBOMの収録漏れを見つけた。
**担当:** 開発／CI担当が生成・投入し、運用担当へ根拠を引き渡す。

1. 最終イメージの不変IDを確定し、OSパッケージとアプリ依存を含むBuild SBOMを生成する。
2. 元SBOM・ハッシュ・digest・CI参照を保存し、対応するDT Project名・成果物版へ送る。
3. 受付・BOM処理・Finding取得の結果を分けて確認し、運用担当が対応と根拠を登録する。

PR・依存更新時はSource SBOMを早期確認に使い、ソースcommit・元文書・生成器の版を残す。
SourceをBuild用Projectへ上書きしない。

**結果:** 新しい成果物を旧版と区別できる。同一成果物のSBOM訂正では成果物IDを維持し、
文書の版と訂正理由を残す。Source SBOMは開発時の補助情報として分ける。
**次の手順:** [npm・uv・Trivyの生成とCI引渡し](sbom-producers.md#3-最終イメージからbuild-sbomを生成する)、[記載品質の確認](sbom-input.md)。

### 3. 配備・切替・停止

**起点:** デプロイ、新旧並存、同じ成果物の再配備、旧版停止。
**担当:** 運用担当（配備先の事実と台帳の申告を区別する）。

1. 配備先の実際の成果物IDと、承認済みDT Projectの版を照合する。
2. 環境・稼働／公開状態・確認者・根拠・日時・期限を申告する。不明は不明のまま残す。
3. 新旧並存なら両方を保持し、旧版停止は確認後に旧版の申告を明示訂正する。

**結果:** 誰がどの環境の何を確認したかが残る。新版登録だけで旧版停止を推測しない。
同じ成果物の再配備ではSBOMを再生成・再送しない。
**次の手順:** [配備変更と稼働申告](assets.md#配備変更と稼働申告)。

### 4. 日常確認・脆弱性通知への対応

**起点:** 定期確認、JPCERT・ベンダーの速報、KEV追加や重大度変更の連絡。
**担当:** セキュリティ担当が確認し、運用／開発担当へ次の調査を依頼する。

1. 登録済み構成に対するDTの分析を読み、syncの優先度・根拠・不足情報を確認する。
2. 速報のCVEや部品を保存済みの成功結果で検索し、対象サービス・配置・担当へ辿る。
3. 元情報と取得時点を確認し、対応候補・不足情報・確認先を合意した作業管理先へ記録する。

**結果:** 対応候補を担当へ引き渡せる。KEV該当はP0になるが、分析判断は自動変更しない。
新しいCVEの公開だけを理由にSBOMを再送せず、一致なし・未取得を影響なしと扱わない。
**次の手順:** [日常の確認](#日常の流れ)／[速報・CVEの調査](investigation.md)。

### 5. 調査・修正・完了確認

**起点:** 対応依頼、再評価依頼、サプライヤーVEX受領。
**担当:** セキュリティ担当が判断し、開発担当が修正、運用担当が配備・停止を確認する。

1. DT分析状態と対象の部品・成果物・配置根拠を確認し、必要ならPoC等の補助情報を調べる。
2. 対応が必要なら修正・テスト・再ビルドを行い、新しいSBOMを投入して配置申告を更新する。
3. 人が対象成果物・解析状況・修正内容・旧版停止を照合し、判断と完了根拠を記録する。

**結果:** 調査中・対象外・例外・修正完了を根拠付きで区別する。
Finding消失や応答安定だけでは完了としない。自動クローズは提供しない。
AIは要約・説明・修正案に限定し、抑制・例外承認・優先度変更を決定しない。
**次の手順:** [更新・担当変更・停止の確認](#同じサービスで更新担当変更停止を通す)／
[VEX受領時の確認](investigation.md#vex受領時の確認)。

### 調達・共通基盤と確認範囲

調達担当は外部製品の供給元に対象製品・版のSBOMと署名情報を要求し、組織の受入手順で
対象との一致や出所を確認する。基盤担当は共通ベースイメージのSBOMと対象digestを提供し、
サービス担当は採用したベースを記録したうえで、自分たちの最終イメージからもBuild SBOMを生成する。
供給元署名の検証・隔離受入、署名済みベースイメージの配布基盤は本PJでは未提供であり、
DTへの取込成功をその検証の代わりにしない。

この整理は[利用者提示のライフサイクル指針](https://github.com/DharmaDoll/product-security-guidance/blob/main/sources/user-supplied/user-supplied-sbom-lifecycle-guidance-ja.md)
を本PJの操作へ対応付けたもの。Source／Build／運用の観測を分ける方針は
[仕様の結合契約](../SPEC.md#sbomライフサイクルの結合契約後続実装の基準)に従う。
現在の運用情報は人の申告・照合が中心で、Runtime SBOMの自動生成、実行メモリの完全な収集、
デプロイ基盤の自動発見は提供していない。Build SBOMも生成器の網羅性を保証しない。

## 日常の運用とログ

**担当:** セキュリティ担当が評価と次の行動を判断し、運用担当が台帳・ログを管理する。
**前提・入力:** 初回の登録・照合済み台帳、DT読取キー・URL・対象Project UUID、KEV取得または
利用可能なキャッシュ。初回設定は[DT演習](getting-started.md#運用担当者向けの初回演習)を参照。
**期待結果:** Finding・優先度・担当・配置申告・不足情報を確認し、判断と確認日時を残す。
**失敗時:** [障害時の確認](#障害時の確認)で失敗段階を分ける。古い出力や0件で代用しない。

### 日常の流れ

1. DTの登録済み構成・分析状態を確認する。新成果物やSBOM訂正がある場合だけCIから投入し、受付、処理token、Findingの状態を区別する。
2. `sync --wait-for-analysis --asset-db PATH --no-github` で評価と資産対応を確認する。
3. 担当者が対応対象・不足情報を判断し、修正後のSBOMで再確認する。

`--wait-for-analysis` は応答安定の確認であり、修正確認ではない。
自動クローズは提供しない。GitHub有効化は[任意連携](github-sync.md)として別に扱う。
出力仕様と制限は[SPEC](../SPEC.md#execution-model)を参照する。

機械処理には `--output json`、記録には `--sync-log-file` を追加する。

```bash
mkdir -p var/operator-review
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --asset-db var/assets.sqlite3 \
  --wait-for-analysis --dry-run --no-github --output json \
  --sync-log-file var/operator-review/sync.jsonl
```

ログには分析メモや担当情報も含まれる。Gitへ入れず、閲覧権限と保持期間を管理する。
ログ書込失敗はstderrへ警告され、同期の終了コードはそのためには変更されない。
失敗時の記録は実行済みの全操作を追跡できないため、書き込み運用前の改善課題である。

### バックアップと復旧

台帳は定期的に検査し、別の永続ストレージにもバックアップを保管する。
次は上書きしないバックアップと、そのファイルを開けるかの検査例である。

```bash
sbom-ops assets --db var/assets.sqlite3 check
mkdir -p var/backups
export ASSET_BACKUP="var/backups/assets-$(date +%Y%m%d-%H%M%S).sqlite3"
sbom-ops assets --db var/assets.sqlite3 backup --output "$ASSET_BACKUP"
sbom-ops assets --db "$ASSET_BACKUP" check
```

ファイル検査だけで業務復旧まで確認したとは扱わない。本番前に復元手順と訓練を決める。

復元は[通し演習のバックアップ例](#同じサービスで更新担当変更停止を通す)のように、
検査済みバックアップから未使用の別パスへ複製し、`audit-links`と読取専用syncで確認する。
元DBを上書きせず、書込み元の停止・切替対象・権限・バックアップ以降の変更を確認してから切り替える。
移行前のDBへ戻す場合は、移行後の登録・変更・取得情報が含まれない。
任意連携の[GitHub操作記録DB](github-sync.md#作成の操作記録sqlite)は別管理で、
資産台帳の復元と一緒に巻き戻さない。

### 障害時の確認

| 症状 | 確認・再開の条件 |
| --- | --- |
| DTの401/403 | URL・キーの用途・読取権限・対象Projectへの可視性を確認。権限表は[DT API](dependency-track/api.md#操作ごとの権限dt-4143) |
| 429/5xx・timeout・不正応答 | 再試行上限・DT側の処理とログを確認してから同じ対象を再実行。読取失敗は0件ではない |
| Finding 0件・件数変動 | 対象UUID・版・SBOM・処理token・抑制・データソースを確認。応答安定も修正完了の証明ではない |
| 台帳なし・不正・移行必要 | DBパスと`assets check`を確認。新規空DBで代用しない。検査済みバックアップを用意して明示移行／別DB復元 |
| 資産未紐付け・期限切れ・矛盾 | [Project照合](assets.md#dtから読み戻して紐づける方法)・[稼働申告](assets.md#配備変更と稼働申告)を再確認 |
| ログ保存の警告 | 標準エラー・保存先・権限・空き容量を確認。同期成功とログ保存成功を分けて記録 |
| 速報／PoCの取得失敗 | [調査手順](investigation.md)の取得状態・待機時刻を確認し、過去の成功情報を最新と扱わない |

キーや未加工の資産情報をIssueへ貼らず、対象・実行時刻・run ID・失敗段階を記録する。
復旧後も人が修正完了を判断する。自動クローズやDTの分析状態変更は行わない。

### 同じサービスで更新・担当変更・停止を通す

新版導入時や運用訓練で行う通し演習。毎日の確認では上の[日常の流れ](#日常の流れ)を使う。

初回演習の後、[CI成果物の確認手順](assets.md#ciが作った成果物での確認)を使って次の流れを試す。DB・サービスID・配布単位は同じものを使う。
各段階の`sync --asset-db ... --dry-run --no-github --output json`を別ファイルへ保存する。
新旧イメージが別IDでも、中身が同じ再ビルドなら脆弱性修正とは限らない。
同じ名前・別の版としてDTへ投入し、既存ProjectのSBOMを上書きしない。

| 段階 | 操作と確認すること |
| --- | --- |
| 旧版の稼働 | CIの出所・チェックサム・イメージID・healthを照合。Project名・版・UUID・ComponentをDT画面で確認し、台帳へ承認する。 |
| 新版と並存 | 同じサービスの新版SBOMを直接投入。新しいProject UUIDを別途承認し、各版に稼働申告を登録。両Projectで別々にsyncし、版を取り違えないことを確認する。 |
| 担当変更 | `update-service`のプレビューを確認してから`--apply`。新しいsyncの担当は変わるが、Findingや優先度は変わらない。変更理由を`history`で確認する。 |
| リンク訂正 | 演習用のリンクだけを`revoke-link`で撤回し、syncが担当・稼働を結び付けなくなることを確認。DTの名・版・UUIDを再確認して`approve`し直す。過去履歴は消さない。 |
| 申告の期限切れ | 演習では短い期限の申告へ明示訂正し、期限前後のsyncを比較。`expired`は「今は不明」であり、`not_deployed`ではない。コンテナが動いていても申告は失効する。 |
| 実際の停止 | 演習コンテナのIDを照合して停止を確認し、`--supersedes-report`で同じ成果物の申告を`not_deployed`へ訂正。新旧両版で確認する。停止してもDTのFindingは残る。 |
| バックアップから確認 | `backup`→バックアップの`check`→別DBとして復元→`audit-links`とsync。担当・承認・申告・履歴・PoCが引き継がれるか確認する。元DBは上書きしない。 |

担当変更とバックアップの例。`DEMO_SERVICE_ID`とDBパスは今回の演習用の値を使い、
バックアップ・復元先は未使用の名前にする。

```bash
sbom-ops assets --db var/assets.sqlite3 update-service \
  --service "$DEMO_SERVICE_ID" --owner training-team-b \
  --actor your-name --reason '演習での担当引継ぎ'
# プレビューを確認してから、同じコマンドに --apply を付けて保存する
sbom-ops assets --db var/assets.sqlite3 history --service "$DEMO_SERVICE_ID"
sbom-ops assets --db var/assets.sqlite3 backup --output var/exercise-backup.sqlite3
sbom-ops assets --db var/exercise-backup.sqlite3 check
# backupコマンドを使い、検査したバックアップから別のDBへ複製する
sbom-ops assets --db var/exercise-backup.sqlite3 backup --output var/exercise-restored.sqlite3
sbom-ops assets --db var/exercise-restored.sqlite3 audit-links
sbom-ops sync --project "$SBOM_OPS_DT_PROJECT_UUID" \
  --asset-db var/exercise-restored.sqlite3 --dry-run --no-github --output review
```

PoC対応の採用履歴も使う場合は、最後のsyncに`--use-reviewed-identifiers`を明示する。
復元しても期限は延びない。過去の「稼働中」やPoC件数を、復元した時点の事実へ読み替えない。
本番での復旧では、書き込み元の停止・保管先・ファイル権限なども別途決める。
各段階の「予想／確認した事実／疑問／次の確認先」を残す。実施例と限界は
[DT検証記録](../lab/dependency_track/EXPERIMENTS.md)の2026-10-19項を参照。


## YAML configuration

設定例は[examples/config.yaml](../examples/config.yaml)、契約は
[SPEC](../SPEC.md#configuration-contract)に集約する。
CLI → 環境変数 → YAML → 既定値の順で、YAMLの秘密情報は `env:変数名` で参照する。
KEVキャッシュは任意。`--refresh-kev` はTTL内でも再検証し、
取得失敗時に古い値を使うには明示設定が必要。結果の `kev_used_stale_cache` を確認する。

## 旧リンクからの案内

既存のREADME・Issue・外部ブックマークの見出しリンクを維持する。
[文書配置表](documentation-map.md)に分類と移動先を記載する。仕様の正本は[SPEC](../SPEC.md)。

### 初回確認とDT演習への旧リンク

- <a id="運用担当者向けの初回演習"></a>[運用担当者向けの初回演習](getting-started.md#運用担当者向けの初回演習)
- <a id="1-架空例で役割分担を理解する約10分"></a>[1. 架空例で役割分担を理解する（約10分）](getting-started.md#1-架空例で役割分担を理解する約10分)

- <a id="2-人が資産を登録しdtへ直接sbomを送る約20分"></a>[2. 人が資産を登録し、DTへ直接SBOMを送る（約20分）](getting-started.md#2-人が資産を登録しdtへ直接sbomを送る約20分)
- <a id="3-dt画面でprojectとfindingを追う約20分"></a>[3. DT画面でProjectとFindingを追う（約20分）](getting-started.md#3-dt画面でprojectとfindingを追う約20分)

- <a id="4-dt-projectを資産台帳へ紐づける約10分"></a>[4. DT Projectを資産台帳へ紐づける（約10分）](getting-started.md#4-dt-projectを資産台帳へ紐づける約10分)
- <a id="5-sbom-opsの結果と照合する約20分"></a>[5. sbom-opsの結果と照合する（約20分）](getting-started.md#5-sbom-opsの結果と照合する約20分)

- <a id="任意-稼働環境の情報が必要になったら"></a>[任意: 稼働環境の情報が必要になったら](getting-started.md#任意-稼働環境の情報が必要になったら)
- <a id="記録と完了条件"></a>[記録と完了条件](getting-started.md#記録と完了条件)

### 資産登録・成果物根拠・配備変更への旧リンク

- <a id="sbomと稼働資産を結ぶ運用フロー一部実装"></a>[SBOMと稼働資産を結ぶ運用フロー（一部実装）](assets.md#sbomと稼働資産を結ぶ運用フロー一部実装)
- <a id="登録単位と新規サービスの開始順序"></a>[登録単位と新規サービスの開始順序](assets.md#登録単位と新規サービスの開始順序)

- <a id="ライフサイクルで情報を混同しないための確認"></a>[ライフサイクルで情報を混同しないための確認](assets.md#ライフサイクルで情報を混同しないための確認)
- <a id="sourcebuild根拠の登録と訂正"></a>[Source/Build根拠の登録と訂正](assets.md#sourcebuild根拠の登録と訂正)

- <a id="架空のsource再ビルドsbom訂正を登録する"></a>[架空のSource・再ビルド・SBOM訂正を登録する](assets.md#架空のsource再ビルドsbom訂正を登録する)
- <a id="dtから読み戻して紐づける方法"></a>[DTから読み戻して紐づける方法](assets.md#dtから読み戻して紐づける方法)

- <a id="担当重要度を変更する"></a>[担当・重要度を変更する](assets.md#担当重要度を変更する)
- <a id="資産の廃止と紐付けの訂正"></a>[資産の廃止と紐付けの訂正](assets.md#資産の廃止と紐付けの訂正)

- <a id="将来の資産収集と台帳の保管"></a>[将来の資産収集と台帳の保管](assets.md#将来の資産収集と台帳の保管)
- <a id="固定成果物を使ったローカル通し検証"></a>[固定成果物を使ったローカル通し検証](assets.md#固定成果物を使ったローカル通し検証)

- <a id="ciが作った成果物での確認"></a>[CIが作った成果物での確認](assets.md#ciが作った成果物での確認)

### 日常確認・ログ・復旧への旧リンク

[日常の運用とログ](#日常の運用とログ)へ本文を統合した。

### 速報・CVEからの調査と任意の補助情報への旧リンク

- <a id="保存済みの結果からcve部品を逆引きする"></a>[保存済みの結果からCVE・部品を逆引きする](investigation.md#保存済みの結果からcve部品を逆引きする)
- <a id="架空の速報から資産担当を確認する外部通信なし"></a>[架空の速報から資産・担当を確認する（外部通信なし）](investigation.md#架空の速報から資産担当を確認する外部通信なし)

- <a id="任意の評価入力"></a>[任意の評価入力](investigation.md#任意の評価入力)
- <a id="poc報告を明示的に取得する"></a>[PoC報告を明示的に取得する](investigation.md#poc報告を明示的に取得する)

- <a id="poc更新を定期実行する"></a>[PoC更新を定期実行する](investigation.md#poc更新を定期実行する)
- <a id="cve対応候補を確認する"></a>[CVE対応候補を確認する](investigation.md#cve対応候補を確認する)

- <a id="cve対応候補の採用取消を記録する"></a>[CVE対応候補の採用・取消を記録する](investigation.md#cve対応候補の採用取消を記録する)
- <a id="採用したcve対応をpoc取得表示へ使う"></a>[採用したCVE対応をPoC取得・表示へ使う](investigation.md#採用したcve対応をpoc取得表示へ使う)

- <a id="cisa評価の取得保存表示"></a>[CISA評価の取得・保存・表示](investigation.md#cisa評価の取得保存表示)
- <a id="同期結果に参照情報を添える"></a>[同期結果に参照情報を添える](investigation.md#同期結果に参照情報を添える)

- <a id="bod参照の判断支援を架空データで試す"></a>[BOD参照の判断支援を架空データで試す](investigation.md#bod参照の判断支援を架空データで試す)
- <a id="運用担当者が確認する順序"></a>[運用担当者が確認する順序](investigation.md#運用担当者が確認する順序)

### 任意のGitHub同期と復旧への旧リンク

- <a id="github同期の確認"></a>[GitHub同期の確認](github-sync.md#github同期の確認)
- <a id="権限と送信先を先に固定する"></a>[権限と送信先を先に固定する](github-sync.md#権限と送信先を先に固定する)

- <a id="複数ビルドを一つの修正作業として扱う"></a>[複数ビルドを一つの修正作業として扱う](github-sync.md#複数ビルドを一つの修正作業として扱う)
- <a id="本文の扱いと復旧"></a>[本文の扱いと復旧](github-sync.md#本文の扱いと復旧)

- <a id="作成の操作記録sqlite"></a>[作成の操作記録（SQLite）](github-sync.md#作成の操作記録sqlite)
- <a id="有効化前の確認"></a>[有効化前の確認](github-sync.md#有効化前の確認)

- <a id="限定した実環境での確認手順"></a>[限定した実環境での確認手順](github-sync.md#限定した実環境での確認手順)

### SBOMの生成・投入・記載品質の確認への旧リンク

- <a id="sbom最低要素の確認について"></a>[SBOM最低要素の確認について](sbom-input.md#sbom最低要素の確認について)
- <a id="コンテナのsbomを生成してdtへ送るタイミング"></a>[コンテナのSBOMを生成してDTへ送るタイミング](sbom-producers.md#コンテナのsbomを生成してdtへ送るタイミング)

- <a id="実際に生成したsbomで試す"></a>[実際に生成したSBOMで試す](sbom-input.md#実際に生成したsbomで試す)
- <a id="欠落を改善する担当と訂正例外の扱い"></a>[欠落を改善する担当と、訂正・例外の扱い](sbom-input.md#欠落を改善する担当と訂正例外の扱い)

- <a id="ciで結果を保存してから終了コードを返す"></a>[CIで結果を保存してから終了コードを返す](sbom-input.md#ciで結果を保存してから終了コードを返す)
