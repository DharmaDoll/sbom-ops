# 日常確認・ログ・復旧

[作業別の入口へ戻る](operations.md)。コマンドはリポジトリのルートで実行する。

**担当:** セキュリティ担当が評価と次の行動を判断し、運用担当が台帳・ログを管理する。
**前提・入力:** 初回の登録・照合済み台帳、DT読取キー・URL・対象Project UUID、KEV取得または
利用可能なキャッシュ。初回設定は[DT演習](getting-started.md#運用担当者向けの初回演習)を参照。
**期待結果:** Finding・優先度・担当・配置申告・不足情報を確認し、判断と確認日時を残す。
**失敗時:** [障害時の確認](#障害時の確認)で失敗段階を分ける。古い出力や0件で代用しない。

通常は[日常の流れ](#日常の流れ)、台帳の保全は[バックアップと復旧](#バックアップと復旧)へ進む。
以下の通し演習は新版の導入や運用訓練が必要なときに行う。

## 日常の運用とログ

### 同じサービスで更新・担当変更・停止を通す

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
