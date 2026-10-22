# Implementation Specification

現在の製品の動作と守る境界を定義する。
操作は[運用ガイド](docs/operations.md)、未実装・既知の課題は[ROADMAP](ROADMAP.md)、
設計理由は[ADR](docs/adr/README.md)に記載する。将来機能を実装済みとは扱わない。

## Scope

実装範囲はDT Finding取得、KEV補完、DT由来EPSS、優先度計算、資産台帳、
補足JSON読込、CLI、任意のGitHub Issue同期。
VEX書き込み、到達可能性分析、LLM、Jiraは未実装。
外部EPSSの `EpssClient` はスタブであり、設定したURLへの自動フォールバックはない。

## Design Constraints

- SBOM構成・Finding・Analysisの正本はDT。対応状況の正本はGitHub Issues。
- sbom-opsは人が登録した資産とDTへの対応を保持する。外部の社内台帳は前提にしない。
- 例外承認・抑制・リスク受容・Analysis変更を自動化しない。
- Python 3.12以上。型注釈を付け、業務ルールはdomain、調整はservices、
  API通信はclients、SQLite永続化はstorageへ分離する。
- 製品DT通信は `src/sbom_ops/clients/dependency_track.py` に限定する。
  製品からlabをimportしない。DT API変更には契約テストまたは文書化したfixtureが必要。
- GitHub無効でも同じFinding評価を生成する。資産・補足情報の取得とIssue操作を区別する。

## Execution Model

`sync` は設定読込 → Project選択 → DT取得・KEV補完 → 評価 → 任意のIssue同期 →
結果出力を行うCLIジョブ。SBOM生成・投入はCIの責務で、`sync` は投入しない。
全対象ProjectのFinding読取が成功した後にIssue同期へ進む。
GitHub同期中の失敗などに対する書込みの一括取消しは行わない。

- Project指定がなければアクセス可能な全Projectを処理する。
  明示指定のUUIDが一覧にない場合は、補完・GitHub操作前に失敗する。
- Findingは `suppressed=true` で取得する。抑制による非表示を消滅とみなさない。
- Project一覧の各ページは `X-Total-Count` と実取得件数を照合する。
  不正応答・不完全なページ取得・読取失敗を空の正常結果に置換しない。
- `--wait-for-analysis` は、識別子・スコア・説明・Analysis・抑制などが一致する
  2回連続のFinding応答を待つ。タイムアウトは失敗。
  結果の `analysis_snapshot_status` は `not_requested / stable / no_projects`。
  `stable` は解析完了や応答の完全性を証明しない。
- `absence_verification` は `finding_state=UNKNOWN / remediation_state=OPEN /
  action=NOOP / missing_count=0 / reason=absence_not_verified`。
  空・一部のみ・安定した応答でも、見えないFindingの解決を確認したとは扱わない。
  失敗時は終了コード2。JSONは `status=failed / analysis_snapshot_status=unknown` と
  同じ未確認の判定を返し、件数・評価一覧を出さない（0件の成功ではない）。
- タイムアウト・一時的なHTTP障害には上限付き再試行、401/403には終端エラーを返す。
  書込再試行の安全性は[既知の課題](ROADMAP.md#github同期を有効にする前の必須事項)に残る。

## Configuration Contract

優先順位は **CLI → 環境変数 → YAML → 既定値**。
`--config` がなければ `SBOM_OPS_CONFIG_FILE` を使う。`.env`の自動読込はしない。
YAMLの秘密情報は `env:VARIABLE_NAME` で参照する。未知の節・キーは拒否する。

設定例は[examples/config.yaml](examples/config.yaml)、
対応する環境変数・検証処理は[config.py](src/sbom_ops/config.py)にある。

| 設定群 | 主な項目と既定値 |
| --- | --- |
| dependency_track | URL・APIキー必須。page_size=100、timeout_seconds=30、max_retries=3、retry_backoff_seconds=1、analysis_wait_timeout_seconds=120、analysis_poll_interval_seconds=5 |
| github | enabled=false、issue_label_prefix=sbom、timeout_seconds=30、max_retries=3、retry_backoff_seconds=1。有効時のみowner・repo・token必須 |
| intelligence | CISA KEV URL、DTを優先するEPSS URL設定、timeout_seconds=30、max_retries=3、retry_backoff_seconds=1、任意のKEVキャッシュ |
| priority | p1_epss_threshold=0.7、p2_cvss_threshold=7.0、create_issues_for=[P0,P1] |
| runtime | dry_run=false、project_uuids=[]、log_level=INFO、wait_for_analysis=false、任意のsync_log_file |
| workflow | close_missing_findings=falseのみ。missing_confirmation_runs=2（最小2）は旧設定互換用で判定には使わない。issue_journal_fileはGitHub書込時に必須のSQLite操作記録 |
| routing | projects=[]。設定する場合、処理対象Projectごとに一意のowner・repo、任意のissue_label_prefix |

GitHubトークンは `SBOM_OPS_GITHUB_TOKEN`、未設定なら `GH_TOKEN` を使う。
GitHub連携はコード・サンプルYAMLとも既定で無効。tokenやrepoを設定しても有効化しない。
`github.enabled=true` は接続の有効化であり、書込み許可とは別である。
書込みには実行ごとの `sync --github-write` と初期化／移行済みの操作記録DBを必要とする。
有効な連携をdry-runでなく実行し、書込み許可がなければ、外部API・操作記録DBの利用前に失敗する。
`--github-write` はYAMLや環境変数に保存できず、`plan` では指定できない。
Pythonから直接使う場合も `RuntimeConfig(github_write=True)` の明示指定を必要とする。
`--dry-run` と `--no-github` は書込み許可より優先し、併用時も書き込まない。
`--no-github` は設定より優先し、GitHubアクセス・認証情報を不要にする。
routing設定時に対象Projectの経路がなければ、既定リポジトリへ流さず失敗する。

CVSS/EPSSと閾値は有限の数値に限定し、bool・NaN・無限大を認めない。
CVSSは0〜10、EPSSは0〜1。範囲外の観測値は欠損として扱う。

KEVキャッシュの契約:

- パス未設定なら通常取得。TTL既定値は18,000秒。期限切れ利用は既定で無効。
- `--refresh-kev` はTTL内でも接続し、ETag/Last-Modifiedによる304を利用できる。
  再取得失敗時の古いキャッシュ利用は明示設定が必要で、結果に `kev_used_stale_cache` を出す。
- 新規キャッシュはschema v1とSHA-256を持つ。不正な記録は古い値の代用にもしない。
  旧形式は妥当なら読み、成功した更新時に置換する。ハッシュは出所証明ではない。
- 同じパスの取得・更新はローカルSQLiteロックで直列化し、上限時間で失敗する。
  ネットワーク共有ファイルは対象外。

## Domain Model

正確なフィールド定義は[models.py](src/sbom_ops/domain/models.py)を参照する。

| モデル | 必ず保持する意味 |
| --- | --- |
| Finding | Project、Component UUID/PURL・名・版、脆弱性の主ID・source・明示alias、severity、CVSSと版、CWE、説明 |
| Enrichment | KEV該当、DT由来EPSS、Analysis・抑制・分析メモ、既知の悪用入力 |
| PrioritizedFinding | Finding・Enrichment・P0〜P3・判断理由 |
| FindingAssessment | Issueに依存せず評価を解釈できる識別子・入力値・優先度・理由・任意の補足情報 |

主IDがないFindingは拒否し、aliasから主IDを作らない。
KEV照合は主CVEまたはDTの明示CVE aliasに限定し、空白除去・大文字小文字を正規化する。
元の主IDとFinding keyは変えない。現在の実行経路では既知悪用入力もKEV該当から設定する。
欠損スコアは `null`、数値0は有効値。`analysis_detail` は人のメモとして保持し、
自動判断の入力にしない。

Findingの観測状態（ACTIVE/MISSING/RESOLVED/UNKNOWN）、DTのAnalysis、
修正タスクのOPEN/CLOSEDは別の状態。
Analysisの変更だけでタスクをクローズしない。

## Priority Rules

副作用のない決定的なルールとして、次の順で評価し理由を返す。

| 順序 | 条件 | 結果 |
| --- | --- | --- |
| 1 | KEV該当、または既知の実悪用入力 | P0 |
| 2 | severityがCRITICAL、またはEPSSが設定閾値以上 | P1 |
| 3 | 数値CVSSが設定閾値以上 | P2 |
| 4 | いずれも非該当 | P3 |

CVSSは有効なv3 → v4 → v2の順で選び、使った版を結果に残す。
P3の理由にはスコア欠損と閾値未満を区別して表示する。
HIGHラベルを数値CVSSの代わりにはしない。P3は低リスクの証明ではない。
資産重要度・公開状況・PoCでP0〜P3やSLAを自動変更しない。
判断の責任分担は[優先度方針](docs/priority-policy.md)を参照する。

### トリアージ根拠モデル

[triage_evidence.py](src/sbom_ops/domain/triage_evidence.py) は、公開状態・KEV・
悪用の自動化可能性・技術的影響・KEVとは独立した悪用報告を保持する純粋なドメイン処理。
まだ通常のsync、外部取得、SQLite保存、期限計算には接続していない。

- 出典・記録ID・出典版・観測時刻・有効期限・任意の確認者/理由を元の値とともに残す。
  `known` は情報源の明示報告が有効期間内という意味で、正しさや採用の承認ではない。
- 脆弱性IDと名前空間の完全一致だけで集約する。別名解決やPoC用のCVE採用を流用しない。
  公開状態はサービス・配布単位・環境・成果物・Projectの完全一致に加え、呼出元による
  対応確認が必要。このモデル自体は台帳を照会せず、対応を承認しない。
- 評価日時を明示し、`observed_at <= 評価日時 < expires_at` を有効期間とする。
  未確認・期限切れ・未来・矛盾を区別し、いずれも集約値はunknown。欠損をNoにしない。
- 有効な報告が相反すればconflict。有効な報告と期限切れ等が混在すればunknown。
  履歴の最新版を黙って選ばず、採用する版の選択は呼出元の責任とする。
  入力順に依存せず、同じ根拠IDの重複は拒否する。
- PoCから自動化可能性・実悪用を推測せず、悪用報告からKEV掲載を作らない。
  P0〜P3・SLA・DT分析・Issue操作は変更しない。詳細と検証方法は[優先度方針](docs/priority-policy.md#根拠モデルの検証)。

## Asset Registry

単一ホストのローカル永続ディスク上にSQLiteを置く。CIからDBへ直接書き込まない。
台帳はDT FindingやGitHub Issue本文の複製ではない。

- サービスは安定ID、担当、事業重要度、理由を持つ。配布単位はサービスに属する。
- CIは `service_id/deployable_id` をProject名、不変の成果物IDを版としてDTへ直接投入する。
  CIからの誤登録リスクは初期設計で受容し、アップロード用中間サーバは設けない。
- 候補を人が確認し、UUID・名・版と確認者・確認時刻を保存する。
  版なし・重複・既存対応との矛盾は承認しない。名前一致だけで自動承認しない。
- `sync --asset-db` は既存DBを検査して読み取り専用で使う。
  `registry_projects` は `matched / unlinked / identity_changed / ambiguous / retired / revoked`。
  担当・重要度は承認済みUUID・名・版が一致した場合だけ表示する。
- 稼働申告はサービス・配布単位・環境・成果物ID、稼働・公開状態、
  確認者・根拠・観測日時・有効期限を持つ追記式の人の申告である。
- `registry_deployments` は承認済み対応に加え、Project版と申告の成果物IDが完全一致した場合だけ結合する。
  状態は `unverified_link / unreported / other_artifact / expired /
  future_observation / conflict / reported`。相反する有効な申告は自動選択しない。
  `reported` は実稼働・公開・SBOMの出所を独立に証明した意味ではない。
- schema v3の訂正は同一対象の旧申告を一対一で指定する。
  新申告の観測日時以降だけ旧申告を無効にし、履歴を残す。
  新規DBはv9（CVE対応候補の採用・取消履歴を追加）。v1〜v8の資産は読取可能。移行は `assets migrate --backup PATH` で
  バックアップ先行で明示し、自動移行しない。移行後の検査失敗もschema変更ごと取り消す。
- `assets update-service`は担当・重要度・事業影響の理由を更新する。
  安定IDは変更不可。変更者・変更理由が必須で、既定は読み取り専用プレビュー。
  v4の`--apply`で現在値と履歴を同じトランザクションに保存する。
  確認した現在値が保存時点で変わっていれば拒否し、履歴保存の失敗時も全て取り消す。
  `assets history --service ID`で変更前後・変更者・理由・UTC時刻を確認できる。
  登録時やv4移行前の履歴は遡って生成しない。同じ値への更新は拒否する。
  更新は次のsyncの参考情報に反映するが、優先度・稼働申告・DT分析・Issueを変更しない。
- JSON登録はschema v1のservices/deployablesのみ。1 MiB以下、
  サービス1〜1,000件、配布単位最大1,000件。未知キー・重複・不明な参照を拒否する。
  既定は書込なしのプレビュー、`--apply` は全件を単一トランザクションで登録する。
  既存IDを上書きせず、衝突時は全件ロールバックする。
- 新規DBは所有者のみ読み書き可能。登録以外で存在しないDBを黙って作らない。
  integrity/外部キー検査、既存出力を上書きしないオンラインバックアップを提供する。
  書込競合待ちは5秒。保持期間と実運用の復元訓練は未完了。

v5の`retire-service / retire-deployable / revoke-link`は変更者・理由が必須で
既定はプレビュー、`--apply`で状態・影響対象の旧リンク・UTC時刻を履歴に保存する。
サービス廃止は全配布単位へ適用し、配布単位の廃止は同じサービスの他単位へ波及しない。
廃止済みサービスへの新規配布単位登録と、廃止済み資産へのリンク承認を拒否する。
廃止はレコード削除や実停止ではなく、過去のリンク・稼働申告を保存する。
稼働申告の追記・同一対象訂正は継続できるが、廃止を取り消した意味にはならない。

リンク撤回は旧リンクを履歴へ保存し、現在の承認表から取り除く処理を原子的に行う。
訂正は撤回後に既存の`assets approve`でDTのUUID・名前・版を再確認する二段階操作。
失敗した再承認は撤回済み状態を維持する。同じUUIDを再承認しても旧履歴は残す。
`sync`は廃止・撤回済みの資産情報を有効な担当・環境として使わず、Finding自体は残す。
廃止コマンド自体は優先度・DT Analysis・抑制・GitHubを変更しない。廃止取消は未実装。
次のGitHub同期で既存の修正作業の資産対応を確認できなくなった場合は、上書きせず停止する。
操作は[運用ガイド](docs/operations.md#資産の廃止と紐付けの訂正)を参照。

## Asset Inventory Context

旧評価入力 `--asset-inventory PATH` はSQLiteとは別形式のJSONである。
[v1例](examples/asset-inventory.example.json)はschema_version、snapshot_id、
timezone付きgenerated_at、deploymentsを持つ。上限は1 MiB・2,000件。

各行はProject UUID・service・environment、nullableなowner/deployed_version、
deployment_status、exposure_status、criticality、source、観測・期限、任意のreviewerを持つ。
未知キー、同じProject/service/environmentの重複、観測以前の期限を拒否する。
非稼働の行は稼働版を持てない。期限切れでは有効な担当・版をnull、他の状態をunknownにする。

結果は入力SHA-256・時刻、選択Projectの資産情報、未紐付け・DTに見えないUUIDを出す。
不正な任意ファイルは警告し `asset_inventory_status=invalid` で同期を継続する。
UUID以外の成果物同一性は検証しない。Findingへの適用性や実稼働を証明せず、
優先度・Analysis・Issue経路・状態を変えない。別入力の公開申告と黙って統合しない。

## Advisory Evidence and Deployment Context

[ADR 0002](docs/adr/0002-advisory-evidence-boundaries.md)に基づき、
`--advisory-snapshot PATH` で事前生成JSONを読む。取得元への通信は行わない。
[形式例](examples/advisory-snapshot.example.json)と[読込処理](src/sbom_ops/services/advisory_snapshot.py)を参照。

取得は独立した `poc-fetch --findings sync.json` で対象をプレビューし、
`--execute` を明示した場合だけ行う。保存先は `--db`（既定 `var/assets.sqlite3`）。
資産と同じSQLiteの `poc_observations` にCVE・情報源別で保存し、DT台帳は複製しない。
通常のsyncには外部取得を足さない。schema v6以降の `--asset-db` からPoCも自動読込する。
別DBを選ぶ場合は `--poc-db`。JSONの `--advisory-snapshot` を明示した場合はJSONを優先し、
DBのPoCとは混ぜない。`--poc-db` とJSONの同時指定は拒否する。
成功したsyncの主ID・明示aliasからCVEを重複排除し、未解決IDは別記する。
プレビューと取得結果の`selection`にCVE数・未解決ID数を出す。
状態は`no_findings`（入力0件）、`no_resolvable_cves`（CVE対応0件）、
`partially_resolved`（一部未解決）、`resolved`。件数はそれぞれの集合サイズで解決率ではない。
CVE対応0件かつ未解決ありなら通信せず部分結果（終了コード1）とし、PoCなしとしない。
Vulnerability-Lookupの `GET /api/sighting/` にCVEと
`type=published-proof-of-concept&page=1&per_page=1` を送り、件数と先頭報告を検証する。
資産・Project情報は送らない。PoC本体、参照URL、投稿者情報は保存・追跡しない。
件数は情報源の報告件数であり、独立したPoCの数や動作確認済み件数ではない。
先頭以外を未取得なら `complete=false` とするが、確認できた報告の存在は表示する。
0件の完全な応答だけを未観測とし、404を含むHTTP失敗や不正・未来日時の応答はunknown。
既定は25 CVE以内、呼出間隔3.1秒以上、期限6時間。CLIで上限・間隔・期限を指定できる。
通信失敗で残りの取得を停止し、即時再試行しない。成功・失敗を一件ずつDBへ確定保存する。
既定の更新間隔は1時間（`--refresh-seconds`）。間隔未満かつ期限内の成功結果だけを再利用し、
期限切れ・未来日時・失敗したCVEは次の取得対象とするが、情報源の待機中は通信しない。
TTL変更は次の取得結果から適用。
中断後も確定済みの新しい成功結果は再利用する。PoC本文の差分取得ではなく、対象CVEの選別である。
失敗時は最終成功の件数・時刻・期限を残し、直近の試行日時・エラー・HTTP状態を別列に保存する。
syncのPoC判定は取得失敗が残っていればunknownとし、過去の件数で現在の有無を断定しない。
`collection.results`に最終成功時刻・失敗理由・HTTP状態・未実行・キャッシュ再利用を出す。
`--output NEW_FILE` は任意のJSONエクスポート。DB保存後に行い、既存ファイルは上書きしない。
PoC更新はv7〜v9に対応し、自動移行しない。移行コマンドと新規作成は最新v9を使う。
v6は読み取りのみ継続できる。
PoCだけの読込失敗は任意入力の失敗としてDT評価を継続する。
`poc_source_state`に情報源別の連続失敗数・再試行可能時刻・エラーを、観測と同じトランザクションで保存。
失敗時は今回の通信を止め、既定60秒から倍増（設定上限3600秒）。CLIの
`--retry-base-seconds / --retry-max-seconds`で設定できる。
Retry-Afterの秒数・HTTP日時を解釈し、指定が有効なら計算した待機時刻との遅い方を採用する。
取得先の指定はローカル上限で切り詰めない。欠落・不正な値は設定した待機を使う。
待機中も有効な成功キャッシュは読めるが、新たな取得はせず、終了コード1と`source_state.retry_at`を返す
（全対象をキャッシュで満たせる場合は0）。別CVEの指定でも待機を回避できない。
成功した通信で連続失敗を解消する。待機の省略・リセット用フラグは設けない。
同じDB・同じ情報源識別子を使うこと。取得中はDBの実体パスに対応する`.poc.lock`を保持し、
重複起動は待たずに終了コード3で停止する。プレビューはロックも作らない。
単一ホストのUnix系OS・ローカルファイルシステムが対象。別DB・ハードリンク・共有ストレージでの排他は保証しない。
ロックファイルは残し、OSがプロセス終了時にロックを解放する。運用中にファイルを削除しない。
`scripts/refresh_poc.py`は外部タイマーから呼び出す単発処理。既定はプレビューで、
`--execute`時のみ、対象1 Projectのsync JSON→PoC取得→確認用一覧を実行する。
既存v7以降の資産DBを要求し、自動作成・移行はしない。常に`--dry-run --no-github`を使う。
全体は別の`.poc-job.lock`で重複起動を防ぐ。同期結果は実行ごとの一時ディレクトリに置き、
同期失敗・不正な入力では取得を止め、過去の入力に代替しない。
PoC部分失敗（終了コード1）でも一覧を出す。各段階の制限時間は既定900秒、
`--stage-timeout`で指定できる。失敗・時間切れは2、重複起動は3。
タイマーの登録・全試行履歴の保管は行わない。定期運用の実環境での通し確認は未完了。

`id-candidates`は成功したsync JSONの未解決GO/GHSA/PYSEC IDに限定してOSVを照会する独立コマンド。
既定はプレビュー、`--execute`でのみ通信・保存、`--show`は保存履歴の読取のみ。
最大25 ID、明示`--id`で入力中の対象を選択可能。主IDを保持し、OSVの明示aliasだけから
CVE候補を作る。応答ID一致、timezone付きmodifiedが観測時刻以下であることを検証する。
複数候補・候補なし・撤回・取得失敗を区別し、説明文・related・upstreamは使わない。
schema v8の`identifier_observations`へ元ID・DT情報源・要求ID・出典・観測/更新日時・候補・
状態を追記する。観測行の`approved=false`は取得時点の状態で変更しない。
採用状態は別のレビュー履歴で管理する。候補を保存しただけではPoC取得・表示・KEV判定へ接続しない。
単一ホストで同じDBの候補取得をロックし、3.1秒間隔、初回エラーで残りを止める。
手動確認用。候補取得のキャッシュ、再試行待機、定期取得は未実装。
契約根拠は[OSV ID API](https://google.github.io/osv.dev/get-v1-vulns/)と
[OSV schema](https://ossf.github.io/osv-schema/)。合成応答による製品テストを持つ。

`id-review`はv9の`identifier_reviews`へ採用・取消を追記する。既定プレビューで、
`--execute`でのみ保存する。観測ID・元ID・DT情報源・選択CVE・変更者・理由・日時を保持し、
採用には明示した期限が必要。既定24時間の観測年齢上限は`--max-age-hours`で変更できる。
期限は現在より後、観測日時＋年齢上限以下。未来・古い観測、最新でない観測、候補外CVE、
DT情報源不一致、撤回済み・失敗観測は拒否する。複数候補からは明示した1 CVEだけを採用する。
採用の再確認と追記は`BEGIN IMMEDIATE`の同一トランザクション内で行う。
元ID＋DT情報源ごとの最新判断だけが有効。取消はその最新採用の観測ID・CVEと一致する必要がある。
期限切れ・未来の判断・新しい観測の追加は有効扱いにしない。内容が同じ再取得でも再確認を要求する。
変更者は入力された申告名であり、認証や署名ではない。実行者の保護はローカルDBのアクセス権で行う。
`id-review`自体は判断の保存・表示だけを行い、`poc_connected=false`を返す。
PoCへの接続は次の独立した明示オプションで行う。

`poc-fetch`と`sync`の`--use-reviewed-identifiers`は既定無効。
取得では`--db`、表示では`--poc-db`（省略時は`--asset-db`）のv9を読取専用で確認する。
JSON snapshotとの併用、自動的なDB作成・移行は行わない。
DTの主ID・明示aliasにCVEがない場合だけ、元ID＋DT情報源の完全一致で最新の有効な採用を使う。
主CVE・DT aliasを上書きせず、他のDT情報源への採用は流用しない。
未採用・取消・期限切れ・未来・新観測で無効になった対応では補完しない。
取得対象の上限・重複排除・再利用・待機制御は通常経路と共通とする。
取得対象の選択根拠は`collection.identifier_selection`と`identifier_selection_at`に残し、
各CVEのキャッシュ利用前と通信待機後にも採用を再確認する。無効なら
`identifier_review_changed`で見送り、情報源の失敗回数や過去のPoC観測は変更しない。
通信中の取消で既に送った要求は取り消せない。取得したCVE別観測自体は保存する。

syncでは通常の評価・Issue処理の完了後に、`published_poc`だけを表示へ補完する。
元ID・DT情報源・採用CVE・出典・観測ID/時刻・採用ID/時刻・申告者・理由・期限を
`assessments`/`review_queue`の`poc_identity`へ出す。情報源別件数は`poc_reports`に表示する。
補完経路が使えなければ`poc_identity_status=invalid`と警告を出し、通常のDT評価は残す。
取消・新観測は次のsyncで再確認し、期限切れは表示時にも再判定する。
保存済みJSONは過去の出力であり、取消後に自動更新されない。
一般alias・KEV照合・EPSS・P0〜P3・Analysis・Issue操作へは補完を渡さない。
同等条件でのPoC報告あり優先の表示順のみ、既存のルールに従う。
定期実行スクリプトはこのオプションを指定せず、従来の主ID・DT aliasだけを使う。

- schema_versionは整数1、snapshot_id、timezone付きgenerated_at、
  vulnerability_observations、project_exposureが必要。
  上限5 MiB、各配列10,000件、脆弱性観測あたりHTTP(S)参照20件。
- 脆弱性観測はID・情報源・signal・outcome・観測時刻・freshness・件数・complete・参照を保持する。
  同じID/source/signalの重複を拒否する。
  `not_observed` は完全取得・0件・参照なしに限定する。失敗はunknown。
  部分取得で未観測を断定しないが、有効な報告があればavailableを保持できる。
- 通常のsnapshotは主IDまたはDTの明示aliasと大文字小文字を無視して完全一致する場合だけ結合する。
  採用CVEによるPoC表示の補完は上記の明示オプションに分離する。
  CVE情報の存在はComponentへの影響や公開環境での稼働を証明しない。
- `published_poc` は有効なCVEと、観測より後のexpires_atが必須。
  有効なfresh/availableがあればPoCはreported、全情報源が有効で未観測ならnot_observed、
  それ以外はunknown。件数は情報源別で保持し、合算しない。
- 鮮度は表示時に再評価する。観測前はunknown、期限に達したらstale。
  freshとして使う期間は `observed_at <= 現在時刻 < expires_at` とし、時差を考慮する。
  未来日時の入力も元の申告・件数を残して読み込むが、PoCあり・未観測・優先表示の根拠にはしない。
- PoCは実行・有効性評価しない。一般のexploit-record、スキャナーテンプレート、
  実悪用報告、Component適用性、到達可能性、インターネット公開を区別する。
- 現在の出力順は同じProject・優先度・KEV・severity・CVSS・EPSS・Analysis・抑制の組の中で、
  reportedなPoCを先にする。全体はP0→P3順とし、同一優先度の無関係な位置は維持する。
  P0〜P3とIssue操作は変えない。PoC有無はBOD 26-04への適合を意味しない。
- 公開申告はProject/環境・status・source・観測・期限を持ち、期限は観測より後。
  期限切れの有効状態はunknown。個々のFindingへの適用を推測しない。
- 不正・読込不能な任意入力は警告し `advisory_snapshot_status=invalid` で同期を継続。
  参照URLは取得しない。成功時はsnapshot_id・生成時刻・入力SHA-256を残す。
  ハッシュは入力の識別であり出所の証明ではない。

## Workflow Rules

GitHub同期は任意で、既定の作成対象はP0/P1。
作成対象の設定は新規作成だけに適用する。既存のopen IssueはP2/P3への変更でも
本文・管理ラベルを更新し、優先度低下だけを理由に閉じない。
抑制済み・NOT_AFFECTED・FALSE_POSITIVEはIssueの作成条件・管理ラベルの優先度から除外するが、
Finding一覧と修正作業の内訳には残す。現在の対象が全て除外なら通常の作成・更新は行わない。
Analysisだけを理由に既存Issueを閉じない。

Finding keyは `v2:{project_uuid}:sha256(machine_identity)`。
identityはProject＋Component UUID＋vulnerability UUID、次にProject＋PURL＋source＋主ID、
最後にProject＋表示名・版＋source＋主IDを使う。旧keyも既存Issue照合に使う。
検索APIの先頭結果ではなく、対象repoのopen/closed両方のIssue一覧と管理keyを完全一致で照合する。
ラベルが外れたIssueも確認し、PRは対象外。ページ継続はLinkを検証し、最大10ページ
（1ページ100件、PR含む）で終わらなければ失敗する。別repoの応答・ページ内外の番号重複・
不正な応答・取得失敗で部分一覧を返さない。全対象repoの一覧を読んでから書込みへ進む。
現行keyと旧keyで複数のIssueに一致する場合、または旧keyを複数の現行Findingが共有する
移行では、推測して選ばず失敗する。同じFindingの重複入力は1実行につき1操作とする。
key・Finding状態をIssue本文の機械用マーカーに保存する。
`<!-- sbom-ops:managed:start -->` から `<!-- sbom-ops:managed:end -->` までが
自動管理範囲で、範囲外の本文と既存タイトルは保持する。優先度の最新値は管理範囲内に記載する。
管理ラベルは設定されたprefixそのものと `prefix-P0`〜`prefix-P3` の予約名に限る。
最新のIssue応答から不足分の追加と不要な優先度ラベルの削除を計画し、
全ラベルの置換は行わない。人のラベル、似た名前、別prefixのラベルは変更しない。
追加結果で必要なラベルを確認してから古い優先度を1個ずつ外す。
名前は大文字小文字を同一視し、削除には取得した表記を使う。
欠損・不正なラベル応答は空集合とみなさず失敗する。追加／削除の失敗は自動再送せず停止し、
次回は最新のIssueから差分を再計算する。dry-runは変更予定だけを表示する。
閉じたIssue・Analysisによる除外対象の管理ラベルは変えない。
本文更新・ラベル追加・個別削除は一括処理ではないため、途中失敗では部分反映が残る。
prefixの変更時に旧prefixを推測して削除することはない。移行は人が確認する。
更新直前に対象repoのIssueを再取得し、open・Issue番号・PRではないこと・Finding keyを照合する。
区切りの欠損・重複・逆順やkeyの不一致では書き込まず失敗する。dry-runも同じ照合を行う。
旧形式は元の本文を一字も削らず「移行前の本文」として範囲外に残し、新しい管理範囲を追加する。
旧本文内のkey・状態・欠落回数は以後の判定に使わない。外部の説明文は制御マーカーにならないよう
HTML文字をエスケープする。
開いているIssueを更新し、なければ作成する。閉じたIssueに一致した場合は
`review-closed`を返し、作り直し・再オープン・本文更新をしない。再開の判断は人が行う。
POSTは自動再送しない。応答喪失や作成応答の不正時は一覧を再取得して完全一致で照合し、
一意に見つかれば`create-reconciled`を記録する。確認できなければ失敗して停止する。
GitHub書込みには明示初期化した `workflow.issue_journal_file` のSQLiteを必須とする。
POST前にrepo・Finding key・run ID・作成意図ID・時刻をpendingとしてコミットし、
確認できたIssue番号と確認run IDを保存する。Issue本文・認証情報・対応状態の正本は複製しない。
次回は対象repoの過去の記録をすべて照合し、一意に同じkeyを確認できたpendingだけ確定する。
見つからない・複数一致・確定済み番号と異なる場合は、今回のFinding一覧にない記録でも
全書込みを止める。POSTの自動再送、記録の期限切れ・削除・初期化による再試行は行わない。
単一ホストの同一DBを使い、同期全体でDB inodeの排他ロックを保持する。SQLiteの書込み
トランザクションはHTTP待機をまたがない。競合時は待たず失敗する（CLI終了コード3）。
DB未設定・欠損・不正・他者が読める権限では書き込まず、DBを自動作成しない。
`--no-github` はDBを開かない。dry-runはDB未設定でも利用できるが、設定時は読み取り専用で
過去の操作を照合し、pendingを確定せず `reconcile-create` を予定として表示する。
別DB・複数ホスト・ネットワークディスクによる並列実行、古いバックアップへの巻戻しは非対応。
送信前停止と応答喪失を区別できない場合の再送解除は未提供。限定検証以外の書込みはまだ有効にしない。

自動クローズは未提供。`close_missing_findings=true` は設定エラーとして拒否する。
過去のMISSING状態・欠落回数は解決判定に使わず、加算もしない。
見えないFindingのIssueは変更せず開いたままにし、実行結果ではUNKNOWNを返す。
再出現したFindingは管理範囲の状態をACTIVEに戻し、欠落回数を消す。
移行前の本文は履歴として保持する。読取失敗時はIssueを書き換えない。
将来の有効化には、対象成果物とSBOMの同一性、解析・取得の完全性、
連続不在の証拠と中断時の扱いを別途定義・検証する必要がある。
本文のPATCHは通信失敗時に自動再送しない。古い本文で人の追記を上書きしないため、
結果を確認してから読取り直す。GETとPATCHは一括処理ではなく、間の同時編集を防ぐ保証はない。
[GitHubの条件付きリクエスト](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests)
は、個別の明記がない書込みでは利用できない。既存Issue本文を更新する間の同時編集を避ける運用を前提とする。
有効化には本文・ラベル・重複防止の限定実環境確認と、途中失敗の監査などを必要とする。
[有効化前の必須事項](ROADMAP.md#github同期を有効にする前の必須事項)の
実装・検証状況は[開発Issue #7](https://github.com/DharmaDoll/sbom-ops/issues/7)で管理する。

## CLI Contract

| コマンド | 動作 |
| --- | --- |
| plan | 設定を検証・表示。外部接続やDB照合の成功を保証しない |
| sync | DT取得・評価・任意のIssue同期。text/json/review出力 |
| upload | 既存UUIDにBOMを投入し処理tokenを待つ。--no-waitで受付後に戻る |
| assets --db PATH | 登録・更新・廃止・紐付け撤回・history・承認・照合・稼働申告・検査・backup・migrate |

`sync` は `--config / --project / --dry-run / --log-level / --wait-for-analysis /
--refresh-kev / --advisory-snapshot / --asset-inventory / --asset-db / --no-github / --github-write /
--output / --sync-log-file` を持つ。正確な引数は各コマンドの `--help` で確認する。
`--dry-run` はIssue書き込みを止めるが読取は行う。`--no-github` はGitHub操作全体を止める。
設定・APIなどの処理済みエラーは終了コード2、成功は0。assets audit-linksの不一致も非ゼロ。

`--output review` は日本語の確認用一覧。JSON/JSONLには既存フィールドを残して
`review_queue`を追加する。いずれもP0→P3順で、1項目は1 Finding。
同じCVEでも別部品・別ProjectのFindingはまとめず、非CVEのID・抑制済みFindingも残す。
環境は`environments`の内訳とし、複数環境をFinding件数へ加算しない。
出力形式の切替は優先度・DT分析状態・Issue操作を変更しない。

一覧の資産情報はSQLite台帳の照合結果だけを使う。`--asset-inventory`の評価用JSONや
別入力の公開申告とは混ぜない。台帳未指定は`not_requested`、未紐付け・Project変更・
曖昧な対応はそれぞれ明示して担当・環境を補完しない。照合済みの場合も稼働申告の
期限切れ・未来日時・矛盾・別成果物・未申告を維持し、実稼働の証明とは扱わない。
PoC件数は情報源別の申告値であり、期限等の有効状態と一緒に表示する。

### 修正作業の候補

`review_queue`のFinding識別は変えず、別に`remediation_groups`をJSON/JSONLと
`--output review`へ出す。台帳の`matched`なサービスID・配布単位ID・PURL全文・
脆弱性の情報源/IDが全て一致したFindingを一組にする。Project UUID・ビルド版・
担当者・環境は組のkeyに含めず、`members`に個々のFindingと資産・環境・分析状態を残す。
`repair-v1:`のkeyは上記の識別値のJSON配列をSHA-256でハッシュしたもので、
同じ修正対象ならビルドの追加・消失や担当変更では変わらない。権限を表すkeyではない。

部品版・qualifier・subpathを含むPURLは構文変換せず完全一致で扱う。
異なる部品版の修正経路まで同一とは仮定しない。名前だけの部品やCVE alias・PoC用対応
だけではまとめず、情報不足・未承認・撤回・廃止などはProject/Finding keyで個別に残す。
`finding_count`は異なるFinding keyの数で、重複入力も`members`から黙って消さない。
`highest_observed_priority`は抑制済みを含む観測上の最優先値であり、各Findingの評価や
DTの判断を上書きせず、そのままIssue作成条件にも使わない。

候補の内訳は選択して観測したProjectの範囲だけであり、全稼働版の網羅や欠落したFindingの
修正完了を保証しない。GitHub有効時は確認済み資産の候補をrepoごとに分け、
`repair-v1:` keyで一つのIssueに同期する。未確認資産・識別情報不足は従来のFinding単位。
同じrepo・同じ組に異なるラベル経路がある場合や、既存の組の資産対応・経路が変わった場合は
推測で移行せず失敗する。repoをまたいで本文や状態を転用しない。

Issueの管理範囲内にversion 1の`repair-record`を保存する。JSONをBase64化し、
外部説明文が制御マーカーにならないようにする（暗号化ではない）。各Findingの現行/旧key、
Project、最後の優先度・分析除外・説明・今回観測の有無を保持する。本文が6万文字を超えれば
切捨てや別Issue作成ではなく停止する。重複field・不正な型・未知version・key不一致も拒否する。

初回作成・旧Issue移行では、同じサービス/配布単位・同じrepoの照合済みProjectを全て選択する。
今回確認できない旧Finding単位Issueが同範囲にあれば、別の修正作業だと推測せず停止する。
既存Issueが一つなら本文外・タイトル・番号を保持して移行し、現行/旧Finding keyは内訳へ残す。
SQLiteの旧作成記録を削除・書換えず、この内訳で同じ番号へ照合し続ける。
複数の既存Issueに一致する場合はopen/closedを問わず停止し、勝手な統合・削除をしない。

移行後は一部Projectだけの同期でも、前回の未観測メンバーを「今回未確認」として保持する。
作成条件と管理ラベルは分析除外を除いた最優先値を使い、未観測メンバーの最後の値も残す。
したがって欠落だけで優先度を下げない。全対象が解析除外なら更新・クローズをせず確認待ち。
FindingごとのP0〜P3やDT分析自体は変更しない。実環境での有効化確認は
[#7](https://github.com/DharmaDoll/sbom-ops/issues/7)で追跡する。

## Logging

成功結果はrun_id・duration_seconds・件数・評価・資産/補足状態・予定/実行操作を保持する。
`runtime.sync_log_file` または `--sync-log-file` で任意のJSONLへ追記する。
親ディレクトリは事前に作る。ログ書込失敗はstderrで警告し、stdoutや同期結果を置き換えない。
CLIは引数解析後、設定読込み前にrun IDを発行し、成功・失敗・中断・作成意図・操作監査で共有する。
成功記録はsucceeded、処理済みエラーはfailed、KeyboardInterruptはinterrupted（終了コード130）。
JSON失敗結果もworkflow_eventsを持つが、不完全な評価一覧や成功件数は返さない。

GitHub書込み時は操作記録DB schema v2のworkflow_eventsへ開始・終了と各書込みの
operation_started／operation_confirmed／operation_unknown／operation_reconciledを追記する。
開始記録を確定保存してからHTTPへ進み、本文更新・ラベル追加・個別削除を別の操作IDで追う。
createの操作IDは作成意図IDと共通で、後続runによる照合も結び付ける。
確認済みとはAPI応答または再取得で確認できたことを表し、DBとGitHubを一括更新する保証ではない。
startedだけの操作は未送信と送信済みを区別できない。終了記録がないrunも結果不明であり、
動作中・成功・未実行のいずれとも断定しない。強制終了時は残った記録とGitHubを照合する。
監査保存失敗では後続書込みを止め、元の障害を別の監査障害で隠さない。失敗JSONの
audit_persistence_failed=trueはメモリ上の記録とSQLiteに差があることを示す。
DBを開けない・設定エラー・dry-run・--no-githubではSQLiteへ監査を保存せず、
通常の結果／失敗出力で同じrun IDを使う。任意のJSONLは必須のSQLite操作監査の代替ではない。
v1 DBへの書込みは拒否し、バックアップ付きworkflow migrateで明示移行する。
過去の監査を推測で補完しない。workflow auditはrun IDで読み出せる。
記録は時刻・対象repo/key/番号・操作種別・ラベル名・例外型に限定し、本文・認証情報・
応答本体・例外メッセージは操作監査に保存しない。ローカルDB管理者への改ざん耐性は保証しない。

秘密情報を記録しない。分析メモ・担当者情報は結果に含まれるため、アクセス・保持期間を管理する。

## Testing Strategy

製品テストは `tests/`、APIの模擬応答契約は[fixtures](tests/fixtures/README.md)。
設定・優先度・識別子・状態遷移・失敗時動作・資産照合を独立に検証する。
実APIの観測結果と固定fixtureを混同せず、脆弱性件数を恒久的な期待値にしない。

labの実行・権限・削除契約は[AGENTS](AGENTS.md)と
[DT lab](lab/dependency_track/README.md)に集約する。
実験は製品の未解決リスクに限定し、DT機能の採用・制約のテスト化・不足機能の実装・
見送りのいずれかを判断する。失敗・部分結果もEXPERIMENTSへ残す。
labは製品パッケージ外とし、生の結果・環境UUID・認証情報はignoredなvar配下に置く。
変更実験は使い捨てProject・限定権限・明示的opt-inが必要。
削除は実行単位の台帳・実対象の同一性確認・専用キー・明示実行・監査を必要とする。
token完了直後に削除せず、非同期処理の静穏を確認して別操作で行う。
即時の自動削除は禁止する（Immediate automatic cleanup is prohibited）。

## Google Cloud Deployment Contract

Google Cloudはローカル運用の前提ではない。導入する場合も次の要件を維持する。

- API、ブラウザ用frontend、永続PostgreSQLを別の実行責務として扱う。
- 実行基盤は[ADR 0001](docs/adr/0001-gcp-secure-delivery-runtime.md)で決定する。
  Cloud Runを前提にせずGKE等と比較し、変更前に[google/skills](https://github.com/google/skills)の関連指針を確認する。
- GitHub ActionsはOIDC/WIFを使用し、長期サービスアカウントキーを置かない。
  組織・リポジトリの不変ID、保護ref/environment、承認済みworkflow identityへ信頼を限定する。
- CIは保護したBOM_UPLOADキーでDTへ直接送る。自動Project作成にはPROJECT_CREATION_UPLOADを追加する。
  管理・分析権限を付けず、人の資産紐付け承認を省略しない。
- サービス間認証とブラウザ認証を別に検証する。
- 本番公開前に構造化ログ、認証・投入監査、失敗通知、バックアップ・復元・移行・
  アップグレード・ロールバックを検証する。

基盤の変更には脅威モデルへの影響・戻し方・検証方法を記録する。
実行用資料は[infra/gcp/poc](infra/gcp/poc/README.md)を参照する。

## Open Items

未完了の作業と優先順位は[ROADMAP](ROADMAP.md)のみで管理する。
将来のVEX書込では、参照を解決してComponent/Projectの対象範囲と全Finding差分を
承認に結び付け、投入後に対象集合を照合する。Componentの承認をProject全体へ拡大しない。
未解決参照・追加/欠落変更は失敗として扱い、コメント付き更新を無条件に再試行しない。
現行の製品にVEX書込権限を追加する根拠とはしない。
