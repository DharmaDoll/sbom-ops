# Implementation Specification

現在の製品の動作と守る境界を定義する。
操作は[運用ガイド](docs/operations.md)、未実装・既知の課題は[ROADMAP](ROADMAP.md)、
設計理由は[ADR](docs/adr/README.md)に記載する。将来機能を実装済みとは扱わない。

## Scope

実装範囲はDT Finding取得、KEV補完、DT由来EPSS、優先度計算、資産台帳、
補足JSON読込、CLI、任意のGitHub Issue同期。
VEX書き込み、到達可能性分析、LLM、Jiraは未実装。
外部EPSSの `EpssClient` はスタブであり、設定したURLへの自動フォールバックはない。

DTのPolicy Violations（ライセンス・セキュリティ・運用ポリシー違反）は初期製品の対象外。
違反の取得・分析状態変更・作業起票を行わず、Findingの優先度へ混ぜない。
このため製品にPolicy Violations用の追加権限・状態遷移は導入しない。
必要な組織はDT側で確認し、担当への振り分け需要が具体化した時点で別途検討する。
この対象外判断は、Findingと資産情報を用いるBOD参照表示には影響しない。

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
- 新規キャッシュはschema v2とSHA-256を持ち、取得元URLとカタログ版・公開日時・件数も保存する。
  不正な記録や別URLのv2記録は古い値の代用にもしない。
  旧形式は妥当なら読み、成功した更新時に置換する。ハッシュは出所証明ではない。
- 同じパスの取得・更新はローカルSQLiteロックで直列化し、上限時間で失敗する。
  ネットワーク共有ファイルは対象外。
- `KevClient.get_snapshot()` は取得元、版識別、取得/304再検証日時、有効期限、
  取得経路（fetched/cache/revalidated/stale）と掲載CVE集合を返す。
  キャッシュ再利用で取得日時は更新しない。取得失敗時は例外となり、前回の結果を残さない。
  既存の集合取得APIとP0〜P3は維持する。新しい根拠モデル・通常syncへの接続は未完了。
- 未掲載Noは、有効な完全カタログと正確なCVEがある場合だけ。
  完全性は宣言された件数・重複なしの正規CVE集合・版・公開日時の整合を指す。
  全項目のJSON Schema検証や、世界中の脆弱性の網羅性・真正性の保証ではない。
  旧形式/v1に欠ける根拠は304でも補完せず、完全性不明とする。
  期限切れ、未来の取得/公開日時、stale代用、不完全なカタログでは掲載判定はunknown。
  TTLは既存設定に従い、0以下では参照判定を既知にしない。

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
syncの明示的な参照表示で利用できる。期限計算には未接続。
CISA入力には下記のSQLite保存・独立CLIを利用できる。
外部入力は[CISA公式データの単一CVE取得と変換](docs/priority-policy.md#cisa公式データの入力契約)を用意する。

[triage_identity.py](src/sbom_ops/domain/triage_identity.py) は、参照評価用のCVE対応を
Findingの元ID・情報源・Finding key・aliasから分離して返す。元データは書き換えない。
直接のCVEと明示aliasに含まれるCVEを候補とし、ASCIIの大小文字と前後空白だけを正規化する。
同じCVEの重複はまとめるが、複数候補・不正なCVE形式・元ID欠落では選択せず理由を残す。
説明文やPoC専用の採用結果から候補を作らない。これはID対応だけで、資産との結合は
下記サービスで行う。既存の優先度用KEV照合は変更しない。

[triage_assets.py](src/sbom_ops/domain/triage_assets.py) は、照合済みProjectと同じ台帳の
元申告をサービス・配布単位・環境・成果物で照合し、公開状態の根拠へ変換する。
撤回・廃止・Project名/版の不一致・未来のProject照合では結合しない。
申告ID・申告者・理由・元日時を保持し、未来の訂正は適用前の記録として分離する。
訂正が適用された後は、訂正の期限が切れても旧申告を復活させない。
未配備や矛盾を非公開Noへ変換しない。申告は実稼働の独立検証ではなく、
この変換だけではCVE対応・KEV/CISAとのサービス結合は行わない。

[triage_context.py](src/sbom_ops/services/triage_context.py) は取得済みのFinding、台帳、
照合済みProject、KEV取得結果、CISA評価を読取り専用で結合する。
元IDと参照CVEを分け、複数/未確認CVEなら参照コンテキストを作らず候補と理由を返す。
別Projectや別CVEの情報を渡すことは拒否する。KEV・CISA・資産の観測/期限を維持し、
不足・期限切れ・未来・矛盾は要素ごとに残す。資産が未確認でも有効な脆弱性情報を捨てない。
このサービスは通信・保存・優先度変更を行わない。

`sync --triage-environment NAME --asset-db PATH` で、対象環境の参照情報を別欄へ追加する。
指定しない場合は `triage_context_status=not_requested` と空配列を返す。
CISAは任意の `--cisa-snapshot CVE REVISION ID`（CVEごとに1回）で保存記録を明示選択する。
不正・重複指定、記録欠落・版不一致は同期前にエラーとし、最新行の自動選択・再取得をしない。
KEVは同じ同期取得で保持した元のsnapshotを使い、追加取得しない。根拠を提供しない
互換クライアントでは集合や同期時刻から根拠を創作せず、参照欄は未確認とする。
元Finding・全Projectを用いた資産照合結果・元申告を使い、環境を越えて借用しない。
JSONの `triage_contexts` は元ID/候補CVE・評価時刻・選択記録ID・出典版・各要素の
状態と根拠・未確認理由・元申告/適用前訂正を保持する。text/reviewは要約を表示する。
`evaluated` は評価処理の実施であり、情報が揃ったことを意味しない。
各参照欄の `reference` は固定版の16条件に照合し、日数区分・侵害確認の追加指定・不足要素を返す。
資産照合と4要素のknownが必要で、不足時はpending。出典・確認日・ルール版・参照行を保持する。
最新版の保証ではなく、起算・実期限日・自社SLAは計算しない。
既存の優先度・PoC順・DT・Issue内容を変えない。
`triage_contexts[].guidance` は同じ対象の資産範囲・資産担当・人向けの次の行動を返す。
各行動はcode/reason/role/assignee/instructionを持ち、automatic_actionsはfalse。
照合済み資産のサービスが台帳で一意に確認できる場合だけ資産担当を表示する。
未照合・未登録・重複は未割当。セキュリティ担当の実名は推測せず役割だけを示す。
不足理由（未取得・不明・期限切れ・未来・矛盾）を保ち、確認する情報と依頼先を示す。
条件が揃った場合は修正・緩和計画の確認を案内し、参照表の追加指定がある場合だけ
侵害確認の計画を案内する。担当割当・通知・期限確定・調査の実行は行わない。
このオプションはGitHub操作を許可も禁止もしない。参照だけの運用は `--no-github` を指定する。

[vulnrichment_snapshot.py](src/sbom_ops/domain/vulnrichment_snapshot.py) はCISA入力の
SQLite保存に向けた版付きの直列化契約を定義する。CVE、固定コミット、取得日時、
明示した有効期間（整数マイクロ秒）、元レコードを保持し、復元時も既存の入力検証を行う。
評価時刻・各要素の期限・元の悪用区分・未確認理由を再現し、読込時刻で鮮度を延長しない。
元レコードはUTF-8で1 MiB、保存形式は2 MiB以下。重複キー・非標準JSON定数・
未知の形式版/項目・不正な出典/日時/期間は拒否する。入力辞書の後の変更は取り込まない。
この形式自体は公式取得の真正性や最新版を証明しない。独立したJSONファイル保存は追加せず、
保存は共有DB schema v10の`vulnrichment_snapshots`へ追記し、元の記録を上書きしない。
読込には記録IDと期待するCVE/固定版を指定し、索引と内容の不一致はエラーにする。
DBは明示初期化・移行し、読取専用モードを利用できる。
`cisa fetch` はCVE・40桁固定コミット・正の整数の `--max-age-hours` が必須。
既定は通信もDB作成も行わないプレビュー。`--execute` で1件だけ取得・検証・追記する。
DBの親ディレクトリは事前に作成し、未作成DBは実行時だけ初期化する。旧版は自動移行しない。
取得/検証/保存失敗はエラーとし、過去の成功を今回の成功として返さない。
`cisa show` は記録ID・CVE・固定版を指定して読取専用で表示し、再取得しない。
取得・評価・表示の日時と `effective_status` を区別し、固定版取得では `latest_verified=false`。
終了値0は操作成功であって根拠の新鮮さ・完全性を保証しない。通常sync、資産結合、
優先度/期限変更、DT/製品Issue操作は行わない。操作例は[運用ガイド](docs/operations.md#cisa評価の取得保存表示)。

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
  新規DBはv12（速報の変更履歴の保存領域を追加）。v1〜v11の資産は読取可能。移行は `assets migrate --backup PATH` で
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

## SBOMの生成対象と投入タイミング

コンテナ配布では、CIがビルド後の**実際に配布する最終イメージ**からBuild SBOMを
生成し、DTへ直接送信する。標準の順序はbuild → registryへpush → digest確定 →
そのdigestのイメージからSBOM生成 → DT投入とする。push前に生成する場合も、
生成対象とpush・配布対象の同一性を確認する。可変タグだけでは対応を確定しない。
これは導入CIの運用契約であり、全利用者のCIへの自動組込みを実装済みとするものではない。

- 生成・送信は、リリース候補または配布対象の新しい成果物ができるたびに行う。
  同じcommitの再ビルドでも成果物が異なれば別対象とする。
- 入力はCycloneDX SBOM。OSパッケージとアプリケーション依存部品を収録し、
  OS名・リリース、パッケージ名・版・PURL、利用可能な`distro`情報を保持する。
  生成器・版・設定による収録漏れを確認し、SBOMが存在するだけで網羅性を保証しない。
- マルチステージビルドは最終ステージを対象とする。複数アーキテクチャは各配布
  イメージを対象とし、platform別manifest digestとindex digestを混同しない。
- Source SBOMは開発時の補助情報として別に扱い、Build SBOMを上書きしない。
  イメージ外のホストOS・実行ホストのカーネル・設定不備は、このSBOMの評価範囲外。
- 同一成果物の再配備や新しいCVEの公開だけを理由にSBOMを再生成・再送しない。
  DTの登録済み構成に対する再解析と、SBOM訂正による再投入を区別する。
- アップロード受付・BOM処理完了・脆弱性解析結果の取得を別段階として確認する。
  受付成功やFinding 0件を「解析完了・脆弱性なし」の根拠にしない。

OS脆弱性の検出はDTの版、解析器、有効なデータソースに依存する。DT 4.14の
Alpine/Debian/Ubuntu向けdistro照合にはPURLの`distro`とOSVデータが必要。
導入対象OSの代表イメージで、収録部品・既知の検出対象・本PJでの取得を検証する。
この契約の記載だけでOS別の通し検証を完了したとは扱わない。

根拠: [DT CI/CD](https://docs.dependencytrack.org/usage/cicd/)、
[DT 4.14のOS照合](https://docs.dependencytrack.org/2026/03/09/v4.14.0/)、
[Trivyのイメージ対象とSBOM生成](https://trivy.dev/docs/latest/target/container_image/)。
具体的な確認順は[運用ガイド](docs/operations.md#コンテナのsbomを生成してdtへ送るタイミング)を参照。

## SBOMライフサイクルの結合契約（後続実装の基準）

この節は#20の設計契約であり、現行CLIが以下の根拠をすべて保存できる意味ではない。
既存のAsset Registryを再利用し、不足する保存・表示を#21、教材を#22、逆引きを#23で扱う。

| 情報 | 対象と責任者 | 正本・保持先 | 保証しないこと |
| --- | --- | --- | --- |
| Source SBOM | ソースと依存定義。開発/CIが生成 | 元SBOMとソース参照はCIの成果物保管先 | ビルド後の全構成、配備状態 |
| Build SBOM | 特定の配布成果物。ビルド担当が生成・訂正 | 元SBOMはCI保管、取り込んだ構成/FindingはDT | 生成器の網羅性、署名の信頼性、実稼働 |
| 稼働申告/観測 | 環境への成果物配置。運用担当が確認・訂正 | 資産対応と期限付き申告はSQLite、外部観測は出典参照 | メモリ内の完全な構成、実行可能性、脆弱性の悪用可能性 |

結合の基準は`service_id / deployable_id / artifact_id`。環境は成果物とは別の軸とし、
同じ成果物を複数環境へ配置してもBuild SBOMを環境ごとに複製しない。
コンテナ等では実際に配布した成果物のdigestを不変IDに用いる。可変タグやソースcommitだけで
同一成果物と判断しない。既存の不変ビルドIDも維持するが、digest未確認を検証済みにしない。
DTへの既存規約（Project名=サービス/配布単位、版=成果物ID）と人によるUUID照合は維持する。

後続の根拠記録は、観測種別（source/build/unknown）、ソースのリポジトリ参照とcommit、
成果物IDと任意のdigest、ビルド実行参照、元SBOM参照とファイルdigest、
記録者・記録日時・訂正理由・旧記録への参照を区別して保持する。
存在しない情報はunknown/未指定とし、SBOM内容・Project名・ファイル名から種別を推測しない。
Sourceは対象ソースを識別できても、Buildへの対応が未確認なら成果物へ結合しない。
外部参照に認証情報を保存せず、参照先の自動取得や署名検証をこの記録機能に含めない。
CIからSQLiteへは書かず、手元の明示登録で既存の資産対応と照合する。

最小記録は、登録済みのサービス/配布単位、観測種別、元SBOMを指す参照、
記録者と記録日時を必須とする。Buildには成果物ID、Sourceにはリポジトリ参照と
不変のソース版を必要とする。不足した記録をBuild/Sourceの確定根拠に昇格させず、
unknownとして保持するか、呼出元へ不足を明示して登録を拒否する。
Sourceに成果物対応を添える場合は明示された対応に限定し、同じcommitの全成果物へ伝播しない。
ビルド実行参照とdigestは任意だが、未指定を既存IDから生成しない。
元SBOMファイルdigestと成果物digestは別項目とし、値があるだけで照合済みにしない。
記録日時はシステムの受付時刻、元観測日時は任意の出典時刻として区別する。
記録者は申告名であり、認証済みの署名者ではない。

### 更新の意味と受入例

| 出来事 | 期待する扱い |
| --- | --- |
| 同じcommitから異なる成果物A/Bを生成 | A/Bは別成果物。各Build SBOMとProjectを混同せず、ソース参照の共有だけを表す |
| A/Bが本番で並存 | 両方の配置申告を保持。一つを「最新」として自動消去しない |
| Aを別環境へ再配備 | 同じ成果物に別環境の申告を追加。新ビルドや新SBOMを捏造しない |
| 同じ成果物AのSBOMを訂正 | 成果物IDは維持し、元SBOMの別文書/digest・訂正関係を追記。訂正前の根拠を消さない |
| AからBへ切替後、Aを停止 | Bの稼働とAの停止を別申告とする。B登録だけでA停止を推測せず、停止でFindingを修正済みにしない |
| Source/Buildの部品が相違 | 観測対象の違いとして保持。片方で他方を上書きしたり、完全性を推定したりしない |
| 未承認Project、別成果物、期限切れ、矛盾 | 未確認の状態と元根拠を残し、別対象の有効な値を借用しない |

SBOM訂正の「現在版」は同じ対象・同じ観測種別に対する明示的な訂正関係で決める。
取得順や日時の最大値だけで決めず、訂正先不在・対象違い・競合は拒否または確認待ちとする。
DTに現在取り込まれている内容と元SBOMの一致を未確認なら、履歴登録の成功だけで一致済みにしない。
元SBOMの履歴保管はCI側の責任であり、DTの履歴保存能力を前提にしない。
訂正では旧記録IDと理由を必須とし、サービス/配布単位・観測種別・対象の不変IDを
変更しない。Sourceの対象はリポジトリとソース版、Buildの対象は成果物IDである。
別対象への訂正、存在しない旧記録、既に訂正済みの旧記録への分岐は書込み前に拒否する。
新記録と訂正関係は同一トランザクションで追記し、失敗時は旧状態を維持する。
訂正関係のない複数記録は併存として表示し、任意の一件を現在版に選ばない。
unknownから確定種別への変更は別の確認記録とし、元のunknownを上書きしない。

### 既存機能と今回の追加範囲

既存: サービス/配布単位、承認済みProject対応、成果物IDの完全一致、環境別の期限付き申告、
同一対象の申告訂正、廃止/撤回履歴、元BOMの品質報告とファイルdigest。
追加: Source/Buildの種別とソース・ビルド・元SBOM参照の一体的保存/表示、
SBOM文書の明示訂正履歴。既存の稼働申告訂正をSBOM文書訂正へ流用しない。
DB/CLI形式・入力上限・移行は下記契約に従い、現行データへ推測で補完しない。
中間サーバ、新グラフDB、メモリ収集、署名検証、優先度/SLA/Analysis/Issue操作変更は非対象。

### 根拠登録v1の入力契約

初期版は一回一記録のJSON入力とし、バッチ処理・外部参照の取得を含めない。
型付きモデルとJSON検証・訂正対象一致、SQLite v11への明示移行と保存/読取を実装。
保存は登録済み・廃止されていない資産だけに許可し、訂正先照合と追記を一つの
トランザクションで行う。旧記録と独立した記録は保持し、訂正の分岐を拒否する。
読取時はJSONを再検証し、索引列との不一致を拒否する。登録・履歴CLIは実装済み。
承認済みProjectとの照合は`sync --asset-db`のJSON・通常テキストに表示する。
書込み前に全体を検証し、プレビューではDBの作成/移行/変更をしない。

| 項目 | 契約 |
| --- | --- |
| `schema_version` | 整数1のみ。boolは不可 |
| `service_id`, `deployable_id` | 既存の識別子規則。書込み時に登録済みの有効な配布単位か照合 |
| `kind` | `source / build / unknown`を明示。欠落から推測しない |
| `sbom_ref` | 必須の参照文字列。元文書は台帳にコピーしない |
| `actor` | 必須の申告名。認証された人物の証明ではない |
| `artifact_id` | buildで必須。その他では任意。既存の不変IDと完全一致で扱う |
| `source_repository`, `source_revision` | sourceで両方必須。他種別でも指定するなら両方必要。ソース版は省略形でないGit commit（40/64桁hex）を初期対象とする |
| `artifact_digest`, `sbom_digest` | 任意。`sha256:`と64桁hex。成果物と文書で別項目。digestの申告は照合成功を意味しない |
| `build_ref` | 任意のビルド実行参照 |
| `observed_at` | 任意のtimezone付き時刻。UTCへ正規化。未来の観測は有効な根拠に使わない |
| `supersedes_id`, `reason` | 訂正時に両方必須。IDはbool以外の正整数でSQLite整数範囲内。初回登録に訂正理由だけは指定しない |

受付時刻と保存記録IDはシステムが付与し、入力での上書きを受け付けない。
unknownは利用者が明示する種別であり、不正なsource/buildを自動格下げして保存しない。
unknownの記録は文書参照として残すが、確定した構成根拠へ採用せず、初期版では訂正対象にしない。
確定種別の記録は別途追加する。元記録を消去しない。

入力はUTF-8で最大64 KiB、オブジェクト一つ。未知項目、重複JSONキー、非標準の数値定数、
不正型を拒否する。任意項目は省略またはnullで未指定を表し、空文字を有効な値にしない。
文字列は前後空白・制御文字を拒否し、勝手なtrimで識別子を変えない。
service/deployableは各128文字、artifact IDは既存と同じ512文字、actorは128文字、
reasonは1,000文字、各参照は2,048文字を上限とする。参照は資格情報を含まないHTTPS URL
（userinfo/query/fragmentなし）、または保管先内の相対パスとし、絶対パス・親への移動を拒否する。
初期版では解釈の相違を避けるため、参照内のpercent encodingとバックスラッシュも拒否する。
参照は文字列として保存するだけで、ファイルを開く・URLへ接続する・コードとして実行する操作はしない。
任意の文字列が秘密情報を含まないことまで自動保証できないため、登録者も内容を確認する。

保存は既存SQLiteの次版へ追加し、旧DBはバックアップ付き明示移行まで書込みを拒否する。
既存の資産・PoC・CISA・識別候補データを維持し、旧レコードへ根拠を創作して埋めない。
読取時も保存内容と索引を検証し、破損を「記録なし」に置き換えない。
訂正履歴の読取では訂正元の存在・同一対象・順序・分岐なしも確認する。

#### CLI接続契約

- `assets --db PATH evidence-register --file PATH` は既存v11/v12 DBを読取専用で開き、
  JSONと登録資産・訂正先を照合してプレビューする。DB作成や暗黙移行はしない。
- 同じコマンドに `--apply` を付けた場合だけ保存する。プレビュー後に他の操作が
  あった場合に備え、保存時もトランザクション内で条件を再確認する。
- `assets --db PATH evidence-history --service ID --deployable ID` は履歴を
  読取専用で取得する。登録済み資産の空履歴と未登録資産を区別し、後者はエラーにする。
- 出力はJSON一つとし、登録は `status`（`preview` / `applied`）と `evidence` を含む。
  保存時のみ `record_id` と `recorded_at` を付け、プレビュー時に架空の受付情報を作らない。
  履歴は `service_id` / `deployable_id` / `records` を含み、旧記録もID順に返す。
- 入力はUTF-8のJSON一記録、64 KiBまで。ファイルの読込みにも上限を適用する。
  不正入力・未登録/廃止済み資産への登録・不正な訂正・DB版不一致・破損は失敗とし、
  部分保存せず、入力全文や秘密情報をエラー出力しない。
- 登録成功は根拠を保存したことだけを示す。承認済みProjectとの一致・未来観測・
  撤回・期限切れ等の有効性は資産照合表示の契約で別途判定し、保存成功から推測しない。

#### 根拠とProjectの照合表示

`sync --asset-db`のJSONは`lifecycle_evidence_status`と`lifecycle_evidence`を含む。
前者は`not_requested`（DB未指定）/`migration_required`（旧版）/`loaded`/`invalid`。
後者はProject別に`project_uuid`・既存の`project_status`・根拠の`records`を保持する。
承認・廃止/撤回と根拠履歴は同じSQLite読取トランザクションの時点で取得する。
読取開始後の更新は次回に反映し、異なる時点の情報を混ぜない。
各記録はID・受付日時・入力根拠・照合状態を含む。読取失敗時は全体を`invalid`とし、
一部だけの結果を返さない。既存Finding・優先度・Issue操作を変更せず、読取失敗を
脆弱性ゼロや修正完了と扱わない。通常テキストにも同じ追加情報を表示する。
`--format review`では対応一覧の末尾にProject別の根拠一覧を日本語で表示する。
根拠ID・種別・成果物・元SBOMと確認事項を示し、Findingの順序や修正作業の分類を変えない。

既存のProject観測が`matched`であり、現在の承認済みUUID・名・版・サービス・配布単位と
完全一致する場合だけ、Build根拠の成果物IDとProject版を照合する。撤回・廃止や未来の
承認日時は照合不可。Source/unknownは履歴として残すがBuildの代替にはしない。
観測日時が不明/未来、受付日時が未来の記録は有効候補にしない。未来/日時不明の訂正で
旧記録を無効化しない。過去に有効となった訂正の旧記録は履歴として表示する。
同一成果物の独立した有効候補が複数ある場合は併存を明示し、自動選択しない。
照合結果は構成根拠の対応だけを意味し、実稼働・署名検証・完全性を保証しない。
稼働申告の期限切れ/矛盾/停止は既存の配置観測をそのまま併記し、根拠の照合で上書きしない。

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
PoC更新はv7〜v10に対応し、自動移行しない。移行コマンドと新規作成は最新v10を使う。
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
取得では`--db`、表示では`--poc-db`（省略時は`--asset-db`）のv9以降を読取専用で確認する。
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

### CVE・部品からの逆引き（#23の実装契約）

既存の`review_queue`を再利用し、Findingからサービス・配布単位・成果物・環境・担当へ
辿る読取専用機能とする。検索のためにDT全構成を複製したり、グラフDBを追加したりしない。
初期のCLIは成功したsyncの保存JSONを入力とし、外部取得・SQLite更新・Issue操作をしない。
保存時点の結果であり、検索時点の配置や影響を保証しない。
`lookup --findings PATH` に `--cve ID`、`--vulnerability-id ID --source SOURCE`、
`--purl PURL` のいずれか一つを指定する。`--output review/json`、既定review。
成功・範囲内一致なしは終了0、読取/検証/検索条件の失敗は終了2。失敗時に検索結果は出さない。
JSONには`scope=saved_sync_only`、元run ID、入力件数、検索条件、一致件数と元の確認用行、
ProjectごとのSBOM根拠状態/記録、検索範囲の注意を含む。DBや外部APIへ接続しない。

- 検索条件は一度に一つ。CVE主ID、情報源と組み合わせた脆弱性主ID、PURL全文のいずれか。
  検索値は最大2,048文字、情報源は128文字。空文字・前後空白・制御文字を拒否する。
- CVEは大文字の`CVE-年4桁-番号4〜19桁`。主IDの完全一致だけで検索する。
  非CVE主IDのalias候補やPoC用に採用した対応は、資産への影響を結合する根拠に流用しない。
- 元ID検索は情報源を必須とし、情報源・主IDをともに完全一致で比較する。
  PURLは版・qualifier・subpathを含む全文一致。大小文字変換、部分一致、名前だけの一致をしない。
- 同一CVEの複数Finding、新旧成果物、複数環境、抑制済みを消さず、元の順序と識別子を保持する。
  資産が未紐付けでも検索対象から落とさない。既存の未確認・期限切れ・矛盾を保持し、担当を補完しない。
- 結果は元run ID・Project UUID・Finding key・元ID/情報源・部品識別子と、該当Projectの
  SBOM根拠を参照可能にする。根拠未取得・旧版・破損を空の根拠と同一視しない。
- 正常な空結果は「この入力の検索範囲内に一致なし」。影響なし・修正済みとはしない。
  読取失敗、不正JSON、失敗run、不整合や欠落を持つ入力は検索失敗とし、部分成功に見せない。
  件数整合の検査はDT全体の網羅性の証明ではない。対象外Project・alias未解決は検索範囲外。
- 保存JSONの読取上限は8 MiB・深さ64・Finding 10,000件。通常ファイルのみを読み、
  UTF-8不正・JSON重複キー・NaN等を拒否する。run IDは256文字以内の非空・表示可能文字列。
  findings_processedとreview_queue/assessmentsの件数、両一覧のFinding/Project/元ID・情報源・
  部品識別子の組を件数付きで照合する。Project数より多い異なるProjectを含む入力も拒否する。
  この検査は入力全体の整合性確認の一部であり、各行の資産・環境・根拠検証を代替しない。
  優先度・severity・Analysis・抑制・KEV・スコア・理由も元評価と照合し、不正な列挙値、
  boolを数値に使った入力、非有限/範囲外スコアを拒否する。署名検証ではなく内部整合性検査である。
- 各行の資産・環境は保存されたregistry_projects/registry_deploymentsと照合する。
  未紐付け・曖昧・台帳未指定の行へ担当や環境を補完しない。reported以外の配置観測に
  確定した稼働/公開状態・確認者・有効日時が混ざる入力を拒否する。
  reportedは正整数の申告ID、申告元、環境・成果物・確認者、timezone付き観測/期限を必要とする。
  これは保存時の整合性確認であり、検索時刻でreportedを期限切れに変換する処理ではない。
- P0〜P3、Analysis、SLA、PoC評価、GitHub操作は変更しない。判定ではなく調査の入口とする。

検証は#22のA/B並存・旧版停止にCVE/部品を結合し、担当・環境と元根拠まで辿れること、
誤った情報源・部分一致・alias候補で結合しないこと、空結果と失敗を区別することで行う。

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

## SBOM品質評価の受入仕様（開発中）

[#12](https://github.com/DharmaDoll/sbom-ops/issues/12)の実装契約。現行のuploadやQuick Startが
次の検査を行うという意味ではない。CIで元SBOMを検査してから直接DTへ投入し、中間サーバは設けない。
初期対象はCycloneDX JSON 1.5/1.6とし、その他の版・XML・SPDXは未対応を明示する。
対応形式を絞ることと、2026年版の全要素を満たしたとの主張は区別する。

基準は2026-10-24に確認した[共同執筆機関の公開本文・付録A/B](https://www.cyber.gov.au/publication/2026-minimum-elements-for-a-software-bill-of-materials-sbom)。
下表はその要素に対する本PJの対応案であり、公式なCycloneDX適合判定表ではない。
表現は[CycloneDX 1.5](https://cyclonedx.org/docs/1.5/json/)と
[1.6スキーマ](https://cyclonedx.org/schema/bom-1.6.schema.json)に照合する。
`C` はmetadata.componentおよびcomponents内の入れ子を含む各対象部品。
生成ツール・サービスを対象ソフトの部品へ無条件に混ぜない。

| 2026要素 | 元BOMの確認場所・本PJの扱い |
| --- | --- |
| 作成主体 | metadata.authors。1.6ではmetadata.manufacturerも対象。toolとは別 |
| 作成者署名 | BOM直下signature、または別添署名。部品の署名で代用しない |
| データ形式名 | bomFormat |
| データ形式版 | specVersion |
| 生成コンテキスト | metadata.lifecycles。独自名は対応未確認の理由を残す |
| 更新日時 | metadata.timestamp。ファイル更新日時を代入しない |
| ツール名 | metadata.toolsの旧配列またはcomponents/servicesの各name |
| ツール版 | 同じツールのversion。別ツールの版と組み合わせない |
| SBOM版 | 文書直下version。省略値を入力に記載された証拠としない |
| 部品の作成主体 | C.author、1.6のC.authors/manufacturer。対象ソフトの旧metadata.manufactureも区別して保持 |
| 依存関係 | dependenciesのref/dependsOn。参照先と対象部品の対応を検査 |
| 部品ハッシュ値 | C.hashes[].content。実行可能成果物との照合は別の検証 |
| ハッシュ方式 | 同じhashes要素のalg。方式と値を別の行から継ぎ合わせない |
| 部品識別子 | C.purl/cpe/swid等。bom-refだけで外部識別の十分性を証明しない |
| ライセンス | C.licenses。文書自体のmetadata.licensesを流用しない |
| 部品名 | C.name |
| 部品版 | C.version |

2021年版から追加されたのは、署名・形式名/版・生成コンテキスト・ツール名/版・SBOM版・
ハッシュ値/方式・ライセンスの10項目。既存の7項目も、特に作成主体、部品識別子、
部品の作成主体、部品版の意味を見直す。単なる必須キーの追加として扱わない。

supplier/publisher/groupは作成主体の自動代用にしない。1.5のauthorや旧manufactureなど
表現の制約・非推奨項目は報告し、原文の意味との対応が確定しない場合は検証不能を残す。
署名、実際の依存関係の網羅、生成・訂正の運用、配布先のアクセスは、BOM単体では証明しない。

### 結果・副作用・受入確認

`domain/sbom_quality.py` は項目単位の不変モデルと申告照合を提供する。
元BOMの項目抽出・集計・独立CLIは接続済み。対応範囲の限界を示し、適合認定とはしない。
`domain/sbom_quality_document.py`は文書9項目の抽出と文書向け申告照合を提供する。
作成者はauthorsのname/email、1.6の作成組織はmanufacturer.nameを確認し、
人物/組織を特定できないオブジェクトは検証不能とする。生成ツールや部品の作成主体で代用しない。
日時はタイムゾーン付きの形式と暦を確認するが、うるう秒や不明オフセットは検証不能を残す。
ツールの旧配列/新components・servicesを読み分け、複数ツールで一部の名前/版が欠ける場合や
別ツールの名前と版しかない場合はinvalidとする。SBOM版の省略値1は補完しない。
署名は単一/signers/chainの基本的な構造を観測するだけで、アルゴリズム・鍵・証明書の信頼性を
検証しない。別添署名の入力は未対応で、BOM内に無ければmissingとなる。
独自名の生成コンテキストは検証不能を残す。

`domain/sbom_quality_components.py`は対象ソフト・入れ子を含む部品8項目を観測する。
作成主体や版、申告を親から子へ継承しない。旧metadata.manufactureは対象ソフトだけに適用する。
ハッシュ値と方式を同じ配列要素から確認し、方式別の長さ不一致や不正な16進表現はinvalid。
BLAKE3の可変長の扱いは検証不能を残す。既存の弱い方式名の記載も観測するが、その方式で
ハッシュを計算・推奨しない。成果物との照合は全方式で未実施。
識別子はpurl/cpe/swidの基本構造を観測し、bom-refだけで代用しない。完全な識別子構文・
意味の検証ではない。名前付きライセンスは記載を確認し、SPDXのID/式は対応表・式解析が
未実装のためunverifiableとする。metadata.licensesを部品ライセンスへ転用しない。
`domain/sbom_quality_dependencies.py`はbom-ref重複、依存行の重複、未解決のローカル参照を
検出する。参照対象は部品/サービスであり、作者等のbom-refを依存先として採用しない。
グラフ全体の不整合は各部品の依存項目をinvalidにし、0部品なら入力エラーにする。
依存行の欠落はmissing、行があってdependsOn未指定ならunverifiable、明示的な空配列は
記載ありとするが、実際の依存関係の網羅性を認定しない。外部参照は取得しない。
`services/sbom_quality.py`は元ファイル読取→文書/部品抽出→申告照合→全体集計を通信なしで実行する。
項目IDは`domain/sbom_quality.py`の `QualityField` の17値。`subject` は文書全体なら空文字、
部品ならそのオブジェクトのJSON Pointer。`evidence_paths` は実際の値の場所であり、
欠落時の想定パスを存在する証拠として入れない。モデルはパスを解決せず、抽出器が実在を確認する。
申告は同じ項目/対象のunknownまたはwithheld、申告元の場所、理由を必要とする。
欠落とのみ両立し、記載済み・不正・検証不能な観測を申告で隠さずinvalidにする。
再申告による上書きは拒否する。理由は最大2,048文字、位置は最大4,096文字で制御文字を認めない。
JSON化した項目は `verification=not_performed` を返し、認証や暗号学的検証を表現しない。

明示申告の初期規約は、本PJ独自の任意propertiesとして
`sbom-ops:quality:<項目ID>:state` と `sbom-ops:quality:<項目ID>:reason` の2項目を使う。
stateは文字列unknown/withheld、reasonは空でない理由。標準の適合証明や免除ではない。
文書項目はmetadata.properties、部品項目はその部品のpropertiesに置き、親から子へ継承しない。
同じキーの重複、片方だけの指定、未知の項目/接尾辞、対象種別違いは入力エラーにする。
名前と値は完全一致で解釈し、推測・空白除去・大文字小文字の補正はしない。
同じproperties配列にある他社の通常プロパティは申告に使わない。
申告の無い外部SBOMを、この独自規約が無いという理由だけで不正扱いしない。

- 項目ごとに `present / missing / unknown / withheld / invalid / unverifiable` と理由、
  対象部品、元データのJSON Pointerを保持する。unknown/withheldには明示申告の場所を必要とし、
  欠落や空文字から創作しない。値と申告が矛盾すればinvalidとする。
- 記載状態と真偽の検証を分ける。署名やハッシュがpresentでも、別の検証結果がなければ
  verifiedにはしない。BOM内の鍵やURLを信頼根拠として自動採用・取得しない。
- JSON結果には評価器版・方針版・元BOMのダイジェスト・検査範囲・検証不能事項を含める。
  このダイジェストは評価対象ファイルの識別用であり、部品ハッシュや署名の代わりではない。
- 既定は報告のみ。選択した必須項目と許容状態を明示した場合だけCIの失敗条件にする。
  未対応形式、不正JSON、読込失敗を正常な空レポートにしない。通常uploadへ暗黙適用しない。
- 構造検査と外部証拠の検証を区別する。重複bom-ref、未解決依存参照、不正な日時/ハッシュ、
  型違い、重複JSONキーを失敗例に含める。dependenciesの空配列やcompositionsの申告だけで
  実際の依存関係が完全と認定しない。入力サイズ・深さ・部品数の上限を設ける。
- 受入テストは両版、対象ソフトと入れ子部品、旧/新tools、欠落/明示不明/非開示、
  署名未検証、上記不正入力、未対応形式、報告/必須化の差を含む。
  入力ファイル不変、外部通信なし、DT/優先度/GitHub不変も検証する。
- CIは生成器・成果物・元BOM・実行記録と必要な別添証拠を保持し、評価器は元BOMを読み取る。
  DT再エクスポートを元BOMの代わりにしない。更新頻度・訂正・配布の運用証拠は別途確認する。
  教材に架空の署名やハッシュを加えて適合済みに見せない。

### ファイル入力・全体レポート・終了コードの契約

以下は#12の読取サービスと`sbom-ops sbom-quality BOM_PATH`の実装契約。
初期版はローカルの通常ファイルをUTF-8のJSONとして読み、圧縮ファイル、標準入力、URL、
FIFOやデバイスは受け付けない。JSONの重複キー、NaN/Infinity（数値の桁あふれを含む）、
不正なUTF-8や単独のサロゲート、
文書直下がオブジェクトでない入力は拒否する。未知の通常プロパティは保持してよいが、
入力値やファイルの絶対パスをエラー文へ転記しない。

資源制限の初期値は32 MiB、JSONのコンテナ深さ64、値のノード数250,000、対象部品数10,000。
MiBは1,048,576バイト、深さは文書直下を1とし、ノード数はコンテナと各値を数える
（オブジェクトのキー文字列は数えない）。対象部品にはmetadata.componentとその子、
componentsの全階層を含める。生成ツールはこの部品数に含めない。
境界値は許容し、超過は部分成功ではなく入力エラーとする。
読取は最大バイト数+1で打ち切り、深さはJSON復号前にも確認し、部品走査は再帰に依存しない。
上限は読取設定で明示し、正の整数以外や無制限指定は拒否する。
これらは初期の保護上限であって、大規模SBOMの性能保証ではない。

読取サービス`services/sbom_quality_input.py`はこの入力境界を実装する。
ファイルを開いた後にも通常ファイルか検査し、元バイト列の識別と対象部品の位置を返す。
構造の検査は完全なCycloneDXスキーマ検証でも、17項目の評価でもない。
エラーコードは`read_failed / not_regular_file / invalid_limits / invalid_utf8 /
invalid_unicode / invalid_json / duplicate_json_key / unsupported_format /
invalid_document_structure / invalid_component_structure`、上限超過は
`byte_limit_exceeded / depth_limit_exceeded / node_limit_exceeded / component_limit_exceeded`。
この読取結果は内部入力として項目抽出・全体集計・独立CLIへ接続済み。

全体JSONは`schema_version=1`、`evaluator_version`、`policy_version`、`status`を持つ。
評価できた場合は`status=evaluated`とし、次を必須とする。

- `input`: 元ファイルの全バイト列のSHA-256とバイト数。再整形後のJSONをハッシュしない。
- `scope`: 形式・版、対象部品数、実際に適用した入力上限。
- `checks`: 既存の項目モデルの配列。文書9項目と各部品8項目を省略せず、
  `(subject, field)`の組を重複させない。対象・項目ID順で安定出力する。
- `summary`: 6状態すべての件数。合計はchecksの要素数と一致する。
- `limitations`: 署名の暗号学的検証、成果物ハッシュ照合、依存関係の実際の網羅、
  更新・配布運用を検証していないこと。全項目presentでも適合認定を出さない。
- `policy`: 報告のみか必須化か、その要求と違反した対象/項目。未指定の方針を補わない。

`domain/sbom_quality_report.py`は読取結果と項目別観測からこの全体JSONを組み立てる。
文書9項目と対象部品ごとの8項目が揃わない、重複する、別対象が混ざる場合は集計を拒否する。
項目の観測値を変更せず、件数と終了コードを算出する。観測自体の正しさは抽出器の責務であり、
この集計処理だけでは元BOMの17項目を評価したことにならない。

必須化方針は版と、項目IDごとの空でない許容状態一覧で明示する。同じ項目の重複指定は拒否する。
要求が空なら報告のみ。指定された部品項目は対象部品すべてに適用し、0部品なら
`no_applicable_components`の違反（subject/stateはnull）を返す。その他の違反は
`state_not_allowed`として対象位置と実際の状態を返す。必須化しない項目は失敗条件にしない。
6状態は明示的に選択できるが、missing/unknown/withheld/invalid/unverifiableを許容しても
観測はpresentに変わらず、適合認定や例外承認を意味しない。暗黙の許容は追加しない。
`exit_code`をJSONにも含め、違反があれば1、なければ0。方針・項目の指定順で結果を変えない。
CLIは`--require FIELD`を繰り返して指定し、その項目のpresentのみを許容する。
`--policy-version`は要求がある場合だけ指定できる。未指定なら要求ありは`cli-required-v1`、
報告のみは`report-only-v1`。重複項目や空の版、無効な上限値は入力エラーにする。
入力上限は`--max-bytes / --max-depth / --max-nodes / --max-components`で設定する。
このコマンドはDT/GitHubの設定読込・接続、資産DBやworkflow記録を必要としない。
`--policy PATH`ではJSON方針を読み、項目ごとの許容状態を明示できる。`--require`とは排他で、
`--policy-version`によるファイルの版の上書きも拒否する。
方針JSONのキーは`schema_version`（整数1）、`version`、`requirements`のみ。
各要求は`field`と`allowed_states`（状態文字列の空でない配列）のみとし、
未知キー/項目/状態、重複項目/状態、未対応版、型違いは拒否する。要求は最大17件、状態は最大6件。
要求配列が空なら、そのファイルの版で報告のみとする。項目・許容状態の省略を補完しない。
方針はUTF-8の通常ファイルに限定し、最大32 KiB・コンテナ深さ8で重複JSONキー等を拒否する。
BOMの上限オプションでこの方針上限を緩和しない。読取失敗は`policy_`を付けたエラーコード、
方針構造/値の不正は`invalid_policy`とし、未読の方針を既定の報告のみへ置き換えない。
結果の構造契約は同梱する[data/sbom-quality-report.schema.json](src/sbom_ops/data/sbom-quality-report.schema.json)
（JSON Schema Draft 2020-12、schema_version=1）で定義する。評価済みと入力エラーを排他的にし、
型・必須キー・未検証表示・状態と申告/証拠の関係・終了コードと違反有無を検査する。
参照は同一ファイル内だけで、検証時に元BOM内のURLや外部スキーマを取得しない。
件数の合計、全対象/項目の網羅、証拠位置の実在、方針に従う違反の正しさはこのスキーマだけでは
証明できない。抽出/集計モデルとそのテストで確認する。スキーマ適合もSBOMの適合認定ではない。

形式未対応、読取失敗、構造を安全に走査できない入力、上限超過、申告規約違反では
`status=error`と安定した`error.code`を返し、checksや成功件数を出さない。
一方、走査可能な項目の不正な日時・ハッシュ等はその項目のinvalidとして報告する。
文書が評価できたことと、項目が要求を満たすことを混同しない。

| 終了コード | 意味 |
| --- | --- |
| 0 | 評価完了。報告のみ、または明示した必須条件をすべて満たした。適合認定ではない |
| 1 | 評価完了したが、明示した必須条件に違反。違反を含む全体JSONを出力する |
| 2 | 入力・設定・未対応形式のエラー。品質不足による1と区別する |
| 130 | 利用者による中断。成功レポートを出さない |

CLIの引数解析エラーは標準エラーへの使用法表示と2を許容する。それ以外の評価結果・
入力エラーは標準出力にJSONを1件だけ出し、進捗文を混ぜない。DTや資産DBの設定・接続を
必要とせず、既存upload/syncへこの終了コードや検査を暗黙適用しない。
境界値/超過、重複キー、深い入れ子、無通信、元バイト列の不変、件数一致、
同じ入力に対する結果の安定性、報告のみ/必須化の終了コード差を受入テストで確認する。

## 速報監視の識別・照合契約（#24、開発中）

速報はDTのFindingとは別の情報。公式情報源ごとに記事を保存し、既存のCVE逆引きへ
接続する。以下は実装の受入条件であり、監視が稼働済みであることを示さない。

- 記事の識別は`source_id`と情報源別の`item_key`の組とする。
  JPCERT/CCはfragmentを保持した`rdf:about`の記事URLを使い、`link`との不一致を拒否する。
  `dc:identifier`単独ではWeekly Reportの各項目を区別できないため補足情報に留める。
  RSS 2.0は情報源ごとに検証した`guid`を使用し、無条件でURL扱いしない。
- 同じ記事の内容指紋が同じなら観測を更新し、異なれば履歴を追加する。
  指紋対象は記事のタイトル・リンク・配信日時・CVE抽出元となる本文等の項目とし、
  取得時刻やchannelの更新日時は含めない。本文全文を表示・転載する機能は追加しない。
  別の情報源や別のWeekly Report項目を、CVE一致だけで統合しない。
- `fetched_at`と配信元の日時を区別する。JPCERT/CCの`dc:date`は意味を確認するまで
  元フィールド名付きの日時として保持し、公表日時・更新日時の両方へ複製しない。
  Ubuntuの`pubDate`とchannelの`lastBuildDate`を混同しない。欠落日時を現在時刻で補わない。
- 明示されたCVEだけを抽出し、記事ID・抽出元フィールドに結び付ける。
  CVE未取得を未採番と断定せず原文確認待ちとする。複数CVEは個別に既存逆引きを行う。
  CVEの取得失敗・検索失敗・検索成功だが一致なしを別状態として表示する。
- 逆引きは保存済みrunの範囲に限る。資産未紐付けを落とさず、DT未反映や対象外の可能性を
  残す。製品名だけの自動結合、優先度・Analysis・SLAの変更、Issue自動操作は行わない。
- RSSから消えた記事を削除・解決済みにしない。初回・停止後の取得は履歴の網羅性を保証しない。
  一回の取得成功だけで監視の取りこぼしがないと表示しない。

受入検証では、同じ`dc:identifier`でfragmentだけ異なる2項目を保存・再取得しても
2項目のままであること、一方の訂正だけが履歴追加されること、日時だけに頼らない
変更検知、CVEなし/複数CVE、検索範囲内一致なしを架空フィードで確認する。
初期の取得対象はJPCERT/CCの注意喚起・Weekly Report用RSSと、Ubuntu Security
NoticesのRSSとする。Ubuntuは修正公開の通知であり、未修正の脆弱性や全ベンダーの
速報を網羅する情報源として扱わない。利用条件の確認と実配信の受入検証は公開前に行う。

取得アダプターはsource_idから固定のHTTPS配信先を選び、任意URLを受け付けない。
JPCERTは `https://www.jpcert.or.jp/rss/jpcert.rdf`、Ubuntuは
`https://ubuntu.com/security/notices/rss.xml` とする。TLS検証は無効化しない。
リダイレクト・記事リンク・本文内URLには追従せず、Cookie・APIキーは送信しない。
一回の要求は最大1 MiB、ソケット待ち時間30秒、圧縮応答は要求せず受信時も拒否する。
HTTP 200以外・通信失敗・サイズ超過を区別し、解析や保存は取得成功後に別層で行う。
エラー本文を保存・表示せず、HTTP状態と検証済みRetry-Afterだけを再試行判断に使う。
取得層では自動再試行しない。定期実行層の初期間隔は1時間とし設定で変更可能にする。
429/503のRetry-Afterが有効なら通常間隔より遅い再試行時刻を優先する。
この間隔は製品側の初期値であり、配信元が保証する更新頻度ではない。
初期実装ではRSS内のテキストからのみCVEを抽出する。記事本文の追加取得は行わず、
CVEがなければ原文確認待ちを残す。全文巡回による網羅を暗黙に約束しない。

モデル境界ではsource_idを小文字英数字・`_`・`-`の64 UTF-8 bytes以内（先頭は英字）、
記事key・URL・タイトルを各4,096 bytes以内の非空とする。制御文字・前後空白を拒否する。
URLは認証情報なしのHTTPS参照とし、許可する通信先の検証は取得アダプターが別途行う。
指紋用の元項目は`dc:identifier`、`dc:date`、`pubDate`、`guid`、`description`、
`content:encoded`に限定し、各65,536 bytes以内・重複禁止。本文の改行・タブは保持する。
これらは一時的な抽出入力であり、本文の自動保存・表示を許可するものではない。
指紋は形式版1のJSON配列（source_id、key、URL、タイトル、名前順の元項目）をSHA-256で
計算する。取得時刻・channel日時を入れず、署名や出典の真正性保証とは扱わない。

オフラインの配信解析はJPCERT/CC RSS 1.0とUbuntu RSS 2.0の形式を対象とする。
入力は1 MiB以下、深さ32以下、要素20,000以下、記事500以下。DTD・外部実体を拒否し、
パース中の通信・リンク参照を行わない。channelが一つでない入力、不正な配置のitem、
重複記事ID・重複対象フィールド・日時のtimezone欠落は入力全体の失敗とする。
既知のテキスト項目に子XML要素を含む入力は拒否し、HTMLはエスケープ文字列/CDATAとしてのみ扱う。
CVEはtitle/description/content:encodedに明示された大文字IDから抽出し、元フィールド名を保持する。
同じフィールド内の重複は一つにするが、別フィールドでの記載は保持する。
guidやdc:identifierから推測せず、不正な長いIDの一部分をCVEとして切り出さない。
これは記事内の言及であり、自社資産への適用・実悪用・修正済みを示すものではない。

保存は既存資産DBのv12追加テーブルを使い、保存処理では暗黙の移行・欠落DBの作成をしない。
既存台帳はバックアップ付きの `assets migrate --backup PATH` で明示移行する。
v11の既存データを保持してテーブルを追加し、移行後の検査失敗時はテーブル追加も取り消す。
保存処理は500記事以下を一つのトランザクションで扱い、同一バッチの識別重複を拒否する。
直近の指紋と同じ記事は最終観測日時だけ更新し、異なれば履歴を追記する。
A→B→Aの再出現は3つの履歴として残す。過去の指紋への一致で訂正を隠さない。
観測日時はtimezone必須でUTC保存し、対象記事の直近観測より古い入力は全体をロールバックする。
記事本文は保存せず、タイトル・原文URL・元の日時/識別子・CVE言及の出典項目・内容指紋を保存する。
履歴の読取は一記事10,000件までとし、超過を黙って切り捨てない。破損した記録は失敗として扱う。
この保存処理の単体検証と、資産DBのv12移行・バックアップ・既存機能互換性の検証は別に行う。

速報の確認結果は、最大500記事・重複を除く1,000 CVEを一度に扱う。
保存済みsync結果を一度だけ読み、全記事を同じ検証済みrunに照合する。
記事ごとの出典とCVE言及を保持し、CVEごとの検索結果は共有する。
`cve_not_observed`は原文確認待ち、`cve_observed`は検索対象CVEがあることだけを示す。
個々の検索結果の`matched / no_match_in_input`と混同しない。
不正なsync入力は検索失敗として返し、一致なしに置き換えない。
担当・配置申告の期限切れ・未紐付け・元Finding・根拠は既存lookupの結果を保持する。

情報源ごとの取得状態は最終試行・最終成功・直近エラー・HTTP状態・次回取得可能時刻を
分ける。失敗は最終成功を消さず、成功時だけ直近エラーを解消する。
最終成功がない場合や直近試行が失敗した場合、鮮度は`unknown`とする。
成功から設定間隔未満なら`fresh`、間隔以上なら`stale`とし、記事の網羅性とは区別する。
時計が最終試行より過去なら鮮度は`unknown`、取得は不可とする。
次回時刻は試行時刻＋設定間隔を基本に、429/503の有効なRetry-Afterがそれより後なら
後の時刻を使う。間隔は正のtimedelta、日時はtimezone付きで、古い状態遷移は拒否する。
取得状態もv12のSQLiteへ保存する。成功時の記事履歴と取得状態は同じトランザクションで
更新し、片方の失敗で両方を取り消す。失敗時は記事を追加せず、最終成功を変更しない。
取得前に読んだ状態と保存時の状態が異なる場合は競合として拒否し、古い処理で上書きしない。
破損した取得状態を未取得扱いに戻さず、エラーとして報告する。
取得処理は情報源ごとに実行し、次回取得時刻前は`not_due`として通信・書込を行わない。
成功時は解析済み記事と状態を保存する。通信失敗・解析失敗は`failed`として状態だけを
保存し、DB障害や保存時の競合は取得失敗へ置き換えず呼出元へ返す。
空の正常フィードも取得成功だが、以前の記事を削除・解決扱いにしない。
`advisories review-file --feed PATH --source jpcert|ubuntu --findings PATH`
は最大1 MiBのローカルRSSを解析し、保存済みsync結果へ照合する読取専用CLIである。
既定は確認用表示、`--output json`は構造化結果。入力不正は本文を出さず終了2、
正常な確認結果は一致の有無にかかわらず終了0。sourceは解析形式であり出典認証ではない。
`advisories refresh --db PATH --source jpcert|ubuntu`は既定で通信・書込なしの予定確認。
`--execute`で既存v12 DBへ取得結果を保存する。`--interval-seconds`は正の整数秒、既定3600。
実行時はDB単位のローカルロックで二重取得を防ぎ、ロック中・DB不正・取得失敗は終了2。
成功・再取得待ち・予定確認は終了0。JSONには最終試行/成功・エラー・次回時刻・鮮度を含める。
DBは作成・移行しない。ロックファイルはOSロックの同一性を保つため削除しない。
`advisories list --db PATH --source jpcert|ubuntu`は保存済み記事の最新の版を読取専用で
表示する。`--limit`は1〜500（既定100）、`--after-id`は非負のSQLite整数範囲の記録ID。
訂正前の版は一覧に混ぜず履歴へ残す。ID昇順でページを読み、満杯のページは最終IDを
`next_after_id`として返す。続きが空なら終了。ページ間の同時更新は固定せず、訂正による
同一記事の再登場はあり得る。記事件数ゼロを未取得・影響なし・解決済みの証明にしない。
`advisories review --db PATH --source jpcert|ubuntu --findings PATH`は一覧と同じ
ページ指定で最新の保存記事を検索対象runへ照合する。通信・DB書込は行わない。
本文を復元してCVEを再抽出せず、保存時に検証したCVE言及と元フィールドを使う。
記事の記録ID・初回/最終観測日時を検索結果に添え、`next_after_id`で続きを確認できる。
保存記事の`list`と`review`は各ページの記事と情報源の取得状態を同じSQLite読取
トランザクションで読み、`poll`に最終成功・直近失敗・鮮度・確認時刻を添える。
`--max-age-seconds`は正の整数秒（既定3600）で、表示時の鮮度判定だけに使う。
取得スケジュールや保存状態は変更しない。状態がない記事は鮮度不明として表示する。
`advisories history --db PATH --source jpcert|ubuntu --item-key KEY`は一記事の
保存履歴を記録ID順で読み、初回観測と訂正を区別する。直前の記録ID、変更された保存項目
（title/url/source_fields/cve_mentions）、指紋の変化、各版の保存内容を返す。
本文は復元・表示せず、指紋だけが違う場合に変更箇所を推測しない。履歴は最大10,000件、
超過は黙って切らず終了2。履歴なしは`no_saved_history`で、解決済みと扱わない。

## Open Items

未完了の作業・進捗・優先度はGitHub Issuesで管理し、[ROADMAP](ROADMAP.md)には
実装順序・見送り理由とIssueへのリンクを残す。
将来のVEX書込では、参照を解決してComponent/Projectの対象範囲と全Finding差分を
承認に結び付け、投入後に対象集合を照合する。Componentの承認をProject全体へ拡大しない。
未解決参照・追加/欠落変更は失敗として扱い、コメント付き更新を無条件に再試行しない。
現行の製品にVEX書込権限を追加する根拠とはしない。

## Slack対応候補通知

`slack notify --findings FILE --config FILE` は成功したsync JSONを読み、標準出力に
対象・選定理由・送信予定本文を出す独立コマンド。既定previewで外部通信と台帳変更なし。
既存sync、`--no-github`、GitHub設定ではSlack送信を開始しない。
`enabled: true` と実行ごとの `--execute` の両方が揃う場合のみ送信し、
`--dry-run` が優先する。失敗したsync文書は処理障害として終了し、解消通知を作らない。
空・部分選択・欠落から解消を推論しない。優先度・Analysis・抑制・例外判断は変更しない。

入力は既存の成功sync文書検証を使い、候補は既存RemediationGroupで再構成する。
設定でrepair（既定）/finding単位を選べる。未照合資産はFinding単位のまま。
通知対象は既定P0/P1、抑制・NOT_AFFECTED/FALSE_POSITIVEは対象外。解消判定は行わない。
重要変更は設定したpriority/owners/context/rationaleの差分。時刻・run IDは差分から除外。
通知には対象、担当/未割当、優先度・根拠、脆弱性/部品、影響候補、不足情報、確認行動、
DT/詳細レポート/判断記録先、入力観測日時・実行相関IDを含む。生description/分析メモ/
SBOMやtokenは表示・保存しない。文字列はメンション/マークアップを無効化する。

Slack専用SQLiteを明示initし、送信意図（key・宛先・本文hash・相関ID）をPOST前に確定。
送信結果とchannel/tsを保存。本文は保存しない。同一ホスト・同一DBの全送信を排他し、
台帳の自動再作成/巻戻しはしない。confirmedを再起動後も重複送信しない。
重要変更と任意reminderは既存スレッドへ返信する。最小間隔・再通知間隔は設定し、
既定では定期再通知なし。送信間隔は1秒以上。各実行・各通知の試行数を上限設定する。
429はRetry-After以降に明示retryでのみ再試行。認証/権限拒否も自動再送せず修正後に明示retry。
未復旧の確定失敗がある宛先では、新規候補も停止する。失敗候補を入力に含め、
同じ重要情報で上限内のretryが成功してから新規候補へ進む。
5xx・timeout・応答喪失・不正応答はunknown。pendingのまま停止した場合も不明として扱い、
同じ宛先の後続送信を停止する。監査保存失敗はその場で停止し、既に送ったものは戻さない。
不明の自動解除/無条件再送は提供しない。人がSlack上で該当投稿を確認した場合のみ、
actorとchannel/tsを明示して台帳をconfirmできる。これはセキュリティ判断の承認ではない。
APIのexactly-onceは主張しない。保存参照はSlackのchannel/ts、本文の相関IDで照合する。

Bot APIのchat.postMessage（chat:write、対象チャンネルへBotを招待）を採用。
Webhookより導入負担は増えるが、応答tsの保存と後続スレッドを一つのAPIで扱える。
固定HTTPS宛先、証明書検証、リダイレクト禁止、応答サイズ制限、POST自動再送なし。
単一ホストの永続DBで運用し、一時Actions runnerへの導入は対象外。
実Slack試験と通知量・有用性の運用評価はユーザー指示で保留（2026-10-29）。


## SBOM供給例の引渡し契約

`examples/sbom-producers/`は導入用の例で、runtime CLIと資産台帳への自動登録を追加しない。
SourceはPRのlock／ソースに対応しCI保管のみ。Buildは単一platformの最終イメージ
manifest digestに対応し、元CycloneDXとSHA-256・生成器版・ソースcommit・CI参照を保持する。
DT名はservice/deployable、版と台帳artifact IDはイメージmanifest digestとする。
Source commitやImageIDをmanifest digestの代わりにしない。

投入例は既定で入力確認のみ。明示実行では既存DTクライアントで対象UUID・名・版の
一意な一致を確認し、送信意図を保存してから投入する。API実装は製品クライアントに限定。
HTTP自動再試行は0回。受付不明・BOM処理不明・Finding読取不明を独立して記録し、
空一覧・token idle・CI成功から解析完了／修正完了を推論しない。
結果ファイルは新規名を要求し、保存失敗／取消では残るintentとDT状態の照合を必要とする。
再実行のexactly-onceや結果の真正性・SBOM完全性を保証するものではない。

CIは資産SQLiteへ書かず、運用担当が候補照合・明示承認・根拠登録・配置申告を行う。
PRには資格情報を渡さず、配布と投入は保護されたmain／Environmentに分離する。
この例の採用で製品のGitHub同期・Slack送信・DT Analysis変更を有効にしない。
操作と失敗時対応は[供給ガイド](docs/sbom-producers.md)を正本とする。
