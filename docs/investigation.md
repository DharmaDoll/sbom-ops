# 速報・CVEからの調査と任意の補助情報

[作業別の入口へ戻る](operations.md)。コマンドはリポジトリのルートで実行する。

**担当:** セキュリティ担当が対象・不足情報・次の確認先を特定し、開発／運用担当へ調査を依頼する。
**前提・入力:** 導入済みCLI、成功した`sync --output json`の保存結果とCVE／PURL／元ID。
速報の保存・PoC取得・CISA入力を使う場合は、各節に示すDB・対象・出典・有効期間も必要。
**期待結果:** 元のFinding・取得時点・資産・担当を保持した対応候補が得られる。
**失敗時:** 入力ファイルの対象・時点・成功状態と終了コードを確認する。
通信を伴う操作は各節のエラー・待機条件を確認し、未取得を「該当なし」に変えない。

| 起点 | 最初に開く手順 |
| --- | --- |
| CVE・部品が分かっている | [保存済み結果の逆引き](#保存済みの結果からcve部品を逆引きする) |
| JPCERT・ベンダー速報を受けた | [架空例、取得・保存・照合](#架空の速報から資産担当を確認する外部通信なし) |
| 調査対象にPoC情報を添える | [PoC取得](#poc報告を明示的に取得する)・[CVE対応候補](#cve対応候補を確認する) |
| CISA評価を判断の参考にする | [取得・保存](#cisa評価の取得保存表示)・[判断支援の架空例](#bod参照の判断支援を架空データで試す) |

速報の取得・保存・照合は提供している。タイマー設定は導入者が行う。Slack通知は[別作業で整備中](https://github.com/DharmaDoll/sbom-ops/issues/25)で、通常syncからは送信しない。
調査結果からDTの分析判断・例外・実期限を自動で変更しない。

#### 保存済みの結果からCVE・部品を逆引きする

成功した `sync --output json` の保存結果を検索する。ネットワーク接続・DB書込・Issue操作は行わない。
Docker/APIキー不要の確認例は、リポジトリのルートで次の通り。

```bash
mkdir -p var
python examples/review_scenario.py --output json > var/review-example.json
sbom-ops lookup --findings var/review-example.json --cve CVE-2026-1000
sbom-ops lookup --findings var/review-example.json --purl 'pkg:generic/example-library@1.0.0' --output json
```

このCVEとPURLは教材で3件のFindingに一致する（未紐付けも含む）。実際のPURLは保存JSONの
`review_queue[].component_purl`をコピーする。非CVEの元IDは
`--vulnerability-id ID --source SOURCE`を使い、情報源名も保存値に合わせる。
主ID/情報源/PURLは完全一致。CVEのalias候補やPoC用に採用した対応は検索対象に含めない。

出力はFindingのProject・元ID・部品、資産/担当、配置申告、SBOM根拠を保持する。
JSONの`source_run_id`で元の取得結果に戻れる。`no_match_in_input`はその保存入力に一致がない
意味であり、DT全体の影響なしや修正完了を意味しない。保存時点の期限切れ・矛盾・未紐付けを
そのまま示し、検索時点の状態へ更新しない。最新状態が必要なら別途syncしてから検索する。
根拠の`not_requested`/`migration_required`/`invalid`は未取得/移行必要/読取不正として区別し、
空の根拠を保証するものではない。失敗run・不正/不整合な入力は終了コード2で拒否する。

新旧成果物から同じCVEを探し、環境・担当・SBOM訂正履歴まで確認する例:

```bash
python examples/lifecycle_scenario.py --output sync --stage stopped > var/lifecycle-example.json
sbom-ops lookup --findings var/lifecycle-example.json --cve CVE-2026-1000
```

A/Bの2 Findingが残り、本番Aだけ停止、staging Aと本番Bは稼働申告のまま。
Aの一致する根拠は訂正後の文書、BはB自身の文書となる。`--stage parallel`で新旧並存、
`unapproved`で未承認、`conflict`で矛盾、`expired`で期限切れも試せる。
未承認は担当や根拠を別資産から借用しない。CVE・Finding・P2評価は固定の架空教材であり、
実際のDT取得や優先度計算を行った結果ではない。配置・根拠には既存のローカル演習の判定を使う。

#### 架空の速報から資産・担当を確認する（外部通信なし）

次の教材は実際のJPCERT/CCの注意喚起ではなく、そのRSS形式を使った架空データである。
`--source jpcert`は解析形式の指定で、JPCERT/CCによる発表・真正性を証明しない。
保存済みsync結果だけを検索し、DT・GitHubへの通信やDB書込は行わない。

```bash
mkdir -p var
python examples/lifecycle_scenario.py --output sync --stage stopped > var/lifecycle-example.json
sbom-ops advisories review-file --feed examples/advisory-feed.example.rdf --source jpcert --findings var/lifecycle-example.json
```

3記事について「CVEとFindingの一致」「CVE未取得」「検索範囲内で一致なし」を確認する。
一致した場合も、担当・配置申告・停止情報を読み、人が対応要否を判断する。
未取得は未採番と同義ではなく、一致なしも影響なしではない。`example.invalid`のURLは
架空の原文リンクであり、開く必要はない。機械処理には末尾へ`--output json`を付ける。
このコマンドは読取専用の確認用で、速報の定期取得・保存コマンドとは別である。

公式RSSを取得して保存する場合は、初期化・移行済みの資産DBを指定する。
次の一つ目は予定確認だけで通信しない。二つ目は外部通信とSQLite書込を行う。

```bash
sbom-ops advisories refresh --db var/assets.sqlite3 --source jpcert
sbom-ops advisories refresh --db var/assets.sqlite3 --source jpcert --execute --output json
```

Ubuntuは`--source ubuntu`を指定する。取得間隔は既定1時間、`--interval-seconds 3600`
で変更できる。繰り返し起動しても次回時刻前は取得せず、429/503の待ち時間が長ければ
そちらを優先する。失敗時も過去の記事と最終成功を保持し、鮮度は不明として表示する。
成功は最新情報の網羅を保証しない。DBは自動作成・移行しないので、旧版では先に
`sbom-ops assets --db var/assets.sqlite3 migrate --backup 未使用のバックアップ先`
を実行する。実行中の競合を避ける`.advisories.lock`は削除しない。
定期実行の設定は別途行う。通常の`sync`からは自動取得しない。

Unixのcronを使う場合の例（自動登録はしない）。`/opt/sbom-ops`は実際の導入先へ
置き換え、資産DBを読む・書く権限を持つ専用ユーザーで設定する。

```cron
0 * * * * /opt/sbom-ops/.venv/bin/sbom-ops advisories refresh --db /opt/sbom-ops/var/assets.sqlite3 --source jpcert --interval-seconds 3600 --execute --output json
10 * * * * /opt/sbom-ops/.venv/bin/sbom-ops advisories refresh --db /opt/sbom-ops/var/assets.sqlite3 --source ubuntu --interval-seconds 3600 --execute --output json
```

標準出力・標準エラーと終了コードを運用側で収集する。失敗は終了2、予定確認・成功・
再取得待ちは終了0。ただし再取得待ちでも前回の失敗が残る場合があるため、終了コードだけで
健全性を判断せずJSONの`state.error`・`state.last_success`・`freshness`を確認する。
起動間隔と内部の次回時刻の組み合わせで、次の取得が1周期後になる場合がある。
停止はスケジュールを無効化するだけでよく、保存記事や状態を消す必要はない。
通常の`sync`やPoC更新と独立して運用する。Vulnerability-Lookupは既知CVEのPoC補完に使い、
JPCERT/ベンダー速報の収録範囲・遅延を確認できていないため速報監視の代替にはしない。

保存後は次のコマンドで記事URL・CVE言及・観測日時・内容指紋を確認できる。
訂正された記事は最新の版を表示し、古い版はDBの履歴に残る。

```bash
sbom-ops advisories list --db var/assets.sqlite3 --source jpcert --limit 100 --output json
```

`next_after_id`があれば、その値を`--after-id`に指定して続ける。続きが空なら終了。
ページ間の更新は固定しないため、訂正された記事が再登場することがある。
この一覧操作は通信・DB書込を行わない。`poll`に最終成功・直近失敗・鮮度を表示する。

保存済み記事から関連資産・担当へ進むには、成功したsyncのJSONを指定する。

```bash
sbom-ops advisories review --db var/assets.sqlite3 --source jpcert --findings var/lifecycle-example.json
```

上例のsync JSONは架空教材なので、実運用では実際のsync出力へ置き換える。
`--limit`・`--after-id`で続きを読み、`--output json`で機械処理できる。
記事の保存記録ID・観測日時、元run、CVEの記載元、資産・担当を保持する。
本文は保存していないが、保存時に抽出したCVEから検索できる。外部通信・DB書込はしない。
一覧・照合の`poll`で取得状態を確認し、古い記事を最新の速報と誤認しない。
表示時の鮮度判定は既定1時間。取得間隔に合わせて`--max-age-seconds 3600`で変更できるが、
これは読取時の判定基準だけで、次回取得時刻やDBを変更しない。
取得失敗後も記事の照合結果は残るため、検索結果だけでなく`state.error`と`freshness`も読む。

訂正内容を確認するには、一覧JSONの`articles[].metadata.item_key`をそのまま指定する。
JPCERTのfragment付きURLやUbuntuのguidを加工せず、シェルでは引用符で囲む。

```bash
sbom-ops advisories history --db var/assets.sqlite3 --source jpcert --item-key '一覧からコピーした記事識別子' --output json
```

各版の`change.changed_fields`に変更された保存項目、`previous_record_id`に直前の記録を示す。
変更前後のタイトルやCVE言及を確認できる。本文は保存しないため、指紋だけが変わった場合の
本文差分は分からない。原文へ戻って確認し、過去の内容への復帰も新しい履歴として扱う。
これは自分の取得した範囲の履歴であり、配信元の訂正履歴の完全な複製ではない。

## VEX受領時の確認

**担当・前提:** セキュリティ担当が、サプライヤーVEXの出所・対象製品・版・対象Projectと
根拠を確認する。投入・分析判断は組織のDT運用手順と承認の下で行う。

1. VEXと自社の対象成果物・部品の対応を確認する。対応が不明なら投入へ進まない。
2. 承認された運用担当がDTへの投入を行い、反映された対象と分析状態を確認する。
3. 次の`sync --dry-run --no-github`で分析状態と抑制を読み、判断根拠と作業管理の記録を照合する。

**期待結果・失敗時:** 対象・状態・判断者の根拠を追える。投入成功だけで正しい対象へ
判断が反映されたとは扱わず、不一致なら元VEXとDTの対象・監査履歴を確認する。
`NOT_AFFECTED / FALSE_POSITIVE`や抑制は任意GitHub同期の新規起票対象から除外されるが、
既存Issueの自動クローズは行わない。sbom-opsはVEXを独自解釈して安全と決定しない。
[VEX支援の設計案](vex.md)にある候補キュー・承認UI・将来CLIは現在の操作手順とは区別する。

## 任意の評価入力

PoCなどの事前生成JSONと、旧形式の資産JSONは別の任意入力である。
syncはどちらもファイルから読むだけである。PoCの取得は下記の独立コマンドで行う。
架空の例を実環境の事実と混ぜない。

```bash
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --dry-run --no-github --output json \
  --advisory-snapshot examples/advisory-snapshot.example.json
```

PoCはCVEまたはDTの明示aliasで結合し、情報源別件数を表示する。
古い・取得不能・未解決の情報は「PoCなし」とみなさない。
Vulsの一般公開参照はPoC件数ではない。
[形式と制約](../SPEC.md#advisory-evidence-and-deployment-context)、
[labでの変換手順](../lab/exploit_intelligence/README.md#product-snapshot-handoff)を参照する。
観測日時が未来の場合、元の情報は保持するが、PoC判定はその情報を根拠にしない。
JSONの`poc_reports.sources[].effective_freshness`で`unknown`を確認し、
取得元の時計・入力日時を確認する。別の有効な情報源があれば、その観測で判定する。

旧資産JSONを試す場合は `--asset-inventory path/to/reviewed-assets.json` を追加する。
SQLiteへ取り込む `assets import` とは別形式で、DBへの登録や成果物同一性の確認は行わない。
[資産JSONの仕様](../SPEC.md#asset-inventory-context)を参照する。

### PoC報告を明示的に取得する

まずは `python examples/poc_scenario.py` で、外部通信なしの演習を試せる。
以下は実際に対象CVEを外部サービスへ送る手順。DTへの書込やGitHub操作は行わない。
演習で使ったDT設定・Project UUIDを使い、対象を1サービスに絞る。
PoCの保存先は資産と同じ `var/assets.sqlite3`（専用テーブル）で、JSONファイル管理は不要。
既存DBがv1〜v6の場合だけ、先にバックアップ付きで移行する。自動移行はしない。

```bash
sbom-ops assets --db var/assets.sqlite3 migrate --backup var/assets-before-poc-v10.sqlite3
```

新規DBなら移行は不要。以下の `poc-fetch --execute` でv12を作成する。
v6はsyncでの読取、v7はPoCの読取・更新を継続できる。

```bash
mkdir -p var/poc
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --dry-run --no-github --output json \
  > var/poc/findings.json
# syncが成功したことを確認してから、送信先と対象CVEを確認する（通信なし）
sbom-ops poc-fetch --findings var/poc/findings.json --db var/assets.sqlite3
# 更新が必要なCVEだけを取得し、同じSQLiteに保存
sbom-ops poc-fetch --findings var/poc/findings.json \
  --db var/assets.sqlite3 --execute
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --asset-db var/assets.sqlite3 \
  --dry-run --no-github --output review
```

- 送るのはCVEと検索条件だけ。資産名・担当・Project UUIDは送らない。
  ただし問い合わせ先には関心のあるCVEが伝わるため、プレビューで確認する。
- 最初に `selection` の取得対象CVE数と未解決ID数を確認する。
  `no_resolvable_cves` は脆弱性があるのにCVEへ結び付けられない状態で、
  脆弱性0件の `no_findings` や「PoCなし」とは異なる。取得要求は送らず終了コード1になる。
  `partially_resolved` は一部だけ対応できた状態。DTの主ID・明示aliasを確認し、
  名前や説明文から推測してCVEを補わない。件数はそれぞれの重複排除後で、解決率ではない。
- CVE対応がない場合もDTの設定を安易に変更しない。
  [DT公式のOSV alias説明](https://docs.dependencytrack.org/datasources/osv/#vulnerability-aliases)は、
  誤った同一視の可能性から一括同期を非推奨としている。設定読取の403は権限不足であり、
  alias無効の証拠ではない。通常のPoC取得に `SYSTEM_CONFIGURATION` 権限は不要。
  現在の製品は外部のID対応候補を自動採用しない。未解決は不明のまま残す。
- 既定の送信先は `https://vulnerability.circl.lu`。認証なしで読める。
  キーがある場合だけ `SBOM_OPS_VULNERABILITY_LOOKUP_API_KEY` を環境変数に設定する。
  DTのキーは流用しない。送信先は `--base-url` で変更できるが、キーの対応先も確認する。
- `--max-cves 25`、`--pacing-seconds 3.1`、`--ttl-seconds 21600` が既定値。
  対象数超過は一部を黙って省かずエラーにする。呼出間隔は3.1秒未満にできない。
  期限は取得時点の情報を判断材料にする期間であり、データ自体の最新性の保証ではない。
- `--refresh-seconds 3600` が既定の更新間隔。期限内で前回成功から1時間未満なら再利用する。
  プレビューの `update_cves` は今回の取得予定。成功分を一件ずつ保存するので、
  中断後は同じコマンドで再開できる。失敗分は待機時間経過後の明示実行で再取得する。
  これは対象CVEの選別であり、PoC本文を差分ダウンロードする仕組みではない。
- 終了コード0は取得・再利用完了、1は失敗・未解決IDを含む部分結果、2は入力・保存等のエラー、
  3は同じDBで取得が進行中のための見送り（`poc_update_already_running`）。
  どの終了コードでも既に確定したDB保存は残る。標準出力の `results` と `unresolved_ids` を確認する。
  `error`・`http_status`・`attempted`・`cached` を区別する。
  通信失敗で残りの通信を止め、未取得を未観測扱いにしない。429でも即時再試行しない。
  `source_state.retry_at`（タイムゾーン付き）以降に手動再実行する。早く実行しても追加通信はしない。
  待機中は対象CVEを変えても取得を見送り、`error=source_cooldown` と次回可能時刻を表示する。
  スキップしただけで待機時刻を延ばしたり、過去の成功・失敗記録を上書きしたりしない。
- 待機は既定で60秒→120秒→240秒と増え、設定上限3600秒。
  `--retry-base-seconds / --retry-max-seconds` で変更できるが、既に保存済みの待機は短縮しない。
  取得先のRetry-After指定が長い場合はそちらを優先し、ローカル上限で切り詰めない。
  待機時刻は情報源別にDBへ残るため、再起動しても有効。成功した通信で連続失敗を解消する。
  401/403はキー・権限、404は送信先、通信失敗は接続を確認する。異常に遠い待機時刻は取得先の応答を調査する。
  同じ情報源には同じURL表記・DBを使うこと。別DBや並列起動で制限を回避しない。
  同じDBでの重複取得は自動で止める。定期運用の実環境での通し確認は残っている。
- PoC報告件数は投稿の重複を含み得る。有効性・独立した実装数・当該部品への適用性は評価しない。
  先頭報告だけを確認した場合は `complete=false`。部分取得から「PoCなし」とは判断しない。
- 失敗しても前回成功の件数・時刻・期限は消さない。直近の失敗を別に残し、syncでは
  過去の件数を併記しつつPoC判定を「不明」にする。一度も成功していなければ件数も不明。
  成功すると失敗表示を解消する。全試行の履歴を積む機能ではなく、最終成功と直近の試行を保存する。
- syncはv6以降の `--asset-db` からPoCも読み、通信やDB更新はしない。
  別パスなら `--poc-db PATH`。PoC読込の失敗だけでは通常のDT評価を止めない。
  PoC更新もバックアップに含まれる。旧版へ戻す場合は更新を止め、移行前バックアップを使う。
  移行後の資産変更・PoC取得結果は旧バックアップには入っていない。
- JSONが必要な場合だけ取得時に `--output NEW_FILE.json` を追加する（既存ファイルは上書きしない）。
  保存後のエクスポートに失敗してもDB確定分は残る。`--advisory-snapshot` でJSONを指定すると、
  その同期ではDBのPoCよりJSONを優先する。黙って両者を混ぜない。
  入力の `findings.json` は対象CVE選択のための一時的な同期結果で、PoCの保管先ではない。

公式の[API仕様](https://www.vulnerability-lookup.org/documentation/api.html)と
[アクセス方針](https://www.vulnerability-lookup.org/documentation/access-patterns.html)、
[CIRCL instanceの方針](https://vulnerability.circl.lu/.well-known/api-policy.json)を確認した。
2026-10-13確認時、instanceは匿名20件/分・認証あり40件/分を強制していた。
共用IPや他ジョブのアクセスも考慮し、並列起動を避ける。運用前に最新の制限を再確認する。
同日の製品クライアント確認では、公開CVE-2021-44228への匿名GET 1回で
報告件数153と先頭報告のCVE/typeを取得できた（全件やPoC本体は取得していない）。
最初のsandbox内の通信は失敗し、ネットワーク許可後に成功した。
これは接続・応答形式の確認であり、継続更新や報告の有効性の実証ではない。

2026-10-14の待機制御は、[RFC 9110のRetry-After仕様](https://www.rfc-editor.org/rfc/rfc9110.html#name-retry-after)
を根拠に、模擬429/503・固定時計・一時DBで検証した。再起動・別CVE・長い待機・再取得成功を確認し、
実サービスへ大量アクセスして429を発生させる実験は行っていない。

### PoC更新を定期実行する

リポジトリの `scripts/refresh_poc.py` を外部のタイマーから呼び出せる。
新たな常駐サーバは不要。まず資産を登録し、DBをv7以降にしてから、1 Projectで手動確認する。
このスクリプト自体はタイマーの登録・DBの作成や移行を行わない。

```bash
# 実行内容の確認だけ。通信・DB変更なし
.venv/bin/python scripts/refresh_poc.py --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --db var/assets.sqlite3
# DT用の環境変数を設定した環境で、1回実行
.venv/bin/python scripts/refresh_poc.py --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --db var/assets.sqlite3 --execute
```

処理順は「対象の同期 → PoC更新 → 確認用一覧」。DTは読み取りのみ、GitHubは常に無効。
対象一覧は実行ごとの専用一時ディレクトリに作り、終了時に削除する。
最初の同期が失敗した場合や入力が不正な場合は止め、前回の対象一覧を流用しない。
PoCが部分失敗しても通常の確認用一覧は表示する。
各段階に既定900秒の制限があり、`--stage-timeout`で変更可能（1〜3600秒）。
時間切れではその段階のプロセスを停止するが、既に保存したPoCは残る。

終了コードは0が完了、1がPoC部分結果（待機中を含む）、2がエラー・時間切れ、3が重複起動による見送り。
ログの `stage` と `status` で失敗箇所を確認する。1なら取得結果と次回可能時刻を確認し、
2なら設定・接続・DBを修正して同じコマンドを実行する。3が続く場合は先行プロセスを調べる。
待機を回避するためにDBや取得先URLの表記を変更しない。

同じDB実体パスの `.poc.lock` が手動を含む取得を、`.poc-job.lock` がスクリプト全体を保護する。
空のロックファイルが残るのは正常。終了・強制停止時にOSがロックを解放するため、
運用中にファイルを削除しない。対象は単一ホストのUnix系OS・ローカルストレージ。
NFS等の共有ストレージ、DBのハードリンクや別コピー、複数ホスト間の排他は保証しない。

手動で結果を確認した後、例えばcronで毎時17分に起動できる。以下は配置先が
`/opt/sbom-ops` の例で、実環境のパスへ変更する。自動登録はしない。

```cron
SHELL=/bin/bash
17 * * * * umask 077; cd /opt/sbom-ops && set -a && . /etc/sbom-ops/runtime.env && set +a && .venv/bin/python scripts/refresh_poc.py --config examples/config.yaml --project "$SBOM_OPS_DT_PROJECT_UUID" --db var/assets.sqlite3 --execute >> var/poc-refresh.log 2>&1
```

環境変数は自動では読み込まない。この例の `runtime.env` には既存のDT用設定とProject UUID、
必要な場合だけVulnerability-Lookup専用キーを用意する。実行ユーザー所有・権限600とし、
信頼できる管理者だけが編集する。キーをcron行やGitへ書かない。
手動実行と同じDB・設定・Python環境を使い、ログには資産名やCVEが含まれるため、
閲覧権限とログローテーション・保存期間も設定する。起動間隔とは別に、DB内の更新間隔と待機時刻が有効。

重複起動と強制終了後の解放は実プロセスで検証済み。
処理順、同期失敗、時間切れ、PoC部分失敗は一時DB・模擬コマンドで検証した。
2026-10-15（日本時間）に実DTのGoデモで単発処理を確認した。60件すべてCVE対応なしのため
PoCは部分結果となったが、確認済み担当と期限切れの稼働申告を含む一覧は表示できた。
別のQuick Start用Projectも77件すべてCVE対応なしだった。
同日の追加確認では、別の既存NVD検証Projectの10 CVEで実API取得→SQLite保存→一覧表示に成功。
4 CVEは報告あり、6 CVEは取得先で未検出。別プロセスで再実行すると10件すべてをDBから再利用し、
PoCへの追加通信は0件、取得時刻も変わらなかった（DT等への読取通信はある）。
このProjectの資産は未紐付けのままで、実サービスの担当・稼働まで確認したことにはならない。
自動運用の前に対象のCVE対応を確認する。GO/GHSA等の未解決IDの補完は残課題。
検証用コピーだけを移行し、元のDB・DT設定・cronは変更していない。
詳細と未確認事項は[検証記録](../lab/dependency_track/EXPERIMENTS.md)を参照。

### CVE対応候補を確認する

`poc-fetch` の未解決IDに対して、OSVが明示するCVE候補を調べる補助機能。
**候補は未採用**であり、保存しても通常のsync・PoC検索・優先度・DT分析には反映しない。
採用・取消は下記の別操作で記録する。PoCへの接続には取得・表示それぞれで
[明示オプション](#採用したcve対応をpoc取得表示へ使う)を指定する。
先に次の通信なし演習で候補保存・期限付き採用・期限切れ・取消と境界を確認できる。

```bash
python examples/poc_scenario.py
```

実データでは、上記の成功したsync JSONを入力する。プレビューは通信・DB作成なし。
既定でGO・GHSA・PYSECの未解決IDを最大25件まで対象にする。超過時は黙って間引かず停止する。
`--id` を繰り返して対象を限定できるが、入力JSONにある未解決IDとの完全一致が必要。

```bash
sbom-ops id-candidates --findings var/poc/findings.json --db var/assets.sqlite3
# 多い場合は、一覧で確認したIDを1件選ぶ
sbom-ops id-candidates --findings var/poc/findings.json --id "$DT_VULNERABILITY_ID"
# 候補取得はv8でも動作する。採用・取消にはv9以降が必要。移行コマンドは最新v12へ進める
sbom-ops assets --db var/assets.sqlite3 migrate --backup var/assets-before-identifiers-v10.sqlite3
# 送るIDを確認してから実行。DBがなければv12を作成する
sbom-ops id-candidates --findings var/poc/findings.json \
  --id "$DT_VULNERABILITY_ID" --db var/assets.sqlite3 --execute
# 保存済み履歴の直近100件を表示（通信・DB変更なし）
sbom-ops id-candidates --db var/assets.sqlite3 --show --limit 100
```

送信先は `https://api.osv.dev/v1/vulns/{id}` 固定、APIキー不要。
送るのは脆弱性IDだけで、資産名・DTのURL・Project UUID・担当は送らない。
GHSAはOSVの大小文字に合わせて送るが、元IDとDT情報源は保存する。
明示aliasから候補を取り、応答ID・更新日時を確認する。説明文・related・upstreamは使わない。
状態は `candidate`（1候補）、`ambiguous`（複数）、`unresolved`（候補なし）、
`withdrawn`（撤回済み）、`error`（取得・形式エラー）。候補なしや404はPoCなしの証拠ではない。

保存先は同じDBの `identifier_observations`。出典・観測日時・元データ更新日時・候補・失敗を
1件ずつ履歴として追加し、再実行で過去の成功や失敗を消さない。`--show`は履歴であり、
古い候補が今も正しい保証ではない。生のOSV本文や関連URL先は保存・取得しない。
通信間隔は3.1秒、各要求のタイムアウトは30秒。最初の取得・形式エラーで残りを止める。
終了コード0は取得処理完了で採用完了ではない。1は一部失敗・未対応IDあり、2は入力等のエラー、
3は同じDBでの重複起動。専用ロックファイルは運用中に削除しない。
手動確認用であり、キャッシュ・情報源別待機の永続化・自動更新はまだない。
429等の失敗後に繰り返し実行したり、定期ジョブへ追加したりしない。
DB移行前バックアップに戻す場合、移行後の資産・PoC・候補追加は引き継がれない。

2026-10-17に保存済みのDT同期結果からGO/GHSA各1 IDを選び、製品コマンドでOSVへ問い合わせた。
両方のCVE候補を保存でき、最初の接続失敗も履歴に残った。実候補の採用・PoC取得は行っていない。
詳細は[検証記録](../lab/exploit_intelligence/EXPERIMENTS.md)を参照。

### CVE対応候補の採用・取消を記録する

同一の脆弱性を指す対応かを確認した人が、`id-candidates --show`の観測IDとDT情報源を指定する。
これはPoCの有効性のレビューではない。変更者・理由・期限を記録する機能で、
**採用しただけではPoC取得や表示にはつながらない**（このコマンドは`poc_connected=false`）。
接続には下記の`--use-reviewed-identifiers`を取得・表示のそれぞれで指定する。
候補観測の`approved=false`は取得時点の記録であり、現在の採用状態は`id-review show`で確認する。

```bash
# 以下の変数は、確認した観測・CVE・変更者・理由・期限を指定する
sbom-ops id-review --db var/assets.sqlite3 approve \
  --observation "$OBSERVATION_ID" --dt-source "$DT_SOURCE" --cve "$CVE_ID" \
  --actor "$REVIEWER" --reason "$REVIEW_REASON" --expires-at "$EXPIRES_AT"
# プレビューを確認後、同じコマンドに --execute を付けて保存
sbom-ops id-review --db var/assets.sqlite3 show
# 取消も既定はプレビュー。内容確認後に --execute を付ける
sbom-ops id-review --db var/assets.sqlite3 revoke \
  --observation "$OBSERVATION_ID" --dt-source "$DT_SOURCE" --cve "$CVE_ID" \
  --actor "$REVIEWER" --reason "$REVOCATION_REASON"
```

期限はtimezone付き日時で指定する。既定では観測後24時間以内の候補だけを採用でき、
期限もその範囲内とする。`--max-age-hours`で運用方針に応じて変更可能。
古い観測・未来日時・候補にないCVE・情報源不一致は拒否する。
同じ元ID・DT情報源の最新採用だけが有効。取消で履歴やPoC観測は削除しない。
新しい候補観測が追加されると、同じ内容でも既存採用は`observation_changed`となり再確認が必要。
このほか`active`・`expired`・`future`・`revoked`・`superseded`を表示する。
変更者は申告名で、本人認証ではない。DBとバックアップのアクセス権を管理する。

### 採用したCVE対応をPoC取得・表示へ使う

同じv9以降のDBにPoC観測と採用履歴を保存する。既存DBが古い場合は先にバックアップ付きで移行する。
以下は通常のsyncで保存した`var/sync.json`と、確認して採用した対応を使う例。

```bash
# 対象CVE・未解決ID・採用根拠を通信なしで確認
sbom-ops poc-fetch --findings var/sync.json --db var/assets.sqlite3 \
  --use-reviewed-identifiers
# 確認後に取得。同じDBへCVE別PoC観測を保存
sbom-ops poc-fetch --findings var/sync.json --db var/assets.sqlite3 \
  --use-reviewed-identifiers --execute
# DTを再読取し、有効な対応だけを使ってPoCを表示（PoC APIには通信しない）
sbom-ops sync --project "$DT_PROJECT_UUID" --asset-db var/assets.sqlite3 \
  --use-reviewed-identifiers --dry-run --no-github --output review
```

`DT_PROJECT_UUID`は今回確認するProjectのUUIDに置き換える。JSONが必要なら`--output json`を使う。
対応の元ID・DT情報源・CVE・採用ID・観測ID・出典・理由・期限が一覧にも残る。
採用者と理由はsync JSONや監査ログにも含まれるため、秘密情報を書かず、出力の閲覧権限を管理する。
PoCが0件と確認できた場合と、未採用・取消・期限切れ等で確認できない場合は区別する。
取得待機中に採用が無効になれば`identifier_review_changed`で通信を見送り、結果は一部未完了になる。
このエラーでは取得先の待機時間を延長しない。対応を再確認してからプレビューをやり直す。

取消・新しい候補観測の追加後は、上のsyncを再実行して「不明」に戻ることを確認する。
過去のPoC観測は削除しない。古いJSONや既に出力した画面は更新されないため、判断には新しい出力を使う。
同じIDでもDT情報源が異なれば別の採用が必要。DTに主CVE・明示CVE aliasがあればそちらを使う。
採用済み対応の読取に失敗してもDT評価は残り、`CVE対応入力=invalid`と警告を表示する。
KEV・EPSS・P0〜P3・DT分析・Issue操作は変えず、PoCの有効性も審査しない。
定期ジョブにはまだ接続しない。まず対象を限定した手動操作で確認する。

## CISA評価の取得・保存・表示

`cisa` は単一CVEのCISA評価を確認する独立コマンド。DTやGitHubのキーは不要で、
通常のsyncや優先度を変更しない。固定版からの取得であり、最新版の確認ではない。
以下の版は過去に取得確認した例。168時間は動作確認用で、運用の推奨期間ではない。
評価が古ければ、取得が成功しても `effective_status=expired` になる。

```bash
mkdir -p var
CISA_REVISION=efd7f7117a7d725d0d535472ef4b3f2e078a0b5f
# 対象と有効期間の確認だけ。通信・DB変更なし
sbom-ops cisa fetch --cve CVE-2024-25522 --revision "$CISA_REVISION" \
  --max-age-hours 168 --db var/assets.sqlite3
# 実行する場合だけ指定。未作成DBは初期化、旧版DBは自動移行しない
sbom-ops cisa fetch --cve CVE-2024-25522 --revision "$CISA_REVISION" \
  --max-age-hours 168 --db var/assets.sqlite3 --execute
```

旧版DBでは先に `assets migrate --backup NEW_PATH` を実行する。
結果の `snapshot_id` を控え、次の `1` を実際の値に置き換える。

```bash
# 保存内容を読むだけ。通信・DB更新なし
sbom-ops cisa show --db var/assets.sqlite3 --snapshot 1 \
  --cve CVE-2024-25522 --revision "$CISA_REVISION"
```

`retrieved_at` は取得日時、`assessed_at` はCISA評価日時、`evaluated_at` は表示時の判定日時。
元の `reported_value` と現在の `effective_status` を合わせて確認する。
再表示や再取得で古い評価日時を新しくしない。`latest_verified=false` は固定版の取得だけで
最新性を確認していないことを示す。取得版や有効期間を変える場合は新しい取得を明示し、
新旧の記録を区別する。失敗時は終了値2となり、過去の保存成功を代わりに返さない。
失敗履歴の永続保存はまだ行わないため、コマンドの終了値と標準エラーを実行記録に残す。
終了値0でも評価の欠落や期限切れはあり得る。これはCISA入力の確認であり、
資産の公開状態やKEVを結合したBOD参照結果の表示ではない。

### 同期結果に参照情報を添える

登録済みの資産台帳とCISA記録を使い、DTのFindingに各要素の根拠を添えて確認する。
以下の `1` は取得結果の記録ID、`production` は台帳で申告した環境名に置き換える。

```bash
sbom-ops sync --config examples/config.yaml --no-github \
  --asset-db var/assets.sqlite3 --triage-environment production \
  --cisa-snapshot CVE-2024-25522 "$CISA_REVISION" 1 --output json
```

通常の同期と同じDT/KEV取得は行うが、CISAの再取得はしない。資産/CISAのDBは読取専用。
KEVキャッシュや同期ログの既存動作は変わらない。
別のCVEには `--cisa-snapshot CVE REVISION ID` を追加する。同じCVEの複数指定は拒否する。
指定しなかったCVE、CVEの対応が曖昧なFinding、未照合の資産、別環境の申告、期限切れは
未確認のまま残す。情報が揃ったFindingだけに絞り込む機能ではない。
`triage_contexts` に元ID・CVE対応・出典・観測/評価日時・有効期限・元申告を表示する。
`triage_context_status=evaluated` は評価を実施したという意味で、全要素の確認済みを示さない。
`triage_contexts[].guidance` には対象資産・資産担当と次の行動を表示する。
`actions`のreasonで不足の状態を確認し、role（asset/security）とassigneeを確認する。
assigneeがnullなら未割当。資産担当をセキュリティ担当として自動流用しない。
例えば公開状態の不足は対象環境の稼働・公開申告の確認、自動化評価の期限切れは
CISA評価の版・根拠・有効期限の確認へ進む。PoC有無で不足を埋めない。
text/reviewでも「確認先」「理由」「次の行動」を表示する。案内だけで通知や自動操作はしない。
`--output review` または `text` では値と状態の要約を表示する。
`triage_contexts[].reference` に固定版の参照結果を表示する。4要素が揃えば
3/14/60暦日または次回の予定された主要更新・再構築時の区分、揃わなければ
`pending` と不足要素を返す。侵害確認の「追加指定なし」は調査不要を意味しない。
参照版は2026-10-22確認時点の表で、最新版の保証ではない。自社SLAや実際の期限日は
計算せず、既存のP0〜P3を変更しない。`due_at` は常にnullとなる。
参照オプション自体はGitHub操作の許可設定を変えないため、参照だけなら `--no-github` を付ける。

開発環境では、外部通信や実際のIssue作成なしに合成データで表示を確認できる。

```bash
.venv/bin/python -m pytest tests/unit/test_triage_reference.py
.venv/bin/python -m pytest tests/unit/test_orchestrator.py -k reference_context_preserves
```

後者は資産台帳、KEV取得結果、保存済みCISA入力を同期処理へ渡すテスト。
公開・KEV該当・自動化可能・完全制御なら「3暦日／侵害確認の追加指定あり」、
KEV未掲載なら同じ3暦日でも追加指定なしとなる。
非公開・KEV未掲載・自動化不可・部分的影響なら「次回の予定された主要更新・再構築時」。
別環境や期限切れの情報では「判定待ち」となる。これは合成データの確認であり、
実環境の資産状態、情報の正しさ、最新版との一致を保証するものではない。

#### BOD参照の判断支援を架空データで試す

Quick Startのインストール後、リポジトリのルートで実行する。DT・Docker・APIキーは不要。
入力は[保存済みの架空データ](../examples/triage-scenario.example.json)、実行は
[教材スクリプト](../examples/triage_scenario.py)を使う。

```bash
python examples/triage_scenario.py
python examples/triage_scenario.py --output json
```

外部通信・DB操作は行わず、既存の資産照合・根拠評価・参照判定・表示処理を使う。
時刻は2026-10-23に固定され、実行日によって結果は変わらない。入力のCVE、KEV掲載、
CISA形式の評価、承認済みProject対応、担当はすべて架空で、実際の発表や承認の証拠ではない。
CISA提供者の識別子は形式を再現するための値で、真正性を証明しない。

全ケースで同じCVE、KEV該当、自動化不可、完全制御を使う。

| ケース | 期待する参照表示 | 人が次に確認すること |
| --- | --- | --- |
| 公開環境 | 3暦日・侵害確認の追加指定あり | checkout-teamと修正・緩和計画を確認し、セキュリティ担当の侵害確認計画を決める |
| 内部環境 | 14暦日・追加指定なし | 対象環境の対応計画を確認。追加指定なしを調査不要と解釈しない |
| 公開状態が不明 | 判定待ち・unknown | 資産担当が対象環境の稼働・公開範囲を確認し申告する |
| 公開申告の期限切れ | 判定待ち・expired | 資産担当が現在の状態を確認し、有効な申告を登録する |
| 資産担当が未登録 | 参照結果は表示できるが担当は未割当 | まず担当を特定する。別資産の担当で穴埋めしない |

担当未登録は、承認済み対応があってもサービスの担当情報が取得できない場合の安全側の
表示を再現する入力であり、通常の台帳登録で空の担当名を登録する手順ではない。
セキュリティ担当の実名は全ケースで未割当。資産担当をその役割へ自動流用しない。

JSONの`cases[].context`に、対象環境・元の根拠・参照版・`guidance.actions`がある。
確認の問いは「何が不足しているか」「誰に依頼するか」「何を確認するか」の3点。
案内は人向けの提案で、通知・調査・DT更新・期限確定を実行しない。
教材は実際のsync取得や優先度計算を実行せず、参照表示への入力を再現する。
参照期限は自社の実期限ではなく、`due_at=null`を維持する。

#### 運用担当者が確認する順序

まず`--no-github`で対象環境を一つ指定し、同じFindingの既存優先度と参照欄を
並べて確認する。参照欄の数字を、そのままチケットの実期限へ転記しない。

| 状況 | 出力で確認すること | 次の操作 |
| --- | --- | --- |
| 本番の公開資産で4要素が揃う | `reference.status=matched`、参照行、侵害確認の追加指定、出典版 | 元の資産・CVE対応を確かめ、人が対応方針を判断する |
| 同じサービスでも別環境を指定 | 公開状態が借用されず`pending`になる | 対象環境の申告を確認する。値を推測して埋めない |
| CISA評価や資産申告が期限切れ | 要素の状態と`reference.missing` | 期限切れの根拠を更新する。再表示だけで期限を延ばさない |
| CVE未確認、またはCISA記録未指定 | Findingを消さず不足情報を表示する | 元IDと対応根拠を調べ、確認できるまで判定待ちにする |
| 新しいCISAデータ版を採用する | 新旧の記録ID・CVE・Gitコミットを区別する | 新記録を明示選択する。旧記録の上書きや自動最新版選択はしない |

「版更新」には二種類ある。混同すると、データを更新しただけで判断基準も
更新されたと思い込むため、別々に確認する。

- **CISAデータの版:** `cisa fetch`で指定する40桁のGitコミット。
  新しい版は前節の手順で取得・保存し、`cisa show`で評価時刻と有効期限を確認する。
  同じCVEについて同期へ渡すのは新旧どちらか一つの`REVISION ID`である。
  取得日時が新しくても、元の評価が古ければ期限切れのままになり得る。
  取得失敗時は古い記録を「更新成功」と扱わない。
- **参照表の版:** 製品同梱の`data/bod_26_04_reference.json`にある16条件。
  CISAデータの取得では変わらず、CLIで任意の別表へ切り替える機能もない。
  更新する場合は開発変更として出典・確認日・条件差分をレビューし、全16条件と
  未確認時のテストを通して公開する。既存のP0〜P3や実期限への適用とは別の判断である。

CISA版の保存・明示選択・期限切れの扱いは、外部通信なしで次の既存テストでも確認できる。

```bash
.venv/bin/python -m pytest tests/unit/test_vulnrichment_storage.py tests/unit/test_vulnrichment_snapshot.py tests/unit/test_cisa_cli.py
```

上記は模擬通信と一時SQLiteによる確認であり、実運用DBを変更しない。
自社SLAへ接続する前には、適用対象、起算日時、例外の承認者と期限、
期限超過時の連絡先、最終判断者を人が決める必要がある。
未承認の間は`organizational_sla_adopted=false`、`due_at=null`の参照表示として使う。
