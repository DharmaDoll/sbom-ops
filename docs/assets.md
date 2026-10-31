# 資産登録・成果物根拠・配備変更

[作業別の入口へ戻る](operations.md)。コマンドはリポジトリのルートで実行する。

**担当:** サービス担当がID・担当・事業影響を決め、運用担当が台帳へ登録・照合する。
**前提・入力:** 導入済みCLI、ローカル永続ディスクのSQLite、サービス・配布単位・担当。
Project承認にはDTの読取設定、CIの成果物ID・元SBOM・実行記録が必要。
稼働申告には配備先を確認した日時・根拠・期限を用意する。
**期待結果:** 登録内容・承認・根拠・配置申告を別々に確認でき、変更前の履歴が残る。
**失敗時:** DBのパスと`assets check`、対応する入力・schema版を確認する。
移行は[バックアップと復旧](daily-operations.md#バックアップと復旧)を参照。
候補不一致・重複・未承認は根拠を再確認し、名前だけで承認しない。

| すること | 手順 |
| --- | --- |
| 初回登録 | [登録単位と開始順序](#登録単位と新規サービスの開始順序) → [登録・Project照合](#dtから読み戻して紐づける方法) |
| 成果物とSBOMを結ぶ | [根拠登録・訂正](#sourcebuild根拠の登録と訂正) |
| 配備・更新・停止 | [稼働申告](#配備変更と稼働申告)・[新旧並存の架空演習](#架空のsource再ビルドsbom訂正を登録する) |
| 担当変更・廃止 | [担当・重要度](#担当重要度を変更する)・[廃止と紐付け訂正](#資産の廃止と紐付けの訂正) |

<a id="sbomと稼働資産を結ぶ運用フロー一部実装"></a>

## SBOMと稼働資産を結ぶ運用フロー

### 登録単位と新規サービスの開始順序

人が最初に登録する資産の基本単位は、**担当チームが一つの責任範囲として運用し、
脆弱性対応を判断できるサービス**とする。システム全体やコンテナイメージを
そのまま資産の基本単位にしない。境界が曖昧な場合は、担当、公開範囲、事業影響、
更新・修正の判断を独立して行えるかで分ける。

| 単位 | 役割 | 例 |
| --- | --- | --- |
| システム | 複数サービスの任意のまとめ。初期登録には必須としない | `commerce` |
| サービス | 人が登録する資産と担当・事業影響の基本単位 | `checkout-api` |
| 環境 | サービスの稼働・公開状況が異なる単位 | `production`, `staging` |
| 配布単位 | 個別にビルドしSBOMを作るアプリまたはイメージ | `checkout-api/web`, `checkout-api/worker` |
| 成果物 | 配布単位の変更不能なビルドID。複数環境で再利用できる | `image@sha256:...` |
| DT Project | 一つの成果物のSBOMとFindingを管理する対象 | 配布単位名 + 変更不能な版 |

一つのサービスが複数イメージを含めば、配布単位・成果物・SBOMをそれぞれ
対応付ける。逆に一つの成果物を複数環境に配布しても、環境ごとに同じSBOMを
複製しない。環境固有の公開状況や稼働申告はsbom-ops側に持つ。ライブラリや
依存パッケージは原則としてサービス資産ではなくSBOM内のComponentとして扱う。
DTの親子・Collection Projectは表示上のまとめに使えても、この対応関係の
代わりにはしない。
[DTのProject階層](https://docs.dependencytrack.org/usage/collection-projects/)。

新しいサービスは、まず人がサービスID、担当、事業影響とその理由、配布単位IDを
SQLite台帳に登録する。この時点でDT Project UUIDや稼働版は不要。CIは台帳を
更新せず、CycloneDX SBOMをDTへ直接送る。`Project名 = service_id/deployable_id`、
`Project版 = 変更不能な成果物ID`という規則を使い、DTのBOM APIで必要なら
Projectを作成する。アップロード後、運用担当者はCIの実行記録・成果物・DTの
Project名/版/UUIDを確認し、候補を明示的に承認する。自動承認はしない。
DT 4.14のBOM APIでは`BOM_UPLOAD`が必要で、`autoCreate=true`には追加で
`PROJECT_CREATION_UPLOAD`（またはより広い`PORTFOLIO_MANAGEMENT`）が必要。
このフローでは前者を使い、キーはCIの保護されたシークレットに置く。
詳細なコマンドは[初回演習](getting-started.md#運用担当者向けの初回演習)にある。DTの処理は非同期なので、
アップロード受付だけで分析完了とみなさない。
[DTのCI/CD連携](https://docs.dependencytrack.org/usage/cicd/)。

### ライフサイクルで情報を混同しないための確認

以下は[結合契約](../SPEC.md#sbomライフサイクルの結合契約後続実装の基準)に沿う運用上の確認であり、
Source/Build根拠は下記CLIで一記録ずつ登録する。一括登録やDTへの自動反映は行わない。

1. 開発時のSource SBOMと配布成果物のBuild SBOMを別の観測として保管する。
   CI側で元SBOM、生成器/実行記録、ソースcommit、実際の成果物IDを残す。
2. DTへ投入するときは、配布した成果物と対象Projectの名・版を照合する。
   Source SBOMを同じProjectへ送ってBuildの構成根拠を上書きする運用にしない。
3. 配置は環境・成果物ごとに申告する。新版の登録は旧版の停止を意味しない。
   切替後に旧版を停止したことを確認してから、その対象の停止申告を行う。
4. 同じ成果物のSBOMを訂正するときは、元/訂正後の文書と訂正理由をCI保管先へ残す。
   再ビルドとは区別し、記録の追記だけでDTへの反映まで成功したと扱わない。
5. 対応や鮮度が確認できなければ未確認のまま残す。ソースcommitの一致、
   SBOMの署名欄、稼働申告の存在だけで成果物・出所・実稼働を検証済みにしない。

これらの保存/表示で不足する機能は[#21](https://github.com/DharmaDoll/sbom-ops/issues/21)、
新旧切替の再現教材は[#22](https://github.com/DharmaDoll/sbom-ops/issues/22)で扱う。
根拠の登録はProjectの承認・稼働申告とは別であり、これらの代わりにはならない。

#### Source/Build根拠の登録と訂正

サービスと配布単位を先に登録する。既存DBがv10以前なら、バックアップ先を指定した
`assets --db PATH migrate --backup BACKUP_PATH`で明示移行する。
入力はUTF-8のJSON一記録（64 KiB以内）。例えば次を`evidence.json`へ保存する。
以下のIDと参照先は架空の例なので、自分の登録内容に合わせる。

```json
{
  "schema_version": 1,
  "service_id": "shop",
  "deployable_id": "api",
  "kind": "build",
  "artifact_id": "build-a",
  "sbom_ref": "boms/build-a.cdx.json",
  "actor": "operator"
}
```

```sh
sbom-ops assets --db var/assets.sqlite3 evidence-register --file evidence.json
sbom-ops assets --db var/assets.sqlite3 evidence-register --file evidence.json --apply
sbom-ops assets --db var/assets.sqlite3 evidence-history --service shop --deployable api
```

最初は確認のみ、`--apply`付きで保存する。出力の`record_id`が記録ID。
訂正は同じ対象のJSONへ`supersedes_id`（旧記録ID）と`reason`（訂正理由）を追加し、
同じ手順で確認・保存する。旧記録は残り、訂正済みの記録から分岐する訂正は拒否する。
独立した登録は併存し、最新日時の記録を自動採用しない。
Sourceの場合は`kind: source`と`source_repository`・`source_revision`が必要。
詳しい入力条件は[SPEC](../SPEC.md#根拠登録v1の入力契約)を参照する。

#### 架空のSource・再ビルド・SBOM訂正を登録する

通し演習は `python examples/lifecycle_scenario.py` で実行できる。
保存済みの4入力を登録し、未承認→旧版Aの本番配置→新版Bとの並存→Aのstaging再配備
→本番Aだけ停止→Bの申告矛盾→期限切れ、の順に既存の配置判定で確認する。
配置日時は実行時刻を基準にし、期限切れだけは3日後の読取を模擬する。実機を待った結果ではない。
毎回新しい一時DBを使い、終了時にそのDBを削除する。DTのProject情報・承認も架空であり、
実際のDT APIの挙動を検証するものではない。`--output json` で各段階の根拠状態も確認できる。
既定の演習はFindingやIssueを処理しない。`--output sync`のみ逆引き用の架空Findingを添える。
いずれも停止を脆弱性修正の証明として扱わない。

確認ポイント:

- `parallel`: A/Bの本番が両方 `reported / deployed`。同じソースでも別の成果物。
- `stopped`: 本番Aだけ `not_deployed`。本番Bとstaging Aは `deployed` のまま。
- `conflict`: 本番Bは `conflict`。勝手に新しい申告を選んで解消しない。
- `expired`: 申告済みの配置は `expired`。一度も申告していないstaging Bは `unreported`。
- JSONの根拠履歴: Sourceは `not_build`、Aの訂正前は `superseded`。
  別成果物の記録は `different_artifact`。登録や照合の成功を実稼働の証明にしない。

以下は登録操作を一つずつ試す手順。

リポジトリのルートから、インストール済みの `sbom-ops` で試せる。
Docker・APIキー・外部通信は不要。既存の台帳ではなく、毎回新しい一時DBを使う。
以下は根拠登録の演習であり、Projectの承認や配置・実稼働の確認はまだ行わない。

```bash
demo_dir=$(mktemp -d)
sbom-ops assets --db "$demo_dir/assets.sqlite3" import --file examples/asset-registration.example.json --apply
sbom-ops assets --db "$demo_dir/assets.sqlite3" evidence-register --file examples/lifecycle/source.json --apply
sbom-ops assets --db "$demo_dir/assets.sqlite3" evidence-register --file examples/lifecycle/build-a.json
sbom-ops assets --db "$demo_dir/assets.sqlite3" evidence-register --file examples/lifecycle/build-a.json --apply
sbom-ops assets --db "$demo_dir/assets.sqlite3" evidence-register --file examples/lifecycle/build-b.json --apply
sbom-ops assets --db "$demo_dir/assets.sqlite3" evidence-register --file examples/lifecycle/build-a-corrected.json --apply
sbom-ops assets --db "$demo_dir/assets.sqlite3" evidence-history --service checkout-api --deployable web
```

履歴には4件が残る。保存しないpreviewは記録IDを消費しない。

| 記録ID | 内容 | 確認すること |
| --- | --- | --- |
| 1 | Source | ソース参照はA/Bと共通だが、成果物の構成根拠として代用しない |
| 2 | Build A | 成果物IDは `build-a` |
| 3 | Build B | 同じソースcommitでも成果物ID・digest・ビルド実行はAと異なる |
| 4 | AのSBOM訂正 | 成果物ID・digestはAのまま。SBOM参照・digestだけが変わり、記録2を訂正する |

[入力ファイル](../examples/lifecycle/)のcommit、digest、観測日時、人物名、参照先は
すべて架空。`fictional/` の元SBOMは実在せず、署名やハッシュの照合もしていない。
参照先を取得する操作はない。訂正ファイルの `supersedes_id: 2` は上記の新規DBと
登録順序専用であり、既存台帳へそのまま投入しない。
実行後の一時DBは `$demo_dir/assets.sqlite3` に残るので履歴を読み直せる。
既存資産やDT、GitHubは変更しない。配置切替・停止の判定とは別の演習である。

CLIは参照文字列を保存するだけで、SBOMの読込み・DTへの送信・署名検証をしない。
`sync --asset-db var/assets.sqlite3 --output json`では、`lifecycle_evidence_status`と
Project別の`lifecycle_evidence`を確認する。`matched`は承認済みProjectの成果物との
対応だけを示し、保存成功や照合成功を影響評価済み・実稼働確認済みと扱わない。
日時不明は`observation_unknown`、未来は`future`、独立候補の併存は`multiple_candidates`。
`migration_required`は明示移行が必要、`invalid`は読取/整合性確認に失敗した状態であり、
「根拠なし」ではない。通常テキストにも表示する。
`--output review`では末尾の「SBOM根拠」欄で、Project別の根拠ID・成果物・元SBOM・
確認事項を日本語で読める。訂正前も履歴として残るため、状態を確認して利用する。
終了コード1の場合は入力・登録資産・DB版・訂正先の履歴を確認する。

### DTから読み戻して紐づける方法

`assets candidates`は登録済み配布単位とDT Projectの名前が完全一致したもの
だけを表示する。版なし・同名同版の重複・既存承認とのUUID不一致は承認しない。
`assets approve`は再度DTからProject一覧を読み、UUIDと名/版が一意に一致する
場合だけ、承認者と時刻をSQLiteに保存する。DTへの書込みやIssueの変更はしない。
人が申告した配布情報は、schema v3以降の台帳にサービス・配布単位・環境・成果物ID・
稼働状態・公開状態・確認者・根拠・観測時刻・有効期限として追記できる。同じ対象の
訂正は旧申告IDを指定した新しい申告として残し、古い記録を消さない。
`sync --asset-db`は確認済みの
Project UUID・名・版がDTと一致し、その版と申告された成果物IDも完全一致する場合
だけ、Project/環境ごとの申告状態を読み取り専用で表示する。未確認リンク、申告なし、
別成果物、期限切れ、未来時刻、矛盾は別の状態として示す。矛盾する有効な申告を
自動選択せず、Finding・優先度・Issueにも反映しない。実稼働の独立検証はまだ
行わない。`assets list`の`current`は申告の有効期間内という意味だけで、稼働を
証明しない。

この方式ではCIの自己申告やProject名だけで実行元の認可を証明できない。
限定したDTアップロードキー、CIシークレットの保護、登録済み配布単位との照合、
人の確認を当面の対策とし、悪意あるCIからの誤登録リスクは受容する。
必要性が立証されるまで中間サーバは設けない。CycloneDXは独自`properties`を
記述できるが、DTのCycloneDX書き出しは元SBOMの原本ではなく再生成結果である。
既存ラボでも`serialNumber`、`metadata.tools`、Componentの`bom-ref`が
投入時と異なった。したがって独自`metadata`や元SBOMのハッシュがDTから
そのまま読み戻せるとは仮定しない。DTタグは初回登録時の補助情報にはなるが、
変更アップロードで更新されない例があり、Project propertiesの専用読取
エンドポイントはラボの最小権限キーでHTTP 403だった。どちらもこの対応の
唯一の根拠にしない。

本番導入前に、使うDT版で再投入・訂正時の動作、必要な権限、CI実行記録の
保管を確認する。元SBOMの正確なハッシュやCI実行元の証拠は、DTから必ず
読み戻せるとは限らないため、CI成果物・実行記録で別途保持する。
[CycloneDX properties](https://cyclonedx.org/guides/sbom/) 、
[DTのProject書き出しAPI](https://github.com/DependencyTrack/dependency-track/blob/4.14.3/src/main/java/org/dependencytrack/resources/v1/BomResource.java)。

単にDT Project UUIDを資産JSONへ書くだけでは、そのProjectのSBOMが現在稼働する
ビルドを表すと証明できない。特に再ビルド、同時に複数版が動く更新、複数コンテナを
含むEKS/ECSのワークロードを考慮する。次の一連の確認を本番運用の受入条件とする。

1. CIが実際に配布する成果物を識別する変更不能なID（コンテナならイメージの
   digestなど）を確定し、その成果物に対応するSBOMを生成する。サービスID、
   成果物ID、SBOMのハッシュ、生成元を記録する。
2. CIは登録済み配布単位から定めたProject名と変更不能な版を指定し、SBOMを
   DTへ直接送る。アップロード受付だけで成功とせず、処理結果とCI実行記録を
   確認する。別の成果物のSBOMを同じProjectへ黙って上書きせず、同じ成果物の
   SBOMを訂正するときも版と訂正履歴を残す。
3. 運用担当者がサービス、環境、担当、稼働版、公開状況、重要度を、根拠・
   確認者・確認時刻・有効期限とともに登録する。分からない項目は`unknown`とする。
   将来のECS/EKS収集は環境・ワークロード・コンテナごとの稼働成果物を
   別の観測としてDBへ追加し、人の申告を黙って上書きしない。
4. sbom-opsの照合処理が、申告または観測された成果物IDから登録済みの
   SBOM/DT Projectへ一意に辿れるか検証する。人が登録した稼働情報は
   `申告`、独立して取得・照合した情報は`観測`と区別する。更新中に旧版と
   新版が同時稼働していれば両方を残す。Project UUIDだけ、または可変タグ
   だけの一致は稼働中の根拠にしない。
5. 一致したProjectのFindingに、サービス・環境情報とその確認状態を添える。
   `--output review`では同じ項目、既定のtext出力では別枠で示す。
   未登録、複数候補、版の不一致、期限切れ、収集失敗は`unknown`/`conflict`として
   可視化し、勝手に「非稼働」や「安全」としない。資産情報で優先度は
   変更しない。任意のGitHub同期では確認済み対応を修正作業のまとめ方に使う。
6. Security担当が対応対象と不明点を確認する。DTはSBOM・Finding・分析状態、
   sbom-ops資産DBは人の申告と対応関係の一次記録、デプロイ基盤は収集できる
   稼働事実の観測元、合意した作業管理先は対応状況の一次情報源として維持する。GitHub同期は別途有効化する任意連携である。

ECSは実行タスクの`imageDigest`を、EKSではPodの実行状態の`imageID`を
観測候補にできる。ただし値の表現や収集範囲を正規化・検証するまでは、
単純な文字列一致を稼働証明にしない。参照先:
[ECSの実行タスク](https://docs.aws.amazon.com/boto3/latest/reference/services/ecs/client/describe_tasks.html)、
[KubernetesのイメージID](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)、
[DTへのSBOM投入](https://docs.dependencytrack.org/usage/cicd/)。

社内に別の資産台帳がない前提なので、**sbom-opsが小さな資産DBを持つ**。
最初の実装は単一ホスト上のSQLiteを採用し、人によるサービス・配布単位登録と
DT Project対応の承認、稼働申告の履歴・訂正を提供する。
サービスの更新・廃止とリンク撤回も提供する。独立したデプロイ観測は未提供。
CIの実行記録、手入力、将来のデプロイ観測が
別時刻・別プロセスから届くため、次を再起動後も保持する。

- サービスID、担当、事業重要度、申告者・確認時刻・有効期限。担当不明の
  サービスも未分類のまま保存し、勝手に担当を決めない。
- 成果物の変更不能なID、SBOMハッシュ、DT Project UUID、登録元、処理結果。
- 環境・ワークロード・コンテナごとの稼働申告と、将来のAWS等からの観測を
  出所別に保持する。新旧版が並存する期間は両方を残す。
- 公開状況を含む人の判断と機械観測を別々に保持し、矛盾、収集失敗、
  訂正履歴を残す。

登録手段は現在CLIのみ。サービスと配布単位は
[`examples/asset-registration.example.json`](../examples/asset-registration.example.json)
の形式でも登録できる。最初はプレビューだけを表示し、内容を確認してから
`--apply`を指定する。JSONの全件を検証して1つのトランザクションで登録し、
既存IDとの衝突時は全件を取り消す。`--apply`で新規DBを作る場合は、親ディレクトリを
先に作成する。例のデータは架空であり、実環境の担当・重要度は人が確認する。

```bash
mkdir -p var/assets
sbom-ops assets --db var/assets/assets.sqlite3 import \
  --file examples/asset-registration.example.json
sbom-ops assets --db var/assets/assets.sqlite3 import \
  --file examples/asset-registration.example.json --apply
sbom-ops assets --db var/assets/assets.sqlite3 list
```

JSON取込はサービス・配布単位だけに限定し、DT Project対応の承認や
デプロイ申告は自動で作らない。既存の`register-service`と
`register-deployable`と同じ入力モデルを通る。`assets report-deployment`は
人の申告を追記し、
`assets list`は履歴と期限状態を表示する。申告を訂正する場合は、同じ
サービス・配布単位・環境・成果物IDの新しい申告に`--supersedes-report 旧ID`を
指定する。旧申告は削除されず、新申告の観測時刻までは有効である。
以後は`assets list`で旧申告を`freshness=superseded`と表示する。
指定しない相反する申告は引き続き`conflict`となる。既存のschema v1/v2 DBは
読み取り可能で、訂正機能を使う前に`assets migrate --backup PATH`で
バックアップを作成し、明示的に現行スキーマへ移行する。新規DB・移行先はv12。
CISA入力の保存テーブルも追加される。[専用CLI](investigation.md#cisa評価の取得保存表示)から取得・表示できる。
既存のPoC・CVE対応候補・採用履歴は保持する。
既存の`sync --asset-inventory`は別の読み取り専用評価入力であり、
このJSON取込で資産DBに登録する形式とは互換ではない。
担当・重要度・公開状況は、AWSからの推測で決めない。手入力の稼働申告も
「人が確認した情報」であって、実行中コンテナとの照合がない限り、
技術的に検証された稼働事実とは区別する。

### 配備変更と稼働申告

**担当・入力:** 運用担当が、登録済みサービス・配布単位・環境・実際の成果物IDと、
確認者・観測日時・有効期限・根拠を用意する。DBは`assets check`で確認する。
初回は[Project照合](#dtから読み戻して紐づける方法)を済ませる。
同じ成果物を再配備するときは既存のBuild SBOMを参照し、SBOMを再投入しない。

1. 配備先で確認した成果物IDをDT Projectの版と照合する。可変タグだけでは確認済みにしない。
2. 以下の各値を自分の確認結果へ置き換える。日時はタイムゾーン付きで指定する。
   `report-deployment`は実行時に保存するコマンドで、`--apply`によるpreviewはない。
3. `assets list`で申告と期限を確認し、同じProjectをsyncして対応と申告を照合する。

```bash
sbom-ops assets --db var/assets.sqlite3 report-deployment \
  --service "$SERVICE_ID" --deployable "$DEPLOYABLE_ID" \
  --environment "$ENVIRONMENT" --artifact "$ARTIFACT_ID" \
  --status "$DEPLOYMENT_STATUS" --exposure "$EXPOSURE" \
  --reviewer "$REVIEWER" --evidence "$EVIDENCE" \
  --observed-at "$OBSERVED_AT" --expires-at "$EXPIRES_AT"
sbom-ops assets --db var/assets.sqlite3 list
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --asset-db var/assets.sqlite3 \
  --dry-run --no-github --output review
```

`DEPLOYMENT_STATUS`は`deployed / not_deployed / unknown`、`EXPOSURE`は
`confirmed / rejected / unknown / conflict`から、実際に確認できた値を設定する。
`confirmed`はインターネット公開、`rejected`は公開していない申告、`conflict`は矛盾を表す。
上記の変数は自動設定されない。確認していない値は`unknown`にする。
APIキーと接続先は[初回演習](getting-started.md#2-人が資産を登録しdtへ直接sbomを送る約20分)で準備する。

**切替・停止:** 新しい成果物は別の申告にする。新旧並存なら両方を残す。
同じ対象の訂正・停止は旧申告IDを確認して`--supersedes-report 旧ID`を付ける。
訂正先のサービス・配布単位・環境・成果物IDを変えない。新版Bへの切替で旧版Aを停止したら、
Aの停止とBの稼働を別々に記録する。停止は脆弱性修正や台帳廃止を意味しない。

**期待結果・失敗時:** `reported`は期限内の申告がある意味で、独立した稼働証明ではない。
`unverified_link / other_artifact`ならProject承認と成果物ID、`expired`なら根拠と期限、
`conflict`なら相反する申告と訂正先を確認する。最新申告を推測で採用しない。
外部通信なしで新旧並存・停止を試すには[ライフサイクル教材](#架空のsource再ビルドsbom訂正を登録する)を使う。

### 担当・重要度を変更する

外部接続なしの練習は`python examples/asset_update_scenario.py`。
保存済みの架空登録データを一時DBへ入れ、変更前後の確認・保存・履歴確認を行う。
続けて、模擬DTデータで紐付け承認・撤回・再承認・資産廃止を試せる。
終了時に一時DBを削除する。DT、GitHub、既存の資産台帳は変更しない。

実台帳では、まず`assets --db var/assets.sqlite3 check`で対象パスを確認する。
v1〜v3のDBは更新前に次を実行する。バックアップ先はまだ存在しないパスにする。
バックアップや移行に失敗したら更新へ進まない。担当更新だけならv4以上で移行は不要。

```bash
sbom-ops assets --db var/assets.sqlite3 migrate --backup var/assets-before-update.sqlite3
```

以下は登録済みの`checkout-api`の変更例。自分のサービスID・担当・理由に置き換える。
`--reason`は今回の変更理由、`--impact-reason`はサービスの事業影響の説明であり別項目。
省略した更新項目は現在値を保つ。変更がない指定はエラーになる。

```bash
sbom-ops assets --db var/assets.sqlite3 update-service \
  --service checkout-api --owner team-payments --criticality critical \
  --impact-reason '決済停止が全店舗に影響' \
  --actor your-name --reason '担当移管・影響範囲の見直し'
```

`before`と`after`、変更者・理由を確認する。まだ保存されていない。
問題なければ同じコマンドに`--apply`を追加する。別コマンドでのプレビューは値を予約しないため、
他の人が変更していれば再確認する。`--apply`はその実行時点の現在値を読み直す。
同じ実行内で読取後に値が変わった場合や履歴を保存できない場合は更新全体を取り消す。
履歴は次のコマンドで確認する。

```bash
sbom-ops assets --db var/assets.sqlite3 history --service checkout-api
```

変更前後・変更者・理由・UTC時刻をJSONで表示する。登録時や移行前の履歴はない。
変更者名は入力された申告であり、本人認証・改ざん防止監査ログではない。
次の`sync --asset-db ... --output review --no-github`には新しい担当・重要度を表示するが、
優先度やDTの判断、稼働申告、Issue操作は変えない。履歴に個人情報を含める場合は
DBとバックアップのアクセス権を管理する。

v4を扱えない旧版へ戻す場合は更新を止め、移行前バックアップを別パスで検査して
そのDBを使う。移行後の変更は移行前バックアップには含まれない。

### 資産の廃止と紐付けの訂正

これらの操作にはschema v5以上が必要。v1〜v4は先にバックアップ付きで移行する。
旧版へ戻す場合は更新を止め、移行前バックアップを別パスで検査して使う。
v5の廃止・撤回は旧DBに含まれないため、旧DBへ戻すと以前の対応も戻る点に注意する。

```bash
sbom-ops assets --db var/assets.sqlite3 migrate --backup var/assets-before-v10.sqlite3
```

配布単位だけを廃止する例。まず対象と`before.links`の影響範囲を確認する。
保存には同じコマンドに`--apply`を追加する。廃止取消はまだないため対象を慎重に確認する。

```bash
sbom-ops assets --db var/assets.sqlite3 retire-deployable \
  --service checkout-api --deployable web --actor your-name --reason 'この配布単位の管理を終了'
```

サービス全体なら`retire-service --service checkout-api --actor your-name --reason '廃止理由'`を使う。
全配布単位が対象になる。どちらもデータは消さず、`assets list`と`history`で状態・履歴を確認できる。
廃止後は新しい紐付け承認を拒否し、廃止サービスに配布単位を追加しない。
`sync --output review`では「台帳上で廃止」と表示し、担当・環境を有効な情報として使わない。
Findingとその優先度は残る。既存の修正作業Issueがある場合は、次の同期で
資産対応を確認できないため上書きせず停止する。停止確認ができた場合の稼働申告は
従来どおり別途行う。廃止だけで`not_deployed`や安全と判定しない。

誤紐付けは撤回してから再承認する。撤回操作自体はDTへ接続しない。

```bash
sbom-ops assets --db var/assets.sqlite3 revoke-link \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --actor your-name --reason '誤紐付けの訂正'
```

プレビュー後、同じコマンドに`--apply`を追加する。旧リンクと理由を履歴へ残し、
有効な承認から外す。以降のsyncは「紐付け撤回済み」を表示する。
DTの対象を確認し、正しいProject UUIDで通常の承認をやり直す。

```bash
sbom-ops assets --db var/assets.sqlite3 candidates
sbom-ops assets --db var/assets.sqlite3 approve \
  --service checkout-api --deployable web \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --reviewer your-name
sbom-ops assets --db var/assets.sqlite3 history --service checkout-api
```

UUID・名前・版・重複を再確認し、名前が合うだけで承認しない。再承認に失敗しても
旧リンクを自動復活させず撤回済みのままにする。履歴の`lifecycle_events`に
撤回前のUUID・名前・版・旧承認者・承認時刻と、撤回者・理由・時刻が残る。
別コマンドのプレビューは値の予約ではない。実行中に対象リンクが変わった場合は再確認を要求する。
これらの操作はDT Projectの削除、Analysis・抑制変更、GitHub Issue終了を行わない。

### 将来の資産収集と台帳の保管

将来AWS収集を追加する場合、デプロイ直後の通知だけに依存せず、設定された
アカウントとクラスタを定期的に全件照合する。単発の収集失敗や一度の不在では
資産を削除・非稼働にしない。
ECSはサービスと実行タスクを列挙・詳細取得し、EKSはKubernetes APIから
ワークロードとPodの状態を読む。タグ・ラベルはサービスIDの対応候補に使うが、
AWSの共通タグ検索はタグなしリソースを返さないため、それだけを発見手段にしない。
収集者には対象を限定した読み取り権限のみを与える。EKSではAWSへの認証に加え、
Kubernetes APIの閲覧権限を別に設定する。
[ECSサービスAPI](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeServices.html)、
[AWSタグ検索の制限](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html)、
[EKSのアクセス制御](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html)。

このDBはDTの全FindingやGitHub Issue本文を複製する場所ではない。
SQLiteはローカルの永続ディスク上で単一ホストから使い、短いトランザクション、
スキーマ移行、整合性検査、オンラインバックアップと復元テストを用意する。
現在の`assets check`はSQLiteの整合性・外部キーを確認し、
`assets backup --output PATH`はオンラインバックアップを作る。
既存の出力先は上書きしない。新規DBは所有者だけが読み書きできる権限で作る。
登録以外のコマンドはDBパスの誤りを空DBの新規作成として扱わない。
バックアップは別の永続ストレージに保管し、`assets --db BACKUP_PATH check`
で開けることを定期的に確かめる。別DBへ復元して照合する手順は[運用演習](daily-operations.md#同じサービスで更新担当変更停止を通す)を参照する。
本番での切替手順とバックアップの自動保持期間は未整備である。
複数ホストから同じファイルを共有する運用やネットワークファイルシステムには
使わない。その運用が必要になればサーバー型DBへ移行する。
GitHub Actionsのように実行環境が毎回破棄されるジョブには、DBファイルを
直接置かない。現行方針ではCIはDTへ直接アップロードし、DBの登録・承認は
常設ホストの運用担当者がCLIで行う。
[SQLiteの適用範囲](https://www.sqlite.org/whentouse.html)、
[WALの制約](https://sqlite.org/wal.html)、
[オンラインバックアップ](https://www.sqlite.org/backup.html)。
DBの配置、バックアップ、保存期間、収集権限と対象範囲は本番運用前に決める。
現行の`--asset-inventory`は読み取り専用の評価用入力として残し、DB実装と混同しない。

### 固定成果物を使ったローカル通し検証

`examples/identity-demo/`は、外部依存のない小さなGo HTTPアプリである。
本番アプリの代わりにはならないが、実際にビルド・起動したイメージの固定IDを
SBOM、DT Project版、資産DBの申告へ一貫して渡せるかを試せる。Go 1.22以上、
Docker、Trivy、ローカルDT、[初回演習](getting-started.md#運用担当者向けの初回演習)で設定したアップロード／読み取りキーが必要。
作業ファイルはGit管理外の`var/`に置く。

```bash
mkdir -p var/identity-demo
(cd examples/identity-demo && go test ./... && \
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -buildvcs=false -ldflags=-buildid= -o ../../var/identity-demo/demo .)
docker build --network=none -f examples/identity-demo/Dockerfile \
  -t sbom-ops/identity-demo:local var/identity-demo
export DEMO_IMAGE_ID="$(docker image inspect sbom-ops/identity-demo:local \
  --format '{{.Id}}')"
docker run --rm -d --name sbom-ops-identity-demo \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1::8080 sbom-ops/identity-demo:local
docker inspect sbom-ops-identity-demo --format '{{.Image}} {{.State.Running}}'
export DEMO_PORT="$(docker port sbom-ops-identity-demo 8080/tcp | sed 's/.*://')"
curl --fail --silent --show-error "http://127.0.0.1:$DEMO_PORT/health"
trivy image --image-src docker --format cyclonedx \
  --output var/identity-demo/demo.sbom.cdx.json --offline-scan \
  --scanners license --skip-java-db-update "$DEMO_IMAGE_ID"
```

`docker inspect`のイメージIDが`DEMO_IMAGE_ID`と完全一致することを確認する。
再実行時に同名コンテナが残っている場合は、先にそのIDと用途を確認し、
この検証用コンテナだけを停止するか、別のコンテナ名を使う。
ここでのTrivy実行はSBOM作成用であり、脆弱性DBを用いた評価ではない。
[初回演習](getting-started.md#運用担当者向けの初回演習)と同じ手順でサービス・配布単位を登録し、
`Project名=service_id/web`、`Project版=$DEMO_IMAGE_ID`を指定して
`scripts/upload_bom.sh var/identity-demo/demo.sbom.cdx.json`からDTへ直接送る。
たとえば次のように、毎回異なる検証用サービスIDを使う。

```bash
export DEMO_SERVICE_ID="identity-demo-$(date +%s)"
sbom-ops assets --db var/identity-demo/assets.sqlite3 register-service \
  --service "$DEMO_SERVICE_ID" --owner local-test \
  --criticality standard --reason 'Disposable local artifact-chain exercise'
sbom-ops assets --db var/identity-demo/assets.sqlite3 register-deployable \
  --service "$DEMO_SERVICE_ID" --deployable web
unset SBOM_OPS_DT_PROJECT_UUID
export SBOM_OPS_DT_PROJECT_NAME="$DEMO_SERVICE_ID/web"
export SBOM_OPS_DT_PROJECT_VERSION="$DEMO_IMAGE_ID"
scripts/upload_bom.sh var/identity-demo/demo.sbom.cdx.json
```

BOM処理トークンの完了を確認し、DTのProject名・版・UUIDとコンポーネントを
読み戻してから`assets approve`する。`assets report-deployment`の環境は
`local-demo`、成果物IDは`DEMO_IMAGE_ID`とし、確認者・根拠・期限を明記する。
`sync --asset-db ... --dry-run --no-github`でProject対応と申告を別々に確認する。
終了時は`docker stop sbom-ops-identity-demo`で専用コンテナを停止する。
`--rm`でそのコンテナは自動削除されるが、ローカルイメージ、DT Project、
SQLite DBは残る。別の実験対象を誤って削除しないこと。

実施済みの結果・制約・ローカル証拠パスは
[DT検証記録](../lab/dependency_track/EXPERIMENTS.md)に残す。
2026-10-08/09のローカル検証と2026-10-12のCI成果物検証で、
稼働から停止への明示訂正を確認した。本番稼働・公開範囲・SBOM網羅性は未検証。

### CIが作った成果物での確認

CIの`identity-demo-artifact`ジョブは、同じサンプルをテスト・ビルドし、
Dockerイメージのアーカイブ、イメージID、ソースコミット、ファイルのSHA-256を
7日間のGitHub Actions artifactとして保存する。DTキーはCIに渡さず、
DTへのアップロードや資産DBの変更もしない。
2026-10-12の通し検証は[DT検証記録](../lab/dependency_track/EXPERIMENTS.md)を参照。
このサンプルは外部依存がないため、SBOMの網羅性や本番稼働は証明しない。

mainの成功した`ci`実行を選ぶ。PRやforkの実行結果を運用対象にしない。
次の例では`RUN_ID`をその実行番号へ置き換え、`gh run view`の結果が
`conclusion=success`、`headBranch=main`であることを目視確認する。

```bash
export RUN_ID=123456789
gh run view "$RUN_ID" --repo DharmaDoll/sbom-ops \
  --json conclusion,headSha,headBranch,workflowName
export CI_DIR="var/identity-demo/ci/$RUN_ID"
test ! -e "$CI_DIR"
mkdir -p "$CI_DIR"
gh run download "$RUN_ID" --repo DharmaDoll/sbom-ops \
  --name identity-demo-image --dir "$CI_DIR"
(cd "$CI_DIR" && sha256sum -c SHA256SUMS)
export CI_SOURCE_SHA="$(gh run view "$RUN_ID" --repo DharmaDoll/sbom-ops \
  --json headSha --jq .headSha)"
test "$(cat "$CI_DIR/source-commit.txt")" = "$CI_SOURCE_SHA"
export CI_IMAGE_ID="$(cat "$CI_DIR/image-id.txt")"
trivy image --input "$CI_DIR/image.tar" --format cyclonedx \
  --output "$CI_DIR/demo.sbom.cdx.json" --offline-scan \
  --scanners license --skip-java-db-update --cache-dir "$CI_DIR/trivy-cache"
test "$(jq -r '.metadata.component.properties[] | select(.name=="aquasecurity:trivy:ImageID") | .value' \
  "$CI_DIR/demo.sbom.cdx.json")" = "$CI_IMAGE_ID"
```

このTrivy実行はDockerデーモン不要である。オフライン・ライセンススキャンで
作るSBOMなので、脆弱性検出や依存関係の網羅性まで確認したことにはならない。
Dockerが使える環境では、続けてアーカイブを読み込み、IDと起動を確認する。

```bash
docker load --input "$CI_DIR/image.tar"
test "$(docker image inspect "sbom-ops/identity-demo:$CI_SOURCE_SHA" \
  --format '{{.Id}}')" = "$CI_IMAGE_ID"
```

固定IDのイメージだけをlocalhostに起動して`/health`を確認する。そのIDを
Trivyの`image --format cyclonedx`の対象、DT Project版、
資産DBの申告成果物IDに同じ値で渡す。前節と同じくDT Projectを読み戻し、
対応を承認して`sync --asset-db ... --dry-run --no-github`を確認する。
停止時は新しい申告で`--supersedes-report 旧ID`を明示し、履歴と有効状態を確認する。

この照合は「選んだCI実行から取得したアーカイブ」とローカルの稼働イメージの
一致を確認するもので、署名付きのビルド証明や本番環境の稼働証明ではない。
アーカイブ内のSHA-256一覧だけを独立した出所証明とみなさない。
