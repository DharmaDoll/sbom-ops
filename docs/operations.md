# Operations

Detailed operational scenarios and acceptance conditions are defined in
[`docs/use-cases.md`](use-cases.md).

Security teamはDependency-Trackのプロジェクト横断Findingを一元的に
トリアージし、sbom-opsの優先度ルールとGitHub Issueの対応状況を管理する。
例外承認、VEX判断、リスク受容は自動化せず、Security teamの判断記録を
一次情報とする。

## 運用担当者向けの初回演習

目的は、一件のFindingについて「何がDT由来の事実で、どこまで資産との対応を
確認でき、次に誰が何を調べるか」を説明できるようになること。目安は60〜90分。
[READMEのQuick Start](../README.md#quick-start)と同じ順に進める。
ローカルの使い捨てProjectを一つ作る演習であり、既存の本番ProjectへSBOMを
再投入しない。DTのAnalysis、コメント、抑制、VEX、データソース設定は変更しない。
GitHub Issueも作らない。CLIは`--dry-run --no-github`で実行する。

各段階で一度止まり、「予想」「画面・CLIで確認した事実」「疑問」を共有する。
質問への回答が次の操作に影響する場合は、解消してから先へ進む。

### 1. 架空例で役割分担を理解する（約10分）

[READMEのQuick Start](../README.md#quick-start)でPython環境を準備し、
次を実行する。認証情報もネットワークも不要。

```bash
python examples/asset_scenario.py
```

入力は[架空のDT Project/Finding](../examples/asset-scenario-dt.example.json)と
[架空の資産台帳](../examples/asset-inventory.example.json)。前者は生のDT API応答ではない。
同じCVEでも本番・開発・期限切れ・対応付けなしで、担当者が知りたいことが
どう違うかを確認する。これは後で使うSQLite台帳とは別の、旧来の評価用JSON。
架空のProject UUIDや稼働状況を実DTへコピーしない。

**停止点A:** 「DTだけで分かること」と「人が資産として申告したこと」を
それぞれ一つ挙げる。資産情報を付けても優先度やIssue操作が変わらない理由は何か。

### 2. 人が資産を登録し、DTへ直接SBOMを送る（約20分）

既存のローカルDTが`http://localhost:8080`で開ければ再起動しない。
開けなければ[Quick Start](../README.md#quick-start)のCompose手順で起動し、
`http://localhost:8080/api/openapi.json`が応答することを確認する。
まず[Quick Start](../README.md#quick-start)どおり、`DEMO_SERVICE_ID`を作り、
`assets register-service`と`register-deployable`でSQLite台帳へ登録する。
`assets list`でサービス、担当、理由、配布単位を確認する。この時点でDT Project
UUIDはなく、稼働環境や公開状況も登録していない。DBは`var/assets.sqlite3`に
残るので、演習ごとに新しいサービスIDを使い、既存DBを消さない。

**停止点B:** 人が登録したサービスと配布単位は何が違うか。担当・事業影響の
根拠は入力できたか。DT Projectがまだ存在しないのに、ここで分かる情報は何か。

次にアップロード用キー（`BOM_UPLOAD`と、自動作成には
`PROJECT_CREATION_UPLOAD`）を準備し、CIの代役として次を実行する。
`env -u`は以前の`SBOM_OPS_DT_PROJECT_UUID`が残っていても、別Projectへ
上書き投入しないため。スクリプトはDTのBOM APIへ直接POSTし、sbom-opsを
経由しない。

```bash
env -u SBOM_OPS_DT_PROJECT_UUID \
  SBOM_OPS_DT_PROJECT_NAME="$DEMO_PROJECT_NAME" \
  SBOM_OPS_DT_PROJECT_VERSION="$DEMO_PROJECT_VERSION" \
  scripts/upload_bom.sh examples/sboms/vulnerable-demo.cdx.json
```

**停止点C:** 受付応答は「分析完了」か。使ったSBOM、Project名・版、
アップロード元、実際の成果物IDについて、何が証拠として残っているか。
この演習の`training-*`版は実際のコンテナdigestではなく、稼働版の証明に
使えない。実運用のCIでは変更不能な成果物IDを版に使う。

### 3. DT画面でProjectとFindingを追う（約20分）

DTのProjectsで`$DEMO_PROJECT_NAME`と`$DEMO_PROJECT_VERSION`に一致する
Projectを選び、Componentsと脆弱性の監査画面からFindingを一件開く。
Project UUID、コンポーネント名・版・PURL、脆弱性ID・情報源、CVSS・EPSS、
Analysis状態、抑制の有無を記録する。表示される場合は依存経路と監査履歴も見る。
投入後の分析は非同期なので、件数が変動中なら待って再確認する。
Findingがゼロでも「安全」と判断せず、SBOMの取り込み、データソース、
処理待ちを分けて確認する。

**停止点D:** DTが直接示すのは何か。Project名から「本番で稼働中」や
「このCIから来た」と断定できるか。Findingが見えないとき、何を先に確認するか。

DTの[SBOM投入手順](https://docs.dependencytrack.org/usage/cicd/)、
[権限](https://docs.dependencytrack.org/administration/users-and-permissions/)、
[監査の基本](https://docs.dependencytrack.org/triage/auditing-basics/)を参照する。
画面上のトリアージ操作は読み取りのみで、`VULNERABILITY_ANALYSIS`を使う
判断や変更はしない。

### 4. DT Projectを資産台帳へ紐づける（約10分）

読み取り用キー（`VIEW_PORTFOLIO`）を`SBOM_OPS_DT_API_KEY`に設定して、
DTから候補を読み込む。候補に出たというだけで紐づけは確定しない。

```bash
sbom-ops assets --db var/assets.sqlite3 candidates
```

`name=$DEMO_PROJECT_NAME`の行の`status=candidate`、UUID、版を、
DT画面および直前のアップロード記録と照合する。合わない場合は承認しない。
合致を確認したら、確認者の名前を付けて明示的に承認する。

```bash
export SBOM_OPS_DT_PROJECT_UUID=replace-with-reviewed-project-uuid
sbom-ops assets --db var/assets.sqlite3 approve \
  --service "$DEMO_SERVICE_ID" --deployable web \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --reviewer your-name
sbom-ops assets --db var/assets.sqlite3 candidates
sbom-ops assets --db var/assets.sqlite3 list
sbom-ops assets --db var/assets.sqlite3 audit-links
```

`status=reviewed`と承認者・時刻を確認する。これはProjectと配布単位の
対応を人が確認した記録で、SBOMの出所、実際の稼働版、インターネット公開、
脆弱性の影響有無を承認したわけではない。版なし・重複・既存承認との矛盾は
`missing_version`/`conflict`となり、承認しない。
`audit-links`は承認後の対応をDTと再照合し、一致なら`matched`、現在の
読取結果にUUIDがなければ`not_visible`、名・版の変更なら`identity_changed`、
重複なら`ambiguous`を示す。`not_visible`は権限や一時的な読取範囲の問題も
あり得るため「削除」と断定しない。不一致やリンクなしの場合は終了コードが
非ゼロになり、いずれも自動で登録内容を書き換えない。

**停止点E:** 何を見て承認したか。第三者が翌日この対応を再確認するとき、
どのCI記録・SBOM・DT画面が必要か。分からない点は「未確認」として残す。

### 5. sbom-opsの結果と照合する（約20分）

既存の読み取り用キーと`SBOM_OPS_DT_BASE_URL`を
[Quick Start](../README.md#quick-start)に従って環境変数に設定する。
キー値は画面共有、記録、Issueへ載せない。DT画面で確認したUUIDを指定し、
対象を一Projectに絞る。この同期にはCISA KEV feedへのアクセスまたは
利用可能なローカルキャッシュも必要で、通信失敗はDTのFinding不足と区別する。

```bash
sbom-ops plan --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --dry-run --no-github
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" \
  --wait-for-analysis --asset-db var/assets.sqlite3 --dry-run --no-github
```

Findingが多数なら全件を初回に精査しない。DT画面で一件選び、CLIの
`vulnerability=`とComponentを手掛かりに同じ行を探す。同じFindingの
コンポーネント、脆弱性ID、CVSS・EPSS、DT分析状態と、
sbom-opsの優先度・根拠を照合する。`--wait-for-analysis`はFindingの
連続した読み取りが安定したかを見るもので、DTの全ての背景処理の完了証明では
ない。DTの読取失敗、応答形式の異常、Project一覧の途中欠落は同期エラーとして
止まり、Findingがゼロ件だったことにはしない。401/403は権限を確認し、
429/5xxやタイムアウトは設定された再試行の上限を確認する。応答の形が正常でも
Finding一覧が本当に完全かまでは証明できないため、自動Issueクローズの運用は
別途確認が必要。差があれば件数だけで結論を出さず、対象Project、表示条件、抑制状態、
処理時刻を確認する。`--no-github`中にIssue操作は行わない。

`--asset-db`を指定した場合だけ、既存SQLite台帳を読み取り専用で開き、
`registry-project`に承認済み対応を表示する。`matched`なら担当・事業重要度を
表示し、`unlinked`、`identity_changed`、`ambiguous`ではその情報を
紐づいた事実として表示しない。版やUUIDが合っても、SBOMの出所、稼働版、
環境、公開状況は証明されない。この表示は優先度やIssue操作に影響しない。
台帳ファイルが無い・壊れている場合は同期を始めず失敗する。

**停止点F:** DT由来の事実、sbom-opsが計算した優先度、人が登録・承認した
資産情報を区別して説明する。DTだけで担当者や稼働環境を知れるか。
`sync --asset-db`では何が増え、何はまだ分からないか。

### 任意: 稼働環境の情報が必要になったら

この初回演習では稼働版・公開状況を入力しない。SQLite台帳にはまだ環境・
デプロイの登録機能がないため、`status=reviewed`を「本番稼働確認済み」と
読まない。旧来の`sync --asset-inventory`は、環境・稼働・公開状況を別の
レビュー済みJSONから表示する評価用入力であり、SQLite台帳との連携ではない。
必要になったときだけ[READMEの任意入力](../README.md#optional-evaluation-inputs)と
[SPEC](../SPEC.md#asset-inventory-context)に進む。架空の4件をそのまま実DTへ
適用せず、根拠がない担当や稼働状態は`unknown`とする。

### 記録と完了条件

各段階で「予想／実際に見えた事実／迷った点／次に確認する人や情報」を短く記録する。
匿名化した結果と疑問を共有し、食い違いを解消してから次の段階へ進む。
Project UUID、Findingの識別子、実行時刻、使用したSBOM、SQLite DBのパス、
承認者・承認時刻も控える。
キーや未加工の自社資産情報はGitへ入れず、必要な改善点だけ匿名化してIssueや
ドキュメントへ反映する。生の実行結果は無視対象の`var/operator-review/`に置く。

質疑応答では、各停止点について次の形で共有する。答えを推測で埋めず、
分からない欄は「未確認」と書く。

```text
停止点: A〜F
予想:
確認した事実（DT画面 / CLI / CI記録のどれか）:
疑問・食い違い:
次に確認したい操作または担当:
```

完了の目安は、運用担当者が一件のFindingについて、DT由来の事実、
sbom-opsの計算、人が登録・承認した情報を区別し、優先度の根拠、未確認の
稼働情報、次の確認先を説明できること。
画面や出力が分かりにくい場合は、その迷い自体を改善課題として残す。
その後に人のコード・仕様レビューを行い、UI/説明の不足、データの不足、
判断ルールの不足を分けて次の実装を決める。

## SBOMと稼働資産を結ぶ運用フロー（一部実装）

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
詳細なコマンドは[README](../README.md#quick-start)にある。DTの処理は非同期なので、
アップロード受付だけで分析完了とみなさない。
[DTのCI/CD連携](https://docs.dependencytrack.org/usage/cicd/)。

### DTから読み戻して紐づける方法

`assets candidates`は登録済み配布単位とDT Projectの名前が完全一致したもの
だけを表示する。版なし・同名同版の重複・既存承認とのUUID不一致は承認しない。
`assets approve`は再度DTからProject一覧を読み、UUIDと名/版が一意に一致する
場合だけ、承認者と時刻をSQLiteに保存する。DTへの書込みやIssueの変更はしない。
人が申告した配布情報は、schema v2の台帳にサービス・配布単位・環境・成果物ID・
稼働状態・公開状態・確認者・根拠・観測時刻・有効期限として追記できる。同じ対象の
訂正も新たな申告として残し、古い記録を消さない。`sync --asset-db`は確認済みの
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
5. 一致したProjectのFindingに、サービス・環境情報とその確認状態を別枠で示す。
   未登録、複数候補、版の不一致、期限切れ、収集失敗は`unknown`/`conflict`として
   可視化し、勝手に「非稼働」や「安全」としない。資産情報による優先度やIssueの
   自動変更は、別途レビューされた判断ルールができるまで行わない。
6. Security担当が対応対象と不明点を確認する。DTはSBOM・Finding・分析状態、
   sbom-ops資産DBは人の申告と対応関係の一次記録、デプロイ基盤は収集できる
   稼働事実の観測元、GitHub Issuesは対応状況の一次情報源として維持する。

ECSは実行タスクの`imageDigest`を、EKSではPodの実行状態の`imageID`を
観測候補にできる。ただし値の表現や収集範囲を正規化・検証するまでは、
単純な文字列一致を稼働証明にしない。参照先:
[ECSの実行タスク](https://docs.aws.amazon.com/boto3/latest/reference/services/ecs/client/describe_tasks.html)、
[KubernetesのイメージID](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)、
[DTへのSBOM投入](https://docs.dependencytrack.org/usage/cicd/)。

社内に別の資産台帳がない前提なので、**sbom-opsが小さな資産DBを持つ**。
最初の実装は単一ホスト上のSQLiteを採用し、人によるサービス・配布単位登録と
DT Project対応の承認を提供する。修正・履歴閲覧やデプロイ観測は後続の課題。
CIの実行記録、手入力、将来のデプロイ観測が
別時刻・別プロセスから届くため、次を再起動後も保持する。

- サービスID、担当、事業重要度、申告者・確認時刻・有効期限。担当不明の
  サービスも未分類のまま保存し、勝手に担当を決めない。
- 成果物の変更不能なID、SBOMハッシュ、DT Project UUID、登録元、処理結果。
- 環境・ワークロード・コンテナごとの稼働申告と、将来のAWS等からの観測を
  出所別に保持する。新旧版が並存する期間は両方を残す。
- 公開状況を含む人の判断と機械観測を別々に保持し、矛盾、収集失敗、
  訂正履歴を残す。

登録手段は現在CLIのみ。`assets report-deployment`は人の申告を追記し、
`assets list`は履歴と期限状態を表示する。既存のschema v1 DBは読み取り可能で、
新しい申告を記録する前に`assets migrate --backup PATH`でバックアップを作成し、
明示的にv2へ移行する。新規DBはv2で作成する。レビュー済みJSONの取り込みは
未実装であり、
既存の`sync --asset-inventory`は別の読み取り専用評価入力である。
担当・重要度・公開状況は、AWSからの推測で決めない。手入力の稼働申告も
「人が確認した情報」であって、実行中コンテナとの照合がない限り、
技術的に検証された稼働事実とは区別する。

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
で開けることを定期的に確かめる。自動保持期間と復元手順は未整備である。
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
Docker、Trivy、ローカルDT、README記載のアップロード／読み取りキーが必要。
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
READMEのQuick startと同じ手順でサービス・配布単位を登録し、
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

2026-10-08の実施では、Goテスト・固定イメージの起動・localhostのhealth応答、
CycloneDX 1.6の3コンポーネント生成、DTによる同じ3件の取込、
Project版と稼働イメージIDの一致、SQLiteの確認済み対応・稼働申告の表示を確認した。
DTはGo標準ライブラリに47件のFindingを返したが、この検証はそれらの
脆弱性評価やSBOM網羅性を判定するものではない。GitHub操作は0件だった。
停止申告を追記すると、先の稼働申告と有効期間が重なるため、現行実装は
`conflict`を返した。Findingと優先度は停止前後で同一だった。
これは安全側の表示だが、通常の更新を解決するには明示的な訂正・継承手続きが
必要である。ローカルの根拠は無視対象の
`var/product-validation-20261007-identity-demo/`にあり、鍵・環境固有UUID・
生の結果はGitへ入れない。本番のCIビルド由来、外部環境の実稼働、公開範囲は
この演習では未検証である。

Daily

1. CI uploads the SBOM and waits for the Dependency-Track processing token to
   report `processing=false` (the separate `sbom-ops upload` helper may do this).
2. Orchestrator polls findings using `sync --wait-for-analysis`.
3. Orchestrator confirms a stable project read.
4. Orchestrator reads Dependency-Track EPSS/VEX analysis state.
5. Orchestrator enriches findings with KEV.
6. Priority calculation.
7. GitHub Issue creation (optional final action).
8. Developer remediation.
9. CI verifies.
10. First verified absence marks the Issue as missing and leaves it open.
11. A later verified absence may close it only when automatic closure is
    explicitly enabled and the configured confirmation count is met.

`SBOM_OPS_CLOSE_MISSING_FINDINGS` defaults to `false`. Enabling it also requires
`sync --wait-for-analysis`.
`SBOM_OPS_MISSING_CONFIRMATION_RUNS` defaults to `2` and cannot be lower than 2.

GitHub Issue operations can be disabled while retaining Dependency-Track
collection and prioritization. Set `github.enabled: false`, export
`SBOM_OPS_GITHUB_ENABLED=false`, or pass `sbom-ops sync --no-github` (the CLI
flag takes precedence). `plan --no-github` displays the same mode.

The sync result always includes the Finding key, vulnerability source, severity,
numeric CVSS and EPSS values (including explicit `null` when unavailable),
Priority, Dependency-Track Analysis/suppression state, and prioritization
rationale before any external action is selected. This assessment output is
therefore available for future Jira, notification, VEX, or reporting adapters
without coupling them to GitHub. A `P3` result with `cvss_score: null` is not
evidence of low severity; it means the configured numeric CVSS rule did not
match the observed input.

For downstream adapters, use machine-readable output:

```bash
sbom-ops sync --no-github --output json
```

Each result contains a unique `run_id` and `duration_seconds`, which can be
used to correlate later audit events or persistent synchronization logs.

To persist completed results as JSONL, set `runtime.sync_log_file` or
`SBOM_OPS_SYNC_LOG_FILE`. The file is only written when explicitly configured;
its parent directory must already exist.

Successful records have `status: succeeded`. If the configured sync encounters
a handled API, configuration, or client error, a `status: failed` record with
an error type and message is appended as well. Log sink write failures do not
replace the original sync result. They emit a warning on stderr, while JSON
output on stdout and the primary command exit status remain unchanged. Monitor
stderr because a successful synchronization without its configured audit record
is an operational evidence gap.

The JSONL sink is isolated from CLI and orchestration logic so it can later be
replaced with a database or centralized logging adapter.

For local GitHub authentication, keep the token in GitHub CLI's credential
store and export it only for the process that runs sbom-ops:

```bash
export GH_TOKEN="$(gh auth token)"
sbom-ops sync --dry-run
```

`GH_TOKEN` is accepted when `SBOM_OPS_GITHUB_TOKEN` is not set. Never commit
the token or put it in `.env.example`.

## YAML configuration

`sync` and `plan` accept a YAML configuration file with `--config PATH`. When
the flag is omitted, `SBOM_OPS_CONFIG_FILE` is used. Environment variables
override YAML values, and CLI flags override both. Secret values should use an
environment reference such as `api_key: env:SBOM_OPS_DT_API_KEY` rather than
being committed to the repository.

The supported schema and validation rules are documented in [`SPEC.md`](../SPEC.md).
An executable example is available at [`examples/config.yaml`](../examples/config.yaml).

The KEV client can use an optional local TTL cache with
`intelligence.kev_cache_file` and `intelligence.kev_cache_ttl_seconds` (or the
corresponding `SBOM_OPS_KEV_CACHE_*` variables). Without a cache path, each
sync fetches the feed normally. A stale or malformed cache is ignored rather
than used as authoritative data.

Set `intelligence.kev_cache_allow_stale: true` only when continued operation
with an explicitly stale KEV snapshot is acceptable. The setting is also
available as `SBOM_OPS_KEV_CACHE_ALLOW_STALE=true` and applies only after a
fresh feed request fails.
JSONL and JSON sync results expose `kev_used_stale_cache` so downstream
consumers can distinguish current KEV data from an explicitly stale snapshot.
When the cache has validators, refresh requests use `If-None-Match` and
`If-Modified-Since`; a `304 Not Modified` response refreshes the cache timestamp
without downloading the feed body.

```bash
export SBOM_OPS_DT_API_KEY=replace-me
sbom-ops plan --config examples/config.yaml --no-github
```
