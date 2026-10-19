# 運用ガイド

初回は[演習](#運用担当者向けの初回演習)を順に進める。
普段は[日常運用・ログ・バックアップ](#日常の運用とログ)、
[任意の評価入力](#任意の評価入力)、[GitHub同期](#github同期の確認)を参照する。
登録単位の説明は[資産の運用フロー](#sbomと稼働資産を結ぶ運用フロー一部実装)、
業務シナリオと受入条件は[ユースケース](use-cases.md)にある。

Security teamはDependency-Trackのプロジェクト横断Findingを一元的に
トリアージし、sbom-opsの優先度ルールとGitHub Issueの対応状況を管理する。
例外承認、VEX判断、リスク受容は自動化せず、Security teamの判断記録を
一次情報とする。

## 運用担当者向けの初回演習

目的は、一件のFindingについて「何がDT由来の事実で、どこまで資産との対応を
確認でき、次に誰が何を調べるか」を説明できるようになること。目安は60〜90分。
[READMEのQuick Start](../README.md#quick-start)でインストールした後、以下を順に進める。
ローカルの使い捨てProjectを一つ作る演習であり、既存の本番ProjectへSBOMを
再投入しない。DTのAnalysis、コメント、抑制、VEX、データソース設定は変更しない。
GitHub Issueも作らない。CLIは`--dry-run --no-github`で実行する。

各段階で一度止まり、「予想」「画面・CLIで確認した事実」「疑問」を共有する。
質問への回答が次の操作に影響する場合は、解消してから先へ進む。

### 1. 架空例で役割分担を理解する（約10分）

[READMEのQuick Start](../README.md#quick-start)でPython環境を準備し、
次を実行する。認証情報もネットワークも不要。

```bash
python examples/review_scenario.py
```

入力は[架空のDT・資産データ](../examples/review-scenario.example.json)。
生のDT API応答や本番用importファイルではなく、承認済みの台帳を模擬する専用サンプル。
本番公開・開発環境の矛盾・期限切れ・対応付けなしを表示する。3件のFindingのまま、
環境は内訳として示す。先頭のP1はDTでは抑制済みなので、優先度だけで対応を決めない。
DB保存や実環境への承認は行わない。旧形式の資産JSONの比較例は
`python examples/asset_scenario.py`で残している。
架空のProject UUIDや稼働状況を実DTへコピーしない。

**停止点A:** 「DTだけで分かること」と「人が資産として申告したこと」を
それぞれ一つ挙げる。資産情報を付けても優先度やIssue操作が変わらない理由は何か。

### 2. 人が資産を登録し、DTへ直接SBOMを送る（約20分）

既存のローカルDTが`http://localhost:8080`で開ければ再起動しない。
開けなければ[Quick Start](../README.md#quick-start)のCompose手順で起動し、
`http://localhost:8080/api/openapi.json`が応答することを確認する。
DTの管理画面で、アップロード用と読み取り用のAPIキーを別チームに作る。

| 用途 | 必要な権限 |
| --- | --- |
| SBOM投入と演習Projectの自動作成 | `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` |
| sbom-opsの読み取り | `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` |

以下の値を置き換えて設定する。以後は同じシェルで実行する。
`.env`は自動では読み込まれない。キー値はGitや実行結果の記録へ入れない。

```bash
export SBOM_OPS_DT_BASE_URL=http://localhost:8080
export SBOM_OPS_DT_API_KEY=replace-with-orchestrator-read-key
export SBOM_OPS_SBOM_UPLOAD_API_KEY=replace-with-upload-key
mkdir -p var
export DEMO_SERVICE_ID="operator-demo-$(date +%s)"
export DEMO_PROJECT_NAME="$DEMO_SERVICE_ID/web"
export DEMO_PROJECT_VERSION="training-$(date +%s)"
sbom-ops assets --db var/assets.sqlite3 register-service \
  --service "$DEMO_SERVICE_ID" --owner training-team --criticality standard \
  --reason 'Local operator exercise; not a production deployment'
sbom-ops assets --db var/assets.sqlite3 register-deployable \
  --service "$DEMO_SERVICE_ID" --deployable web
sbom-ops assets --db var/assets.sqlite3 list
```

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

手順2で読み取り用キーと`SBOM_OPS_DT_BASE_URL`を設定したシェルを使う。
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

担当・環境とFindingを一緒に見るには、同じコマンドに`--output review`を付ける。
P0→P3順の日本語一覧になり、優先度の理由・DT分析・抑制・PoCの有無を併記する。
1項目は1 Findingで、複数環境はその内訳。抑制済みの行も表示するため、上から機械的に
対応依頼を出さずDTの判断も確認する。期限切れ・矛盾・未紐付けは安全という意味ではない。
PoC未取得は「不明」であり「なし」ではない。情報源別件数を合算して独自PoC数にしない。
`--output json`の`review_queue`にも同じ内容を出し、従来の`assessments`等は残す。
資産一覧はSQLiteの承認済み対応だけを使い、評価用の`--asset-inventory`とは混ぜない。
外部接続なしの練習は`python examples/review_scenario.py`で試せる。

**停止点F:** DT由来の事実、sbom-opsが計算した優先度、人が登録・承認した
資産情報を区別して説明する。DTだけで担当者や稼働環境を知れるか。
`sync --asset-db`では何が増え、何はまだ分からないか。

### 任意: 稼働環境の情報が必要になったら

SQLiteには期限付きの稼働・公開申告を登録できる。ここでは実際の稼働を
確認していないので、どちらも`unknown`として操作を試す。
`status=reviewed`はProject対応の承認であり「本番稼働確認済み」ではない。

```bash
export DEMO_OBSERVED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export DEMO_EXPIRES_AT="$(python -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
sbom-ops assets --db var/assets.sqlite3 report-deployment \
  --service "$DEMO_SERVICE_ID" --deployable web \
  --environment training --artifact "$DEMO_PROJECT_VERSION" \
  --status unknown --exposure unknown --reviewer your-name \
  --evidence 'Training declaration; runtime was not checked' \
  --observed-at "$DEMO_OBSERVED_AT" --expires-at "$DEMO_EXPIRES_AT"
sbom-ops assets --db var/assets.sqlite3 list
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --asset-db var/assets.sqlite3 \
  --wait-for-analysis --dry-run --no-github
```

`registry-deployment`の`reported`は期限内の申告が見つかった意味で、
実稼働を検証した意味ではない。訂正には新しい申告で`--supersedes-report 旧ID`を
指定する。旧申告は履歴に残り、新申告の観測時刻以降に有効対象から外れる。
同じサービス・配布単位・環境・成果物IDだけを訂正できる。
指定しない相反する有効申告は`conflict`のままにする。
既存v1/v2 DBでは先に`assets migrate --backup 新規バックアップ先`を行う。

旧来の`--asset-inventory`は別形式の評価用JSONで、SQLiteには登録されない。
詳細は[任意の評価入力](#任意の評価入力)を参照する。

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
詳細なコマンドは[初回演習](#運用担当者向けの初回演習)にある。DTの処理は非同期なので、
アップロード受付だけで分析完了とみなさない。
[DTのCI/CD連携](https://docs.dependencytrack.org/usage/cicd/)。

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
DT Project対応の承認、稼働申告の履歴・訂正を提供する。
サービスの更新・廃止、リンク撤回、独立したデプロイ観測は後続の課題。
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
バックアップを作成し、明示的にv9へ移行する。新規DBはv9で作成する。
既存の`sync --asset-inventory`は別の読み取り専用評価入力であり、
このJSON取込で資産DBに登録する形式とは互換ではない。
担当・重要度・公開状況は、AWSからの推測で決めない。手入力の稼働申告も
「人が確認した情報」であって、実行中コンテナとの照合がない限り、
技術的に検証された稼働事実とは区別する。

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
sbom-ops assets --db var/assets.sqlite3 migrate --backup var/assets-before-v9.sqlite3
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
Findingは残り、優先度・Issue操作は変わらない。停止確認ができた場合の稼働申告は
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
Docker、Trivy、ローカルDT、本書の初回演習で設定したアップロード／読み取りキーが必要。
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
本書の初回演習と同じ手順でサービス・配布単位を登録し、
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

## 日常の運用とログ

1. CIがSBOMをDTへ直接送る。受付、処理token、Findingの状態を区別する。
2. `sync --wait-for-analysis --asset-db PATH --no-github` で評価と資産対応を確認する。
3. 担当者が対応対象・不足情報を判断し、修正後のSBOMで再確認する。

`--wait-for-analysis` は応答安定の確認であり、修正確認ではない。
自動クローズは既定の無効を維持する。GitHub有効化は下記の別工程とする。
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
sbom-ops assets --db var/assets.sqlite3 migrate --backup var/assets-before-poc-v9.sqlite3
```

新規DBなら移行は不要。以下の `poc-fetch --execute` でv9を作成する。
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
採用・取消は下記の別操作で記録できるが、PoCへの接続は今後の作業。
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
# 候補取得はv8でも動作する。採用・取消も使うならv9へ明示移行する
sbom-ops assets --db var/assets.sqlite3 migrate --backup var/assets-before-identifiers-v9.sqlite3
# 送るIDを確認してから実行。DBがなければv9を作成する
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

同じv9のDBにPoC観測と採用履歴を保存する。既存DBが古い場合は先にバックアップ付きで移行する。
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

## GitHub同期の確認

当面は `--no-github` を使う。本文保存・ラベル更新・重複防止・途中失敗の監査など、
[有効化前の必須事項](../ROADMAP.md#github同期を有効にする前の必須事項)が残っている。
以下は書き込みをしない確認用である。

```bash
export SBOM_OPS_GITHUB_ENABLED=true
export SBOM_OPS_GITHUB_OWNER=your-org
export SBOM_OPS_GITHUB_REPO=your-repo
export GH_TOKEN="$(gh auth token)"
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --wait-for-analysis --dry-run
```

`SBOM_OPS_GITHUB_TOKEN`がある場合はそちらが優先される。
検証後は `SBOM_OPS_GITHUB_ENABLED=false` に戻すか、必ず `--no-github` を指定する。
既知の問題の解消と対象・権限・経路の確認後に、限定した対象で書き込みを検証する。

## YAML configuration

設定例は[examples/config.yaml](../examples/config.yaml)、契約は
[SPEC](../SPEC.md#configuration-contract)に集約する。
CLI → 環境変数 → YAML → 既定値の順で、YAMLの秘密情報は `env:変数名` で参照する。
KEVキャッシュは任意。`--refresh-kev` はTTL内でも再検証し、
取得失敗時に古い値を使うには明示設定が必要。結果の `kev_used_stale_cache` を確認する。
