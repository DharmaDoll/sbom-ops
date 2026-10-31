# 初回確認とDT演習

[作業別の入口へ戻る](operations.md)。コマンドはリポジトリのルートで実行する。

## 最短の初回確認（外部通信なし）

**担当:** サービス担当・運用担当・セキュリティ担当。
**前提:** [READMEのQuick Start](../README.md#quick-start)でPython 3.12以上と本PJを導入済み。
**入力:** 同梱の架空DT・資産データ。Docker・APIキーは不要。

```bash
python examples/review_scenario.py
sbom-ops assets --db var/assets.sqlite3 import \
  --file examples/asset-registration.example.json
```

**期待結果:** 4件のFindingと3組の修正作業候補を確認し、担当・矛盾・期限切れ・未紐付けを
区別できる。登録コマンドはpreviewだけで、DBを作成・変更しない。
候補は作業のまとめ方の提案であり、対応要否はセキュリティ担当が判断する。
**失敗時:** `sbom-ops`が見つからなければ仮想環境とインストールを、入力エラーなら
実行ディレクトリと同梱ファイルを確認する。架空データを実資産として承認しない。

実台帳への登録は[資産登録](assets.md#登録単位と新規サービスの開始順序)、
既存のDTで一件追う場合は以下の演習へ進む。

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
本番公開・開発環境の矛盾・期限切れ・対応付けなしを表示する。4件のFindingのまま、
環境は内訳として示す。先頭のP1はDTでは抑制済みなので、優先度だけで対応を決めない。
同じサービス`checkout-api/web`の2ビルドは同じ部品と脆弱性を含み、修正作業の候補は
計3組になる。元のFindingは消さず、未紐付けのProjectは同じCVEでも別に残す。
DB保存や実環境への承認は行わない。旧形式の資産JSONの比較例は
`python examples/asset_scenario.py`で残している。
架空のProject UUIDや稼働状況を実DTへコピーしない。

**停止点A:** 「DTだけで分かること」と「人が資産として申告したこと」を
それぞれ一つ挙げる。この練習で資産情報を付けても優先度が変わらず、
GitHub操作が無効のままである理由は何か。
4件のFindingが3組の候補になる理由と、紐付けが不明なProjectをまとめない理由も確認する。

### 2. 人が資産を登録し、DTへ直接SBOMを送る（約20分）

既存のローカルDTが`http://localhost:8080`で開ければ再起動しない。
開けなければ[Quick Start](../README.md#quick-start)のCompose手順で起動し、
`http://localhost:8080/api/openapi.json`が応答することを確認する。
DTの管理画面で、アップロード用と読み取り用のAPIキーを別チームに作る。

| 用途 | 必要な権限 |
| --- | --- |
| SBOM投入と演習Projectの自動作成 | `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` |
| sbom-opsの読み取り | `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` |

操作別の内訳と未検証事項は[DT API権限表](dependency-track/api.md#操作ごとの権限dt-4143)を参照。
`SYSTEM_CONFIGURATION`は設定の変更も許可するため、通常の読取キーには追加しない。

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
Finding一覧が本当に完全かまでは証明できないため、自動Issueクローズは提供しない。
`workflow.close_missing_findings=true`（環境変数でも同じ）は設定エラーになる。
旧 `missing_confirmation_runs` は互換用に受け付けるが、解決判定には使わない。
過去のIssueの欠落回数は引き継がず、欠落だけならIssueは変更しない。
同じ修正作業の別Findingを更新する場合も、未確認の内訳は削除しない。
再出現時は管理範囲をACTIVEに戻して欠落回数を取り除く。移行前の本文は履歴として残す。
`--no-github`中はIssue操作を行わない。

出力の「解決確認=未確認」、JSONの `absence_verification.finding_state=UNKNOWN` は、
**取得できたFindingの評価とは別に、見えないFindingの解決は未確認**という意味。
`stable` や0件を「脆弱性なし」「修正完了」と読み替えない。
読取失敗時は終了コード2、JSONは `status=failed` で件数・評価一覧を出さない。
全対象Projectを読み終えるまではGitHub操作を始めない。

再試行の上限に達した場合や件数に差がある場合は、対象ProjectのUUID・版、
投入したSBOMと処理token、DTの表示条件・抑制状態、データソースの更新状況、
読取キーの権限を確認する。原因を直した後で同じ対象を再実行し、
DT画面と取得結果を照合する。再実行の成功も欠落だけを根拠にした修正証明にはしない。

`--asset-db`を指定した場合だけ、既存SQLite台帳を読み取り専用で開き、
`registry-project`に承認済み対応を表示する。`matched`なら担当・事業重要度を
表示し、`unlinked`、`identity_changed`、`ambiguous`ではその情報を
紐づいた事実として表示しない。版やUUIDが合っても、SBOMの出所、稼働版、
環境、公開状況は証明されない。資産情報でFindingの優先度は変えないが、
GitHub有効時は確認済み資産を修正作業のまとめ方にも使う。
台帳ファイルが無い・壊れている場合は同期を始めず失敗する。

担当・環境とFindingを一緒に見るには、同じコマンドに`--output review`を付ける。
P0→P3順の日本語一覧になり、優先度の理由・DT分析・抑制・PoCの有無を併記する。
1項目は1 Findingで、複数環境はその内訳。抑制済みの行も表示するため、上から機械的に
対応依頼を出さずDTの判断も確認する。期限切れ・矛盾・未紐付けは安全という意味ではない。
PoC未取得は「不明」であり「なし」ではない。情報源別件数を合算して独自PoC数にしない。
CVSS・EPSSが未提供のFindingもある。DT画面の`-`とCLIの`null`を照合し、
P3でも理由に「未取得」があれば低リスクの証明とは扱わない。担当者は情報源の助言と
利用しているパッケージ・関数を確認する。画面を開いた直後の集計値だけで判断せず、
Component一覧・監査一覧が読み込まれた後に対象の行を確認する。
`--output json`の`review_queue`にも同じ内容を出し、従来の`assessments`等は残す。
資産一覧はSQLiteの承認済み対応だけを使い、評価用の`--asset-inventory`とは混ぜない。
外部接続なしの練習は`python examples/review_scenario.py`で試せる。

一覧の末尾には「修正作業の候補」を出す。確認済みの同じサービス・配布単位で、
PURL全文と脆弱性の情報源/IDが一致すれば、複数ビルドのFindingを一組にする。
部品の版違いは別組。候補keyと内訳から元のFindingを確認できる。
JSONの`remediation_groups`も同じまとまりで、環境・抑制・期限切れなどは各`members`に残る。
これは選択したProject内の確認用表示で、Issue数の予測や自動同期への適用ではない。
一部Projectだけを選んだ実行でメンバーが減っても「解決した」と判断しない。
GitHub有効時は確認済みの組をrepoごとに一つのIssueへ同期する。未確認の資産は個別扱い。
候補数と作成数は一致するとは限らない。表示確認だけを理由に実書込みを有効化しない。

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
詳細は[任意の評価入力](investigation.md#任意の評価入力)を参照する。

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
