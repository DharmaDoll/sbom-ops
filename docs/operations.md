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

## 利用者の作業一覧：いつ・どこで・何をするか

初回は導入準備 → Build SBOM投入 → 配備先との対応確認 → 日常の確認の順に進める。
Source SBOMは早期確認を補助する。運用時は既存のBuild SBOMと配置情報を結び付ける。
以下の「確認結果」は、その工程で利用者が残す根拠であり、ツールの成功表示だけで代用しない。

| タイミング | 担当・操作場所 | 利用者の作業と手順 | 残すもの・確認結果 |
| --- | --- | --- | --- |
| 導入・新サービス追加 | サービス／運用担当、sbom-ops CLI | [登録単位と開始順序](#登録単位と新規サービスの開始順序)に沿ってサービス・配布単位・担当を登録。CI担当はDT接続先と投入権限を準備 | サービスID・配布単位ID・担当と、送信先の合意 |
| PR・依存更新 | 開発担当、開発CI | 依存定義等からSource SBOMを生成し早期確認。[根拠登録](#sourcebuild根拠の登録と訂正)でソース版と文書参照を保持 | commit、元文書、生成ツール・版。Build SBOMとは区別し、同じDT Projectへ上書きしない |
| リリース候補・配布物の生成 | CI担当、ビルドCI → DT | [最終イメージの生成・投入手順](#コンテナのsbomを生成してdtへ送るタイミング)をCIに組み込む。OSパッケージとアプリ依存の収録を確認 | イメージdigest、元SBOMとハッシュ、CI実行参照、DT Project、処理結果。受付と解析結果を区別 |
| 初回配備・新版への切替・再配備 | 運用担当、実際の配備先とsbom-ops CLI | 配備した成果物を確認し、[Projectの照合](#dtから読み戻して紐づける方法)と[稼働情報の登録](#任意-稼働環境の情報が必要になったら)を行う | 環境、成果物ID、確認者・日時・根拠・有効期限。新旧並存なら両方保持 |
| 日常・脆弱性の速報 | セキュリティ／運用担当、DTとsbom-ops CLI | [日常の流れ](#日常の流れ)でsync結果を確認。[逆引き](#保存済みの結果からcve部品を逆引きする)で影響候補を探し、担当と次の行動を確認 | 対象資産、担当、確認日時、不足情報、対応判断。古い保存結果や一致なしを安全の証明にしない |
| 修正・旧版停止・担当変更 | 開発／運用担当、CI・配備先・sbom-ops CLI | 再ビルドして新SBOMを投入し、[更新・担当変更・停止](#同じサービスで更新担当変更停止を通す)を記録。セキュリティ担当が修正を確認 | 新版の根拠、旧版停止の根拠、変更履歴。Finding消失だけで修正完了にしない |
| SBOMの収録漏れ・誤記を発見 | CI／運用担当、CI成果物保管先・DT・sbom-ops CLI | 同じ成果物のSBOMを訂正して再投入し、[根拠の訂正](#sourcebuild根拠の登録と訂正)を記録 | 成果物IDは維持、文書の版・ハッシュ・訂正理由と旧記録を保持 |

DTは構成・Finding・分析状態を保持する。元SBOMとCI証拠はCI成果物保管先、
サービス・担当・配置申告と対応関係はsbom-opsの資産台帳へ保存する。
対応判断と修正作業は担当者が管理する。製品のGitHub Issues自動同期は本番有効化を保留しており、
この一覧の作業で自動的に有効にはならない。

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
`sync --asset-db var/assets.sqlite3 --format json`では、`lifecycle_evidence_status`と
Project別の`lifecycle_evidence`を確認する。`matched`は承認済みProjectの成果物との
対応だけを示し、保存成功や照合成功を影響評価済み・実稼働確認済みと扱わない。
日時不明は`observation_unknown`、未来は`future`、独立候補の併存は`multiple_candidates`。
`migration_required`は明示移行が必要、`invalid`は読取/整合性確認に失敗した状態であり、
「根拠なし」ではない。通常テキストにも表示する。
`--format review`では末尾の「SBOM根拠」欄で、Project別の根拠ID・成果物・元SBOM・
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
バックアップを作成し、明示的にv10へ移行する。新規DBはv10で作成する。
CISA入力の保存テーブルも追加される。[専用CLI](#cisa評価の取得保存表示)から取得・表示できる。
既存のPoC・CVE対応候補・採用履歴は保持する。
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
で開けることを定期的に確かめる。別DBへ復元して照合する手順は下記の運用演習を参照する。
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

### 同じサービスで更新・担当変更・停止を通す

初回演習の後、前節のCI成果物を使って次の流れを試す。DB・サービスID・配布単位は同じものを使う。
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

1. CIがSBOMをDTへ直接送る。受付、処理token、Findingの状態を区別する。
2. `sync --wait-for-analysis --asset-db PATH --no-github` で評価と資産対応を確認する。
3. 担当者が対応対象・不足情報を判断し、修正後のSBOMで再確認する。

`--wait-for-analysis` は応答安定の確認であり、修正確認ではない。
自動クローズは提供しない。GitHub有効化は下記の別工程とする。
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
sbom-ops assets --db var/assets.sqlite3 migrate --backup var/assets-before-poc-v10.sqlite3
```

新規DBなら移行は不要。以下の `poc-fetch --execute` でv10を作成する。
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
# 候補取得はv8でも動作する。採用・取消にはv9以降が必要。移行コマンドは最新v10へ進める
sbom-ops assets --db var/assets.sqlite3 migrate --backup var/assets-before-identifiers-v10.sqlite3
# 送るIDを確認してから実行。DBがなければv10を作成する
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

## GitHub同期の確認

### 権限と送信先を先に固定する

開発Issueの更新・コードのpush用認証と、製品の脆弱性Issue同期用認証は別の用途である。
現在の製品クライアントは `https://api.github.com` を使う。GitHub Enterprise Serverの
独自API URLや、GitHub Appのトークン発行・更新は提供していない。

| 製品が行う操作 | API（`/repos/{owner}/{repo}` 以下） | 必要なrepository permission |
| --- | --- | --- |
| 全Issue一覧・更新前の本文確認、dry-run | `GET /issues`、`GET /issues/{number}` | Issues: read |
| 新規作成・管理範囲の本文更新 | `POST /issues`、`PATCH /issues/{number}` | Issues: write |
| 管理ラベルの追加・個別解除 | `POST /issues/{number}/labels`、`DELETE /issues/{number}/labels/{name}` | Issues: write |

表は[Issues API](https://docs.github.com/en/rest/issues/issues)と
[Labels API](https://docs.github.com/en/rest/issues/labels)の権限に対応する。
実書込みでは読取りも必要。Contents・Pull requests・Administrationの書込み権限は要求しない。
自動クローズ、Issue削除、コメント投稿、repoの作成・設定変更は同期処理の対象外。
tokenの権限だけで実行アカウントの権限が増えるわけではない。
特に新規Issue作成時のラベル指定は、実行者にrepoへのpush accessがないと無視され得るため、
後述の限定検証では「作成成功」だけでなく管理ラベルの反映まで確認する。

最初の限定検証は、有効期限を設けたfine-grained PATで、Repository accessを検証先のみに
限定し、IssuesをRead and writeにする。読取りだけのdry-runならRead-onlyでよいが、
それでは実書込み可能なことの証明にはならない。Metadataなど自動付与される読取りと、
明示的に付与する権限を区別する。組織の承認が必要なら承認完了を確認する。
長期運用ではGitHub Appも候補だが、発行・更新は運用側で用意し、権限を広げる代替策にはしない。
詳細は[GitHubのトークン管理](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)を参照。
秘密値は承認済みの保管先から実行環境の `SBOM_OPS_GITHUB_TOKEN` へ渡す。
本文・YAML・Issue・ログへ貼らず、開発用の広いtokenを暗黙に流用しない。
この変数が未指定なら `GH_TOKEN` を使うため、実行環境に残っている認証の用途も確認する。

対象は次のように固定する。資産の担当者情報からrepoやIssue担当者を自動で決める機能ではない。

- `--project` または `runtime.project_uuids` で検証Projectを明示する。省略時は閲覧可能な全Projectになる。
- `routing.projects` が空なら全対象を `github.owner/repo` へ送る。
  一件でも経路を設定したら、全対象ProjectのUUIDに経路を用意する。未登録Projectは停止し、既定repoへ逃がさない。
- 複数repoの経路があってもtokenは共通。全経路の必要権限を確認し、許可するrepoを最小限にする。
  初回検証は一つのrepoだけにする。経路の変更は既存Issueの移動ではなく、別repoでの新規作成につながり得るため事前レビューする。
- prefixと `prefix-P0`〜`prefix-P3` の5ラベルを確認し、既存用途と衝突しないものを選ぶ。
  検証前にrepo側で用意し、後からprefixを変えて既存Issueを見失わせない。
- `plan` は接続せず設定の概要と経路の件数を示すだけで、権限や全送信先の検証にはならない。
  設定・環境変数による上書きを確認し、続いて実際の `sync --dry-run` のrepo・key・操作予定を確認する。

Issue本文には部品・脆弱性・サービス/配布単位などの情報が出る。
非公開資産を公開repoへ送らない。既存Issueも読むため、dry-run出力・操作記録の保管先と閲覧者を決める。
専用prefixは認証上の隔離ではなく、設定誤りで他Issueを変更できない保証でもない。
tokenのrepo制限と、確認済みProject・経路・管理keyの組合せで対象を絞る。

### 複数ビルドを一つの修正作業として扱う

`--asset-db`の照合済みサービス・配布単位、PURL全文、脆弱性の情報源/IDが一致すれば、
同じrepo内ではビルドが増えても一つのIssueへまとめる。repoが違えば別のIssueになる。
部品の版違い・未確認の紐付けは推測でまとめない。DT分析と各Findingの優先度は変えず、
Issueの作成条件・管理ラベルには分析除外を除いた最優先値を使う。

最初の作成・移行は、同じサービス/配布単位・同じrepoに対応する照合済みProjectを全て
`--project`で選び、dry-runする。一部だけでは、選ばなかったビルドの旧Issueを見逃すため停止する。
同範囲に今回確認できない旧FindingのIssueがある場合も、対応を調べるまで新しい組を作らない。
既存Issueが一つなら番号・タイトル・管理範囲外のメモを保持して移行する。複数あれば停止し、
自動で一つを選んだり、余りを閉じたりしない。閉じたIssueを無視して新規作成することもない。

移行後に一部Projectだけを同期した場合、以前の内訳は「今回未確認」として残る。
そのFindingの最後の優先度も維持するため、選択範囲を狭めただけではラベルが下がらない。
現在の対象が全て抑制・NOT_AFFECTED・FALSE_POSITIVEなら更新せず、Issueは閉じない。
資産の再紐付け・同じ組でのラベル経路の不一致は停止して確認する。台帳を省略して
旧Finding単位へ戻す操作も、既存の組を壊さないよう停止する。

本文の`repair-record`は内訳を次回へ引き継ぐ機械用記録で、管理範囲と一緒に保持する。
Base64は暗号化ではないので秘密情報を入れない。SQLiteの旧送信記録は残し、保存された
旧Finding keyから同じIssueへ照合する。移行のためにDBを削除・初期化する必要はない。
本文全体が6万文字を超えたら、メンバーを捨てたり別Issueを増やしたりせず停止する。
記録を手で削って再送を通さず、対象範囲と表現の見直しが必要な状態として扱う。
実環境の有効化検証が済むまでは、以下の手順もdry-runまでに留める。
外部通信なしでこの同期処理を試すには、開発用依存を導入後に
`python -m pytest -q tests/unit/test_grouped_workflow.py`を実行する。
模擬GitHubと一時SQLiteで、作成・旧Issue移行・一部ビルドの同期・応答喪失などを検証し、
実Issueや既存DBは変更しない。

### 本文の扱いと復旧

Issue本文の `<!-- sbom-ops:managed:start -->` と `<!-- sbom-ops:managed:end -->` の
間は自動更新する。担当者の判断、作業メモ、チェックリストはこの範囲の外かコメントに書く。
範囲外の改行・空白を含む本文と、人が変更したタイトルは保持する。
既存タイトルは更新しないため、最新の優先度は本文の管理範囲で確認する。

優先度ラベルも更新する。標準設定では `sbom` と `sbom-P0`〜`sbom-P3` が
sbom-ops専用の名前になる。この5個は人の独自用途に使わないこと。
`bug` や `team:backend`、`sbom-P0-note` など、それ以外のラベルは保持する。
P0/P1からP2/P3に下がっても既存Issueの本文・ラベルは更新するが、Issueは閉じない。
新規作成は設定した優先度（既定はP0/P1）だけが対象となる。

ラベル全体を置き換えず、必要なものを追加して確認した後、古い優先度だけを外す。
これは[GitHubのラベル追加・個別削除API](https://docs.github.com/en/rest/issues/labels)を使い、
対象repoのIssues書込み権限を必要とする。本文のPATCHにラベル一覧を含めないため、
同期中に人が別のラベルを追加しても消さない。ただし予約名の同時編集は避ける。
応答喪失・403・404などで失敗したら、本文だけ更新済み、または新旧の優先度が両方ある
可能性がある。GitHubで状況と権限を確認し、dry-runの `labels ... add=... remove=...` を
確認してから再実行する。次回は最新のラベルから変更を組み直し、古い操作は自動再送しない。
prefixを変更しても旧prefixは自動削除しない。予約名の移行は対象Issueを確認して行う。

旧形式のIssueは、元の本文全体を「移行前の本文」として残し、新しい管理範囲を追加する。
古いスコア・状態は履歴であり、現在の判定ではない。繰り返し同期しても履歴を重ねて追加しない。
移行前の本文も、人が必要箇所を整理するまで自動削除しない。

区切りやkeyが壊れているときは、推測して本文を上書きせずエラーにする。
Issueの編集履歴とFindingを確認し、区切りと対応関係を直した後にdry-runで再確認する。
本文更新がタイムアウトした場合、反映済みの可能性がある。まずGitHub上の本文を確認する。
古い本文の自動再送はしない。新規作成の結果が不明な場合は、以下の操作記録でも再送を防ぐ。

Issueの対応は、閉じたものも含めた一覧と管理keyで照合する。複数の一致や、
旧keyが複数のFindingに対応する場合は止まる。対象を確認し、勝手な統合・削除はしない。
一覧は最大10ページ（各100件、PRを含む）までで、続きがあれば不完全として失敗する。
ページ取得失敗を「既存Issueなし」とみなして新規作成することはない。
`review-closed`は、同じFindingのIssueが既に閉じられているので人の確認が必要という意味。
Findingと完了理由を照合し、必要なら人がIssueを再オープンしてから再実行する。

作成リクエストの応答が失われた場合はPOSTを再送せず、一覧を再取得する。
`create-reconciled`なら対応するIssueを一意に確認できたことを示す。
`create outcome is unknown`や再取得エラーでは、**同期をすぐに再実行しない**。
GitHub上で作成されたかと対象Findingを確認する。次回はSQLiteの未確定記録を先に照合し、
Issueを一意に確認できた場合だけ記録を確定する（`reconcile-create`）。
見つからなければ、送信前に停止した可能性があっても再送せず停止する。
確定済みIssueの削除・移動・key変更・別番号への置換でも勝手に作り直さない。
記録を消す、別DBを使う、古いバックアップへ戻す方法で回避してはいけない。

### 作成の操作記録（SQLite）

GitHub書込みを行う場合は、単一ホストのローカル永続ディスクに操作記録DBを用意する。
これは資産・PoC台帳とは別の**送信事故防止用DB**で、GitHubの対応状態をコピーするものではない。
資産台帳を復元しても、送信済みの記録が巻き戻らないよう分離している。
認証情報や本文は保存しないが、repo・Finding key・Issue番号を含むため権限は0600とする。
次の初期化は最初の1回だけ。既存ファイルは上書きせず、同期時にも自動作成しない。

```bash
mkdir -p var
sbom-ops workflow --db var/workflow.sqlite3 init
export SBOM_OPS_ISSUE_JOURNAL_FILE=var/workflow.sqlite3
sbom-ops workflow --db var/workflow.sqlite3 show
```

旧版の操作記録DB（schema v1）がある場合は、同期を停止してから次の移行を1回行う。
既存の作成記録を保持したまま、監査用テーブルを追加する。バックアップ先の上書きはしない。
資産台帳の `assets migrate` とは別の操作である。

```bash
sbom-ops workflow --db var/workflow.sqlite3 migrate --backup var/workflow-before-audit.sqlite3
sbom-ops workflow --db var/workflow.sqlite3 audit --run-id '同期結果に出たrun_id'
```

`audit` は読取り専用。`--run-id` を省略すると全記録を表示する。
run IDはCLIの開始からエラー出力まで共通で、本文更新やラベル操作の経過を追える。
`operation_started` は送信前の記録、`operation_confirmed` は確認済み、
`operation_unknown` は結果未確認、`operation_reconciled` は再照合で確認できた操作である。
本文更新だけconfirmedで、ラベル操作がunknownなら、そのIssueの本文とラベルを確認する。
startedしかない操作は「未送信」とは限らない。終了記録のないrunも、プロセス状態と
GitHubを確認するまで成功・失敗・実行中と断定しない。作成意図は `show` でも照合する。
監査保存が失敗すると後続書込みは止まり、失敗JSONに `audit_persistence_failed=true` が出る。
その場合、出力にある記録がDBに残っていない可能性があるため、両方を保全する。
Ctrl+Cはinterrupted（終了コード130）、強制終了では終了記録自体が残らない場合がある。
dry-runや `--no-github`、DBを開く前の失敗はSQLiteには記録されない。
旧DBを移行しても過去の操作監査は追加されない。これはローカルの復旧用記録であり、
DB管理者が書き換えられない監査基盤ではない。

`show` は読取りだけで、`pending`（結果未確定）／`confirmed`（番号確認済み）、
元のrun IDと確認時のrun IDを表示する。`pending` は「未送信」を意味しない。
送信前停止と応答喪失を区別できない記録の再送解除コマンドはまだ提供していない。
その場合はDBとGitHubの状況を保全し、書込みを停止して調査する。

同じDBを使う同期を同時起動すると、後続は終了コード3で停止する。
DBを変えた並列実行や複数ホスト・ネットワークディスクでは保護できない。
DBの移動・バックアップは全同期を停止してから行い、書込み後に古いコピーへ戻さない。
破損・紛失時は新規DBで続けず、GitHubとの照合・復旧を先に行う。
dry-runはDB未設定でも可能だが、実行環境のDBを設定すると未確定記録も確認できる。
dry-run中は記録を変更せず、`--no-github` ではDB自体を使わない。
なお、これだけで有効化準備が完了するわけではない。限定実環境での確認などが残るため、
タイマー実行・本番書込みはまだ有効化しない。

更新直前に本文を読み直すが、読取りと書込みの間の同時編集までは防げない。
有効化検証中は同期を1実行に限定し、その短い更新時間にはIssue本文の編集を避ける。
本文への追記は同期後、または別リソースであるコメントで行う。

### 有効化前の確認

GitHub連携は既定で無効。`github.enabled=true` または `SBOM_OPS_GITHUB_ENABLED=true` に
しただけでは書き込めない。書込みには、その実行の `--github-write` と操作記録DBが必要になる。
書込み許可をYAMLや環境変数に保存する設定はない。旧運用で `enabled=true` のまま
`sync` していた場合、許可の省略はエラーになる。まず `--dry-run` で対象と差分を確認する。
`--github-write` 単独では連携自体を有効化しない。また `--dry-run` や `--no-github` と
併用した場合は、書込み禁止の方を優先する。`plan` は常に表示だけで書き込まない。

当面は `--no-github` を使う。本文・ラベル・重複防止の実環境確認や途中失敗の監査など、
[有効化前の必須事項](../ROADMAP.md#github同期を有効にする前の必須事項)の
最新状況は[開発Issue #7](https://github.com/DharmaDoll/sbom-ops/issues/7)を確認する。
以下は書き込みをしない確認用である。

```bash
export SBOM_OPS_GITHUB_ENABLED=true
export SBOM_OPS_GITHUB_OWNER=your-org
export SBOM_OPS_GITHUB_REPO=your-repo
# SBOM_OPS_GITHUB_TOKENは承認済みの保管先から実行環境へ渡しておく。
sbom-ops sync --config examples/config.yaml \
  --project "$SBOM_OPS_DT_PROJECT_UUID" --wait-for-analysis --dry-run
```

`SBOM_OPS_GITHUB_TOKEN`がある場合はそちらが優先される。
検証後は `SBOM_OPS_GITHUB_ENABLED=false` に戻すか、必ず `--no-github` を指定する。
既知の問題の解消と対象・権限・経路の確認後に、限定した対象で書き込みを検証する。
その段階でのみ、確認した同じ `sync` の `--dry-run` を外して `--github-write` を付ける。
通常のQuick startや評価だけの実行には付けない。タイマー実行でも実行コマンド側に明示し、
先に `plan` とdry-runでProject・repo・経路・DBの対象を確認すること。

### 限定した実環境での確認手順

検証用repoとProject、許可するIssue操作・件数を先に合意する。開発Issue更新の許可を
製品によるIssue作成の許可とみなさない。架空の資産と検証用Findingを用い、
初回は1サービス・2ビルド・同一部品/脆弱性の一組、作成は最大1 Issueに限定する。
旧形式からの移行は、別の一組・既存の検証用1 Issueを対象にする。
検証用DB・設定・run ID・対象Issue番号を記録し、本番のDBを使い回さない。
これは検証の開始時に対象を分けるためであり、結果不明時に別DBへ逃げる手順ではない。

| 順序 | 操作 | 確認する結果 |
| --- | --- | --- |
| 1 | 同じ設定・台帳・Project選択でGitHub有効のdry-run | 想定repoの一組だけが作成予定。意図しない更新がない。DBとIssueは非変更 |
| 2 | 各回に `--github-write` を指定し、同じ入力で順に2回同期（並列実行しない） | 2ビルドで1 Issue、2回目は同じ番号。管理ラベル・本文・作成記録・監査が対応する |
| 3 | 検証Issueの管理範囲外にメモ、人のタイトルとラベルを設定して再同期 | 人の変更は保持。優先度変更を伴う検証入力では管理ラベルだけ更新 |
| 4 | 片方のビルドだけ選んで同期、続いて元の全選択で同期 | 未選択の内訳を失わず「今回未確認」。再出現しても同じIssueで、選択縮小だけでは優先度を下げない |
| 5 | 検証用旧形式Issueを、全ビルド選択でdry-run後に同期 | 番号・人の本文・タイトルと旧作成記録を保持し、再実行でも重複しない |
| 6 | 読取り専用tokenで書込みを試す限定失敗検証（別途許可した対象のみ） | エラー・run ID・監査を記録し、成功扱いしない。GitHubと記録を読戻し、後続書込みや重複がない |
| 7 | 同期を止め、結果と残存物を確認 | 本文・ラベル・DB監査・run IDを照合し、連携を無効へ戻す。勝手にIssueや記録を削除しない |

各段階で想定外のrepo/key/番号/件数、403/404、応答不明、監査失敗があれば先へ進まない。
「失敗したからもう一度作る」ことはせず、[本文の扱いと復旧](#本文の扱いと復旧)と
[操作記録](#作成の操作記録sqlite)に従う。read-only検証の失敗を理由に権限を広げない。
通信応答喪失・プロセス停止・監査保存失敗は模擬GitHubと一時DBの回帰テストで確認する。
実GitHubへ意図的なネットワーク障害を起こして、同じ証明を得たことにはしない。
実検証の記録には日時、commit、対象の範囲、tokenの種類と権限（値は不可）、
各操作の期待値・結果・Issue番号・run ID、ローカル証跡の場所、未確認事項を残し、
開発Issue #7へ秘密値や非公開の本文を転載せず検証要約を反映する。
限定検証の成功は本番全体や定期実行の承認ではない。展開範囲・保管・同時実行の条件を別途確認する。

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

## SBOM最低要素の確認について

現行の `sbom-ops upload` と `scripts/upload_bom.sh` は、2026年版の最低要素を
検査するコマンドではない。投入成功やDTでの表示を適合の証明にしない。
`examples/sboms/vulnerable-demo.cdx.json` は脆弱性を表示するための合成教材であり、
作成者・署名・生成コンテキスト・部品ハッシュなどを備えた適合サンプルではない。
Quick Startでは引き続き教材として使用できる。

品質評価の[受入仕様](../SPEC.md#sbom品質評価の受入仕様開発中)は別に定義する。
`sbom-ops sbom-quality`で元BOMを通信なしで評価できる。評価後に直接DTへ投入する方針は変えない。
元BOMと成果物ID・生成器/実行記録・別添証拠を保持し、DT再出力で置き換えない。
不足値を架空の署名・ハッシュや推測した作成者で埋めてはならない。

開発中の品質評価では、不明・非開示を明示する場合に任意の独自propertiesを使う。
例えば、次は部品オブジェクト内の抜粋であり、完全なSBOMや適合済みサンプルではない。

```json
"properties": [
  {"name": "sbom-ops:quality:component_version:state", "value": "unknown"},
  {"name": "sbom-ops:quality:component_version:reason", "value": "提供元が版を公開していない"}
]
```

実際に知っているが公開しない場合はwithheldを指定する。値が既に書かれているのに
不明・非開示とする矛盾はエラーとなる。これは検査免除ではなく、申告内容を区別するための規約。
通常の外部SBOMにこの独自プロパティを要求しない。読み取りモデルは
元BOMの評価処理と品質評価CLIへ接続済みだが、現行uploadはこの申告を評価しない。
元ファイルの読取処理には容量・深さ・部品数などの上限と不正JSONの拒否を実装している。
Quick Start教材も読取テストで確認するが、読めることは最低要素を満たす証明ではない。
結果集計は既定で報告のみとし、CIの失敗条件は選んだ項目と許容状態で明示する。
「不明を許容」しても「記載あり」には変えず、署名検証や適合認定をした扱いにはしない。
CLIの`--require`では指定項目のpresentを必須とする。それ以外の許容状態は`--policy`で明示する。
文書9項目と各部品8項目の抽出・集計を接続済み。Quick Start教材では対象ソフトを含む
5部品、計49件の観測を返すテストがある。部品ハッシュを必須にすると教材の5部品が違反となる。
これは教材の欠落を説明するための確認であり、適合認定ではない。SPDX ID/式の厳密検証、
成果物照合、署名検証は未実施で、識別子も基本構造の観測に限る。

```bash
# 報告のみ。欠落があっても評価できれば終了コード0
sbom-ops sbom-quality examples/sboms/vulnerable-demo.cdx.json

# この教材では5部品のハッシュ欠落により終了コード1（想定どおり）
sbom-ops sbom-quality examples/sboms/vulnerable-demo.cdx.json \
  --require component_hash --policy-version company-ci-v1

# 複数項目を指定。この教材の各部品には名前と版があり、終了コード0
sbom-ops sbom-quality examples/sboms/vulnerable-demo.cdx.json \
  --require component_name --require component_version
```

標準出力はJSON1件。終了コードは0=報告完了/指定条件を充足、1=指定条件違反、
2=不正入力・未対応形式・設定エラー、130=中断。入力エラーには成功件数を出さない。
CLI引数の構文エラーは標準エラーへ使用法を表示して2となる。
JSONの`policy.violations`で違反対象を確認し、`limitations`で未検証事項を確認する。
SPDX ID/式は現在unverifiableなので、`--require component_license`では違反になる。
CIで必須化する項目は、対象とこの検証範囲を確認して選ぶ。既定の報告結果0を適合と解釈しない。

`--require`は[仕様の17項目ID](../SPEC.md#sbom品質評価の受入仕様開発中)から選び、
同じ項目の重複指定はエラー。`--policy-version`は必須項目を指定する場合のみ利用する。
指定しなければ報告のみは`report-only-v1`、必須化は`cli-required-v1`と記録する。
入力上限は`--max-bytes`、`--max-depth`、`--max-nodes`、`--max-components`で正の整数を指定する。
既定は32 MiB・深さ64・250,000ノード・10,000部品。大きくする場合は実行環境の資源を確認する。
結果JSONの構造は[同梱スキーマ](../src/sbom_ops/data/sbom-quality-report.schema.json)で検査できる。

同じ条件をCIで繰り返し使う場合は、[JSON方針の例](../examples/sbom-quality-policy.example.json)を
リポジトリで管理できる。

```bash
sbom-ops sbom-quality examples/sboms/vulnerable-demo.cdx.json \
  --policy examples/sbom-quality-policy.example.json
```

この例は部品名のpresentと、部品版のpresent/unknownだけを許容する最小の教材であり、
2026年最低要素への適合方針ではない。unknownは明示申告と理由がある場合のみで、
版の単なる記載漏れはmissingのまま違反となる。許容しても観測結果は変更しない。
要求配列を空にすると報告のみになるため、CIではレビューしてから採用する。
`--require`との併用や`--policy-version`による上書きは禁止。版はファイル内のversionへ記す。
設定例のschema_versionは1。未知キー、型違い、項目/状態の重複、未対応版を拒否する。
方針ファイルは最大32 KiB・深さ8で、読取失敗時は終了コード2となり、報告のみへ自動変更しない。

CIや他ツールで結果JSONを読む場合は、Draft 2020-12対応の検証器を使う。
このPJの開発用依存には`jsonschema`を含むが、製品CLI自体はこのライブラリを必要としない。
Quick Startの開発用インストール後、例えば次のように検査できる。

```bash
mkdir -p var
sbom-ops sbom-quality examples/sboms/vulnerable-demo.cdx.json > var/sbom-quality-report.json
python - <<'PY'
import json
from importlib.resources import files
from pathlib import Path
from jsonschema import Draft202012Validator

schema = json.loads(files("sbom_ops").joinpath("data/sbom-quality-report.schema.json").read_text())
report = json.loads(Path("var/sbom-quality-report.json").read_text())
Draft202012Validator.check_schema(schema)
Draft202012Validator(schema).validate(report)
print("結果JSONの構造を確認しました")
PY
```

スキーマ検証の成功は「JSONの構造が契約どおり」という意味で、品質条件の充足や適合認定ではない。
CIでは品質評価コマンド自身の終了コードも扱う。エラーJSONも正しいスキーマに適合する。
項目件数の整合、証拠の正しさ、依存関係の網羅はスキーマ検証だけでは確認できない。

### コンテナのSBOMを生成してDTへ送るタイミング

[生成・投入契約](../SPEC.md#sbomの生成対象と投入タイミング)に従い、CI担当が
リリース候補・配布対象イメージの生成ジョブへ次の処理を組み込む。
下記は導入時の手順であり、本番CIの接続やOS別検出の検証が完了済みという意味ではない。

1. 最終イメージをbuildし、registryへpushして配布対象のdigestを確定する。
   複数アーキテクチャではplatformと個々のイメージdigestを記録する。
2. 確定したイメージを対象にTrivy等でCycloneDX SBOMを生成する。
   ツール名・版・設定を固定して記録し、OS名・リリース、OSパッケージ、アプリ依存、
   PURLと`distro`の収録を確認する。ソースディレクトリだけの収集で代用しない。
3. 元SBOMとそのファイルハッシュ、イメージdigest、ソースcommit、CI実行参照を
   CI成果物として保持する。SBOMファイルのハッシュとイメージdigestは別物として扱う。
4. 登録済み配布単位に対応するProject名・不変の成果物版へ、CIからDTに直接送る。
   既存の[投入手順](dependency-track/setup.md#upload-a-cyclonedx-sbom)を使い、
   別の成果物やSource SBOMで同じProjectを上書きしない。
5. アップロードとBOM処理の結果を記録し、Componentの収録とFindingの取得を確認する。
   解析途中・失敗・空の応答を安全判定にしない。導入時は対象OSの代表イメージで
   期待する部品・既知脆弱性と照合し、DT版・解析器・データソース設定を確認する。
6. 同じdigestをデプロイ対象として追跡し、運用担当が既存の資産対応・稼働申告を登録する。
   DTへの投入成功自体は、デプロイ成功や実稼働を意味しない。

push前のローカルイメージから生成する場合も、配布物との同一性を確認する。
マルチステージのビルド用イメージやホストOSは、最終イメージと別の対象として扱う。
導入CIでDT解析をデプロイ判定に使う場合は、待機・timeout・承認条件を別途定義する。
この手順だけで自動的なデプロイ許可・禁止は追加しない。

新しい成果物では再生成・再送する。同じ成果物の再配備では既存のBuild SBOMを参照する。
新しいCVEについてはDTの登録済み構成の定期再解析を使い、再送を日次処理にしない。
収録漏れなどを訂正するときは、成果物IDを維持してSBOM文書の版・ハッシュ・訂正理由を残す。
DTの再解析については[公式CI/CDガイド](https://docs.dependencytrack.org/usage/cicd/)を参照。

### 実際に生成したSBOMで試す

[生成済みサンプル](../examples/sboms/identity-demo.generated.cdx.json)は、既存のGoデモの
イメージアーカイブからTrivyで生成した未加工の出力である。
[生成記録](../examples/sboms/identity-demo.generated.provenance.json)に、元ソースのコミット、
CI実行番号、成果物と生成器のSHA-256、生成オプション、確認の限界を残している。
サンプルの評価だけならDocker・Trivy・DT・APIキーは不要。

```bash
sbom-ops sbom-quality examples/sboms/identity-demo.generated.cdx.json
sbom-ops sbom-quality examples/sboms/identity-demo.generated.cdx.json \
  --policy examples/sbom-quality-policy.example.json
```

1つ目は4部品・41項目（記載あり17、欠落24）で終了コード0。
2つ目は対象イメージ、demo、アプリのモジュールの版が欠けるため、3件の違反で終了コード1。
ツールが生成したSBOMも、選んだ品質条件を自動的に満たすとは限らない。
Trivyの版表記`dev`は記載ありとして観測するが、リリースの特定や真正性を証明しない。
作成者・署名・ハッシュ等を補って成功に見せず、生成元の設定や運用を見直す。
別添のアーカイブハッシュは部品ハッシュへ転記しない。`vulnerabilities: []`も
脆弱性なしの証明ではない（今回はライセンススキャンによるSBOM生成のみ）。

再生成は本ガイドのデモビルドまたはCI成果物取得手順を使い、対象イメージのIDを確認する。
古いCI成果物は保存期限切れの可能性がある。その場合は新しくビルドし、コミット、
イメージID、ファイルハッシュ、生成器の版と実行オプション、日時を新しい記録に残す。
元の記録を流用しない。時刻とUUIDは再生成で変わるため、バイト単位の一致は要求しない。

### 欠落を改善する担当と、訂正・例外の扱い

生成サンプルは、適合に向けて不足を見つけるための出発点であり、完成済みの適合例ではない。
まず自社で作るSBOMを報告のみで評価し、生成器の設定・成果物管理で埋められる項目を改善する。
次に対象のCIと必須項目を限定して方針をレビューし、版を付けて必須化する。
外部SBOMや既存の教材へ、この方針を暗黙に流用しない。

| 担当 | 行うこと | sbom-opsが代行しないこと |
| --- | --- | --- |
| ビルド・サービス担当 | 作成主体、対象成果物、版、生成コンテキスト、依存関係を確認し生成設定を直す | ツール名やファイル名から主体・版を推定すること |
| 成果物・署名の管理担当 | 元成果物と部品の対応を確認し、必要なハッシュ・署名・証明を生成して別途検証する | アーカイブのハッシュを全部品に流用すること、署名の存在だけで真正と認定すること |
| 運用・セキュリティ担当 | 対象別の必須項目、許容状態、保存期間、閲覧権限、更新・再確認の契機を決める | 品質評価結果から自動で例外承認や優先度変更を行うこと |
| sbom-ops | 元BOMを読み、欠落・明示不明・非開示・不正・検証不能を分けて記録する | 実際の依存関係の網羅性や配布運用を認定すること |
| Dependency-Track | 受領したSBOMのインベントリと脆弱性情報を管理する | 元BOMの出所・署名・生成記録を再エクスポートだけで証明すること |

今回の生成サンプルなら、版が欠ける3対象の版管理と、文書の作成主体・生成コンテキストを
担当者が確認する。ハッシュと署名は対象の実物・検証方法を確定してから生成する。
標準ライブラリなど単独の実行成果物との対応が曖昧なものは、推測したハッシュで埋めない。
確認できない情報をunknownと申告する場合も、対象項目と理由を記録し、元BOMとは区別した
訂正版を作る。単なる欠落を評価器がunknownへ変換することはない。

例外が必要なら、人が対象（サービス・成果物・項目）、理由、承認者、期限、再確認条件を
既存の開発Issue等へ残す。本コマンドに期限付き例外管理機能はない。`--policy`で状態を許容する
変更は、その項目の全対象部品に効くため、1部品だけの例外のつもりで全体を緩めない。
報告のみへ戻す場合も対象と理由を明示する。例外やwithheldは品質・安全性の証明ではない。

新しいリリース、依存関係の変更、生成器や方針の変更、誤記の発見時には再生成・再評価する。
訂正前の元BOMと結果を消さず、新旧ファイルのハッシュ、成果物ID、生成器/方針版、訂正理由と
日時を結び付けて保管する。必要な受領者へ訂正版を配布し、旧版との対応を知らせる。
再評価の成功だけで署名検証や依存関係の網羅性まで再確認したとは扱わない。
別添署名・証明の検証結果と配布履歴も、閲覧制限した保存先で管理する。

### CIで結果を保存してから終了コードを返す

CIにsbom-opsをインストールした後、DT送信とは別のステップとして実行する。
以下はBashの例。報告のみなら`--policy`の行を外す。
出力先は実行ごとに新規作成し、既存の結果を上書きしない。

```bash
set -eu
QUALITY_DIR="$(mktemp -d var/quality-ci.XXXXXX)"
quality_exit=0
sbom-ops sbom-quality examples/sboms/identity-demo.generated.cdx.json \
  --policy examples/sbom-quality-policy.example.json \
  > "$QUALITY_DIR/report.json" 2> "$QUALITY_DIR/stderr.txt" || quality_exit=$?
printf '%s\n' "$quality_exit" > "$QUALITY_DIR/exit-code.txt"
printf '品質評価の保存先: %s\n' "$QUALITY_DIR"
exit "$quality_exit"
```

事前に`mkdir -p var`を実行する。CIではこのステップが失敗しても、後続の証拠保存ステップを
実行するよう設定し、上記ディレクトリと元BOM・方針ファイル・生成記録を保管する。
`|| true`や保存処理の成功で品質評価の失敗を隠さない。JSONが空の場合も標準エラーと
終了コードを残す。BOMには内部情報が含まれ得るため、保存先の閲覧権限と保持期限を決める。
必須化するなら終了コード0のときだけ、既存のCI→DT直接送信へ進む。
報告のみでも不正入力の2・中断の130は成功扱いにしない。
この例を追加しただけでは既存CIやuploadの拒否条件は変わらない。

## YAML configuration

設定例は[examples/config.yaml](../examples/config.yaml)、契約は
[SPEC](../SPEC.md#configuration-contract)に集約する。
CLI → 環境変数 → YAML → 既定値の順で、YAMLの秘密情報は `env:変数名` で参照する。
KEVキャッシュは任意。`--refresh-kev` はTTL内でも再検証し、
取得失敗時に古い値を使うには明示設定が必要。結果の `kev_used_stale_cache` を確認する。
