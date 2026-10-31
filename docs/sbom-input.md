# SBOMの生成・投入・記載品質の確認

[作業別の入口へ戻る](operations.md)。コマンドはリポジトリのルートで実行する。

**担当:** 開発担当が依存関係を更新し、CI担当が最終成果物からSBOMを生成・保存・投入する。
運用担当が引渡された成果物とDT Projectを照合する。
**前提・入力:** 登録済みサービス・配布単位、対象成果物の不変ID、生成器・版・設定、
元CycloneDX SBOM。投入にはDT接続先と用途を限定したアップロードキーが必要。
**期待結果:** 元SBOM・ハッシュ・成果物ID・CI参照・DT Project・各処理結果を結び付けて残す。
**失敗時:** [投入後の確認と失敗時対応](#投入後の確認と失敗時対応)へ進む。
品質評価の違反は`policy.violations`、不正入力は標準エラーと終了コードで確認する。

最初は[生成・投入の順序](#コンテナのsbomを生成してdtへ送るタイミング)を読む。
以下の品質評価はローカルで実行でき、DT投入とは別の操作である。
npm・uv・Trivyの生成例と担当間の引渡しは[SBOM供給の導入手順](sbom-producers.md)を使う。
導入先の通信・権限・保持期間は担当者が設定・検証する。

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

品質評価では、不明・非開示を明示する場合に任意の独自propertiesを使う。
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

### 投入後の確認と失敗時対応

アップロードの実行例は[DT投入手順](dependency-track/setup.md#upload-a-cyclonedx-sbom)、
一件を追う演習は[初回演習](getting-started.md#2-人が資産を登録しdtへ直接sbomを送る約20分)を使う。
このページは生成・投入の運用契約であり、生成ツールやCI接続を自動設定しない。

| 確認段階 | 期待結果・失敗時に確認すること |
| --- | --- |
| 生成・品質評価 | 対象digestと生成設定を保存し、期待するOS・アプリ依存を元SBOMと照合。記載欠落は生成器／サービス担当へ確認し、架空値を補わない |
| DT受付 | 受付応答・処理tokenを記録。401/403はキーの用途・権限を確認。通信断では受付済みの可能性を調べてから再投入を判断 |
| BOM処理 | 対象Project名・版・UUIDと処理状況を確認。timeoutを完了に読み替えず、対象・処理token・DTログを保存して調査 |
| Component・Finding | 収録とデータソース・解析状況を確認。0件や応答安定は安全・修正済みの証明にしない |
| 運用担当への引渡し | 元SBOM参照・ハッシュ・イメージdigest・CI参照・DT Project・各段階の結果を渡し、[対応承認](assets.md#dtから読み戻して紐づける方法)と[根拠登録](assets.md#sourcebuild根拠の登録と訂正)へ進む |

SBOM訂正なら成果物IDを維持し、旧文書・新文書・訂正理由を残す。
再ビルドで成果物が変わったら別のProject版として扱う。成功と失敗の引渡しを分け、
未確認の解析結果や配備状況を成功欄へ補わない。

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

再生成は[デモビルド](assets.md#固定成果物を使ったローカル通し検証)または
[CI成果物取得](assets.md#ciが作った成果物での確認)の手順を使い、対象イメージのIDを確認する。
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
