# Finding情報源と取得方法

このプロジェクトでは、Findingに関する情報を一つの外部ソースだけで
完結させない。Dependency-Trackをインベントリ・脆弱性分析・VEX判断の
中心に置き、KEVだけを外部情報源から補完する。

## 「取得方法」の読み方

この文書に出てくるAPIは、呼び出し先ごとに次の3種類に分かれる。

- `Dependency-Track API`: Dependency-Trackが提供するAPI。URLは設定した
  `SBOM_OPS_DT_BASE_URL`を起点にする。
- `CISA API/feed`: CISAが公開するKEV JSON feed。sbom-opsが直接取得する。
- `GitHub API`: GitHubが提供するREST API。sbom-opsがIssue同期のために直接取得・更新する。

このPJ（sbom-ops）は、現時点では外部から呼び出す独自のWeb APIを提供して
いない。`sbom-ops sync`というCLIが、外部APIを呼び出す側である。

## 外部システムとの接続関係

```text
sbom-ops CLI
     │
     ├─ Dependency-Track API
     │    ├─ Project
     │    ├─ Finding
     │    ├─ EPSS
     │    └─ VEX / Analysis state
     │
     ├─ CISA KEV feed
     │
     └─ GitHub REST API
          └─ Issue作成・更新・クローズ
```

例えば、次のURLはDependency-TrackのAPIである。

```text
https://dtrack.example.com/api/v1/finding/project/{uuid}
```

`dtrack.example.com`の部分は`SBOM_OPS_DT_BASE_URL`で決まり、認証には
`SBOM_OPS_DT_API_KEY`を使う。

## 情報源の全体像

| 分類 | 情報 | 一次情報源 | 呼び出し先 | 呼び出す主体 | 主な用途 |
| --- | --- | --- | --- | --- | --- |
| インベントリ | Project、Component、Version | Dependency-Track | Dependency-Track API | sbom-ops | 対象範囲とFinding key |
| 脆弱性 | Finding、CVE/Advisory、Severity、CVSS、CWE、Description | Dependency-Track | Dependency-Track API | sbom-ops | ドメインFindingへの正規化 |
| 脆弱性情報源 | NVD、GitHub Advisories、OSV、OSS Index、Snyk、Trivy等 | Dependency-Track Analyzer | Finding内の`vulnerability.source` | Dependency-Track | 脆弱性検出と識別 |
| 脅威情報 | EPSS | Dependency-Track | Findingレスポンスの`vulnerability.epssScore`（またはトップレベルの`epssScore`）、不足時は脆弱性API | sbom-ops | P1判定 |
| 脅威情報 | KEV | CISA KEV catalog | CISA JSON feed | sbom-ops | P0判定 |
| トリアージ | Analysis state、Suppression、分析メモ | Dependency-Track | Finding内の`analysis` | sbom-opsが読み取り | Issue作成除外・Security判断の反映 |
| VEX | CycloneDX VEX | サプライヤー／製品チーム → Dependency-Track | Dependency-TrackへのVEX投入後、Findingの`analysis`を読み取り | DT／Security team | `NOT_AFFECTED`等の判断反映 |
| 対応管理 | Issue、担当、対応状況 | GitHub Issues | GitHub REST API | sbom-ops | Issue作成・更新・クローズ |

## 1. Dependency-TrackのFinding

### 取得

プロジェクト一覧から対象プロジェクトを確定し、プロジェクトごとにFindingを
取得する。

```text
GET /api/v1/project
GET /api/v1/project/{uuid}
GET /api/v1/finding/project/{uuid}
```

Findingから次の情報を取得する。

- Component名・バージョン
- Vulnerability ID
- Vulnerability UUID
- Finding UUID
- Severity
- CVSS
- CWE
- Description
- EPSS
- Analysis state
- Suppression state
- Analysis detail

Dependency-TrackのFinding APIには`VIEW_VULNERABILITY`権限が必要である。
APIの実際のレスポンスは、対象Dependency-TrackのOpenAPI仕様を基準に
確認する。

### Vulnerability source

Dependency-Trackは複数のAnalyzer／データソースを統合して脆弱性を分析する。
したがって、NVDやGitHub Advisoryなどをsbom-opsが個別に取得してFindingを
再構成することはしない。Dependency-Trackに格納されたVulnerabilityと
Findingを利用する。

Vulnerabilityの`source`は、Findingがどの情報源に由来するかをSecurity担当が
追跡するための情報として、`vulnerability_source`に保持する。

## 2. EPSS

### 一次取得

EPSSはDependency-Trackが保持する値を優先する。

```text
GET /api/v1/finding/project/{uuid}
```

このAPIのレスポンスは、FindingごとのJSONオブジェクトの配列である。
「Finding内」とは、この配列要素の中を指す。概念的には次の構造になる。

```json
[
  {
    "component": {"name": "openssl", "version": "3.0.0"},
    "vulnerability": {
      "vulnId": "CVE-2026-0001",
      "source": "NVD",
      "epssScore": 0.91
    },
    "analysis": {"state": "NOT_SET", "isSuppressed": false}
  }
]
```

現在の実装では、次の順序でEPSSを探す。

1. `finding["vulnerability"]["epssScore"]`
2. `finding["epssScore"]`
3. 値がなければ、次のプロジェクト脆弱性APIを補完取得する。

```text
GET /api/v1/vulnerability/project/{uuid}
```

### 扱い

- EPSSの値はP1判定に利用する。
- 外部FIRST EPSS APIの値でDependency-Trackの値を上書きしない。
- 外部EPSSクライアントは、将来の明示的なfallback／検証用途に限定する。
- EPSSが取得できない場合もFinding処理は失敗させず、`P1`判定を行わない。

## 3. CISA KEV

### 取得

KEVはDependency-Trackの標準Finding情報だけに依存せず、CISAのJSON feedを
sbom-opsが取得する。

```text
GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

URLは`SBOM_OPS_KEV_FEED_URL`で変更できる。

`cveID`を集合として読み込み、Findingの`vulnerability_id`と照合する。
一致したFindingはP0とする。

KEV該当は業務上の緊急度を示すものであり、Dependency-TrackのAnalysis stateを
自動変更する根拠にはしない。

## 3.1 将来の脆弱性Enrichment: Vulnerability-LookupとVuls vuls.db

PoC、公開Exploit、実悪用観測、KEV、EPSS、vendor VEX等を補助情報として扱う
ため、[`Vulnerability-Lookup`](https://github.com/vulnerability-lookup/vulnerability-lookup)
をオンライン取得の第一候補として`lab/exploit_intelligence`で評価する。
Vulnerability-LookupはCVE単位のHTTP APIを提供し、Sighting、複数KEV catalog、
EPSS、VEXを個別に取得できる。保守中のVuls `vuls.db`は比較・オフライン候補、
旧[`vulsio/go-exploitdb`](https://github.com/vulsio/go-exploitdb)はアーカイブ済み
比較基準に限定し、いずれも現時点では本番依存にしない。

Vulnerability-LookupのSightingは`published-proof-of-concept`、`exploited`、
`confirmed`等を区別するが、種別名だけを事実認定に使わない。公式コレクタでは
Exploit-DBレコードが`exploited`、Nuclei templateが`confirmed`として登録される
ため、`type`、source URL、author、origin、観測日時を別々に保持する。
`exploited`を無条件に実悪用確認済みへ変換せず、CISA KEV等の由来が明確な強い
証拠と、公開ツール・記事・scanner templateを分けて人へ提示する。

オンラインラボはendpointごとに独立した`available` / `not_observed` / `unknown`
を記録する。APIの`404`だけを`not_observed`とし、timeout、HTTP障害、Schema不一致
は`unknown`とする。Sightingの`content`とVEXの大きな`details`は保存せず、件数、
source、種別、識別子、時刻等のbounded metadataだけを残す。公開APIへの大規模
実行はcorpus round-robinとCVE IDで決定論的に25 CVEへ絞り、別の25 CVE guardも
適用する。両方を明示的に引き上げた場合だけ取得件数を増やせる。

2026-09-05の小規模API probeでは、Log4Shellに対してEPSS、4件のKEV assertion、
1,963件のSighting、Red HatとSUSEの2件のVEX summaryが返った。Sightingは
`per_page=2`でも大きなfree-form `content`を含み、`X-Fields`による除外要求も当該
公開instanceでは反映されなかった。このため一括`with_*`取得や大量record保持は
避け、signalごとの小さなページとmetadata countを使う。架空CVEの基本検索が
HTTP 200で別identifierを返す事例も観測したため、全endpointで要求CVEとresponse
内identifierの一致を検証し、不一致は`unknown`として隔離する。

`vuls.db`側では2026-09-04にExploitDB、GitHub PoC、inTheWild、Trickest、Nuclei、
Metasploitのsourceとraw／extracted commitを取得できた。2026-09-05の実SBOM
Findingサンプルでは151 CVE中55件に計231件の参照が紐づいたが、206件はTrickest
由来で一般的なCVE一覧リポジトリも含まれた。そのため、両候補を同一CVE集合で
比較し、coverage、鮮度、重複、誤関連、response size、latencyを測定するまで
`vuls.db`を廃止しない。

2026-09-06には同じDT captureから決定論的に選んだ25 CVEを比較した。
Vulnerability-Lookupの125 signal requestはunknownなしで232秒、EPSSは25件、
PoC型Sightingは2件、confirmed型は2件、exploited型は1件、KEVは1件で取得できた。
Sighting系と`vuls.db` public-referenceのcoverageは、両方5件、`vuls.db`のみ13件、
Vulnerability-Lookupのみ0件、両方なし7件だった。したがってPoC coverageの代替
とはせず、Vulnerability-LookupはEPSS、KEV、実悪用観測等のオンライン補完、
`vuls.db`は広いpublic-reference比較・offline候補として併用評価する。全151 CVE
への拡大前にcheckpoint/resumeとpacingを用意し、件数よりsource URLの精度確認を
優先する。`vuls.db`のみの13件は全件にTrickestが含まれ、9件はTrickest単独で、
一般的なCVE monitorやcatalogもあった。この差を「13件のPoC欠落」とは解釈しない。

同13件の保持済みrecordから人手review queueを作ると、37 recordは27 URLに集約
され、32 recordがTrickest由来だった。3 URLが複数CVEで再利用され11 recordへ
影響し、2組の同一CVE／URLは複数datasourceに重複していた。URL再利用、CVE IDの
URL内存在、datasource重複等は機械的hintとしてのみ扱い、全項目を`unreviewed`で
開始する。URL patternや件数でPoC品質を自動判定しない。

人手reviewはvuls.db snapshot digest、CVE、datasource、source ID、URL等から作る
不変record identityへ結び付ける。queue run IDとsnapshot digestが一致し、reviewer、
timezone付き日時、明示label、rationaleが揃った項目だけを部分適用できる。別snapshot
のlabelは自動継承せず、再確認なしに本番のpriorityやworkflowへ昇格させない。
同一queue／snapshotを独立した2名がreviewした結果は、両者が完了した項目だけを母数
として完全一致率、偶然一致率、Cohen's kappa、confusion matrix、不一致項目を比較
できる。ただし一致度は判断の一貫性であって正しさではないため、自動合格閾値は
設けず、本番状態を変更する根拠にもしない。実際の37 recordに対する人手reviewと
adjudication方針は未検証である。

どちらの候補もCVE単位の情報であり、SBOM Componentのpurl／versionへの適用性は
Dependency-Trackと人によるreviewに残す。公開レコード、Sighting、KEV assertion、
外部VEXの存在だけで`EXPLOITABLE`、優先度、抑制状態、Issueクローズを自動変更
しない。EPSSはDependency-Trackの値を優先し、CISA direct feedをP0のauthorityと
する現在のpolicyも維持する。

## 4. VEXとAnalysis state

### 初期値と後続入力

SBOMを取り込んでFindingが生成された直後は、通常、Analysis関連の値は
次の初期状態になる。

| フィールド | 初期状態 | 意味 |
| --- | --- | --- |
| `analysis.state` | `NOT_SET` | Security担当による分析がまだ開始されていない |
| `analysis.isSuppressed` | `false` | Findingは抑制されていない |
| `analysis.detail` | 未設定または空 | 分析メモがまだない |

つまり、`analysis`はFinding検出時に確定する脆弱性情報ではなく、Findingに
対して後から加えられるトリアージ結果・運用判断を表す。

一方、EPSSはDependency-Trackの脆弱性情報更新や分析処理によって自動的に
付与・更新される値であり、Security担当が手入力するAnalysis情報とは性質が
異なる。EPSSが存在しない場合もあり得る。

後から値が入る代表的な経路は次の通り。

```text
SBOM登録
  ↓
Finding生成（analysis.state = NOT_SET）
  ├─ Dependency-Trackの脆弱性情報更新 → EPSS等が更新される場合がある
  ├─ Security担当の監査 → analysis.state / detail / suppressionが更新される
  └─ CycloneDX VEX投入 → Dependency-Trackがanalysisへ反映する
```

Dependency-Trackでは`NOT_AFFECTED`や`FALSE_POSITIVE`等の分析状態が監査履歴
付きで管理される。sbom-opsはこれらを読み取るが、MVPでは自動的に書き換えない。

### Findingのライフサイクル

```text
SBOM登録
    ↓
  Finding生成
    ├─ analysis.state = NOT_SET
    ├─ isSuppressed = false
    └─ detail = 未設定
         ↓
         ├─ Security担当が手動トリアージ
         │    ├─ EXPLOITABLE
         │    ├─ IN_TRIAGE
         │    ├─ NOT_AFFECTED
         │    └─ FALSE_POSITIVE
         │
         └─ CycloneDX VEXをDependency-Trackへ投入
              ↓
            analysisへ反映
```

### 情報の流れ

```text
Supplier / Product Team
        ↓ CycloneDX VEX
Dependency-Track
        ↓ analysis state / suppression
sbom-ops
        ↓ Issue作成判断
GitHub Issues
```

sbom-opsがVEX文書を独自に解析して安全性を決定することはしない。
Dependency-Trackで反映された次の状態を読み取る。

- `EXPLOITABLE`
- `IN_TRIAGE`
- `NOT_AFFECTED`
- `FALSE_POSITIVE`
- `NOT_SET`
- `isSuppressed`
- `detail`

MVPでは`NOT_AFFECTED`、`FALSE_POSITIVE`、抑制済みFindingを新規Issue作成から
除外する。ただし、既存Issueを自動的にクローズするかどうかは、Finding消滅と
Analysis state変更を区別した明示的な運用ルールで決める。

## 5. GitHub Issues

GitHubはFindingの検出元ではない。Remediation workflowの一次情報源である。

### 取得・更新

- Finding keyを含むOpen Issueを検索
- 既存Issueがあればタイトル・本文を更新
- なければP0/P1等の設定対象だけ作成
- Dependency-TrackからFindingが消えた場合、連続した検証済み不在を記録し、
  明示的に有効化された安全なクローズ条件を満たしたときだけ対応Issueをクローズ

Finding keyは次の形式でIssue本文に保存する。

```text
v2:{project_uuid}:sha256(machine_identity)
```

`machine_identity`はcomponent UUIDとvulnerability UUIDを優先する。これらが
取得できない場合はPURL、vulnerability source、vulnerability IDを使い、最後に
表示用のcomponent name/versionへfallbackする。旧形式の表示由来keyは移行期間中
の重複検索に使うが、新規Issue本文に保存する正本はv2 keyである。

## 優先度計算への入力関係

```text
Dependency-Track Finding
 ├─ CVSS / Severity ─────────┐
 ├─ EPSS ────────────────────┼─→ Priority Engine ─→ P0/P1/P2/P3
 ├─ Analysis / VEX state ────┘
 └─ Component / Project

CISA KEV ────────────────────────────────┘
```

Analysis stateによる除外は、優先度計算後かつIssue作成前に行う。
つまり、VEXで除外されたFindingがP0相当の属性を持っていても、新規Issueは
作成しない。

## 管理上の原則

- Inventory、Finding、EPSS、VEX判断の一次情報源はDependency-Track。
- KEVはCISA feedを補完情報源とする。
- NVD等のAnalyzerデータをsbom-opsで二重取得しない。
- GitHub Issuesは対応状況の管理元であり、脆弱性分析の管理元ではない。
- 情報源・取得失敗・欠損値はログとIssue本文で追跡可能にする。
- 情報源の値を根拠なく上書きしない。

ラボの`triage-delegation-boundary`とVEXシナリオにより、Analysis判断、詳細、
Suppression、コメントと監査履歴はDTを正本にできる。GitHub／Jiraは対応タスク
状態の正本とする。sbom-opsが保持するのはstable Finding key、最後に観測した
semantic digest、観測結果／時刻、work-item相関であり、監査コメント本文を複製
しない。DT 4.14.3にはAnalysis変更cursorやETagがないため、再同期は必ず
`suppressed=true`を指定した完全Finding snapshotで行う。MVPのAnalysis／VEX
書き込み経路は引き続き読み取り専用とし、独自のトリアージ正本を追加しない。

## キャッシュ、永続化、LLM利用

KEVは任意で5時間を初期値とする設定可能なTTLキャッシュへ保存できる。
キャッシュはCISA feedの代替の正本ではなく、ETag／Last-Modified、取得時刻、
stale状態を持つ運用補助データとする。stale cacheの利用は明示設定が必要で、
JSON/JSONL結果には`kev_used_stale_cache`として記録する。

同期結果とFinding／Analysis state／Priority／Issueの変化は、将来的に監査用
ストアへ保存する。Dependency-Trackのトリアージ判断とGitHubの対応状態は、
それぞれのシステムを一次情報源として維持する。

LLMは将来的にFindingの要約、影響説明、修正案、追加調査事項の提案へ利用する。
LLMの出力は提案として保存し、Security担当の確認なしにPriority、VEX／Analysis
state、抑制、例外承認、Issueクローズを変更しない。
