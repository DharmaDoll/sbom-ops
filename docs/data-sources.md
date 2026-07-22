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
- Dependency-TrackからFindingが消えた場合、対応Issueをクローズ

Finding keyは次の形式でIssue本文に保存する。

```text
{project_uuid}:{component_name}:{component_version}:{vulnerability_id}
```

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

## 将来の永続化とLLM利用

KEVは将来的に5時間を初期値とする設定可能なTTLキャッシュへ保存する。
キャッシュはCISA feedの代替の正本ではなく、ETag／Last-Modified、取得時刻、
ハッシュ、stale状態を持つ運用補助データとする。

同期結果とFinding／Analysis state／Priority／Issueの変化は、将来的に監査用
ストアへ保存する。Dependency-Trackのトリアージ判断とGitHubの対応状態は、
それぞれのシステムを一次情報源として維持する。

LLMは将来的にFindingの要約、影響説明、修正案、追加調査事項の提案へ利用する。
LLMの出力は提案として保存し、Security担当の確認なしにPriority、VEX／Analysis
state、抑制、例外承認、Issueクローズを変更しない。
