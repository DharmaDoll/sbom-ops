動くMVP」から「壊れにくい脆弱性運用基盤」へ上げるために、仕様上いくつか重要な修正が必要です。

まず、設計思想はかなり良い

現状の責務分離は明快です。

CI/CD
  │
  │ SBOM
  ▼
Dependency-Track
  │
  │ Finding / EPSS / Analysis / VEX state
  ▼
sbom-ops
  │
  ├─ KEV enrichment
  ├─ Priority calculation
  └─ Workflow synchronization
  │
  ▼
GitHub Issues
  │
  ▼
Developer remediation

Dependency-Trackを「在庫＋技術的FindingのSoT」、GitHub Issuesを「修正作業のSoT」とし、sbom-ops自身は両者をつなぐOrchestratorに限定しています。

この判断は非常に重要です。

sbom-ops自身に、

* SBOM DB
* 脆弱性DB
* VEX判断エンジン
* EPSS DB
* チケット管理

まで持たせ始めると、Dependency-Trackの劣化コピーになってしまいます。

今の境界は維持した方がいいです。

⸻

P0：Findingが消えたらIssueをClose、は危険

現在の仕様では、

Dependency-TrackからFindingが返らなくなったらIssueをclose

となっています。

業務フローにも同様に、

修正版SBOM → Finding消滅 → 次回sync → GitHub Issue close

とあります。

これは理想フローとしては正しいのですが、運用システムとしては危険です。

例えば、

Dependency-Track API timeout
Finding pagination failure
project取得失敗
SBOM analysis未完了
project filter変更
一時的なDT不整合

でも、

Finding not found

になり得ます。

この状態でIssueを自動closeすると、

脆弱性が治っていないのにチケットだけ閉じる

可能性があります。

改善案

absence != resolved にします。

状態を例えば、

ACTIVE
MISSING
RESOLVED
SUPPRESSED
NOT_AFFECTED
UNKNOWN

に分ける。

そして、

ACTIVE
  ↓
MISSING
  ↓
MISSING
  ↓
RESOLVED

のように N回連続で消失を確認する。

さらに、

sync completed successfully
AND
target project analysis completed
AND
finding absent

をclose条件にします。

つまり、

Issue closureは「Findingが無い」ではなく、「Findingが安全に消滅したことを証明できた」場合だけ

にしたいです。

これはP0です。

⸻

P0：Finding keyが弱い

現在のFinding keyは、

{project_uuid}:{component_name}:{component_version}:{vulnerability_id}

です。

これは人間には分かりやすいのですが、machine identityとしては弱いです。

理由は、

component_name
component_version

が必ずしも一意ではないからです。

例えば、

lodash:4.17.20

が同じプロジェクト内に複数経路で存在する場合。

あるいは、

github.com/foo/bar
foo/bar
pkg:golang/github.com/foo/bar

のような正規化問題もあります。

さらに vulnerability_id も、

CVE-...
GHSA-...
OSV-...

などsource差があります。

推奨

可能なら、

project_uuid
+
component_uuid
+
vulnerability_uuid

を内部primary keyにする。

Dependency-Track UUIDに強く依存したくなければ、

project_uuid
+
purl
+
vulnerability_source
+
vulnerability_id

です。

例えば、

sha256(
  project_uuid
  + purl
  + vuln_source
  + vuln_id
)

を、

finding_key

とする。

人間向け表示は別に、

log4j-core 2.14.1 / CVE-2021-44228

とすればよいです。

⸻

P0：Priority Engineが少し単純すぎる

現在は、

KEV → P0
active exploitation → P0
Critical → P1
EPSS >= 0.7 → P1
CVSS >= 7 → P2
otherwise → P3

です。

MVPとしては十分ですが、実運用ではすぐ限界が来ます。

例えば、

CVSS 9.8
EPSS 0.01
Internet exposed
Production
Critical payment API

と、

CVSS 9.8
EPSS 0.01
Internal test tool
No network exposure

が同じP1になります。

逆に、

CVSS 6.5
EPSS 0.65
Internet facing
Auth bypass

などがP3/P2になる可能性があります。

つまり現在は、

Vulnerability Risk

だけで、

Organizational Risk

が入っていません。

⸻

Priority Engineはこう進化させたい

最終的には、

Technical Risk
    +
Exploit Intelligence
    +
Exposure
    +
Asset Criticality
    +
Exploitability / Reachability
    +
Compensating Controls

です。

例えば、

priority_context:
  vulnerability:
    cvss: 8.8
    epss: 0.72
    kev: false
  exposure:
    internet_facing: true
  asset:
    criticality: high
  runtime:
    reachable: unknown
  analysis:
    affected: true

から、

P1

を導出する。

ただし、これはMVPに全部入れなくていいです。

今の設計に、

PriorityContext

という抽象だけ追加しておけばいい。

⸻

P1：PriorityとSLAを分離した方がいい

今は、

P0
P1
P2
P3

だけです。

でも実際の業務では、

Priority

と

Remediation SLA

は似ていますが別物です。

例えば、

P0 = immediate
P1 = urgent

は業務優先度。

一方、

fix_due_at = 2026-08-17

はSLA。

仕様にはSecurity teamがSLAを管理するとありますが、domain modelにはまだありません。

将来、

class RemediationPolicy:
    priority: Priority
    due_days: int
    escalation_days: int

のように分けた方がいいです。

⸻

P1：一番重要なのにまだ薄いのが「State Machine」

このシステムの本質は、実はPriority Engineより、

Vulnerability lifecycle synchronization

です。

現在は、

Finding
→ Issue create
→ update
→ close

程度です。

でも実際には、

Detected
   ↓
Triaged
   ↓
Action Required
   ↓
Assigned
   ↓
Fixing
   ↓
Verification
   ↓
Resolved

があります。

さらに、

Not Affected
False Positive
Suppressed
Accepted Risk
Exception

への枝分かれがあります。

したがって、domain側に明示的な、

RemediationState

を入れた方がいいです。

例えば、

NEW
TRIAGE
OPEN
IN_PROGRESS
WAITING_VERIFICATION
RESOLVED
ACCEPTED_RISK
NOT_AFFECTED
SUPPRESSED

です。

Dependency-Track Analysis StateとGitHub Issue stateをそのまま同一視しないのが重要です。

⸻

P1：3つのStateを分離する

ここはかなり重要です。

このシステムには実は、

1. Vulnerability State
2. Analysis State
3. Workflow State

があります。

例えば、

Vulnerability State
    affected / resolved
Dependency-Track Analysis
    exploitable
    in_triage
    not_affected
    false_positive
GitHub Workflow
    open
    assigned
    fixing
    closed

です。

これを1つにまとめると、後で破綻します。

なので、

FindingState
AnalysisState
RemediationState

を別々に持つことを勧めます。

⸻

P1：SBOM upload責務がSPEC内で揺れている

Execution Modelでは、

If a new SBOM is supplied, upload it

となっています。

一方、Client Contractでは、

upload_bom(...)

はDeferredです。

さらにuse-caseでは、

CI/CDがSBOMをDependency-Trackへアップロード

と明確に分離されています。

私は後者を支持します。

つまりMVPでは、

sbom-ops should NOT upload SBOM

で良いです。

責務は、

CI
 └─ SBOM generation/upload
sbom-ops
 └─ post-analysis orchestration

です。

この境界をSPECでも統一した方がいいです。

⸻

P1：GitHub repository routing

現在、

SBOM_OPS_GITHUB_OWNER
SBOM_OPS_GITHUB_REPO

なので、

全部のFindingが1つのGitHub Repositoryへ行くモデル

です。

しかし、Security teamによる「全プロジェクト横断管理」という思想とは少し衝突します。

実際には、

Dependency-Track Project A
 → GitHub repo A
Dependency-Track Project B
 → GitHub repo B

となるはずです。

したがって、

routing:
  projects:
    dt-project-a:
      github: org/service-a
    dt-project-b:
      github: org/service-b

というMapping Layerはかなり早い段階で必要です。

ROADMAPではmulti-repo routingがOpen Item扱いなので、これはv0.2くらいへ繰り上げてもいいでしょう。

⸻

P2：LLMの位置付けは今の方針で正しい

ROADMAPではv0.3に、

LLM Triage
OpenAI
Claude

があります。

ただし、

LLMは説明・修正案・不足情報の提示まで。Priority、VEX、Suppression、Issue Closeなどは変更不可

と明記されています。

これはそのまま維持した方がいいです。

このシステムにおけるAIは、

Decision Maker

ではなく、

Decision Support

です。

例えば、

CVE summary
impact explanation
upgrade recommendation
likely affected code
missing context
developer-facing remediation draft

はAIに向いています。

一方、

NOT_AFFECTED
ACCEPT_RISK
P0 → P3
CLOSE

は決定論またはHuman-in-the-loop。

この境界は非常に良いです。

⸻

v0.3.xのOperations Foundationはむしろ早めたい

ROADMAPでは、

* structured sync history
* audit history
* KEV cache
* ETag
* stale cache fallback
* failure alert

がv0.3.xです。

私は一部を v0.2以前 に持ってきます。

特に、

sync run id
sync result
finding previous state
finding current state
action taken
action reason

は最初から必要です。

例えば、

{
  "finding_key": "...",
  "previous_state": "ACTIVE",
  "current_state": "MISSING",
  "action": "NOOP",
  "reason": "first_missing_observation"
}

を残す。

これがあるだけで、運用事故の調査能力が大幅に上がります。

⸻

私なら仕様をこの構造に整理します

                    ┌──────────────┐
                    │    CI/CD     │
                    │ SBOM generate│
                    └──────┬───────┘
                           │
                           ▼
                 ┌──────────────────┐
                 │ Dependency-Track │
                 │ Inventory / VEX  │
                 │ Analysis / EPSS  │
                 └────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │     sbom-ops      │
                │                   │
                │ Finding Snapshot  │
                │        ↓          │
                │ KEV Enrichment    │
                │        ↓          │
                │ Priority Policy   │
                │        ↓          │
                │ State Machine     │
                │        ↓          │
                │ Routing           │
                │        ↓          │
                │ Action Planner    │
                └─────────┬─────────┘
                          │
                          ▼
                   GitHub Issues
                          │
                          ▼
                      Developer
                          │
                          ▼
                         CI

そして内部的には、

Observe
  ↓
Normalize
  ↓
Enrich
  ↓
Evaluate
  ↓
Compare Previous State
  ↓
Plan
  ↓
Apply
  ↓
Audit Log

という reconciliation loop にしたいです。

実は、この考え方にすると sbom-ops は単なるスクリプトではなく、

SBOM Vulnerability Reconciliation Controller

になります。

Kubernetes Controllerとかなり似た思想です。

⸻

優先順位を付けるなら

Priority	修正
P0	finding missing = close を廃止し、安全なResolution判定を導入
P0	Finding keyをUUID/PURLベースへ変更
P1	Finding / Analysis / Remediation stateを分離
P1	SBOM uploadをCI責務としてSPEC統一
P1	Multi-repository routingを前倒し
P1	Sync audit historyを早期実装
P2	Asset criticality / exposureをPriorityContextとして拡張可能に
P2	PriorityとSLAを分離
P2	LLMは現状どおりadvisory限定

一番大事なのは、このPJを「脆弱性情報をIssueに投げるbot」にしないことです。

目指すべきは、

Dependency-Trackに集約されたSoftware Supply Chain Riskを、組織の優先度ポリシーに基づいて継続的にreconcileし、開発チームのRemediation Workflowへ安全に変換するControl Plane

だと思います。

この定義にすると、今あるDependency-Track、KEV、EPSS、VEX、GitHub Issues、将来のReachability、LLM、Jiraが全部きれいに一つの設計に収まります。
