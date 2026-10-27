# Dependency-Track API Usage

Official API documentation is the source of truth.

Before changing API code, check:

- endpoint path
- HTTP method
- required permission
- request format
- response format
- pagination behavior
- async processing behavior
- error response behavior

## Used API Areas

The orchestrator is expected to use API areas related to:

- Projects
- BOM upload
- Findings
- Vulnerabilities
- Analysis
- VEX
- EPSS and finding risk metadata
- Teams/API keys

## 操作ごとの権限（DT 4.14.3）

以下は保存済みのDT 4.14.3 OpenAPIと現在のクライアントを2026-10-27に照合した表。
現在の接続先で各キーを試した結果ではなく、最小権限の実証済み一覧でもない。
版更新時は[公式REST API案内](https://docs.dependencytrack.org/integrations/rest-api/)に従い、
対象サーバーのOpenAPIで再確認する。パスは`/api`から記載する。

| 用途 | メソッド・パス | 契約上の権限 | 本PJでの利用 |
| --- | --- | --- | --- |
| Project一覧・個別読取 | `GET /api/v1/project`、`GET /api/v1/project/{uuid}` | `VIEW_PORTFOLIO` | 製品sync・資産照合 |
| Finding・分析状態読取 | `GET /api/v1/finding/project/{uuid}` | `VIEW_VULNERABILITY` | 製品sync。抑制済みも取得 |
| 脆弱性・EPSS補完 | `GET /api/v1/vulnerability/project/{uuid}` | `VIEW_PORTFOLIO` | 製品sync |
| Component一覧 | `GET /api/v1/component/project/{uuid}` | `VIEW_PORTFOLIO` | lab。製品syncはFinding内の部品情報を利用 |
| 既存ProjectへのSBOM投入 | `POST /api/v1/bom` | `BOM_UPLOAD` | CIスクリプト・明示した製品upload-and-wait・lab |
| SBOM投入時のProject自動作成 | 同上、`autoCreate=true` | 上記に加え`PROJECT_CREATION_UPLOAD`または`PORTFOLIO_MANAGEMENT` | CI演習・lab。通常は前者を選び、管理権限を付けない |
| 非同期処理の確認 | `GET /api/v1/event/token/{uuid}` | OpenAPIの個別権限記載なし | アップロード後の待機。認証不要という意味ではない |
| 自分のチームの確認 | `GET /api/v1/team/self` | OpenAPIの個別権限記載なし | labの事前確認。キー値を記録しない |
| 設定の読取 | `GET /api/v1/configProperty` | `SYSTEM_CONFIGURATION` | labの明示調査のみ |
| 設定の変更 | `POST /api/v1/configProperty` | `SYSTEM_CONFIGURATION` | labの明示した管理操作のみ |
| Analysis履歴読取 | `GET /api/v1/analysis` | `VIEW_VULNERABILITY` | lab。通常syncではFindingに含まれる状態を利用 |
| Analysisの変更 | `PUT /api/v1/analysis` | `VULNERABILITY_ANALYSIS` | labの明示opt-inのみ。製品では変更しない |
| Project削除 | `DELETE /api/v1/project/{uuid}` | `PORTFOLIO_MANAGEMENT` | 専用cleanupキーによる実行単位のlab削除のみ |

通常の製品読取には`VIEW_PORTFOLIO`と`VIEW_VULNERABILITY`を使用する。
Analysis履歴を読むだけなら変更権限は不要。
一方、`SYSTEM_CONFIGURATION`は設定のGETとPOSTで共通なので、
「設定を読むためのキー」を読取専用キーと呼ばない。通常syncやPoC取得のために追加しない。
権限名だけでアクセス範囲が決まるわけではなく、Projectのアクセス制御も別に確認する。

### 最小権限の検証と未確認事項

- 保存済みOpenAPIは`var/dt-lab/openapi.json`（Git管理外）。過去の実測は
  [実験記録](../../lab/dependency_track/EXPERIMENTS.md)の権限事前確認、Analysis、設定読取を参照。
  混合権限のキーで成功した結果を、表の権限だけで成功した証拠にはしない。
- 読取・upload・設定・Analysis・cleanupを用途別に検証することが
  [#5](https://github.com/DharmaDoll/sbom-ops/issues/5)の残条件。
  キーを増やすこと自体が目的ではないが、既存の混合権限キーの観測だけでは独立検証を満たさない。
  新規キーの発行や既存チームの権限変更は、運用者が対象・期間を決めてから行う。
- 対象版、操作、付与権限名、対象Projectの範囲、HTTP結果、期待結果との一致を記録する。
  キー値、レスポンス全文、環境固有UUIDは文書に転載しない。
- 401は認証失敗、403はアクセス拒否として停止する。404だけで権限不足・空一覧・未検出とは断定しない。
  通信失敗は未確認とし、管理キーへの自動切替や権限の自動追加をしない。
- 書込検証は使い捨てProjectと明示opt-inが前提。cleanupは名前の接頭辞だけで削除せず、
  実行記録・対象一致・稼働中処理の終了確認・dry-run・明示実行・監査を維持する。

## Implementation Rule

All production Dependency-Track API calls must be implemented in:

`src/sbom_ops/clients/dependency_track.py`

The client must expose intent-based methods, not raw endpoint names.

Exploratory calls belong only in the repository lab adapter at
[`lab/dependency_track/src/dt_lab/client.py`](../../lab/dependency_track/src/dt_lab/client.py).
Product modules must not import the lab. A lab observation becomes production
behavior only through an explicit reviewed decision: use the existing DT
capability, encode a verified constraint in a minimal fixture and product test,
implement a missing orchestration gap, or reject/defer the hypothesis.

Dependency-Track is the preferred source for EPSS values and VEX-derived
analysis state. The client should expose normalized finding fields for these
values, including component UUID/PURL and vulnerability UUID/source for stable
machine identity. VEX upload and analysis-state mutation require explicit workflow
support and permissions; they are not part of the MVP.

The MVP read path uses the following intent-level operations:

- `GET /api/v1/project` to enumerate accessible projects
- `GET /api/v1/project/{uuid}` to resolve project metadata
- `GET /api/v1/finding/project/{uuid}` to retrieve findings and analysis state
- `GET /api/v1/vulnerability/project/{uuid}` as the EPSS fallback source when a
  finding response does not include an EPSS value

The upload-and-wait path uses:

- `POST /api/v1/bom` with multipart `project` and `bom` fields; the response
  contains an asynchronous processing `token`
- `GET /api/v1/event/token/{token}` until `processing=false`
- then the project Finding and vulnerability endpoints above

The v4.14.3 upload contract validates CycloneDX against its schema. A rejected
BOM returns `400 application/problem+json` with RFC 9457 fields and validation
errors and does not return a processing token. HTTP 400 is a deterministic
input rejection: surface its safe problem details and do not retry it. The
production client uploads to an already resolved Project UUID. It does not use
`autoCreate`, which avoids the lab-observed side effect where a coordinate
upload created an empty Project before schema validation failed.

Lab coordinate upload deliberately exercises that boundary. In addition to
`BOM_UPLOAD`, `autoCreate=true` requires either `PROJECT_CREATION_UPLOAD` or
`PORTFOLIO_MANAGEMENT` according to the v4.14.3 OpenAPI contract. Its Project
ledger is therefore written before upload and remains authoritative for
reviewed cleanup even when the BOM is rejected synchronously.

The same v4.14.3 multipart coordinate-upload contract accepts `parentUUID` when
auto-creating a child Project. Portfolio hierarchy can be read with
`GET /api/v1/project/{uuid}/children`, which requires `VIEW_PORTFOLIO`, is
paginated with one-based `pageNumber` and `pageSize`, and returns
`X-Total-Count`. The lab verifies both that collection and the child's nested
`parent` projection rather than keeping a second hierarchy inventory.

Hierarchy and risk aggregation are separate DT capabilities. In the reviewed
parent/child probe, the parent and child both used the default
`collectionLogic=NONE`; the child had Findings and a non-zero
`inheritedRiskScore`, while the empty parent remained at zero. Project and
ProjectMetrics responses expose collection logic and inherited-risk fields, but
hierarchy creation alone is not evidence that risk is aggregated. Changing a
Project's collection logic requires `PORTFOLIO_MANAGEMENT` and remains outside
both the production client and this read-only probe until a separately gated
workflow is justified.

The v4.14.3 multipart upload also accepts comma-separated `projectTags`. When a
Project is created, a key with `PROJECT_CREATION_UPLOAD` can bind the initial
tags. Subsequent tag reconciliation is different: the server requires
`PORTFOLIO_MANAGEMENT`. The reviewed lab request with a changed tag set and a
creation-only upload key still returned HTTP 200 and a processing token, but DT
retained the original tags. Upload success is therefore not evidence that
routing metadata changed.

Tags are visible in the normal Project response and Projects can be selected by
`GET /api/v1/project/tag/{tag}` with `VIEW_PORTFOLIO`. That collection is
paginated and reports `X-Total-Count`. The MVP may use tags as a filter or
consistency check, but its YAML Project-to-repository mapping remains the routing
source of truth unless an explicit management and reconciliation workflow is
introduced.

Project properties are not a least-privilege alternative in v4.14.3. The
dedicated `GET /api/v1/project/{uuid}/property` endpoint itself requires
`PORTFOLIO_MANAGEMENT`; the orchestrator read key received HTTP 403 in the lab.
Properties remain outside the production client rather than forcing a read path
to carry a write-level permission.

The v4.14.3 multipart endpoint accepted equivalent CycloneDX 1.5 JSON and XML
without a format-specific request path. In the reviewed lab probe, DT retained
the same Project and Component identities, direct dependency graph, non-empty
Finding set, vulnerability identities, and normalized CycloneDX re-export
after JSON was replaced by XML. The production upload adapter can therefore
remain serialization-neutral for validated CycloneDX input; it must not add a
JSON/XML conversion layer merely for DT ingestion. This result is bounded to
the exercised 1.5 fields and does not waive input validation for either format.

The event token is the authoritative completion signal for the token-tracked
BOM processing and vulnerability-analysis workflow. It is not a global
quiescence signal: on v4.14.3, repository metadata analysis can continue after
`processing=false`. Finding stability is retained only as a defensive read-side
check when the sync is started without a token. A stable read is not, on its
own, proof that a missing Finding is resolved; safe closure therefore also
requires consecutive successful absence observations and explicit opt-in.

The findings API requires the `VIEW_VULNERABILITY` permission. Endpoint details
must be validated against the target instance's OpenAPI document before
production deployment.

The v4.14 OpenAPI document exposes `offset`/`limit` pagination for project
listing. Finding and project-vulnerability endpoints return their documented
collections without pagination parameters in that version, so the client only
sends pagination parameters where the target contract supports them. This
avoids silently relying on an undocumented query parameter.

The lab's `GET /api/v1/component/project/{uuid}` observation is a separate
documented collection contract. On v4.14.3 it uses one-based `pageNumber`,
`pageSize` defaulting to 100, and the `X-Total-Count` response header. The lab
retrieves every page and rejects an observation when the combined item count
does not match the header. This behavior remains lab-only until a production
use case explicitly requires full Component enumeration.

Good:

```python
list_projects()
get_project_findings(project_uuid)
upload_bom(project_uuid, bom_path)
update_analysis_state(...)
```

Bad:

```python
get_api_v1_finding_project_uuid(...)
post_api_v1_bom(...)
```

The lab-only cleanup adapter uses `GET /api/v1/project/lookup` for live identity
verification followed by `DELETE /api/v1/project/{uuid}`. The captured v4.14.3
OpenAPI contract documents `204` on successful deletion and requires
`PORTFOLIO_MANAGEMENT`; the lookup also requires `VIEW_PORTFOLIO`. These methods
must not be exposed by the production client merely because the lab uses them.

The opt-in lab Analysis experiment uses `PUT /api/v1/analysis` with the target
Project, Component, and vulnerability UUIDs and reads the trail with
`GET /api/v1/analysis`. The captured v4.14.3 contract requires
`VULNERABILITY_ANALYSIS` for the write and `VIEW_VULNERABILITY` for the read.
These methods remain lab-only while the triage delegation boundary is under
evaluation; their presence is not authorization to mutate product Analysis
state. Before the experiment creates a Project, `GET /api/v1/team/self` must
show that the selected key has `VULNERABILITY_ANALYSIS`. The lab accepts the
read-only permissions `VIEW_BADGES`, `VIEW_POLICY_VIOLATION`, `VIEW_PORTFOLIO`,
and `VIEW_VULNERABILITY`, but rejects any other permission.

The completed v4.14.3 reconciliation probe found no `ETag` or `Last-Modified`
on Project Finding or Analysis responses, and their schemas expose no Analysis
revision or update timestamp. An identical PUT with a non-empty caller comment
left the decision unchanged but appended that comment again. Future Analysis
writes must therefore avoid blind retries and reconcile the trail explicitly.

The `suppressed` query parameter on
`GET /api/v1/finding/project/{uuid}` means "include suppressed findings". A
suppressed Finding is absent from the default response but remains present with
`suppressed=true`. Product reconciliation always requests that complete view;
default-view absence is not resolution. Immediate Project metrics did not
reflect the Analysis or suppression changes and are not a write-verification
signal.

The lab adapter also exposes the read-only CycloneDX VEX export observation at
`GET /api/v1/vex/cyclonedx/project/{uuid}`. The v4.14.3 contract requires
`VULNERABILITY_ANALYSIS` and returns `application/vnd.cyclonedx+json`; the
adapter requests the 1.5 variant. VEX upload and round-trip mutation remain in
the explicit `triage-vex-round-trip` lab scenario. The lab-only adapter sends
the documented multipart `POST /api/v1/vex` request for an existing Project and
waits on its asynchronous processing token. The scenario is excluded from the
default lab run and is available only through scenario selection plus the
Analysis-mutation opt-in. This does not enable VEX writes in the product client.
In the completed one-Component v4.14.3 round trip, DT exported the Project UUID
as `vulnerabilities[].affects[].ref`, not the vulnerable Component PURL. Treat
that as a version-bounded Project-scoped observation. The completed
multi-Component probe showed that bare DT-exported and source-SBOM Component
references changed no Finding. Declaring the exact Component in the uploaded
VEX `components[]` collection and referencing its `bom-ref` changed only the
identity-matched Finding; referencing `metadata.component` changed both
Components that shared the vulnerability. This matches the official 4.14.3
importer, which resolves references within the VEX document before matching a
declared Component identity to the Project.

A future product VEX uploader must classify all `affects.ref` targets before
upload, reject unresolved references, distinguish Component and Project scope,
and reconcile the exact expected Finding set after the event token completes.
HTTP acceptance and schema validity do not prove that DT applied a decision.

## Behavior Lab Decision Boundary

The repository-only [Dependency-Track behavior lab](../../lab/dependency_track/README.md)
owns exploratory endpoints, scenario execution, raw observations, and current
behavior notes. It also tests how much triage can remain authoritative in DT
without duplicating state in sbom-ops. This product API guide owns only reviewed
production contracts and explicitly justified adapter behavior.
