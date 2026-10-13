# Priority Policy

## 優先度と対応期限

現在の計算ルールと閾値は[SPEC](../SPEC.md#priority-rules)に集約する。
P0〜P3は設定されたルールの結果であり、P3でもスコア不足のHIGHが含まれ得る。
「低リスク」「監視だけでよい」という結論にはしない。

対応期限（SLA）は別の運用方針であり、製品は現在期限を計算しない。
資産重要度・公開範囲を使うルールも、人が確認してから別途導入する。

## Triage ownership

Priority is an operational decision generated from Dependency-Track data and
the configured policy. Security team owns the final triage decision, including
whether a finding is exploitable, not affected, a false positive, suppressed,
or accepted as risk.

sbom-ops may recommend a priority and create or update a GitHub Issue, but it
must not automatically approve exceptions, accept risk, or change
Dependency-Track analysis state.

Priority expresses work ordering; an SLA expresses a due date and escalation
policy. They must remain separate domain concepts. Asset criticality, exposure,
reachability, and compensating controls are future `PriorityContext` inputs and
must not be inferred from CVSS alone.
The optional reviewed asset inventory now displays criticality, deployment,
owner, and exposure by Project and environment. It does not yet change P0–P3,
Issue routing, or closure. The fictional scenario in the README makes this
boundary visible before a real organizational policy is selected.
The SQLite registry's separate human deployment report is also output-only:
even an exact, current Project/version join is not independent proof that the
artifact is running or internet-facing. Unmatched, expired, future, and
conflicting claims cannot lower a Finding's priority.

## PoC review ordering

Within the same calculated P0–P3 priority, prefer a Finding whose CVE has a
source-reported public PoC over an otherwise equivalent Finding without such a
report. This is a work-order tie-break, not a claim that sbom-ops executed or
validated the PoC. Keep the source, observation time, and per-source count;
do not count generic public references, scanner templates, or exploitation
reports as PoCs, or add duplicate provider counts into one total. A failed,
incomplete, stale, or unsupported lookup is `unknown`, not `no PoC`, and must
not reduce the Finding's priority or place it below a source-scoped negative
report merely because evidence is missing. A positive report can still move
ahead of both. The number of reported PoCs is context, not a linear score.

When a loaded advisory snapshot provides the explicit `published_poc` signal,
JSON, text, and review output sort P0 through P3 first and apply this tie-break
among Findings with identical
Project, P0–P3 category, KEV status, severity, numeric CVSS, EPSS, Analysis
state, and suppression state. Within a priority, other assessments retain their previous relative
positions. The internal Finding order, priority engine, and Issue actions are
unchanged. The Vuls lab exporter provides `exploit-record` (general public
references), so its snapshot does not claim PoC presence or trigger this
ordering. The isolated lab can now convert a recorded Vulnerability-Lookup
PoC Sighting result to the explicit signal; product-runtime acquisition is
still not implemented.

The `published_poc` observation must be source-attributed, declared `fresh`,
and satisfy `observed_at <= review time < expires_at`, comparing timezone-aware
instants. Future observations are retained as reported data but have effective
freshness `unknown`; they establish neither PoC presence nor source-scoped
absence, and cannot promote a Finding in review order. Another current source
may still establish presence. Multiple provider counts remain separate.
No report, expired/stale data, or an incomplete lookup stays `unknown` for
ordering purposes.
Any rule that raises the P0–P3 category or changes a remediation deadline
requires a separately reviewed policy, including asset context and the risk
of counting a signal already reflected in EPSS. PoC presence is not equivalent
to confirmed exploitation or BOD 26-04 exploit automation. Human triage still
owns the final decision; PoC effectiveness is outside sbom-ops scope.

The current P2 rule uses numeric CVSS, not the textual `HIGH` severity label.
When Dependency-Track provides `HIGH` but no numeric CVSS, the current rule falls
through to P3 unless an earlier KEV, active-exploitation, CRITICAL, or EPSS rule
matches. Assessment output therefore exposes source, severity, CVSS, and EPSS;
`P3` with a missing score must not be presented as evidence of low risk.
