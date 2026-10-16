# AGENTS.md

## Project

Dependency-Track SBOM Operations  
This repository implements a Security-as-a-Task orchestrator on top of OWASP Dependency-Track.  
Dependency-Track is the inventory system.  
GitHub Issues (or Jira) is the work management system.

This project bridges the two.

---

# Design Principles

1. SBOM is the source of truth.
2. Dependency-Track owns inventory.
3. GitHub Issues own remediation workflow.
4. Everything should be automatable.
5. AI assists humans but never makes final security decisions.
6. Components should be loosely coupled.
7. Every module should be independently testable.

---

# Architecture

Input

CI/CD
 ↓
CycloneDX SBOM
 ↓
Dependency-Track

↓

Orchestrator

↓

Threat Intelligence

- CISA KEV
- EPSS
- GitHub Advisory
- NVD

↓

Priority Engine

↓

LLM Triage (optional)

↓

GitHub Issues

↓

Developer

↓

CI

↓

Dependency-Track

---

# Coding Guidelines

- Python 3.12+
- Type hints required
- Ruff
- Black
- pytest
- No business logic inside API clients.
- Separate adapters from domain logic.

Example

```
dependency_track.py
    only API communication

priority.py
    only priority calculation

github.py
    only GitHub communication

main.py
    orchestration only
```
---

# Priority Rules

P0

- KEV
- Active exploitation

P1

- EPSS >= threshold
- Critical CVSS

P2

- High CVSS

P3

Everything else

Never hardcode thresholds.
Thresholds belong in config.

---

# AI Usage

LLM must only

- summarize findings
- explain impact
- propose remediation

LLM must never

- suppress vulnerabilities
- approve exceptions
- change priority automatically

---

## Dependency-Track Development Rule

Dependency-Track is an external system and the most important integration point in this project.

Before implementing or modifying any Dependency-Track integration, agents must read:

- https://docs.dependencytrack.org/
- https://docs.dependencytrack.org/integrations/rest-api/
- https://docs.dependencytrack.org/usage/cicd/
- https://docs.dependencytrack.org/usage/vex/
- https://docs.dependencytrack.org/usage/analysis/
- https://docs.dependencytrack.org/getting-started/deploy-docker/

Rules:

1. Do not assume API behavior.
2. Confirm endpoint, method, request body, response body, and required permission from official documentation.
3. Keep production Dependency-Track API code isolated in `src/sbom_ops/clients/dependency_track.py`.
4. Keep exploratory Dependency-Track API code isolated in `lab/dependency_track/src/dt_lab/client.py`; product modules must never import it.
5. Do not put priority logic, GitHub logic, or SLA logic in either Dependency-Track client.
6. Treat Dependency-Track as the source of truth for SBOM inventory.
7. Treat GitHub Issues as the source of truth for remediation workflow.
8. Never overwrite Dependency-Track analysis state without explicit workflow logic.
9. All production Dependency-Track API changes require integration tests or documented mock fixtures.
10. Lab observations are decision evidence, not code to transfer mechanically. For each hypothesis, decide whether to use an existing Dependency-Track capability, encode a verified constraint in product fixtures and tests, implement only the missing orchestration gap, or reject/defer the hypothesis with evidence.
11. Prioritize lab work by unresolved product risk and the shortest path to the project goal. Do not implement a planned scenario merely to complete the scenario list.

## Dependency-Track Lab Isolation Rule

The repository-only behavior lab lives under `lab/dependency_track/` and is not
part of the `sbom-ops` wheel or runtime CLI.

Rules:

1. Product code under `src/sbom_ops/` must not import `dt_lab`.
2. Lab scenarios, adapters, domain models, orchestration, and tests stay under `lab/dependency_track/`.
3. Raw observations and target-specific OpenAPI documents stay under ignored `var/dt-lab/`.
4. Develop experiments on short-lived `lab/*` or `refactor/*` branches; do not maintain a long-lived lab branch.
5. Merge only reproducible scenarios, stable lab code, reviewed fixtures, durable documentation, and justified product decisions or changes.
6. Never merge credentials, raw observations, environment-specific UUIDs, or temporary investigation code.
7. Mutating Analysis, VEX, suppression, policy, or administrative scenarios require a disposable Project, least-privilege key, and explicit CLI opt-in.
8. Run product tests and lab tests independently before merge.
9. Project cleanup must remain run-scoped and dry-run by default; require the lab namespace, matching run marker, live identity verification, a dedicated cleanup key, explicit execution, and a local audit.
10. Never add prefix-only bulk deletion or an implicit full-database reset.
11. Every attempted live experiment must update
    `lab/dependency_track/EXPERIMENTS.md` before merge, including its purpose,
    performed work, observed facts, interpretation or product decision,
    unverified questions, target versions, and local evidence path pattern.
12. Record failed, partial, and inconclusive experiments. Keep facts separate
    from inference, and never move credentials, raw payloads, or
    environment-specific UUIDs from ignored evidence into the ledger.
13. Scenario status `implemented` means runnable, not live-verified. A behavior
    becomes evidence only when its result is recorded in the experiment ledger.
14. Do not delete a Project immediately after BOM event-token completion.
    Repository metadata work may still be asynchronous; review the evidence,
    wait for target quiescence, then use the separate run-scoped cleanup command.


## Google Cloud Infrastructure Development Rule

Google Cloud infrastructure is part of the secure delivery boundary for this project.

Before implementing or modifying Google Cloud infrastructure, deployment
pipelines, Terraform/IaC, Workload Identity Federation, Secret Manager, Cloud
Run, GKE, IAP, logging, monitoring, or SBOM upload gateway code, agents must
review the relevant guidance from:

- https://github.com/google/skills

Rules:

1. Use relevant Google skills when available and applicable to the infrastructure task.
2. Treat Google Cloud and GitHub official documentation as the source of truth for service behavior, IAM, OIDC/WIF claims, permissions, and deployment constraints.
3. Do not assume Cloud Run is the final architecture; compare it with supported alternatives such as GKE/Helm when Dependency-Track runtime characteristics require it.
4. Do not introduce long-lived Google Cloud credentials into GitHub Actions.
5. Prefer Workload Identity Federation, Secret Manager, least privilege, immutable repository/workflow identity checks, and auditable infrastructure changes.
6. All infrastructure changes require documentation of the threat model impact, rollback path, and validation method.


# Future Features

- VEX
- Reachability
- Jira
- Slack
- Teams
- SARIF
- Dependency Graph
- Multi-tenancy



# Repository Rules

When adding new functionality:

1. Define domain models first.
2. Implement business rules.
3. Add service orchestration.
4. Implement external clients.
5. Add CLI entrypoint.
6. Add tests.
7. Update documentation.

Never bypass the architecture.

## 開発Issueの更新・完了手順

開発作業の進捗の正本はGitHub Issuesとする。これは製品が同期する脆弱性対応Issueとは別であり、
この手順で製品のGitHub同期や自動クローズを有効にしてはならない。

1. 着手時に関連Issueの本文・コメント・完了条件を確認し、対象Issueを作業報告で示す。
   実装・検証を始めるときは`status:in-progress`にする。単なる調査回答や状態確認では変更しない。
   対応するIssueがない小さな文書修正などは、無理に新規Issueを作らず「対象Issueなし」と報告する。
2. 作業を区切るときは、Issue本文の現在の状況・チェックリスト・残作業を更新する。
   実装済み、検証済み、公開済みを区別し、履歴コメントだけを追加して古い本文を放置しない。
   未完了なら`status:partial`、未着手なら`status:todo`とし、開いているIssueの進捗ラベルは一つにする。
   先行作業待ちや公開待ちは本文に明記する。
3. コミット・プッシュを行った後は、対象Issueごとに公開された変更と対象コミットのCI結果を確認する。
   ローカルのテスト成功やプッシュ成功だけでは完了扱いにしない。必要な実環境確認も完了条件に従う。
   この手順自体は、依頼されていないコミット・プッシュを行う許可ではない。
4. 完了条件をすべて満たしたIssueだけ、コミット・CI・必要な検証記録へのリンクを付けて
   `completed`としてcloseし、未完了を示す進捗ラベルを外す。
   部分実装では`Closes #N`などの自動クローズ指定を使わない。自動クローズでも完了条件の確認を省略しない。
5. 更新後はGitHubから状態・本文・ラベルを読み直して反映を確認する。
   接続や権限の問題で更新できない場合は、未反映のIssueと必要な更新を最終報告に残し、次の関連作業で再確認する。
6. 最終報告には変更・検証結果に加え、更新／クローズしたIssue、または更新不要の理由を記載する。
   CI待ち・公開待ち・Issue更新失敗を、作業全体の完了として報告しない。

ROADMAPには成果の方向性・実装順序・見送り理由とIssueへのリンクを残す。
進捗、完了チェックリスト、「未コミット」「公開待ち」などの状態はIssueへ集約し、二重管理しない。
仕様はSPEC、操作は運用ガイド、実験の観測事実は各labのEXPERIMENTSに残す。
