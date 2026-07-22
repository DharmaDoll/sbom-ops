# Dependency-Track SBOM Operations

## Overview
This project builds an operational framework around OWASP Dependency-Track.

Dependency-Track is treated as the **SBOM inventory and vulnerability analysis platform**.
GitHub Issues (or Jira) is treated as the **remediation workflow platform**.

An orchestrator connects these systems, uses Dependency-Track-provided EPSS and
VEX/analysis state, enriches findings with CISA KEV data, and creates actionable
engineering tasks.

## Goals
- Centralize SBOM management
- Prioritize vulnerabilities using threat intelligence
- Reduce alert fatigue
- Automate issue creation and lifecycle
- Support VEX and future reachability analysis

## High-Level Architecture
CI/CD → CycloneDX SBOM → Dependency-Track (EPSS/VEX) → Orchestrator (KEV/priority) → GitHub Issues → Developers → CI → Dependency-Track

## Repository Documentation
- AGENTS.md — AI development guide
- ARCHITECTURE.md — system design
- SPEC.md — implementation specification
- docs/use-cases.md — concrete operational flows and usage scenarios
- docs/data-sources.md — Finding情報源と取得方法
- docs/dependency-track/setup.md — local Dependency-Track bootstrap

## Design Principles
1. SBOM is the source of truth for software composition.
2. Dependency-Track is the source of truth for inventory.
3. GitHub Issues is the source of truth for remediation workflow.
4. Threat intelligence drives operational prioritization.
5. AI assists triage but never replaces security decisions.

```text
dependency-track-sbom-ops/
├── README.md
├── AGENTS.md              ← AIエージェント向け開発ガイド
├── ARCHITECTURE.md        ← システム・リポジトリ構成
├── SPEC.md                ← 実装仕様
├── ROADMAP.md             ← 開発計画
├── TASKS.md               ← 実装バックログ
├── CONTRIBUTING.md
├── CHANGELOG.md
├── docs/
│   ├── operations.md
│   ├── workflow.md
│   ├── priority-policy.md
│   ├── vex.md
│   ├── api.md
│   ├── dependency-track/
│   │   ├── README.md
│   │   ├── setup.md
│   │   ├── project-model.md
│   │   ├── sbom-upload.md
│   │   ├── api.md
│   │   ├── analysis-states.md
│   │   ├── permissions.md
│   │   ├── operations.md
│   │   ├── vex.md
│   │   └── troubleshooting.md
│   └── adr/
│       ├── 0001-use-dependency-track.md
│       ├── 0002-priority-engine.md
│       └── 0003-github-issues.md
```
