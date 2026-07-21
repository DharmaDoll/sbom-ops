# Operations

Detailed operational scenarios and acceptance conditions are defined in
[`docs/use-cases.md`](use-cases.md).

Security teamはDependency-Trackのプロジェクト横断Findingを一元的に
トリアージし、sbom-opsの優先度ルールとGitHub Issueの対応状況を管理する。
例外承認、VEX判断、リスク受容は自動化せず、Security teamの判断記録を
一次情報とする。

Daily

1. CI uploads SBOM.
2. Dependency-Track analyzes.
3. Orchestrator polls findings.
4. Orchestrator reads Dependency-Track EPSS/VEX analysis state.
5. Orchestrator enriches findings with KEV.
6. Priority calculation.
7. GitHub Issue creation.
8. Developer remediation.
9. CI verifies.
10. Issue closed.
