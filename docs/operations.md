# Operations

Detailed operational scenarios and acceptance conditions are defined in
[`docs/use-cases.md`](use-cases.md).

Security teamはDependency-Trackのプロジェクト横断Findingを一元的に
トリアージし、sbom-opsの優先度ルールとGitHub Issueの対応状況を管理する。
例外承認、VEX判断、リスク受容は自動化せず、Security teamの判断記録を
一次情報とする。

Daily

1. CI uploads the SBOM and waits for the Dependency-Track processing token to
   report `processing=false` (the separate `sbom-ops upload` helper may do this).
2. Orchestrator polls findings using `sync --wait-for-analysis`.
3. Orchestrator confirms a stable project read.
4. Orchestrator reads Dependency-Track EPSS/VEX analysis state.
5. Orchestrator enriches findings with KEV.
6. Priority calculation.
7. GitHub Issue creation.
8. Developer remediation.
9. CI verifies.
10. First verified absence marks the Issue as missing and leaves it open.
11. A later verified absence may close it only when automatic closure is
    explicitly enabled and the configured confirmation count is met.

`SBOM_OPS_CLOSE_MISSING_FINDINGS` defaults to `false`. Enabling it also requires
`sync --wait-for-analysis`.
`SBOM_OPS_MISSING_CONFIRMATION_RUNS` defaults to `2` and cannot be lower than 2.

For local GitHub authentication, keep the token in GitHub CLI's credential
store and export it only for the process that runs sbom-ops:

```bash
export GH_TOKEN="$(gh auth token)"
sbom-ops sync --dry-run
```

`GH_TOKEN` is accepted when `SBOM_OPS_GITHUB_TOKEN` is not set. Never commit
the token or put it in `.env.example`.
