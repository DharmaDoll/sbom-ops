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
7. GitHub Issue creation (optional final action).
8. Developer remediation.
9. CI verifies.
10. First verified absence marks the Issue as missing and leaves it open.
11. A later verified absence may close it only when automatic closure is
    explicitly enabled and the configured confirmation count is met.

`SBOM_OPS_CLOSE_MISSING_FINDINGS` defaults to `false`. Enabling it also requires
`sync --wait-for-analysis`.
`SBOM_OPS_MISSING_CONFIRMATION_RUNS` defaults to `2` and cannot be lower than 2.

GitHub Issue operations can be disabled while retaining Dependency-Track
collection and prioritization. Set `github.enabled: false`, export
`SBOM_OPS_GITHUB_ENABLED=false`, or pass `sbom-ops sync --no-github` (the CLI
flag takes precedence). `plan --no-github` displays the same mode.

The sync result always includes the Finding key, Priority, Dependency-Track
Analysis state, and prioritization rationale before any external action is
selected. This assessment output is therefore available for future Jira,
notification, VEX, or reporting adapters without coupling them to GitHub.

For downstream adapters, use machine-readable output:

```bash
sbom-ops sync --no-github --output json
```

Each result contains a unique `run_id` and `duration_seconds`, which can be
used to correlate later audit events or persistent synchronization logs.

To persist completed results as JSONL, set `runtime.sync_log_file` or
`SBOM_OPS_SYNC_LOG_FILE`. The file is only written when explicitly configured;
its parent directory must already exist.

Successful records have `status: succeeded`. If the configured sync encounters
a handled API, configuration, or client error, a `status: failed` record with
an error type and message is appended as well. Log sink write failures do not
replace the original sync result.

The JSONL sink is isolated from CLI and orchestration logic so it can later be
replaced with a database or centralized logging adapter.

For local GitHub authentication, keep the token in GitHub CLI's credential
store and export it only for the process that runs sbom-ops:

```bash
export GH_TOKEN="$(gh auth token)"
sbom-ops sync --dry-run
```

`GH_TOKEN` is accepted when `SBOM_OPS_GITHUB_TOKEN` is not set. Never commit
the token or put it in `.env.example`.

## YAML configuration

`sync` and `plan` accept a YAML configuration file with `--config PATH`. When
the flag is omitted, `SBOM_OPS_CONFIG_FILE` is used. Environment variables
override YAML values, and CLI flags override both. Secret values should use an
environment reference such as `api_key: env:SBOM_OPS_DT_API_KEY` rather than
being committed to the repository.

The supported schema and validation rules are documented in [`SPEC.md`](../SPEC.md).
An executable example is available at [`examples/config.yaml`](../examples/config.yaml).

The KEV client can use an optional local TTL cache with
`intelligence.kev_cache_file` and `intelligence.kev_cache_ttl_seconds` (or the
corresponding `SBOM_OPS_KEV_CACHE_*` variables). Without a cache path, each
sync fetches the feed normally. A stale or malformed cache is ignored rather
than used as authoritative data.

Set `intelligence.kev_cache_allow_stale: true` only when continued operation
with an explicitly stale KEV snapshot is acceptable. The setting is also
available as `SBOM_OPS_KEV_CACHE_ALLOW_STALE=true` and applies only after a
fresh feed request fails.
JSONL and JSON sync results expose `kev_used_stale_cache` so downstream
consumers can distinguish current KEV data from an explicitly stale snapshot.
When the cache has validators, refresh requests use `If-None-Match` and
`If-Modified-Since`; a `304 Not Modified` response refreshes the cache timestamp
without downloading the feed body.

```bash
export SBOM_OPS_DT_API_KEY=replace-me
export SBOM_OPS_GITHUB_TOKEN=replace-me
sbom-ops plan --config examples/config.yaml
```
