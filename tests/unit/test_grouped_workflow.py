from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from sbom_ops.clients.dependency_track import (
    DependencyTrackFinding,
    DependencyTrackProject,
)
from sbom_ops.clients.github import GitHubApiError
from sbom_ops.config import (
    AppConfig,
    DependencyTrackConfig,
    GitHubConfig,
    IntelligenceConfig,
    PriorityConfig,
    RuntimeConfig,
    WorkflowConfig,
)
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegisteredService,
    ReviewedProjectLink,
)
from sbom_ops.domain.assets import BusinessCriticality
from sbom_ops.domain.issue_body import IssueBodyError, new_issue_body
from sbom_ops.domain.issue_catalog import IssueIdentityError
from sbom_ops.domain.repair_issue import parse_repair_record
from sbom_ops.services.orchestrator import Orchestrator
from sbom_ops.storage.issue_journal import IssueJournal

P1 = "11111111-1111-4111-8111-111111111111"
P2 = "22222222-2222-4222-8222-222222222222"


class Inventory:
    def __init__(self) -> None:
        self.rows = {
            project: [
                DependencyTrackFinding(
                    project_uuid=project,
                    project_name="checkout/web",
                    component_name="example",
                    component_version="1.0.0",
                    vulnerability_id="CVE-2026-1000",
                    severity="CRITICAL" if project == P1 else "HIGH",
                    cvss_score=9.8 if project == P1 else 8.0,
                    cwes=(),
                    description="sample finding",
                    epss_score=0.1,
                    analysis_state="NOT_SET",
                    is_suppressed=False,
                    analysis_detail=None,
                    finding_id=f"finding-{project}",
                    component_uuid=f"component-{project}",
                    vulnerability_uuid="vulnerability",
                    component_purl="pkg:generic/example@1.0.0",
                    vulnerability_source="NVD",
                )
            ]
            for project in (P1, P2)
        }

    def list_projects(self) -> list[DependencyTrackProject]:
        return [
            DependencyTrackProject(p, "checkout/web", f"build-{i}")
            for i, p in enumerate((P1, P2), 1)
        ]

    def get_project_findings(self, project_uuid: str) -> list[DependencyTrackFinding]:
        return self.rows[project_uuid]


class NoKev:
    def get_known_exploited_vulnerabilities(
        self, *, force_refresh: bool = False
    ) -> set[str]:
        return set()


class Repository:
    def __init__(self) -> None:
        self.issues: dict[int, dict] = {}
        self.created = 0
        self.updated = 0
        self.fail_create: BaseException | None = None
        self.fail_update: BaseException | None = None

    def list_issues(self) -> list[dict]:
        return deepcopy(list(self.issues.values()))

    def get_issue(self, issue_number: int) -> dict:
        return deepcopy(self.issues[issue_number])

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        self.created += 1
        number = len(self.issues) + 1
        issue = {
            "number": number,
            "title": title,
            "body": body,
            "labels": labels,
            "state": "open",
        }
        self.issues[number] = issue
        if self.fail_create:
            raise self.fail_create
        return deepcopy(issue)

    def update_issue(self, issue_number: int, title: str | None, body: str) -> dict:
        assert title is None
        self.updated += 1
        self.issues[issue_number]["body"] = body
        if self.fail_update:
            raise self.fail_update
        return self.get_issue(issue_number)

    def add_issue_labels(self, issue_number: int, labels: list[str]) -> list:
        self.issues[issue_number]["labels"] = sorted(
            set(self.issues[issue_number]["labels"] + labels)
        )
        return self.issues[issue_number]["labels"]

    def remove_issue_label(self, issue_number: int, label: str) -> list:
        self.issues[issue_number]["labels"].remove(label)
        return self.issues[issue_number]["labels"]

    def close_issue(self, issue_number: int) -> dict:
        raise AssertionError("never close automatically")


def registry() -> AssetRegistrySnapshot:
    return AssetRegistrySnapshot(
        services=(
            RegisteredService(
                "checkout", "team-checkout", BusinessCriticality.HIGH, "sample"
            ),
        ),
        links=tuple(
            ReviewedProjectLink(
                p,
                "checkout/web",
                f"build-{i}",
                "checkout",
                "web",
                "operator",
                "2026-01-01T00:00:00Z",
            )
            for i, p in enumerate((P1, P2), 1)
        ),
    )


@pytest.fixture
def config(tmp_path: Path) -> AppConfig:
    path = tmp_path / "workflow.sqlite3"
    IssueJournal.initialize(path)
    return AppConfig(
        DependencyTrackConfig("https://example.invalid", "fixture-only"),
        GitHubConfig("fixture-only", "acme", "repo", enabled=True),
        IntelligenceConfig(),
        PriorityConfig(),
        RuntimeConfig(github_write=True),
        workflow=WorkflowConfig(issue_journal_file=str(path)),
    )


def runner(
    config: AppConfig, dt: Inventory, gh: Repository, *, linked: bool = True
) -> Orchestrator:
    return Orchestrator(
        config, dt, NoKev(), gh, asset_registry=registry() if linked else None
    )


def test_group_creates_once_retains_unobserved_build_and_later_downgrades(
    config: AppConfig,
) -> None:
    dt, gh = Inventory(), Repository()
    first = runner(config, dt, gh).run()
    assert first.issues_created == 1 and first.findings_processed == 2
    body = gh.issues[1]["body"]
    key = parse_repair_record(body).group_key
    assert gh.issues[1]["labels"] == ["sbom", "sbom-P1"]
    gh.issues[1]["body"] = "human before\n" + body + "\nhuman after"
    gh.issues[1]["labels"].append("human-label")
    partial = replace(config, runtime=replace(config.runtime, project_uuids=(P2,)))
    second = runner(partial, dt, gh).run()
    assert second.issues_updated == 1 and second.issues_created == 0
    record = parse_repair_record(gh.issues[1]["body"])
    assert record.group_key == key
    assert {m.project_uuid: m.observed for m in record.members} == {P1: False, P2: True}
    assert "sbom-P1" in gh.issues[1]["labels"]
    dt.rows[P1] = [replace(dt.rows[P1][0], cvss_score=8.0, severity="HIGH")]
    runner(config, dt, gh).run()
    assert set(gh.issues[1]["labels"]) == {"sbom", "sbom-P2", "human-label"}
    assert gh.issues[1]["body"].startswith("human before")
    assert gh.issues[1]["body"].endswith("human after")
    assert gh.created == 1
    with IssueJournal(config.workflow.issue_journal_file, read_only=True) as journal:
        assert len(journal.records()) == 1
        assert journal.records()[0].finding_key == key


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("lost_update", [False, True])
def test_single_old_issue_and_create_journal_survive_migration(
    config: AppConfig,
    legacy: bool,
    lost_update: bool,
) -> None:
    dt, gh = Inventory(), Repository()
    item = runner(config, dt, gh)._prioritize(dt.rows[P1][0], set()).finding
    old_key = item.legacy_finding_key() if legacy else item.finding_key()
    gh.issues[9] = {
        "number": 9,
        "title": "human title",
        "state": "open",
        "labels": [],
        "body": new_issue_body(old_key, "old") + "\nhuman notes",
    }
    with IssueJournal(config.workflow.issue_journal_file) as journal:
        intent = journal.reserve("acme/repo", old_key, "original")
        journal.confirm(intent, 9, "original")
    gh.fail_update = GitHubApiError("response lost") if lost_update else None
    if lost_update:
        with pytest.raises(GitHubApiError):
            runner(config, dt, gh).run()
    else:
        runner(config, dt, gh).run()
    gh.fail_update = None
    runner(config, dt, gh).run()
    assert gh.created == 0
    assert gh.issues[9]["title"] == "human title"
    assert gh.issues[9]["body"].endswith("human notes")
    assert old_key in parse_repair_record(gh.issues[9]["body"]).keys
    with IssueJournal(config.workflow.issue_journal_file, read_only=True) as journal:
        assert journal.records()[0].finding_key == old_key
        assert journal.records()[0].issue_number == 9


@pytest.mark.parametrize("failure", [GitHubApiError("lost"), KeyboardInterrupt()])
def test_group_post_response_loss_or_interrupt_never_reposts(
    config: AppConfig, failure: BaseException
) -> None:
    dt, gh = Inventory(), Repository()
    gh.fail_create = failure
    if isinstance(failure, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            runner(config, dt, gh).run()
    else:
        runner(config, dt, gh).run()
    gh.fail_create = None
    runner(config, dt, gh).run()
    assert gh.created == 1
    assert len(parse_repair_record(gh.issues[1]["body"]).members) == 2


def test_multiple_old_issues_block_all_writes(config: AppConfig) -> None:
    dt, gh = Inventory(), Repository()
    for number, project in enumerate((P1, P2), 1):
        item = runner(config, dt, gh)._prioritize(dt.rows[project][0], set()).finding
        gh.issues[number] = {
            "number": number,
            "state": "open",
            "title": "old",
            "labels": [],
            "body": new_issue_body(item.finding_key(), "old"),
        }
    with pytest.raises(IssueIdentityError, match="multiple"):
        runner(config, dt, gh).run()
    assert gh.created == gh.updated == 0


def test_unverified_assets_or_changed_label_cannot_overwrite_a_group(
    config: AppConfig,
) -> None:
    dt, gh = Inventory(), Repository()
    runner(config, dt, gh).run()
    before = deepcopy(gh.issues)
    with pytest.raises(IssueIdentityError, match="no longer verified"):
        runner(config, dt, gh, linked=False).run()
    changed = replace(
        config, github=replace(config.github, issue_label_prefix="new-prefix")
    )
    with pytest.raises(IssueBodyError, match="route changed"):
        runner(changed, dt, gh).run()
    assert gh.issues == before


def test_analysis_excluded_members_do_not_raise_group_priority_or_create(
    config: AppConfig,
) -> None:
    dt, gh = Inventory(), Repository()
    dt.rows[P1] = [replace(dt.rows[P1][0], is_suppressed=True)]
    result = runner(config, dt, gh).run()
    assert result.issues_created == 0  # Remaining P2 is not a create target.
    assert len(result.assessments) == 2
    assert result.remediation_groups()[0].highest_observed_priority.value == "P1"


def test_dry_run_keeps_db_and_github_unchanged_and_empty_input_never_closes(
    config: AppConfig,
) -> None:
    dt, gh = Inventory(), Repository()
    path = Path(config.workflow.issue_journal_file)
    before = path.read_bytes()
    dry = replace(config, runtime=replace(config.runtime, dry_run=True))
    result = runner(dry, dt, gh).run()
    assert result.issues_created == 1
    assert gh.created == gh.updated == 0
    assert path.read_bytes() == before
    runner(config, dt, gh).run()
    old_body = gh.issues[1]["body"]
    dt.rows = {P1: [], P2: []}
    result = runner(config, dt, gh).run()
    assert result.issues_updated == result.issues_closed == 0
    assert gh.issues[1]["body"] == old_body
    assert any("keep-open repair-v1:" in action for action in result.actions)


def test_repositories_are_separate_even_for_the_same_repair_group(
    config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dt, first, second = Inventory(), Repository(), Repository()
    dt.rows[P2] = [replace(dt.rows[P2][0], severity="CRITICAL")]
    instance = runner(config, dt, first)
    monkeypatch.setattr(
        instance,
        "_github_target",
        lambda project: (
            first if project == P1 else second,
            "sbom",
            ("acme", "first" if project == P1 else "second", "sbom"),
        ),
    )
    result = instance.run()
    assert result.issues_created == 2
    first_record = parse_repair_record(first.issues[1]["body"])
    second_record = parse_repair_record(second.issues[1]["body"])
    assert first_record.group_key == second_record.group_key
    assert first_record.repository == "acme/first"
    assert second_record.repository == "acme/second"
    assert [m.project_uuid for m in first_record.members] == [P1]
    assert [m.project_uuid for m in second_record.members] == [P2]
    instance.run()
    assert first.created == second.created == 1


def test_conflicting_label_routes_for_one_group_stop_before_writes(
    config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dt, gh = Inventory(), Repository()
    instance = runner(config, dt, gh)
    monkeypatch.setattr(
        instance,
        "_github_target",
        lambda project: (
            gh,
            "a" if project == P1 else "b",
            ("acme", "repo", "a" if project == P1 else "b"),
        ),
    )
    with pytest.raises(IssueIdentityError, match="conflicting label routes"):
        instance.run()
    assert gh.created == gh.updated == 0


def test_closed_group_is_not_reopened_or_recreated(config: AppConfig) -> None:
    dt, gh = Inventory(), Repository()
    runner(config, dt, gh).run()
    gh.issues[1]["state"] = "closed"
    result = runner(config, dt, gh).run()
    assert result.issues_created == result.issues_updated == 0
    assert gh.created == 1
    assert any("review-closed repair-v1:" in action for action in result.actions)


def test_late_changed_group_record_is_checked_before_the_update(
    config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sbom_ops.domain.repair_issue import repair_issue_body

    dt, gh = Inventory(), Repository()
    runner(config, dt, gh).run()
    other = replace(parse_repair_record(gh.issues[1]["body"]), repository="acme/other")
    monkeypatch.setattr(
        gh,
        "get_issue",
        lambda number: {
            **gh.issues[number],
            "body": repair_issue_body(other),
        },
    )
    with pytest.raises(IssueBodyError, match="route changed"):
        runner(config, dt, gh).run()
    assert gh.updated == 0


def test_all_excluded_group_is_never_closed_or_rewritten(config: AppConfig) -> None:
    dt, gh = Inventory(), Repository()
    runner(config, dt, gh).run()
    before = deepcopy(gh.issues)
    dt.rows = {
        project: [replace(rows[0], is_suppressed=True)]
        for project, rows in dt.rows.items()
    }
    result = runner(config, dt, gh).run()
    assert result.issues_created == result.issues_updated == result.issues_closed == 0
    assert gh.issues == before


def test_duplicate_rows_with_conflicting_assessments_cannot_pick_a_winner(
    config: AppConfig,
) -> None:
    dt, gh = Inventory(), Repository()
    dt.rows[P1].append(replace(dt.rows[P1][0], is_suppressed=True))
    with pytest.raises(IssueIdentityError, match="conflicting observations"):
        runner(config, dt, gh).run()
    assert gh.created == gh.updated == 0


@pytest.mark.parametrize("old_issue", [False, True])
def test_first_group_needs_all_reviewed_builds_to_find_old_issues(
    config: AppConfig,
    old_issue: bool,
) -> None:
    dt, gh = Inventory(), Repository()
    if old_issue:
        item = runner(config, dt, gh)._prioritize(dt.rows[P1][0], set()).finding
        gh.issues[9] = {
            "number": 9,
            "state": "open",
            "title": "old",
            "labels": [],
            "body": new_issue_body(item.finding_key(), "old"),
        }
    partial = replace(config, runtime=replace(config.runtime, project_uuids=(P2,)))
    with pytest.raises(IssueIdentityError, match="requires all reviewed builds"):
        runner(partial, dt, gh).run()
    assert gh.created == gh.updated == 0


def test_unobserved_old_finding_cannot_be_ignored_during_initial_migration(
    config: AppConfig,
) -> None:
    dt, gh = Inventory(), Repository()
    old = replace(dt.rows[P1][0], vulnerability_uuid="old-vulnerability")
    item = runner(config, dt, gh)._prioritize(old, set()).finding
    gh.issues[9] = {
        "number": 9,
        "state": "open",
        "title": "old",
        "labels": [],
        "body": new_issue_body(item.finding_key(), "old"),
    }
    with pytest.raises(IssueIdentityError, match="unobserved individual issue"):
        runner(config, dt, gh).run()
    assert gh.created == gh.updated == 0


@pytest.mark.parametrize("operation", ["create", "update"])
def test_incomplete_group_response_is_not_a_confirmed_write(
    config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    from sbom_ops.domain.repair_issue import repair_issue_body

    dt, gh = Inventory(), Repository()
    if operation == "update":
        runner(config, dt, gh).run()
    original = gh.create_issue if operation == "create" else gh.update_issue

    def lose_member(*args: object) -> dict:
        response = original(*args)
        record = parse_repair_record(response["body"])
        response["body"] = repair_issue_body(
            replace(record, members=record.members[:1])
        )
        gh.issues[response["number"]] = response
        return response

    monkeypatch.setattr(gh, operation + "_issue", lose_member)
    with pytest.raises(IssueIdentityError, match="confirm repair members"):
        runner(config, dt, gh).run()
    assert gh.created == 1
    with IssueJournal(config.workflow.issue_journal_file, read_only=True) as journal:
        events = journal.events()
        assert events[-1].event == "run_failed"
        assert any(e.event == "operation_unknown" for e in events)
        if operation == "create":
            assert journal.records()[0].state == "pending"
