"""Minimal operation evidence; never accept request/response bodies or secrets."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True)
class WorkflowEvent:
    event_id: str
    run_id: str
    occurred_at: str
    event: str
    operation_id: str | None = None
    operation: str | None = None
    repository: str | None = None
    finding_key: str | None = None
    issue_number: int | None = None
    labels: tuple[str, ...] = ()
    error_type: str | None = None

    def __post_init__(self) -> None:
        strings = (self.event_id, self.run_id, self.occurred_at, self.event)
        optional = (
            self.operation_id,
            self.operation,
            self.repository,
            self.finding_key,
            self.error_type,
        )
        if not isinstance(self.labels, tuple) or any(
            not isinstance(value, str)
            or not value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            for value in (
                *strings,
                *(value for value in optional if value is not None),
                *self.labels,
            )
        ):
            raise ValueError("invalid workflow audit metadata")
        if self.event not in {
            "run_started",
            "run_succeeded",
            "run_failed",
            "run_interrupted",
            "operation_started",
            "operation_confirmed",
            "operation_unknown",
            "operation_reconciled",
        }:
            raise ValueError("invalid workflow audit event")
        if (
            not self.event_id
            or not self.run_id
            or datetime.fromisoformat(self.occurred_at).tzinfo is None
        ):
            raise ValueError("invalid workflow audit identity or timestamp")
        if self.event.startswith("operation_"):
            if self.operation not in {
                "create_issue",
                "update_body",
                "add_labels",
                "remove_label",
            } or not all((self.operation_id, self.repository, self.finding_key)):
                raise ValueError("invalid workflow operation identity")
        if self.issue_number is not None and (
            type(self.issue_number) is not int or self.issue_number <= 0
        ):
            raise ValueError("invalid workflow issue number")

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class WorkflowAudit:
    run_id: str = field(default_factory=lambda: str(uuid4()))
    events: list[WorkflowEvent] = field(default_factory=list)
    persistence_failed: bool = False
    _sink: Callable[[WorkflowEvent], None] | None = field(default=None, repr=False)

    def attach(self, sink: Callable[[WorkflowEvent], None]) -> None:
        if self._sink is not None:
            raise ValueError("workflow audit is already attached")
        self._sink = sink
        for event in self.events:
            self._persist(event)

    def detach(self) -> None:
        self._sink = None

    def _persist(self, event: WorkflowEvent) -> None:
        if self._sink is not None:
            try:
                self._sink(event)
            except BaseException:
                self.persistence_failed = True
                raise

    def emit(self, event: str, **fields: object) -> WorkflowEvent:
        record = WorkflowEvent(
            str(uuid4()), self.run_id, datetime.now(UTC).isoformat(), event, **fields
        )
        self.events.append(record)
        self._persist(record)
        return record

    def start(self) -> None:
        if not self.events:
            self.emit("run_started")

    def fail(self, exc: BaseException) -> None:
        if self.events and self.events[-1].event in {"run_failed", "run_interrupted"}:
            return
        self.start()
        self.emit(
            (
                "run_interrupted"
                if isinstance(exc, (KeyboardInterrupt, SystemExit))
                else "run_failed"
            ),
            error_type=type(exc).__name__,
        )

    def begin(
        self,
        operation: str,
        repository: str,
        finding_key: str,
        issue_number: int | None = None,
        labels: tuple[str, ...] = (),
        operation_id: str | None = None,
    ) -> WorkflowEvent:
        return self.emit(
            "operation_started",
            operation_id=operation_id or str(uuid4()),
            operation=operation,
            repository=repository,
            finding_key=finding_key,
            issue_number=issue_number,
            labels=labels,
        )

    def outcome(
        self,
        started: WorkflowEvent,
        event: str,
        *,
        issue_number: int | None = None,
        error_type: str | None = None,
    ) -> None:
        self.emit(
            event,
            operation_id=started.operation_id,
            operation=started.operation,
            repository=started.repository,
            finding_key=started.finding_key,
            issue_number=(
                issue_number if issue_number is not None else started.issue_number
            ),
            labels=started.labels,
            error_type=error_type,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "workflow_events": [item.as_dict() for item in self.events],
            "audit_persistence_failed": self.persistence_failed,
        }
