"""Serializable shared data contracts for reusable Ludus deployment."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Scope = Literal["roles", "full"]
Outcome = Literal["accepted", "success", "failure", "unknown", "blocked"]


@dataclass(frozen=True)
class ServerKey:
    identity: str
    access_scope: str


@dataclass(frozen=True)
class Capabilities:
    client_version: str
    server_version: str
    identity_rules: dict[str, str]
    correlation_mode: str


@dataclass(frozen=True)
class Target:
    server: ServerKey
    range_id: str
    capabilities: Capabilities


@dataclass(frozen=True)
class Checkout:
    root: Path
    revision: str | None


@dataclass(frozen=True)
class ActiveConfig:
    digest: str
    roles: tuple[str, ...]


@dataclass(frozen=True)
class ResolvedRole:
    identity: str
    source: Path
    resolution_evidence: tuple[str, ...]


@dataclass(frozen=True)
class Manifest:
    policy: int
    digest: str
    entries: tuple[tuple[str, str, int, str], ...]


@dataclass(frozen=True)
class StagedRole:
    role: ResolvedRole
    directory: Path
    manifest: Manifest


@dataclass(frozen=True)
class RangeSnapshot:
    state: str
    busy: bool
    testing: bool
    operation_id: str | None
    cursor: str | None
    observed_at: str


@dataclass(frozen=True)
class UploadEntry:
    server: ServerKey
    role: str
    status: Literal["success", "unknown", "in-flight"]
    manifest: Manifest | None
    run_id: str
    uploaded_at: str | None
    checkout: Checkout
    versions: tuple[str, str]
    identity_evidence: tuple[str, ...]


@dataclass(frozen=True)
class HistoryEntry:
    history_id: str
    status: Literal["running", "success", "failure", "aborted"]
    start: str | None
    end: str | None
    created: str | None


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    target: Target
    scope: Scope
    checkout: Checkout
    config_digest: str
    phase: str
    upload_count: int
    launch_count: int
    baseline: RangeSnapshot | None
    history_baseline: tuple[HistoryEntry, ...]
    launch_started_at: str | None
    launch_finished_at: str | None
    operation_id: str | None
    outcome: Outcome


@dataclass(frozen=True)
class UploadResult:
    disposition: Literal["confirmed", "unknown", "failure"]
    message: str


@dataclass(frozen=True)
class Observation:
    target: Target
    history_id: str | None
    history_status: str | None
    attribution: Literal["unknown", "user-selected"]
    snapshot: RangeSnapshot | None
    candidates: tuple[HistoryEntry, ...]


@dataclass(frozen=True)
class LaunchResult:
    accepted: bool | None
    operation_id: str | None


@dataclass(frozen=True)
class ObservationRecord:
    observation_id: str
    target: Target
    source_run_id: str | None
    history_id: str | None
    attribution: Literal["unknown", "user-selected"]
    outcome: Outcome


@dataclass(frozen=True)
class Summary:
    run_id: str | None
    observation_id: str | None
    history_id: str | None
    outcome: Outcome
    exit_code: int
    message: str
    evidence_dir: Path


@dataclass(frozen=True)
class ResetSummary:
    invalidated_entries: int
    exit_code: int


class DeploymentError(Exception):
    """Safe, user-facing deployment diagnostic."""

    def __init__(self, message: str, exit_code: int, outcome: Outcome):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.outcome = outcome
