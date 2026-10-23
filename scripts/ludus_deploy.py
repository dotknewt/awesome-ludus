#!/usr/bin/env python3
"""Reusable Ludus deployment and read-only observation CLI."""

from __future__ import annotations

import argparse
import math
import shlex
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ludus_deployment import ludus, models, workflow
from scripts.ludus_deployment.state import StateStore


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's default diagnostic embeds arbitrary supplied values.
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def _positive_finite(value: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("timeout must be a finite positive number") from None
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return number


def _build_parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(description="Deploy reusable Ludus roles and observe selected outcomes.")
    commands = parser.add_subparsers(dest="command", required=True)

    deploy = commands.add_parser("deploy", help="upload changed roles and issue one deployment request")
    deploy.add_argument("--range", required=True, help="Ludus range ID")
    deploy.add_argument("--scope", choices=("roles", "full"), default="roles")
    deploy.add_argument("--checkout", type=Path)
    deploy.add_argument("--force-upload", action="store_true", help="upload all resolved roles")

    monitor = commands.add_parser("monitor", help="read-only, explicit outcome observation")
    selectors = monitor.add_mutually_exclusive_group()
    selectors.add_argument("--run", dest="run_id", help="observe the target saved for this local run")
    selectors.add_argument("--range", dest="range_id", help="range for an explicitly selected history record")
    monitor.add_argument("--history-id", help="exact history record to observe; required with --range")
    monitor.add_argument("--wait", action="store_true", help="poll until a known selected-history outcome or timeout")
    monitor.add_argument("--timeout", type=_positive_finite, default=10800)
    monitor.add_argument("--interval", type=_positive_finite, default=30, help="poll interval in seconds")

    commands.add_parser("reset-upload-history", help="clear local upload-history cache (no remote access)")
    return parser


def _safe_display_id(value: str | None, kind: str, *, verified: bool = False) -> str | None:
    """Display an identifier only after a matching persisted record was verified."""
    if not verified or not isinstance(value, str):
        return None
    if kind in {"run", "observation"}:
        try:
            parsed = uuid.UUID(value)
        except (ValueError, AttributeError):
            return None
        return value if str(parsed) == value else None
    if kind == "history":
        return ludus._safe_history_id(value, ())
    return None


def _safe_report_text(value: str) -> str:
    return ludus._safe_metadata_text(value, ()) or "[unavailable]"


def _verified_report_ids(summary: models.Summary, store: StateStore) -> tuple[frozenset[str], tuple[str, ...]]:
    verified: set[str] = set()
    details: list[str] = []
    run = None
    if summary.run_id:
        try:
            run = store.load_run(summary.run_id)
            if run.run_id == summary.run_id and _safe_display_id(run.run_id, "run", verified=True):
                verified.add(run.run_id)
                details.append(f"Target: {_safe_report_text(run.target.server.identity)}; access scope: "
                               f"{_safe_report_text(run.target.server.access_scope)}; range: "
                               f"{_safe_report_text(run.target.range_id)}; scope: {run.scope}; Phase: {run.phase}; "
                               f"uploads: {run.upload_count}; launches: {run.launch_count}")
        except Exception:
            run = None
    if summary.observation_id:
        try:
            observation = store.load_observation(summary.observation_id)
            if (observation.observation_id == summary.observation_id
                    and _safe_display_id(observation.observation_id, "observation", verified=True)):
                verified.add(observation.observation_id)
                details.append(f"Target: {_safe_report_text(observation.target.server.identity)}; access scope: "
                               f"{_safe_report_text(observation.target.server.access_scope)}; range: "
                               f"{_safe_report_text(observation.target.range_id)}")
                details.append(f"Attribution: {observation.attribution}; Phase: observation; "
                               "uploads: N/A; launches: N/A")
                if observation.history_id and observation.history_id == summary.history_id:
                    safe_history_id = _safe_display_id(observation.history_id, "history", verified=True)
                    if safe_history_id:
                        verified.add(observation.history_id)
                        details.append("Selected-record command: python scripts/ludus_deploy.py monitor --range "
                                       f"{shlex.quote(_safe_report_text(observation.target.range_id))} --history-id "
                                       f"{shlex.quote(safe_history_id)}")
                        details.append("This reports the selected history record's outcome, not launch provenance.")
                # Run observations surface adapter-screened candidates to support explicit selection.
                candidate_text = summary.message.partition("candidate history IDs: ")[2].partition(";")[0]
                for candidate in candidate_text.split(", ") if candidate_text else ():
                    safe_candidate = ludus._safe_history_id(candidate, ())
                    if safe_candidate:
                        details.append("Candidate command: python scripts/ludus_deploy.py monitor --range "
                                       f"{shlex.quote(_safe_report_text(observation.target.range_id))} --history-id "
                                       f"{shlex.quote(safe_candidate)}")
                        details.append("This reports the selected history record's outcome, not launch provenance.")
                if observation.source_run_id and observation.source_run_id == summary.run_id:
                    try:
                        source_run = store.load_run(observation.source_run_id)
                        if source_run.target == observation.target:
                            verified.add(source_run.run_id)
                    except Exception:
                        pass
        except Exception:
            pass
    return frozenset(verified), tuple(details)


def _report(summary: models.Summary, *, command: str, details: tuple[str, ...] = (),
            verified_ids: frozenset[str] = frozenset()) -> None:
    print(f"{command}: {summary.message}")
    for detail in details:
        print(detail)
    print(f"Outcome: {summary.outcome}; exit code: {summary.exit_code}")
    if command == "Monitor":
        print("Candidate history selection: python scripts/ludus_deploy.py monitor --range RANGE --history-id ID")
        print("Selected history reports that record's outcome, not launch provenance.")
    run_id = _safe_display_id(summary.run_id, "run", verified=summary.run_id in verified_ids)
    observation_id = _safe_display_id(summary.observation_id, "observation",
                                      verified=summary.observation_id in verified_ids)
    history_id = _safe_display_id(summary.history_id, "history", verified=summary.history_id in verified_ids)
    if run_id:
        print(f"Run: {run_id}")
    if observation_id:
        print(f"Observation: {observation_id}")
    if history_id:
        print(f"Selected history: {history_id}")
    print(f"Evidence: {summary.evidence_dir}")
    if summary.outcome == "accepted" and run_id:
        print("Accepted; completion unobserved")
        print(f"Monitor with: python scripts/ludus_deploy.py monitor --run {shlex.quote(run_id)}")


def _open_store() -> StateStore | None:
    try:
        return StateStore()
    except Exception:
        print("Private local state is unavailable; no operation was performed")
        return None


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "deploy":
        store = _open_store()
        if store is None:
            return 2
        summary = workflow.deploy(args.range, args.scope, args.checkout, args.force_upload, store)
        verified_ids, details = _verified_report_ids(summary, store)
        _report(summary, command="Deploy", details=details, verified_ids=verified_ids)
        return summary.exit_code
    if args.command == "monitor":
        if args.run_id is None and (args.range_id is None or args.history_id is None):
            parser.error("monitor requires --run RUN_ID or both --range RANGE and --history-id ID")
        if args.run_id is not None and args.history_id is not None:
            parser.error("--history-id is only valid with --range")
        store = _open_store()
        if store is None:
            return 2
        summary = workflow.monitor(run_id=args.run_id, range_id=args.range_id,
                                   history_id=args.history_id, wait=args.wait,
                                   timeout=args.timeout, interval=args.interval, store=store)
        verified_ids, details = _verified_report_ids(summary, store)
        _report(summary, command="Monitor", details=details, verified_ids=verified_ids)
        return summary.exit_code
    store = _open_store()
    if store is None:
        return 2
    summary = workflow.reset_upload_history(store)
    if summary.exit_code == 0:
        print(f"Local upload history reset; invalidated {summary.invalidated_entries} entr{'y' if summary.invalidated_entries == 1 else 'ies'}")
    else:
        print("Local upload history reset failed safely")
    return summary.exit_code


if __name__ == "__main__":
    sys.exit(main())
