"""Conservative preflight and single-launch Ludus deployment workflow."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
import sys
import time
import math

from . import ludus, models, source
from .state import StateStore


def select_changed(
    staged: tuple[models.StagedRole, ...],
    entries: dict[str, models.UploadEntry | None],
    installed: frozenset[str],
    force: bool,
) -> dict[str, str]:
    """Return staged role identities requiring upload with safe reason labels."""
    changed: dict[str, str] = {}
    for role in staged:
        identity = role.role.identity
        old = entries.get(identity)
        if force:
            changed[identity] = "forced"
        elif identity not in installed:
            changed[identity] = "missing presence"
        elif old is None:
            changed[identity] = "missing history"
        elif old.status != "success" or old.manifest is None:
            changed[identity] = "untrusted history"
        elif (old.manifest.digest != role.manifest.digest
              or old.manifest.policy != role.manifest.policy):
            changed[identity] = "manifest or policy changed"
    return changed


def check_scope(scope: models.Scope, snapshot: models.RangeSnapshot) -> None:
    """Reject unsafe snapshots and require explicit full scope after destruction."""
    if scope not in {"roles", "full"}:
        raise models.DeploymentError("Deployment scope is invalid", 2, "blocked")
    if snapshot.busy or snapshot.testing:
        raise models.DeploymentError("Range is busy or testing; deployment is blocked", 2, "blocked")
    if snapshot.state == "DESTROYED" and scope != "full":
        raise models.DeploymentError("Full scope required; explicitly request --scope full.", 2, "blocked")
    known = {"DEPLOYING", "DESTROYING", "ERROR", "ABORTED", "DESTROYED", "NEVER DEPLOYED", "SUCCESS"}
    if snapshot.state not in known:
        raise models.DeploymentError("Range state is unsupported; deployment is blocked", 2, "blocked")
    if snapshot.state in {"DEPLOYING", "DESTROYING"}:
        raise models.DeploymentError("Range state is not safe for deployment", 2, "blocked")


def _summary(store: StateStore, run: models.RunRecord | None, outcome: models.Outcome,
             code: int, message: str) -> models.Summary:
    run_id = run.run_id if run is not None else None
    return models.Summary(run_id, None, None, outcome, code, message,
                          store.evidence_dir(run_id) if run_id else store.root)


def _persist(store: StateStore, run: models.RunRecord) -> None:
    _durable_write(store, store.save_run, run)


def _durable_write(store: StateStore, operation, *args):
    if getattr(store, "_workflow_state_unusable", False):
        raise RuntimeError("local deployment state is unavailable")
    try:
        return operation(*args)
    except Exception:
        store._workflow_state_unusable = True
        raise


@contextmanager
def _mutation_guard(store: StateStore):
    lock = store.mutation_lock()
    try:
        lock.__enter__()
    except Exception:
        yield False
        return
    try:
        yield True
    finally:
        lock.__exit__(None, None, None)


def failure_transition(run: models.RunRecord | None, requested_outcome: models.Outcome) -> models.RunRecord | None:
    """Pure immutable transition that never erases a known terminal result."""
    if run is None:
        return None
    if run.phase == "launched" and run.outcome == "accepted":
        return run
    if run.phase == "launch-rejected" and run.outcome == "failure":
        return run
    return replace(run, phase="failed", outcome=requested_outcome)


def _exception_summary(
    store: StateStore,
    run: models.RunRecord | None,
    outcome: models.Outcome,
    code: int,
    message: str,
) -> models.Summary:
    transitioned = failure_transition(run, outcome)
    evidence_ok = True
    if transitioned is not None and not getattr(store, "_workflow_state_unusable", False):
        try:
            with store.run_lock(transitioned.run_id):
                _persist(store, transitioned)
                _durable_write(store, store.write_event, transitioned.run_id,
                               {"type": "outcome", "disposition": transitioned.outcome})
        except Exception:
            store._workflow_state_unusable = True
            evidence_ok = False
    known_acceptance = transitioned is not None and transitioned.outcome == "accepted"
    if known_acceptance:
        return _summary(store, transitioned, "accepted", 4,
                        "Launch acceptance is known; local evidence update is uncertain")
    if not evidence_ok:
        return _summary(store, transitioned, "unknown", 4,
                        "Deployment stopped; local evidence could not be updated")
    return _summary(store, transitioned, outcome, code, message)


def deploy(
    range_id: str,
    scope: models.Scope,
    checkout_override: Path | None,
    force_upload: bool,
    store: StateStore,
) -> models.Summary:
    """Preflight, upload only changed roles, then issue at most one deploy request."""
    with _mutation_guard(store) as lock_acquired:
        if not lock_acquired:
            return _summary(store, None, "blocked", 2,
                            "Deployment state is busy; no target discovery or mutation was attempted")
        store._workflow_state_unusable = False
        session = None
        run = None
        try:
            session = ludus.discover_target(range_id)
            checkout = source.discover_checkout(Path.cwd(), checkout_override)
            config_text = session.read.active_config()
            active = source.parse_config(config_text, session.target.capabilities)
            snapshot = session.read.status()
            check_scope(scope, snapshot)
            session.validate_configured_roles(active.roles)
            roles = source.resolve_roles(checkout, active, session.target.capabilities)
            run = store.new_run(session.target, scope, checkout, active.digest)
            _persist(store, run)

            with store.run_lock(run.run_id):
                staged = source.stage_roles(roles, store.stage_root(run.run_id))
                run = replace(run, phase="staged", baseline=snapshot)
                _persist(store, run)
                entries = {item.role.identity: store.load_entry(session.target.server, item.role.identity)
                           for item in staged}
                installed = session.read.installed_roles()
                changed = select_changed(staged, entries, installed, force_upload)
                _durable_write(store, store.write_event, run.run_id,
                               {"type": "phase", "phase": "preflight"})
                if changed:
                    print("Roles selected for upload: " + "; ".join(
                        f"{identity} ({reason})" for identity, reason in sorted(changed.items())
                    ), file=sys.stderr)
                else:
                    print("Roles selected for upload: none", file=sys.stderr)

                deploy_client = None
                for item in staged:
                    identity = item.role.identity
                    if identity not in changed:
                        continue
                    if source.manifest(item.directory) != item.manifest:
                        run = replace(run, phase="upload", outcome="unknown")
                        _persist(store, run)
                        return _summary(store, run, "unknown", 4, "Staged role integrity changed; deployment stopped")
                    run = replace(run, phase="uploading", upload_count=run.upload_count + 1)
                    _persist(store, run)
                    reservation = models.UploadEntry(
                        session.target.server, identity, "in-flight", item.manifest, run.run_id,
                        None, checkout, (session.target.capabilities.client_version,
                                        session.target.capabilities.server_version),
                        (),
                    )
                    _durable_write(store, store.begin_upload, reservation)
                    if deploy_client is None:
                        deploy_client = ludus.enable_deploy(session)
                    result = deploy_client.upload(item)
                    if result.disposition != "confirmed":
                        _durable_write(store, store.write_event, run.run_id,
                                       {"type": "upload", "role": identity,
                                        "disposition": result.disposition})
                        disposition = "failure" if result.disposition == "failure" else "unknown"
                        run = replace(run, phase="upload", outcome=disposition)
                        _persist(store, run)
                        code = 3 if result.disposition == "failure" else 4
                        return _summary(store, run, disposition, code,
                                        "Role upload was denied" if code == 3 else "Role upload outcome is unknown; deployment stopped")
                    present = session.read.installed_roles()
                    if identity not in present:
                        run = replace(run, phase="upload", outcome="unknown")
                        _persist(store, run)
                        return _summary(store, run, "unknown", 4, "Uploaded role presence could not be verified")
                    verified = replace(
                        reservation, status="success", uploaded_at=datetime.now(timezone.utc).isoformat(),
                        identity_evidence=("user-scoped installed-role presence",),
                    )
                    _durable_write(store, store.save_entry, verified)
                    _durable_write(store, store.write_event, run.run_id,
                                   {"type": "upload", "role": identity, "disposition": "confirmed"})
                    run = replace(run, phase="upload", upload_count=run.upload_count)
                    _persist(store, run)

                # Revalidate all configured roles and active configuration immediately before launch.
                final_config = source.parse_config(session.read.active_config(), session.target.capabilities)
                final_status = session.read.status()
                final_installed = session.read.installed_roles()
                check_scope(scope, final_status)
                if final_config.digest != active.digest or not set(active.roles) <= final_installed:
                    run = replace(run, phase="verified", outcome="unknown")
                    _persist(store, run)
                    return _summary(store, run, "unknown", 4, "Final range preflight did not verify; deployment stopped")
                history = session.read.history_list()
                run = replace(
                    run, phase="launch-reserved", launch_count=1, baseline=final_status,
                    history_baseline=history, launch_started_at=datetime.now(timezone.utc).isoformat(),
                )
                _persist(store, run)
                _durable_write(store, store.write_event, run.run_id,
                               {"type": "launch", "phase": "launch-reserved"})
                if deploy_client is None:
                    deploy_client = ludus.enable_deploy(session)
                launch = deploy_client.launch(scope)
                finished_at = datetime.now(timezone.utc).isoformat()
                if launch.accepted is True:
                    run = replace(run, phase="launched", outcome="accepted",
                                  operation_id=launch.operation_id, launch_finished_at=finished_at)
                    _persist(store, run)
                    _durable_write(store, store.write_event, run.run_id,
                                   {"type": "launch", "disposition": "accepted"})
                    return _summary(store, run, "accepted", 0, "Deployment launch accepted; no outcome observation performed")
                if launch.accepted is False:
                    run = replace(run, phase="launch-rejected", outcome="failure",
                                  launch_finished_at=finished_at)
                    _persist(store, run)
                    _durable_write(store, store.write_event, run.run_id,
                                   {"type": "launch", "disposition": "failure"})
                    return _summary(store, run, "failure", 3, "Deployment launch was rejected")
                run = replace(run, phase="launch-unknown", outcome="unknown",
                              launch_finished_at=finished_at)
                _persist(store, run)
                _durable_write(store, store.write_event, run.run_id,
                               {"type": "launch", "disposition": "unknown"})
                return _summary(store, run, "unknown", 4, "Deployment launch outcome is unknown; do not retry automatically")
        except source.MissingRolesError as exc:
            try:
                message = session.safe_missing_roles_message(exc) if session is not None else "Configured roles could not be resolved safely"
            except Exception:
                message = "Configured roles could not be resolved safely"
            return _exception_summary(store, run, "blocked", 2, message)
        except models.DeploymentError as exc:
            return _exception_summary(store, run, exc.outcome, exc.exit_code, exc.message)
        except Exception:
            # Suppress parser, filesystem, and adapter details that may contain secrets.
            return _exception_summary(store, run, "unknown", 4,
                                      "Deployment stopped safely; local or remote state is uncertain")
        finally:
            if session is not None:
                session.close()
            if run is not None:
                try:
                    with store.run_lock(run.run_id):
                        store.cleanup_stage(run.run_id)
                except Exception:
                    # Cleanup must not mask the deployment result or mutation ambiguity.
                    pass


def correlate(run: models.RunRecord, observation: models.Observation) -> models.Outcome:
    """Automatic history attribution is unsupported; never infer a launch match."""
    return "unknown"


def selected_history_outcome(history_id: str, observation: models.Observation) -> models.Outcome:
    """Classify only the exact explicitly selected history record."""
    if observation.attribution != "user-selected" or observation.history_id != history_id:
        return "unknown"
    if observation.history_status == "success":
        return "success"
    if observation.history_status in {"failure", "aborted"}:
        return "failure"
    return "unknown"


def _observation_summary(store: StateStore, record: models.ObservationRecord,
                         outcome: models.Outcome, code: int, message: str) -> models.Summary:
    return models.Summary(record.source_run_id, record.observation_id, record.history_id,
                          outcome, code, message, store.evidence_dir(record.observation_id))


def _remaining_budget(deadline: float, now: float) -> float:
    """Return a nonnegative remaining monotonic-time budget."""
    return max(0.0, deadline - now)


def _persistable_history_id(observation: models.Observation | None) -> str | None:
    """Only retain a history ID returned through the adapter's screened observation."""
    if observation is None or observation.attribution != "user-selected":
        return None
    return observation.history_id


def monitor(*, run_id: str | None, range_id: str | None, history_id: str | None,
            wait: bool, timeout: float, store: StateStore, interval: float = 30) -> models.Summary:
    """Read-only, one-shot by default observation; no automatic history attachment."""
    valid_run = isinstance(run_id, str) and bool(run_id) and range_id is None and history_id is None
    valid_history = run_id is None and isinstance(range_id, str) and bool(range_id) and isinstance(history_id, str) and bool(history_id)
    if (not (valid_run or valid_history) or not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
            or not math.isfinite(timeout) or timeout <= 0
            or not isinstance(interval, (int, float)) or isinstance(interval, bool)
            or not math.isfinite(interval) or interval <= 0):
        return models.Summary(run_id, None, history_id, "blocked", 2,
                              "Monitor selection or timeout is invalid", store.root)
    try:
        run = store.load_run(run_id) if valid_run else None
    except Exception:
        return models.Summary(run_id, None, None, "unknown", 4, "Saved run could not be read safely", store.root)
    selected_range = run.target.range_id if run is not None else range_id
    session = None
    record = None
    observation = None
    try:
        deadline = time.monotonic() + timeout
        session = ludus.discover_target(selected_range)
        if run is not None and session.target != run.target:
            return models.Summary(run.run_id, None, None, "unknown", 4,
                                  "Discovered target does not match the saved run target", store.root)
        while True:
            if _remaining_budget(deadline, time.monotonic()) <= 0:
                outcome = "unknown"
                break
            observation = (session.read.observe_run(run) if run is not None
                           else session.read.observe_history(history_id))
            if observation.target != session.target:
                outcome = "unknown"
            elif run is not None:
                # Operation correlation is unknown-only for this adapter contract.
                outcome = "unknown"
            else:
                outcome = selected_history_outcome(history_id, observation)
            terminal = outcome in {"success", "failure"}
            remaining = _remaining_budget(deadline, time.monotonic())
            if not wait or terminal or remaining <= 0:
                break
            time.sleep(min(interval, remaining))
        record = store.new_observation(session.target, run.run_id if run else None,
                                       _persistable_history_id(observation))
        attribution = observation.attribution if observation is not None else "unknown"
        record = replace(record, attribution=attribution, outcome=outcome)
        with store.observation_lock(record.observation_id):
            store.save_observation(record)
            store.write_event(record.observation_id, {"type": "outcome", "disposition": outcome})
        if outcome == "success":
            code, message = 0, "Selected history record succeeded"
        elif outcome == "failure":
            code, message = 5, "Selected history record failed or was aborted"
        else:
            candidates = tuple(entry.history_id for entry in observation.candidates) if observation is not None else ()
            candidate_note = ("; candidate history IDs: " + ", ".join(candidates)) if candidates else ""
            code, message = 4, "Outcome remains unknown" + candidate_note + "; no history was attached to the run"
        return _observation_summary(store, record, outcome, code, message)
    except KeyboardInterrupt:
        if record is None and session is not None:
            try:
                record = store.new_observation(session.target, run.run_id if run else None,
                                               _persistable_history_id(observation))
                attribution = observation.attribution if observation is not None else "unknown"
                with store.observation_lock(record.observation_id):
                    store.save_observation(replace(record, attribution=attribution, outcome="unknown"))
            except Exception:
                pass
        if record is not None:
            return _observation_summary(store, record, "unknown", 4, "Observation interrupted; outcome is unknown")
        return models.Summary(None, None, None, "unknown", 4, "Observation interrupted; outcome is unknown", store.root)
    except Exception:
        if record is not None:
            return _observation_summary(store, record, "unknown", 4, "Observation stopped safely; outcome is unknown")
        return models.Summary(None, None, None, "unknown", 4,
                              "Observation stopped safely; outcome is unknown", store.root)
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


def reset_upload_history(store: StateStore) -> models.ResetSummary:
    """Invalidate the local upload ledger under the global mutation lock."""
    try:
        with store.mutation_lock():
            count = store.reset_upload_history()
        return models.ResetSummary(count, 0)
    except Exception:
        return models.ResetSummary(0, 2)
