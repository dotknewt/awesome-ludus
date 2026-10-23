# Reusable Ludus Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy one selected Ludus range using changed local role snapshots, with conservative shared upload history and separately invoked observation.

**Architecture:** A thin Python CLI delegates to source resolution/staging, private local state, a version-verified Ludus adapter, and two separate deploy/monitor workflows. The active checkout supplies roles; XDG state shares upload evidence across worktrees. A research deliverable fixes external semantics before implementation relies on them.

**Tech Stack:** Python >=3.11, PyYAML >=6.0,<7, installed Ludus CLI; Linux file locks/private state. Initial credential support is LUDUS_API_KEY env-only. No keyring dependency; absent env key blocks with secure set-env guidance.

**Spec:** `docs/superpowers/specs/2026-10-23-reusable-ludus-deployment-design.md` (approved).

## Global Constraints

- Planning only is currently authorized. No implementation, commits, live validation, or read-only remote discovery is authorized by this plan-writing task.
- `ansible/roles` in the active checkout/worktree is the sole role source; all configured roles resolve before mutations, even when installed remotely.
- Default scope is `roles`; `--scope full` is explicit. `DESTROYED` plus roles scope blocks before uploads. Never silently widen scope.
- Unknown means changed. Force-upload only changed/unknown roles; `--force-upload` selects all configured roles without bypassing gates.
- Successful deploy invokes launch once even with zero changes, then exits without monitoring. Ambiguous launch never triggers retry.
- Monitor cannot upload, deploy, or change upload history. Timeout is unknown, not success or failure.
- User-approved adjustment: exact effective endpoint/user upload keys, global local mutation lock, cross-key same-role invalidation before upload, and explicit local-only `reset-upload-history`. No context registration/epoch workflow. Default deploy still requires only `--range` and resolves ambient CLI settings.
- Monitor selects either a stored run or an explicit range/history ID. Explicit selection proves which history record is observed, not which launch created it. Run-based automatic attribution remains unknown-only for the researched version.
- Role presence is not content attestation; shared role overwrites can affect other ranges.
- Follow `docs/instructions/ludus-authoring.md` and `live-debugging.md`: static and separately authorized live evidence only; no simulated/fake server or mocked deployment behavior as runtime evidence.
- Local deterministic checks below establish parser/hash/filesystem properties only, not Ludus compatibility or deployment readiness.
- Use an isolated implementation worktree when execution is approved; inspect existing changes, preserve user work, and never select role sources from the script's location.
- Parent owns plan self-review against the spec and final validation; no execution method is selected here.

## Review Focus

1. Use exact endpoint/user keys, one global local lock, and invalidate other same-role entries before upload. Replacement detection is not automatic: document explicit all-upload-history reset after replacement/restore. Unknown authenticated identity blocks (Tasks 1, 3, 4, 7).
2. Duplicate YAML keys, dynamic identities, namespace collisions, and ambiguous resolution must block. A valid exact-folder match may differ from metadata under the verified filename-identity rule; record that mismatch without blocking solely on it (Task 2).
3. Source churn, untracked files, executable-bit changes, and escaping symlinks must not produce a ledger hash different from uploaded staging (Task 2).
4. Crash after upload or launch reservation must leave conservative state, never repeat launch, and never overwrite confirmed earlier upload evidence (Tasks 3, 5, 7).
5. Old terminal states/recaps, superseding deployments, and secret-bearing errors must yield unknown attribution or sanitized evidence, not false success or leaks (Tasks 3, 6, 7).

---

## File structure and dependency order

Create these paths during approved implementation, not during planning:

| Path | Responsibility |
| --- | --- |
| `docs/research/reusable-ludus-deployment-compatibility.md` | Version-specific compatibility evidence and release gates. |
| `scripts/ludus_deploy.py` | Executable argparse entry point only. |
| `scripts/ludus_deployment/__init__.py` | Package marker. |
| `scripts/ludus_deployment/models.py` | Shared dataclasses, enums, errors below. |
| `scripts/ludus_deployment/source.py` | Checkout discovery, config parsing, resolver, staged manifests. |
| `scripts/ludus_deployment/state.py` | Locks, ledger/run persistence, sanitized evidence. |
| `scripts/ludus_deployment/ludus.py` | Verified subprocess adapter; separate read-only and mutating capabilities. |
| `scripts/ludus_deployment/workflow.py` | Preflight, changed selection, single-launch deploy, read-only monitor. |
| `scripts/requirements-ludus-deploy.txt` | Explicit YAML dependency, version constrained by Task 1 findings. |
| `scripts/tests/test_ludus_source.py` | Local parser/resolver/manifest checks. |
| `scripts/tests/test_ludus_state.py` | Real local filesystem/locking/redaction checks. |
| `scripts/tests/test_ludus_contracts.py` | CLI and static mutation-boundary/command-shape checks. |
| `docs/using-ludus-deployment.md` | Usage, evidence limits, retention and recovery. |

Modify `README.md`, `docs/instructions/live-debugging.md`, and `.opencode/commands/live.md` for discovery and optional observation. Only if research requires explicit aliases, create `ansible/role-identities.yml`: schema `schema_version: 1`, `roles: {exact_identity: relative_directory_under_roles}`. No speculative mappings.

Dependencies: Task 1 gates all code; Task 2 defines shared contracts; Task 3 consumes them; Task 4 consumes Tasks 1–3; Task 5 consumes Tasks 2–4; Task 6 consumes Tasks 3–5; Task 7 integrates all. Keep execution sequential unless interfaces have been reviewed and explicit delegation is authorized.

## Shared interfaces (fixed local contract)

Use frozen dataclasses unless durable updates require replacement; `Path`, UTC ISO timestamps, and `str` SHA-256 digests are the common representations. Persist JSON with explicit schema versions. Unknown remote fields are not invented; Task 1 supplies verified decoding rules.

- `Scope = Literal['roles', 'full']`; `Outcome = Literal['accepted', 'success', 'failure', 'unknown', 'blocked']`.
- `ServerKey(identity: str, access_scope: str)`; identity is the exact credential-free effective endpoint, not a canonical server UUID. Scope is the effective authenticated user installation (`user:<validated-user-id>`), never range or credential. No registration record is required.
- `Capabilities(client_version: str, server_version: str, identity_rules: dict[str, str], correlation_mode: str)` contains only researched supported rules.
- `Target(server: ServerKey, range_id: str, capabilities: Capabilities)`; `Checkout(root: Path, revision: str | None)`.
- Private adapter-only `ResolvedContext(endpoint, effective_user, api_key, proxy, verify, executable, child_env)` is immutable, non-serializable, non-repr, and transient. `BoundSession` exposes `target: Target`, `read: ReadClient`, and `close() -> None`; it privately owns ResolvedContext. Raw credentials/config/env never enter shared models. No client can be constructed from Target alone. `discover_target(range_id: str) -> BoundSession`; `enable_deploy(session: BoundSession) -> DeployClient` is an explicit deploy-only capability request sharing the same binding.
- `ActiveConfig(digest: str, roles: tuple[str, ...])`; raw config is transient and not persisted.
- `ResolvedRole(identity: str, source: Path, resolution_evidence: tuple[str, ...])`.
- `Manifest(policy: int, digest: str, entries: tuple[tuple[str, str, int, str], ...])`: entries are relative path, type, executable bits, content digest.
- `StagedRole(role: ResolvedRole, directory: Path, manifest: Manifest)`.
- `RangeSnapshot(state: str, busy: bool, testing: bool, operation_id: str | None, cursor: str | None, observed_at: str)`; unsupported semantics block, not default false.
- `UploadEntry(server: ServerKey, role: str, status: Literal['success','unknown','in-flight'], manifest: Manifest | None, run_id: str, uploaded_at: str | None, checkout: Checkout, versions: tuple[str,str], identity_evidence: tuple[str,...])`.
- `HistoryEntry(history_id: str, status: Literal['running','success','failure','aborted'], start: str | None, end: str | None, created: str | None)`; validated range-scoped metadata. Unknown/malformed status yields an unknown observation, not a fabricated enum value.
- `RunRecord(run_id: str, target: Target, scope: Scope, checkout: Checkout, config_digest: str, phase: str, upload_count: int, launch_count: int, baseline: RangeSnapshot | None, history_baseline: tuple[HistoryEntry,...], launch_started_at: str | None, launch_finished_at: str | None, operation_id: str | None, outcome: Outcome)`; candidate IDs never populate `operation_id` automatically.
- Private adapter-only `_CommandResult(exit_code: int | None, timed_out: bool, stdout: str, stderr: str)` never crosses into workflow or state. `UploadResult(disposition: Literal['confirmed','unknown','failure'], message: str)` contains only a bounded sanitized message. Confirmed requires complete exact success JSON and no timeout/capture/process ambiguity; exit 0 alone is insufficient. Failure is only proven pre-send failure or source-traced pre-install denial; other errors are unknown. Workflow still verifies user-scoped identity before commit.
- `Observation(target: Target, history_id: str | None, history_status: str | None, attribution: Literal['unknown','user-selected'], snapshot: RangeSnapshot | None, candidates: tuple[HistoryEntry,...])` contains safe metadata only, no logs. Status is selected from exactly one range-scoped ID match; missing/pruned/duplicate ID or malformed/truncated response yields unknown.
- `LaunchResult(accepted: bool | None, operation_id: str | None)` distinguishes rejection from ambiguity; pinned acceptance has no operation ID.
- `ObservationRecord(observation_id: str, target: Target, source_run_id: str | None, history_id: str | None, attribution: Literal['unknown','user-selected'], outcome: Outcome)` stores minimal sanitized evidence, no raw logs. It does not mutate the source run's attribution.
- `Summary(run_id: str | None, observation_id: str | None, history_id: str | None, outcome: Outcome, exit_code: int, message: str, evidence_dir: Path)`; explicit-history mode need not have a deployment run ID. `ResetSummary(invalidated_entries: int, exit_code: int)` describes local-only reset.
- `DeploymentError(message: str, exit_code: int, outcome: Outcome)` must contain sanitized diagnostics only.

## Tasks

### Task 1: Publish compatibility gates before implementation

**Files:** Create `docs/research/reusable-ludus-deployment-compatibility.md`.

**Interfaces:** Consumes approved spec and repository policies. Produces an evidence table keyed by client/server version, verified operation/field, official URL or source revision, local adapter rule, evidence provenance, and unresolved release blocker.

- [ ] Identify supported client/server versions from already available evidence; if absent, mark unknown rather than assume latest. Obtain permission before any new remote discovery.
- [ ] During authorized research, read version-matched official CLI, roles, role-development, config/schema documentation and source where necessary. Record actual config forms, upload packaging/name precedence/force behavior, role-list visibility, scope flags, launch acceptance, status states and correlation facilities.
- [ ] Record exact endpoint/user, global lock/invalidation/reset, env-only credentials and verified middleware prefix/full-key authentication chain. Bind transport for discovery and later operations in one private session; no keyring or impersonation fallback. Record actual api_ansible.go naming handler and exact upload wrapper, including JSON CLI exit-0-on-error behavior.
- [ ] Specify metadata-only selected-history observation versus unknown-only run attribution; no raw log lookup. Record no-pagination retained-history list, pruning/missing ID unknown, and safe status decoding. ERROR alone is not rejected by pinned deploy source.
- [ ] Confirm Python/PyYAML constraints, actual local symlink needs, and uploader packaging exclusions. Record the exact supported minimum versions and command argument arrays to implement; do not populate these from guesses in this plan.
- [ ] Obtain separately authorized, read-only server evidence when needed to close identity/visibility questions. If unavailable, leave the gate blocked and report the precise missing evidence; this step authorizes no calls itself.
- [ ] Check every adapter behavior has a citation and every unresolved fact has a fail-closed consequence. Deliver this document for parent acceptance before code work depends on it.

### Task 2: Implement shared models, checkout resolution, and staging

**Files:** Create package marker, `models.py`, `source.py`, dependency file, and `test_ludus_source.py` from the structure above.

**Interfaces:** Consumes Task 1 rules. Produces `discover_checkout(cwd: Path, override: Path | None) -> Checkout`, `parse_config(raw: str, capabilities: Capabilities) -> ActiveConfig`, `resolve_roles(checkout: Checkout, config: ActiveConfig, capabilities: Capabilities) -> tuple[ResolvedRole,...]`, `manifest(directory: Path) -> Manifest`, `stage_roles(roles: tuple[ResolvedRole,...], stage_root: Path) -> tuple[StagedRole,...]`.

- [ ] Add deterministic checks `test_duplicate_keys_rejected`, `test_dynamic_or_ambiguous_identity_blocks`, `test_exact_folder_wins_despite_metadata_disagreement`, `test_missing_namespaced_folder_requires_mapping`, and `test_archive_suffix_identity_rejected`: enforce pinned basename naming, no metadata-only/suffix fallback, and conflicting mapping rejection. Use local YAML/directory fixtures only.
- [ ] Add `test_worktree_override_and_cwd`, using real temporary Git checkouts/worktrees: assert source root follows cwd/override, not executable location. Add `test_manifest_tracks_untracked_deletion_and_exec_bits`: assert each meaningful change changes digest, while mtime does not.
- [ ] Add `test_symlink_escape_rejected` and `test_stage_matches_complete_source_manifest`: assert source/stage manifests match, excluded entries are absent, and changed manifests reject consistency. These checks do not claim concurrent server behavior.
- [ ] Run `python -m unittest discover -s scripts/tests -p test_ludus_source.py -v`; before implementation expect missing interfaces, not unrelated environment errors.
- [ ] Define serializable shared models above (private session/raw-result types stay in adapter). Implement exact-folder-first resolution: configured R uses contained ansible/roles/R even if metadata name differs; require metadata fields but do not treat metadata-only names as competing installed candidates. Without exact folder require explicit contained mapping; conflicting exact-folder/mapping or duplicate identity blocks. Full namespaced folders are exact matches; no namespace inference. Reject unsafe names or those changed by pinned archive-suffix stripping. Validate internal/dependency references separately.
- [ ] Implement private copies and version-1 manifest policy: sorted relative entries, SHA-256 bytes, types and executable bits; exclude `.git`, `__pycache__`, and `*.pyc` consistently in copy/hash, subject to Task 1 packaging confirmation. Reject special files/symlinks; compare full source before/after and staging manifests.
- [ ] Rerun the local checks; require all passing and label them local source-integrity evidence only.

### Task 3: Implement durable state, locks, and evidence security

**Files:** Create `state.py` and `test_ludus_state.py`.

**Interfaces:** Consumes shared models. Produces `StateStore(root: Path | None = None)` with `mutation_lock() -> ContextManager[None]` (global across all keys), `run_lock(run_id: str) -> ContextManager[None]`, `load_entry(server: ServerKey, role: str) -> UploadEntry | None`, `save_entry(entry: UploadEntry) -> None`, `begin_upload(entry: UploadEntry) -> None`, `reset_upload_history() -> int`, `new_run(target: Target, scope: Scope, checkout: Checkout, config_digest: str) -> RunRecord`, `load_run(run_id: str) -> RunRecord`, `save_run(run: RunRecord) -> None`, `new_observation(target: Target, source_run_id: str | None, history_id: str | None) -> ObservationRecord`, `save_observation(record: ObservationRecord) -> None`, `observation_lock(observation_id: str) -> ContextManager[None]`, `stage_root(run_id: str) -> Path`, `evidence_dir(record_id: str) -> Path`, `write_event(record_id: str, event: dict[str, object]) -> None`, `cleanup_stage(run_id: str) -> None`. `begin_upload` requires the global lock, invalidates every other server/user entry with the exact same role, and persists target in-flight before returning. `reset_upload_history` requires the global lock, durably invalidates all upload entries and returns a count, preserving run/observation evidence. Neither performs network calls. Produces `sanitize(text: str, known_secrets: frozenset[str]) -> str`.

- [ ] Add `test_private_paths_and_symlink_rejection`, `test_scope_partition_and_lock_domain`, and `test_real_process_lock_contention`: assert `0700`/`0600`, unsafe-path rejection, Task 1 key partitioning, and non-stealable lock contention using actual local processes, not a fake server.
- [ ] Add `test_inflight_is_unknown_after_reopen`, `test_atomic_record_preserves_confirmed_entries`, and `test_corrupt_state_blocks`: assert persistent conservative recovery, per-role isolation, and no corrupt-cache hit using real temporary files.
- [ ] Add real-filesystem checks for cross-key same-role invalidation before upload reservation, reset invalidating all upload entries while preserving evidence, and shared lock contention across different endpoint/user keys. Failed invalidation blocks remote mutation.
- [ ] Add `test_sanitizes_exception_and_output_canaries`: representative tokens, credential URLs, nested sensitive fields and oversized messages must not reach stored/display-ready events; mark unknown payloads suppressed. This local check does not prove live output sanitization.
- [ ] Run `python -m unittest discover -s scripts/tests -p test_ludus_state.py -v`; expect missing implementation initially.
- [ ] Implement XDG state outside worktrees, one global kernel mutation lock, run/observation evidence locks, atomic replacement/fsync, ownership and path checks. Implement pre-upload cross-key invalidation and all-entry reset. Map in-flight to unknown on read; never resume a launch or repair insecure state automatically.
- [ ] Implement bounded sanitized journals and stage cleanup. Use UUID run IDs; persist minimal metadata, never raw config/credentials/environment. Cap each diagnostic at 64 KiB and each run journal at 10 MiB with an explicit truncation event; document manual retention cleanup rather than adding a scheduler.
- [ ] Rerun checks; review actual durable-write failure paths statically, carrying any unexercised interruption guarantees into Task 7 live gaps.

### Task 4: Implement only verified Ludus adapter operations

**Files:** Create `ludus.py`; create `test_ludus_contracts.py`.

**Interfaces:** Consumes evidence, models and sanitization. Private `resolve_context() -> ResolvedContext` resolves ambient settings and required env key once, without network calls. `discover_target(range_id: str) -> BoundSession` creates that context, uses its frozen transport for version and authenticated selected-config/installed-role reads, and only returns after valid shapes/authentication; `BoundSession.target` is safe, `BoundSession.read` is the default capability. Private `_ReadClient(context: ResolvedContext, target: Target)` exposes `active_config() -> str`, `status() -> RangeSnapshot`, `installed_roles() -> frozenset[str]` (user-scoped identities), `history_list() -> tuple[HistoryEntry,...]`, `observe_history(history_id: str) -> Observation`, `observe_run(run: RunRecord) -> Observation`. No raw log/detail method. `enable_deploy(session: BoundSession) -> DeployClient` explicitly supplies the same context to a deploy-only client with `upload(role: StagedRole) -> UploadResult` and `launch(scope: Scope) -> LaunchResult`; it does not re-resolve credentials/settings. Both clients use private `_execute(argv: tuple[str,...]) -> _CommandResult` with frozen context/env, bounded capture/timeouts, no shell/retry. All public diagnostics/results are sanitized; raw process output remains private. Close session in finally paths; serialization/repr of binding is forbidden.

- [ ] Add local/static `test_adapter_command_shapes_match_research` and `test_read_client_has_no_mutation_entrypoint`: compare exact argument construction to Task 1's documented contract and inspect the read-only call boundary without issuing commands or synthesizing server responses.
- [ ] Run `python -m unittest discover -s scripts/tests -p test_ludus_contracts.py -v`; require the new contracts to fail before adapter implementation.
- [ ] Implement version gating and structured decoding. Upload confirmation requires complete exact `{"result":"Successfully installed role"}` and exit 0 without timeout/truncation; pinned handler returns HTTP 201, but CLI JSON mode also exits 0 on errors. Private raw capture never leaves adapter. Return failure only for local pre-send failure or exact source-traced pre-install authorization denials; other error wrappers/post-install failures/disconnects/nonzero/ambiguous output are unknown. Keep affected ledger unknown and never retry.
- [ ] Resolve initial endpoint/proxy/verify via CLI-compatible env/config/default rules. Require nonempty LUDUS_API_KEY, exactly two nonempty dot-separated parts and safe user prefix; reject ROOT/ambient impersonation. Prefix binding is authenticated by successful same-session config/roles reads (middleware chain in research), not assumed from format. Missing key blocks before calls with secure set-env guidance; no keyring reads/dependency.
- [ ] Freeze resolved executable and private env; strip inherited LUDUS_* then inject captured LUDUS_API_KEY/LUDUS_PROXY, snapshot approved process/certificate/standard proxy vars. Every argv appends --config /dev/null, exact --url, explicit --verify=true|false, --user plus empty argument. Never print secret env/proxy or use mutable ambient config between calls. Add local/static checks for read-only default, explicit deploy capability, frozen binding, no Target-only I/O, and no raw-result leaks; no server mocks.
- [ ] Implement metadata-only history array decoding. Pinned endpoint returns all retained entries without pagination; default pruning retains 10. Exactly one selected ID must match; absent/pruned/duplicate ID, unexpected pagination wrapper, truncation or malformed status yields unknown. No raw detail/log calls or current-state fallback; candidate metadata never attaches to a run.
- [ ] Ensure credential-bearing streams never enter exceptions/events raw; keep config transient, extract known secret values in memory, and suppress diagnostics whose safe representation is uncertain. Reject target/server changes rather than retargeting an existing run.
- [ ] Keep secret registry private to the shared session; populate from captured credentials/config and staged role defaults before upload output handling. Emit only sanitized diagnostics across adapter boundary. Monitor retrieves metadata only and suppresses raw subprocess payloads. Never serialize registry/binding.
- [ ] Rerun static checks and inspect capability boundaries; explicitly record that no server compatibility has been tested by these checks.

### Task 5: Implement preflight and single-launch deploy workflow

**Files:** Create `workflow.py`; extend `test_ludus_contracts.py`.

**Interfaces:** Consumes Tasks 2–4. Produces `select_changed(staged: tuple[StagedRole,...], entries: dict[str,UploadEntry | None], installed: frozenset[str], force: bool) -> dict[str,str]`, `check_scope(scope: Scope, snapshot: RangeSnapshot) -> None`, `deploy(range_id: str, scope: Scope, checkout_override: Path | None, force_upload: bool, store: StateStore) -> Summary`. Under store.mutation_lock, create one session via discover_target(range_id), use session.read for preflight, then explicitly enable_deploy(session) after gates. Consume UploadResult, never _CommandResult; post-upload verification uses the same session.read. Close session on every exit. Only deploy/reset workflows mutate ledger via StateStore.

- [ ] Add local `test_changed_selection` assertions: hash/policy mismatch, missing presence, unknown/in-flight/missing history and force select the role; equal trusted manifest plus presence does not. Add `test_destroyed_requires_explicit_full`: roles raises exit 2 with “Full scope required; explicitly request --scope full.”
- [ ] Add static `test_launch_has_one_callsite_outside_upload_loop` and `test_preflight_precedes_upload`: inspect workflow structure for one reserved launch after gates and no early return on an empty changed set. These checks are structural evidence, not execution-path or server proof.
- [ ] Run the contract checks, then implement lock acquisition before reading ledger/preflight state. Resolve all active-config roles, reject unsafe range state, stage snapshots, and print the complete changed/unknown list before mutations.
- [ ] Implement changed-only force uploads: integrity check staging, call `begin_upload` to durably invalidate other same-role keys and reserve target in-flight before upload, verify exact user-scoped identity after success, then commit only target. Stop on ambiguity/failure; never restore invalidated other-key entries.
- [ ] Implement final all-role presence/config-digest/status checks, durable launch reservation/count one with status/history baseline, then one launch regardless of changed-set size. Record accepted/rejected/unknown and exit without observation; write failure summaries without retry or scope widening.
- [ ] Rerun deterministic/static checks; list launch-loss, partial-upload, source-race and external-client interference behavior as pending actual-entrypoint validation rather than fabricating runtime evidence.

### Task 6: Add monitor-only command and CLI reporting

**Files:** Extend `workflow.py`, `test_ludus_contracts.py`; create `scripts/ludus_deploy.py`.

**Interfaces:** Produces `correlate(run: RunRecord, observation: Observation) -> Outcome` (unknown for pinned automatic attribution), `selected_history_outcome(history_id: str, observation: Observation) -> Outcome`, `monitor(*, run_id: str | None, range_id: str | None, history_id: str | None, wait: bool, timeout: float, store: StateStore) -> Summary`, `reset_upload_history(store: StateStore) -> ResetSummary`, and `main(argv: list[str] | None = None) -> int`. Select run_id alone or range_id+history_id. Monitor calls discover_target(selected_range) once, uses only session.read (never enable_deploy), requires session.target to match saved target for run mode, and writes separate ObservationRecord under its lock. Poll same binding, close on all exits; never edit upload history or attach launch IDs. Reset constructs no session/client, takes global lock, resets local history, reports count.

- [ ] Add CLI checks for deploy range/default roles/full/checkout/force; monitor mutually exclusive run versus range+history-ID selectors; one-shot default, optional wait, positive timeout; local-only reset without target/credentials. Exit 0 means acceptance, selected-history success, or local reset success as labeled; 2 blocker; 3 confirmed upload/launch failure; 4 unknown/nonterminal; 5 selected-history failure/aborted.
- [ ] Add static `test_monitor_has_only_read_capabilities`, `test_monitor_requires_explicit_history_selection`, and `test_reset_has_no_remote_capability`: inspect no monitor deploy/upload/ledger writes, no candidate auto-attachment, exact-ID status selection, no recap shortcut, and reset's client-free path. Reserve actual history/status behavior for authorized live checks, not invented server fixtures.
- [ ] Run the contract checks before implementing CLI/monitor. Implement default one-shot observation, `--wait` with a recommended 30-second interval and 10,800-second default limit, and unknown on timeout/interruption/lost attribution. Verified operation correlation rules come exclusively from Task 1.
- [ ] Implement sanitized summaries with optional source-run ID, observation ID, selected-history ID, attribution, target/range and known scope, phase/counts/outcome/evidence. Acceptance prints `Accepted; completion unobserved` and `python scripts/ludus_deploy.py monitor --run RUN_ID`. Explain selecting a candidate via `monitor --range RANGE --history-id ID [--wait --timeout SECONDS]` reports that record, not launch provenance. Run mode never auto-attaches. Selected success maps to success; failure/aborted to failure; running/missing/unknown to unknown. Reserved/crashed runs remain observation-only. Reset reports local invalidation count.
- [ ] Rerun local/static checks plus `python scripts/ludus_deploy.py --help`; help must not discover a server or read credentials. Confirm default deploy exits after launch by code review, leaving actual runtime proof gated.

### Task 7: Integrate documentation and report verification boundaries

**Files:** Create `docs/using-ludus-deployment.md`; modify `README.md`, `docs/instructions/live-debugging.md`, `.opencode/commands/live.md`; update compatibility evidence with authorized results only.

**Interfaces:** Consumes completed CLI, exit contract and evidence report. Produces one consistent user-facing launch/observe policy and a static/live/unknown verification summary.

- [ ] Document ambient endpoint/proxy/verify selection without registration, env-only LUDUS_API_KEY support and secure guidance for keyring-only users, private frozen session, exact-folder-first resolution, sanitized UploadResult, global lock/cross-key invalidation/reset, force-all-configured override and non-attestation. Explain metadata-only selected-history completion versus unknown launch attribution, retention/missing-ID unknown, one-shot/wait, and no auto-resumed mutations.
- [ ] Reconcile mandatory monitoring in current policy: default deploy is launch-only; `/live` invokes deploy once then monitor for an explicitly requested observed cycle. --run remains unknown without authoritative attribution; user selection of history ID reports only that record's result, never auto-pick a candidate. Preserve range/scope, changed-role scope limits, and prohibit broader flags or retries.
- [ ] Run all three local check files with `python -m unittest discover -s scripts/tests -p 'test_ludus_*.py' -v`; compile only changed Python files using `python -m py_compile <explicit changed files>` and inspect `git diff --check`. Expected: all selected checks pass; report unavailable checks rather than widening to unchanged roles.
- [ ] Prepare a live evidence matrix with separate authorization required per mutating cycle: initial upload, unchanged launch, uncommitted/cross-worktree content, missing/ambiguous local source, destroyed+roles zero-upload block, explicit full, partial/ambiguous uploads, lock contention/crash recovery, ambiguous launch, explicit-history success/failure/aborted/running/missing ID, unrelated newer deployment, run candidates without automatic attribution, observation timeout and production canary sanitization. Check reset locally without remote calls.
- [ ] Execute only individually authorized matrix rows through actual entrypoints; obtain separate permission for remote discovery, failure injection, destructive setup or guest probes. No row or failure implicitly authorizes the next cycle. Record server versions, artifact hashes, exact commands, sanitized outcomes and remaining gaps; absent approval, mark all live rows not run.
- [ ] Hand evidence and changed-file diff to the parent for spec review and final validation. Separate local/static evidence from live compatibility; retain `PASS WITH WARNINGS — NOT VERIFIED` where required by policy. Do not claim deployment readiness, commit, or begin another cycle without the applicable authorization.
