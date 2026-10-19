# Scoped Stock-Log Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the approved two-file reader policy through native producer settings without widening privileges or changing log rotation.

**Architecture:** A fixed-purpose private helper recognizes a reviewed configuration profile, constructs narrowly bracketed legacy actions, preflights and applies descriptor-based group changes and producer configuration. Linux logging invokes it before read checks; existing UF pipeline production ordering remains unchanged. Stateful test adapters isolate privileged operations without replacing policy.

**Tech Stack:** Python standard library, Ansible, pytest, existing sandbox harness.

**Spec:** `docs/superpowers/specs/2026-10-18-stock-log-access.md`.

## Global Constraints

- Only auth.log/syslog group migration; root owner0640 retained; existing splunkfwd/splunk groups only. No accounts/memberships/ACLs/capabilities changes.
- No logrotate configuration, schedule/retention, telemetry/profile, forwarder production or Splunk production changes. Splunk-local composition remains deferred.
- Preserve accepted Laurel installer and tests/test_artifact.py byte-for-byte. Existing Linux tests/test_role.py may be extended from that accepted baseline.
- No downloads beyond already frozen source references, dependencies, real service commands, vendor execution, guest operations, deployment, gate promotion, commits or cleanup of existing evidence.
- One source writer at a time: task2 consumes task1's private policy/model interface; task3 consumes the settled Linux fixture. No parallel fake-command writers.
- Current environment UID/GID1000/1000; rsyslogd absent. Models are explicit, not live root/native-service evidence.

## Review Focus

- Finalization clarification after Task1 review: assemble JSON only after owned
  resource cleanup; report ordered cleanup_errors and stage cleanup on otherwise
  successful application, retaining its valid marker. Preserve primary failures,
  account actual mutations and unconfirmed private leftovers, and never retry
  failed FD closes. See the spec and task-1-finalization-diagnosis.md; this is a
  private additive reporting contract, not a public phase or permission change.

- Restoring FileGroup must preserve every unrelated action and byte, including selectors/template/sync behavior.
- Profile matching must inspect the complete supported include inventory, not ignore unknown rotation or producer fragments.
- Metadata and configuration races/partial failures must never become a false applied marker or downstream activation.
- Existing active consumers and unrelated logs/archives must survive failures unchanged.
- Actual entrypoint tests must use production policy with state-derived privileged-operation fakes, not unconditional helper success.

### Task 1: Fixed-purpose policy helper, references and focused tests

**Files:**
- Create `ansible/roles/ludus_detection_linux_logging/files/configure_stock_log_access.py`.
- Create `ansible/roles/ludus_detection_linux_logging/files/stock-log-profiles/bookworm/` with reviewed profile text files, `manifest.json` and `PROVENANCE.md`.
- Create `ansible/roles/ludus_detection_linux_logging/tests/test_stock_log_access.py` and `tests/stock_access_model.py`.

**Interfaces:** Private CLI takes root prefix, reader, fixed role reference directory and command paths for dpkg-query/getent/systemctl/rsyslogd/runuser. No arbitrary source/group/policy map. Python `main(argv=None, *, host=None)` uses the native host adapter by default; test code may inject the modeled privileged-operation adapter, but CLI/environment has no bypass/test-mode flag. Output is one JSON result with `changed`, `stage`, `changed_paths` and `producer_active`; exit0 only after successful application/convergence. Failure retains truthful partial-state fields. Do not introduce public role phases or readiness objects.

`producer_active` is `true|false|null` under the spec's observation contract.
The native adapter reads named systemd properties (LoadState, ActiveState,
SubState, MainPID, ExecStart, DropInPaths, RootDirectory, RootImage) and checks
process executable/argv/root/mount/start identity through `/proc`; the test
adapter supplies these observations from state without bypassing policy.
Require the exact configured/running argv vector in the spec, including no
alternate `-f`; reject unrecognized/multiple ExecStart records. The native CLI
supports this normal host producer profile, not a live alternate-root service;
test root prefixes are exercised through the injected model only.

- [ ] Vendor exact frozen source bytes, not HTML or recreated approximations. Map required target files and optional rotation names in the manifest, with original URL/version/hash. Global logrotate config is REQUIRED (correcting preflight report's optional label). Include reviewed rsyslog service reference as provenance for expected invocation, not a claim of runtime unit identity.
- [ ] Add `test_candidate_preserves_original_actions_and_unrelated_bytes`: both reader names, exactly two set/restore pairs, original selectors intact, every other byte unchanged, generated form converges, different-reader form refuses.
- [ ] Add `test_profile_rejects_unknown_effective_inputs`: modified/missing required files, unknown producer includes, unknown/changed rotation fragments, nested/alternate includes and overlapping destinations refuse. Accept all combinations of absent/present exact optional apt/dpkg/alternatives/btmp/wtmp fragments.
- [ ] Add `test_preflight_preserves_operational_state`: missing or aliased identities, missing/wrong-mode/owner/group files, symlink/hardlink/shared inode/ACL/untrusted parent, unavailable/invalid native validator, inactive/missing producer and changed configuration snapshots all refuse without operational mutation.
- [ ] Add `test_producer_observation_binds_config_and_restart`: configured/running argv mismatch, alternate -f, wrapper executable, multiple/unrecognized command records, unit override, root/mount mismatch and changing PID/start identity refuse before mutation. Query/proc failures and transitions produce null; known inactive/failed produces false. Post-application identity drift prevents applied-digest publication.
- [ ] Add `test_unknown_restart_state_requires_fresh_active_preflight`: restart failure with each true/false/null observation always fails and publishes no digest; a later unknown/inactive observation refuses without start/restart; a later fully valid active observation permits normal validated reapplication. No sticky permanent recovery block or implicit start.
- [ ] Add `test_apply_and_recover_partial_states`: both readers; failure before/after each group change, publication, restart and applied-record write; mixed-group retry; inactive retry refusal; exact preservation of content, consumer state, old archives and unrelated config. Successful rerun proves no rewrite/restart; valid-digest metadata-only repair avoids restart.
- [ ] Record expected RED before implementing policy. Implement the fixed profile and descriptor-safe application sequence from the spec; use fixed private digest/lock paths below `/var/lib/detection-engineering/`, protected0600 files/0700 private directories. Validate candidate in private staging; no extraction or permission-map framework.
- [ ] Keep filesystem/config parsing real in tests; model only privileged identity/ownership and native commands via the host adapter. Native adapter tests must also prove real unprivileged refusal/symlink handling where possible. No sudo/unshare/package installs or fabricated root success.
- [ ] Run focused tests GREEN; save exact raw commands/exits and report with the stable host-model interface task2/3 will consume. Independently review task1 before consumers change.

### Task 2: Linux main-entrypoint integration

**Files:**
- Modify Linux `tasks/configure.yml`, `defaults/main.yml`, `tests/test_role.py`.
- Create Linux `tasks/stock_log_access.yml`.
- Extend `tests/stock_access_model.py` only as needed by the stable interface; record interface changes before task3.

**Interfaces:** Reuse detection_laurel_read_user/root and existing command seams. Add only Python/rsyslog-validator command-path seams needed to invoke production helper and the test wrapper. Stage helper/reference inputs in private managed temporary space; stage cleanup touches only that invocation's private files. No public profile-selection or group variable. Parse helper JSON for change/failure reporting; preserve immediate failure propagation.

- [ ] Add main-entrypoint RED cases for fresh root:adm0640 sources under both readers, successful group migration before existing UID read checks, unchanged consumer/account/rotation state, and converged rerun.
- [ ] Include stock-access tasks after existing audit/account/regular-file prerequisites and before common-source reads. Add canonical-path assertions before privileged operations. Update obsolete refusal copy; leave Laurel artifact installer/entrypoint semantics intact.
- [ ] Test producer recreation from rendered action-captured groups and normal rotation from original profile's inherited metadata; prove HUP only reopens and restart applies settings. Wrong group/default restoration/duplicate selector/rotation override mutations must fail the model rather than produce successful output.
- [ ] Add entrypoint failure cases for preflight, first/second metadata change, publication, restart and marker write; assert no downstream Laurel account/binary/application marker mutations. Existing producer/consumer state and unrelated resources must match the spec's failure table, not invented rollback.
- [ ] Adapt existing Laurel interruption test without authorizing reader reassignment: keep reader fixed, use a new synthetic artifact digest plus retained old marker to represent interrupted reapplication. Keep accepted multi-entry artifact coverage and source-protection tests.
- [ ] Run focused main-entrypoint tests GREEN with raw logs. Independent review verifies production-helper execution through the test wrapper, real policy/no bypass, and the frozen fixture interface for task3.

### Task 3: Composed UF pipeline regression coverage

**User-approved scope amendment:** Composed testing revealed Forwarder bootstrap
resets the shared private marker parent to0750. Also permit changing only its
marker-parent mode to0700 in `ludus_detection_forwarder/tasks/bootstrap.yml`,
a focused standalone Forwarder bootstrap regression, and restoration of strict
pipeline convergence assertions. Seed-parent mode and all other production
behavior remain unchanged. This supersedes the production freeze only for that
one approved mode. Preserve accepted Linux/helper/model and standalone fixture.

**Files:** Modify only `ansible/roles/ludus_detection_forwarder_pipeline/tests/support.py` and `tests/test_role.py`.

**Interfaces:** Consume task2's stable stock-access model. Both runuser spellings resolve the same UID/GID/mode/inode state; reader existence is tied to the actual modeled package-account marker. Do not modify forwarder production/standalone fixture or pipeline production ordering.

- [ ] Add RED composed cases for all three profiles: package prepares reader before group/config application; producer permission/readiness success precedes UF activation; expected telemetry input counts remain3/4/3.
- [ ] Integrate production helper through the shared test-only host adapter and derive common-file access from metadata instead of unconditional readable records. Missing accounts/units and wrong context must fail.
- [ ] Test producer-access failures before/after mutation, interrupted active rerun, convergence, and rotation/recreation. Assert activation task absence where required, existing consumer credentials/service/markers preserved, partial producer state accurately retained, and unrelated resources unchanged.
- [ ] Run focused tests GREEN; independent review covers the complete three-task delta and integration, not unrelated completed role work.

## Verification Budget and Ownership

- Each writer owns focused RED/GREEN logs and self-review; reviewer owns spec/quality and changed-scope integration. Command specialist owns immutable source/diff packaging and final command evidence. Controller reads artifacts and reconciles results.
- Use existing `/tmp/opencode/detection-engineering-tests/venv/bin/pytest`, `PYTHONPATH=blueprints/detection-engineering/tests`, unique `/tmp/opencode` basetemps. Run Linux and pipeline directories in separate processes to avoid test_role/support collisions.
- After all writers/reviews settle: run full Linux suite once, full pipeline suite once, shared blueprint tests once, changed-YAML lint and existing syntax fixtures. Capture complete commands, stdout/stderr and exit codes. No unrelated old-role suite replay.
- Verify accepted Laurel installer/tests/test_artifact.py hashes unchanged, other pre-existing dirty edits preserved, exact final source scope, and untracked-aware whitespace. Reuse prior real-archive check-only only while its installer/artifact remain unchanged.
- Models cover policy, failure ordering, DAC metadata, recreation and rotation semantics. Native rsyslog syntax/service execution, physical root-owned migration, selected-version runtime/MAC and live rotation/ingestion remain unverified; no deployment readiness claim.
- Leave all changes uncommitted. Update durable handoff and preserve evidence when the increment is accepted.

## Self-review

All tasks share only explicitly sequenced interfaces. The approved permission
boundary is unchanged, profile policy is finite, ordinary reviewed rotation
fragments are included, and each review risk has concrete negative tests.
Task8 remains responsible for supported producer provisioning, naturally
existing sources, actual Splunk-local ordering and authorized live acceptance.
