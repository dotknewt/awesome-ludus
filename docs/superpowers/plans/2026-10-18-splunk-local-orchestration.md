# Splunk Local Logging Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Splunk's actual role entrypoint establish native local telemetry and reader access before bootstrapping Splunk.

**Architecture:** Include the existing Linux logging role after Enterprise package installation and before bootstrap, on both fresh and repeated runs. Align the shared authority directory to root-owned `0700`; retain existing lifecycle guards and producer failure semantics.

**Tech Stack:** Ansible, Python pytest, existing sandboxed production-role execution harness and stateful Linux producer model.

**Spec:** `docs/superpowers/specs/2026-10-16-detection-engineering-design.md` and `docs/superpowers/specs/2026-10-18-stock-log-access.md`. User approved this narrow integration and `0700` amendment on 2026-10-18. It extends Task 8's file scope to the Splunk role and its tests.

## Global Constraints

- Infrastructure and logging only; runner remains paused; no CI jobs or hunting exercises.
- Native Laurel: `/var/log/laurel/audit.log`, `de_linux`, `linux:audit:laurel`.
- Native rotation size `5000000`, generations `10`; preserve native telemetry content.
- Actual local reader is `splunk`; no Universal Forwarder on Splunk and no independently created Splunk account.
- Existing package, factual and maintenance guards remain ahead of mutation.
- Preserve shared roles, ConstructingDefense, Linux/forwarder/pipeline implementation, blueprint configurations, telemetry matrix and factual gates.
- No remote operations, vendor execution, deployment, guest probes, cleanup or maintenance execution in this increment.
- Preserve existing dirty files and accepted evidence. Offline models establish orchestration, not selected-product compatibility or searchable ingestion.

## Review Focus

- Package reported installed but reader missing or mismatched: fail before consumer bootstrap.
- Producer failure on an already-running consumer: preserve existing consumer state and authority.
- Shared state directory with existing sibling markers: migrate trusted `0750` to `0700` once without permission oscillation.
- Missing native prerequisites or canonical logs: fail without fabricating telemetry or bypassing the producer.
- Maintenance refusal or authorized restoration: retain refusal ordering and pending-acceptance semantics.

---

## Files and ownership

One worker owns this cohesive composition increment; no parallel source writers.

- Modify `ansible/roles/ludus_detection_splunk/tasks/main.yml`: input/identity guard, Linux-role include and authority-parent mode only.
- Modify `ansible/roles/ludus_detection_splunk/tests/helpers.py`: compose fixtures while preserving existing helper interfaces.
- Modify `ansible/roles/ludus_detection_splunk/tests/test_role.py`: actual-entrypoint composition and regression tests.
- Create `ansible/roles/ludus_detection_splunk/tests/local_logging_support.py`: sandbox producer/package/service adapters, reusing the accepted stock-access model without editing it.
- This plan and the Task 8 link are the only planning changes.

## Task 1: Compose Splunk with its native Linux producer

**Interfaces:**
- Preserve `make_fixture(tmp_path: Path) -> dict[str, Any]`, `run_role(fixture: dict[str, Any], **updates: Any)` and `command_calls(fixture) -> list[str]`.
- New test helper `configure_local_logging(fixture: dict[str, Any]) -> None` in `local_logging_support.py` augments the existing fixture in place. `make_fixture` invokes it. Implementation-local adapter details may follow the established pipeline harness.
- Consume `detection_linux_host_id`, `detection_laurel_artifact`, `detection_laurel_read_user`, existing rotation inputs, paths and command overrides. Validate reader equals the configured Splunk file owner and production reader contract `splunk`; test identity translation stays in the sandbox adapter, not a production bypass.
- Include `ludus_detection_linux_logging` main after successful package installation or recognition of a matching installed package, before `Create protected Splunk configuration and state directories`.
- Change only the maintenance-authority parent entry from `0750` to `0700`; provenance, configuration/seed and secrets retain their existing policies.

- [ ] **Step 1: Build coherent fixture composition and failing entrypoint tests.**

  Execute Splunk main including real Linux main; do not substitute a successful include. Model package installation creating the reader and units, use one shared sandbox authority parent, and reject missing units/accounts, inaccessible sources and uninstalled Laurel execution. Preserve production task order. Fixtures must clearly label identity/DAC/service behavior as simulated.

  Add these tests with the stated assertions:

  | Test | Required assertions |
  |---|---|
  | `test_local_logging_precedes_fresh_splunk_bootstrap` | Reader absent initially; package creates it; stock access and Laurel apply/read checks precede seed/bootstrap; exactly three existing local monitors, no UF. |
  | `test_local_logging_runs_for_matching_installed_package` | No package reinstall; producer/read-access validation still executes. |
  | `test_local_logging_second_run_is_unchanged` | Successful second run has `changed=0`; no reinstall, producer restart, rebootstrap, token replacement or permission churn. |
  | `test_local_logging_rejects_invalid_reader` | Parameterize missing account/group, root/adm alias, wrong reader and owner mismatch; no downstream bootstrap. |
  | `test_local_logging_rejects_missing_prerequisites` | Parameterize missing auditd package/tool/unit, inactive/unsupported rsyslog, missing logrotate, missing/nonregular canonical logs; no fabricated source files/events. |
  | `test_local_logging_failure_blocks_fresh_bootstrap` | Inject before mutation and after stock mutation, rsyslog/audit application failures, missing/unreadable Laurel output and staging cleanup failure; no seed/bootstrap marker or downstream consumer activation, with expected producer state and marker disposition. |
  | `test_local_logging_failure_preserves_running_splunk` | Snapshot service, credentials, bootstrap and lifecycle authority; producer failure preserves these and unrelated files. |
  | `test_local_logging_shared_parent_converges` | Trusted legacy `0750` becomes `0700` once; sibling marker bytes and seed-parent mode preserved; second run unchanged. |
  | `test_local_logging_refuses_untrusted_parent` | Existing Linux trusted-directory checks refuse invalid objects before downstream consumer work. |
  | Existing lifecycle tests, extended | Nonhealthy refusal precedes package/producer mutation; authorized restore remains `RESTORED_PENDING_ACCEPTANCE`, never HEALTHY. |

- [ ] **Step 2: Record the expected red result.**

  Run `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_splunk/tests/test_role.py -k local_logging`.
  Confirm failures demonstrate absent orchestration/incorrect directory policy, rather than fixture import or setup errors. If the existing environment is unavailable, report that before installing anything.

- [ ] **Step 3: Implement the bounded production changes.**

  Add early Linux input and reader validation without weakening factual/lifecycle guards. Invoke real Linux main at the specified seam on every eligible run; change the shared authority-parent mode. A producer failure stops subsequent Splunk tasks but does not roll back package installation or stop an existing consumer. Preserve Linux partial-failure semantics. No logging toggle, new role wrapper or duplicate readability implementation.

- [ ] **Step 4: Verify focused and complete affected behavior.**

  Run the Step 2 command, then the complete Splunk suite:
  `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_splunk/tests`.
  Run shared blueprint tests in a separate process to avoid duplicate test-module imports:
  `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q blueprints/detection-engineering/tests`.
  Expected: all executed cases PASS; record exact counts and commands. Reuse unchanged accepted Linux/pipeline evidence rather than replaying those suites without a dependency change.

- [ ] **Step 5: Run static checks and preserve a scoped review package.**

  Run `/tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook --syntax-check -i localhost, ansible/roles/ludus_detection_splunk/tests/syntax.yml` with repository roles resolution, then scoped `ansible-lint` using existing project configuration and `git diff --check` on authored paths. Record missing tools or findings honestly and compare pre-existing lint findings without suppression. Snapshot exact changed files/diff and source hashes, including the new untracked helper, for review.

- [ ] **Step 6: Independent review and phase gate.**

  Fresh reviewer checks the full bounded delta and actual-entrypoint evidence. Oracle Gate 2, attempt 1/3, checks identity, permissions, failure ordering and limits of simulated runtime evidence. Run an explorer structure scan alongside the gate because role dependency direction changes. Apply one bounded remediation pass for material issues and rerun affected checks; re-review only materially changed risks, at most two re-reviews.

- [ ] **Step 7: Checkpoint the accepted increment.**

  Update deepwork progress and the current resume checkpoint with exact executed/simulated/reused/unverified evidence. Before any commit, confirm current authorization and stage only these reviewed files; never sweep existing user work into a commit. Report remaining product/template prerequisites and later blueprint materialization separately.

## Self-review

All five review-focus conditions map to named tests. No new production interface or runtime fact is invented. This plan covers only the approved Splunk-local composition amendment; remaining Task 8 materialization, acceptance harness and live verification remain separate phases.
