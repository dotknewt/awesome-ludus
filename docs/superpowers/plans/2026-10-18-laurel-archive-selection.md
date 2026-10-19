# Laurel Archive Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accept the acquired official Laurel multi-entry archive while installing only its root `laurel` binary and retaining fail-closed validation.

**Architecture:** Keep the existing installer CLI and role ordering. Validate the complete archive before mutation, select exactly one regular root `laurel`, ignore validated safe companion entries, and retain the existing atomic installation/convergence behavior.

**Tech Stack:** Python standard library, pytest, existing Ansible sandbox tests.

**Spec:** User-approved repair description in the current conversation; approval and acquired evidence recorded in `.superpowers/sdd/2026-10-18-deployment-prerequisites/progress.md`. Existing native logging contract remains applicable except for the explicitly approved single-member archive restriction.

## Global Constraints

- No vendor binary execution, installation on the host, guest probe, deployment, new downloads, or dependency installation.
- No blueprint/gate/interface changes, log-permission changes, telemetry expansion, or companion-binary installation.
- Do not modify forwarder/pipeline roles or shared test helpers. Preserve unrelated dirty files and original artifact evidence.
- Preserve checksum-before-processing, validation-before-account/binary mutation, `--check-only` no-write behavior, mode0755, atomic replacement, and unchanged-content convergence.
- Acquired archive SHA256: `110fd0436cb492fafab2ee68fcae681e611488baf376657ff9eab875608ceb6c`; locally observed, not independently publisher-authenticated.

## Review Focus

- Unsafe companion paths/types must fail even when the selected binary is valid.
- Duplicate/aliased names or a missing/nonregular root binary must fail deterministically.
- Rejection or failed replacement must preserve existing destinations and unrelated files.
- Real-layout success must install only selected bytes, never laurel2audit/docs.
- Synthetic entrypoint tests prove integration only; real archive check-only proves layout acceptance, not runtime compatibility.

### Task 1: Safe selected-member installer and regressions

**Files:**
- Modify `ansible/roles/ludus_detection_linux_logging/files/install_laurel_artifact.py`.
- Modify `ansible/roles/ludus_detection_linux_logging/tests/test_role.py`.
- Create `ansible/roles/ludus_detection_linux_logging/tests/test_artifact.py` for fast installer-level regressions.

**Interfaces:** Existing `main()` and `--archive`, `--sha256`, `--check-only`, `--destination` remain unchanged. Preserve success output (`OK safe archive`, `OK`, `CHANGED content`, `CHANGED mode`) and nonzero refusal behavior; rejection text may be made accurate for selected-member validation.

- [ ] Add `test_accepts_release_layout_installs_only_laurel`: build a synthetic archive with the acquired14-entry path/type layout and harmless binary bytes; check-only writes nothing; installation writes exactly selected bytes mode0755; companion paths remain absent; rerun converges.
- [ ] Add parametrized `test_rejects_unsafe_archive_without_mutation`: checksum mismatch, missing/duplicate/nonregular laurel, absolute/traversal/ambiguous paths, duplicate companion names, symlink/hardlink/FIFO/device entries (including unselected entries), and corrupt/truncated archive. Assert existing destination bytes/mode and unrelated sentinel unchanged; absent destination parent remains absent.
- [ ] Add `test_replace_failure_preserves_destination`: inject replacement failure, assert old bytes/mode and unrelated sentinel retained, temporary staging file removed. Do not execute selected bytes.
- [ ] Run focused new tests with the existing venv and unique `/tmp/opencode` basetemp; record expected RED for safe multi-entry acceptance against the current installer.
- [ ] Replace the exact-one-member check with complete safe-entry validation and unique regular root selection. Reject unsupported types and ambiguous/duplicate canonical paths; allow regular companion files and directories only. Read/install only the selected payload; never use extractall or write archive-provided paths. Retain atomic destination code.
- [ ] Update the existing malicious-archive assertion to the new accurate error. Extend role fixture(s) to carry safe multi-entry layout so actual main-entrypoint fresh install, convergence, and rejection-before-account-mutation are exercised. Do not redesign fake services or imply live fidelity.
- [ ] Run focused tests GREEN; report exact changed files and raw commands/exits. Worker owns RED/GREEN; no commit.

## Verification Budget and Ownership

- Worker: focused installer regressions and relevant actual-role entrypoint cases; record RED/GREEN and source manifest. No old forwarder suite rerun.
- Independent reviewer: changed installer/tests, approved scope, all-entry safety, no-write/refusal/atomic behavior, and test adequacy. No duplicate execution unless a specific coverage defect requires it.
- Command specialist, after writers settle: run Linux logging suite once and pipeline suite once in separate pytest processes (both have `test_role.py`/support imports); use existing venv and `PYTHONPATH=blueprints/detection-engineering/tests`. Unique basetemps under `/tmp/opencode`; require zero failures. Changed installer invalidates prior composition evidence.
- Command specialist: run production installer `--check-only` against the acquired archive with the recorded digest; require exit0/`OK safe archive`, no destination and no binary execution. Retain existing exit1 reproduction as RED evidence.
- Command specialist: scoped whitespace and complete diff/manifest verification; reuse YAML/syntax/shared-blueprint evidence only if those inputs remain unchanged. No staging/commit/push without separate instruction.
- Controller: read final artifacts, review and command outputs; record executed vs modeled vs reused evidence. Deployment, real auditd/Laurel behavior, runtime compatibility and stock auth/syslog access remain unverified.

## Self-review

One task covers the approved small change. All five review risks have explicit assertions. CLI and role inputs remain stable; no new operational permissions or dependency requirements. Final acceptance is limited to safe archive handling and offline composition.
