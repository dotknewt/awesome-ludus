# Forwarder Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Track the checkbox steps below.

**Goal:** Prove the approved prepare → native Linux logging → activate composition through a private role, without materializing a deployable range.
**Architecture:** `ludus_detection_forwarder_pipeline` owns ordering only for GitLab, runner, and workload hosts. It invokes the existing forwarder public phase entrypoints around the actual private Linux logging role; distro auditd remains an earlier Ludus `linux.packages` prerequisite. Splunk's local-reader path is separate.
**Tech Stack:** Existing Ansible roles and Python pytest sandbox infrastructure; no new dependencies.
**Spec:** User-approved wrapper description and offline integration tests (2026-10-17); `RESUME-DETECTION-ENGINEERING.md`; `.superpowers/sdd/2026-10-16-detection-engineering/role-contract-addendum.md:162-189`.

## Global Constraints
- Keep `ludus: []`, factual gates and existing range projections unchanged. This is a Task8 increment, not Task8 completion.
- Preserve native Laurel `/var/log/laurel/audit.log`, `de_linux`, `linux:audit:laurel`, 18-row matrix and UF 3/4/3 profiles.
- No duplicate accounts, package installer, ACL framework, sanitizer, telemetry expansion, phase markers, or modifications to existing producer/consumer roles and shared test support.
- No deployment, guest probes, host audit/service experiments, installation of dependencies, push, cleanup, or factual-gate promotion.
- Existing isolated worktree and unrelated changes remain. Sparse visibility restored with user approval; backup/report: `/tmp/opencode/forwarder-sparse-restore-20261018T000000Z/restore-report.md`.

## Review Focus
- Shared reader mismatch must fail before preparation; wrapper serves `splunkfwd`, never local Splunk.
- Missing auditd or unreadable stock sources must halt before activation; package preparation may already have succeeded.
- Failure after producer mutation must not activate UF or falsely undo authoritative producer state.
- Rerun after successful activation must preserve valid service/configuration state; failure must preserve unrelated resources.
- Fresh install must obtain reader from package before running the actual producer, not a test-written Laurel output file.

### Task 1: Private orchestration entrypoint and composed tests
**Files:** Create `ansible/roles/ludus_detection_forwarder_pipeline/tasks/main.yml`, `README.md`, `tests/test_role.py`, `tests/syntax.yml`; optionally `tests/support.py` for the role-local composed fixture. No existing production/test files change. Evidence goes under `.superpowers/sdd/2026-10-17-forwarder-orchestration/`.
**Interfaces:** Consume existing forwarder and native Linux logging variables unchanged. Assert `detection_forwarder_profile` is gitlab/runner/workload and `detection_laurel_read_user == 'splunkfwd'` before any included role. Include forwarder `tasks_from: prepare`, Linux logging default entrypoint, forwarder `tasks_from: activate`, in that order. Propagate failures normally; no ignore/rescue that continues or rolls back another role's state. All included roles must be installed/discoverable; no eager metadata dependencies that execute them out of order.

- [ ] **Write RED tests:** Execute the actual new wrapper with actual included roles, not copied task order or stub roles. A role-local combined fixture must model package/account creation, auditd prerequisites, Laurel extraction/start/output, reader access and UF bootstrap/unit/service transitions. Reject missing units, wrong identity/context, unreadable sources and unextracted execution. Test all three profile input counts on fresh success; rerun convergence; reader mismatch before mutation; preparation failure before/after package mutation; auditd/source failures before producer mutation; producer failure after mutation; activation refusal/failure and protected credential/transaction disposition. Assert managed and unrelated state, plus absence of downstream calls, at each boundary. Derive native Laurel output from modeled execution of the real producer tasks rather than test setup.
- [ ] **Record RED:** `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_forwarder_pipeline/tests`; confirm failures identify absent wrapper/behavior rather than harness errors. Writer owns focused TDD; tests may reuse existing fixture utilities read-only without changing shared APIs.
- [ ] **Implement:** Add the thin entrypoint and concise README with variables, install/discovery prerequisites, failure/rerun behavior, auditd outside the wrapper, blocked rotation/product facts and source-only scope. No range role-list changes yet. Document official Ludus source evidence: `c6528cccb36f2e30c2fe896171ce1ffd62095a3c`, `ludus-server/ansible/range-management/templates/user-defined-roles.yml.j2` (no `tasks_from` propagation) and `ludus.yml` (packages before user roles on full runs); installed-version/selective-tag ordering is not verified.
- [ ] **GREEN:** Writer runs complete new wrapper suite once after focused fixes and records raw commands, exits, artifacts and simulation limits. No live compatibility claims. If existing roles cannot compose without production changes, stop and report the exact interface contradiction rather than widen scope.
- [ ] **Validate and review:** Command specialist freezes all new files plus dependency hashes; runs syntax, YAML lint, untracked-aware whitespace and shared blueprint contract tests. Reuse unchanged role evidence only when code, dependencies and environment still match; changed composed behavior is established by new suite, not old summaries. Independent reviewer checks real entrypoint coverage, truthful stateful fakes, boundary state/credentials, exact scope and docs. Controller reconciles artifacts. No duplicate full-suite run absent a specific evidence gap.
- [ ] **Commit/checkpoint:** After acceptance, command specialist stages only new wrapper files and this approved plan, inspects diff/secrets and commits in repository style; verifies committed blobs match reviewed hashes. Controller updates handoff. Preserve evidence and unrelated dirty work; no push.

## Evidence boundary
Static order tests alone are insufficient. Production Ansible composition with stateful command fakes is the chosen offline evidence; real package scripts, auditd/kernel behavior, Laurel compatibility/output fidelity, log replacement/rotation and installed Ludus ordering remain unverified. Authorization for those live checks is separate.
