# Migration status and checkpoints

This is the **sole authoritative status/checkpoint ledger** for the migration evaluation documented in [migration-plan.md](migration-plan.md). The plan explains context and proposed direction; this file records progress. Creating these research documents does not complete any migration task.

## Status definitions

- **proposed** — suggested work, not yet approved or started.
- **ready** — prerequisites and scope are resolved and the task may be considered for authorization. **Ready does not authorize execution.**
- **in-progress** — explicitly authorized work has started.
- **blocked** — cannot proceed; state the missing decision, evidence, access, or authorization in the task's checkpoint.
- **done** — acceptance criteria have been met and evidence recorded. Research/document creation alone does not qualify.

All tasks below are **proposed and unchecked**. Update status only when the definition is met; record evidence and blockers here. Do not treat a checkbox as implied authorization.

## Tasks

- [ ] **MIG-001 — Set migration governance and scope** — Status: proposed. Decide owner, repository visibility/names, maintainers, scope, and whether legacy `role_*` directories are candidates. **Accept:** decisions and approver are recorded here. See plan: Recommendation; Proposed decisions §1 and §5.
  - [ ] Checkpoint: identify repository owner and approver.
  - [ ] Checkpoint: decide public/private visibility and naming.
  - [ ] Checkpoint: decide legacy role scope and release/update owner.
- [ ] **MIG-002 — Establish role ownership/publication allowlist** — Status: proposed. Assess each candidate's upstream, revision, authorship, modifications, license/notices, history and secret exposure. **Accept:** per-role allowlist/denylist with evidence and required attribution; no ownership inferred from metadata. Depends on MIG-001. See plan: Evidence and current inventory; Proposed decisions §1.
  - [ ] Checkpoint: inventory candidates and upstream provenance.
  - [ ] Checkpoint: resolve redistribution terms and required notices.
  - [ ] Checkpoint: review retained history as well as extracted files for secrets.
- [ ] **MIG-003 — Resolve installed role identity and compatibility baseline** — Status: proposed. Select target client/server version and establish an evidence-backed name mapping before renames or cutover. **Accept:** every in-scope role maps repository, submodule directory, requirements `name`, manual directory, range-config/internal references, metadata identity, and actual installed identity; discrepancies and evidence recorded. Depends on MIG-001, MIG-002. See plan: Confirmed official contracts; Proposed decisions §2.
  - [ ] Checkpoint: choose target Ludus client/server version.
  - [ ] Checkpoint: collect version-matched docs and authorized read-only identity evidence.
  - [ ] Checkpoint: complete and review per-role identity map; resolve discrepancies.
- [ ] **MIG-004 — Define independent role dependency closure** — Status: proposed. Inventory transitive role/collection dependencies and specify versions and who installs each for standalone consumers. **Accept:** every eligible role has a documented complete dependency contract; pin format is checked against selected version; no same role is redundantly source-local and declared in aggregator requirements. Depends on MIG-002, MIG-003. See plan: Evidence and current inventory; Proposed decisions §3.
  - [ ] Checkpoint: inventory direct and transitive roles/collections.
  - [ ] Checkpoint: define standalone dependency acquisition and compatible pins.
  - [ ] Checkpoint: record target-version evidence for requirements pin semantics.
- [ ] **MIG-005 — Decide release and reproducibility policy** — Status: proposed. Define independent role/template releases and coordinated immutable mapping. **Accept:** release/version policy and a verifiable aggregator → role commits → dependency pins → template-source commit manifest are specified, including referenced-commit retention. Depends on MIG-001, MIG-003, MIG-004. See plan: Proposed decisions §5.
  - [ ] Checkpoint: choose versioning, tags, maintenance and compatibility policy.
  - [ ] Checkpoint: define coordinated mapping and commit-retention approach.
- [ ] **MIG-006 — Settle template distribution contract** — Status: proposed. Choose separate templates-only source or another documented-and-verified aggregation layout; preserve names/paths unless approved otherwise. **Accept:** source layout, registration/build prerequisites, relative references, collision/version policy, and non-nesting evidence are recorded. Depends on MIG-001. See plan: Confirmed official contracts; Proposed decisions §4.
  - [ ] Checkpoint: decide separate registration or validate an alternative against selected version.
  - [ ] Checkpoint: inventory relative paths and template names/collisions.
  - [ ] Checkpoint: specify build provenance and installed-image masking controls.
- [ ] **MIG-007 — Approve execution and verification scope** — Status: proposed. Define which static work, publication, isolated checks, deployments, cleanup and rollback actions are authorized. **Accept:** explicit authorization boundaries and evidence criteria are recorded; live/destructive actions have separate authorization. Depends on MIG-002–MIG-006. See plan: Staged rollout and rollback; Verification boundaries.
  - [ ] Checkpoint: scope static validation and acceptance evidence.
  - [ ] Checkpoint: separately decide whether any isolated live verification is authorized.
  - [ ] Checkpoint: document rollback layers and separate guest-state recovery boundary.
- [ ] **MIG-008 — Execute staged migration, if authorized** — Status: proposed. Only after prerequisite decisions and explicit authorization, prepare disposable extraction, pilot roles, migrate remaining approved roles, publish templates, then cut over aggregator last. **Accept:** each stage meets MIG-007 criteria and release mapping; no unapproved artifacts or live operations. Depends on MIG-001–MIG-007. See plan: Staged rollout and rollback.
  - [ ] Checkpoint: prepare/pilot one simple role and review evidence.
  - [ ] Checkpoint: publish eligible roles and dependency closure in stages.
  - [ ] Checkpoint: publish/register/build templates source with provenance.
  - [ ] Checkpoint: cut over aggregator last and record coordinated release.

## Reusable checkpoint format

Add small, user-extensible checkpoints under the relevant stable task ID:

```text
- [ ] Checkpoint: <observable outcome> — owner: <optional>; evidence: <optional>
```

Keep status, blockers, decisions, and evidence in this ledger; do not duplicate the plan here. The orchestrator owns final review of both linked documents and validates that edits stay within the requested documentation scope.
