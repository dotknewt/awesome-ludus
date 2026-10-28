# Role identities and detect-evil Implementation Plan

> **Execution update:** The user requested continuation without SDD after a dispatcher failure. Use ordinary specialist orchestration, sequential implementation and scoped validation, followed by one final review. Preserve the existing evidence workspace. Steps use checkbox syntax for tracking.

**Goal:** Complete repository-scoped ROLES-001, then reassess and fix RANGE-001.

**Architecture:** Standardize source-local role directory and metadata identities without changing public variable APIs. Document staged migration, leaving installed legacy roles untouched. Re-review detect-evil only after the finalized identities pass review; retain K3s-only telemetry.

**Tech Stack:** Ansible YAML, Python static checks, official Ludus JSON schema.

**Spec:** `docs/TODO.md` ROLES-001 and RANGE-001, plus the user's explicit implementation authorization and subsequent “Proceed conservatively” choice on 2026-10-28. The user waived further design questions. This plan records the bounded implementation decisions, not additional scope.

## Global Constraints

- Preserve author attribution and existing variable APIs; variable-prefix renames are not part of this task.
- Canonical identities: `linux_splunk_server`, `linux_gitlab_ce`, `linux_logging`, `linux_gitlab_runner`, `linux_k3s_bootstrap`, `linux_install_docker`.
- Do not install/remove server roles, deploy, probe guests, merge, or push. Do not claim server compatibility without target-version/catalog evidence.
- Document staged migration without compatibility aliases; leave installed legacy identities untouched until separately authorized migration.
- Retain K3s-only container telemetry. Docker-job collection is explicitly deferred; do not change executor architecture.
- No Malcolm capture-topology work, fleet-wide Linux telemetry expansion, Defender overlap cleanup, blueprint metadata cleanup, or schema-header-only cleanup.
- Follow `docs/instructions/ludus-authoring.md`. Static checks are not live evidence; no simulations or stateful fakes. Record unavailable checks and unverified targets.
- Controller owns TODO completion/evidence status. Workers do not mark TODOs done or commit; controller delegates validation and commits to fast-generic.

## Review Focus

- Task 1: remaining active legacy identities versus intentionally preserved variable APIs and labeled historical references.
- Task 1: preserved author/default input contracts across directory moves.
- Task 1: installed-role migration safety and honest compatibility boundaries.
- Task 2: exact VM/role dependency pairs and forwarder-before-logging ordering, with explicit `splunkfwd` Laurel reader.
- Task 2: global Windows/Linux inputs and GPO link shapes versus role contracts and current official schema.

### Task 1: Standardize six source-local Linux identities

**Files:** Six role trees under `ansible/roles/`; active references in `source.yml`, `blueprints/`, current documentation and static checks. Add `docs/role-identity-migration.md`. Preserve historical spec/plan evidence with explicit historical labeling rather than rewriting recorded events. Exclude unrelated role changes.

**Interfaces:** Consumes current role defaults and author metadata. Produces canonical directory names matching `galaxy_info.role_name`, active role/dependency references matching these names, unchanged variable inputs, and staged migration instructions. Task 2 consumes these finalized names.

- [ ] Inventory active identity references and existing static tests; classify exact identity tokens separately from variables and history.
- [ ] Add/update focused static assertions for all six canonical directory/metadata pairs, author preservation, and reference consistency. Record expected pre-change failures through the validation owner where practical.
- [ ] Change metadata identities; move `ludus_gitlab_runner` to `linux_gitlab_runner`, `ludus_k3s_bootstrap` to `linux_k3s_bootstrap`, and `linux_docker` to `linux_install_docker`. Update active dependencies, role calls, examples and static harnesses without renaming variables.
- [ ] Document old-to-new mapping and staged migration: inventory target version/catalog and deployed references; separately authorize canonical installation; switch ranges only after identity verification; retain legacy roles until no ranges reference them; separately authorize retirement. Verify official source/role naming guidance and cite URLs/access date; missing target evidence remains explicit.
- [ ] Supply validation owner with exact changed-file inventory, static commands and expected results; inspect resulting artifacts for unintended variable/author changes. Controller obtains changed-file validation and reconciles artifacts before advancing.

### Task 2: Re-review and fix detect-evil configuration

**Files:** `blueprints/detect-evil/range-config.yml`, relevant focused static checks, and `blueprints/detect-evil/README.md` only for scope/evidence documentation. No blueprint metadata cleanup.

**Interfaces:** Consumes Task 1 canonical role identities and unchanged public inputs. Produces schema-checked range data with exact assigned-role dependency pairs, required logging order/read user, correct global inputs/GPO link shapes, and explicit deferred Docker-job telemetry/runtime gaps.

- [ ] Read the then-current range and the actual referenced role input contracts. Fetch current official configuration documentation and `https://docs.ludus.cloud/schemas/range-config.json`, retain URL/date/hash evidence, and separate schema defects from role-input defects.
- [ ] Add focused static assertions for dependency target membership, forwarder-before-logging and explicit `splunkfwd`, applicable global inputs and GPO structures. Preserve any correct existing values. Do not assume earlier review snippets remain valid.
- [ ] Apply only confirmed in-scope defects; retain Kubernetes mode and `/var/log/pods`, existing executor architecture, and exclusions.
- [ ] Record Docker-job logs as deferred by user choice, schema/static evidence and live gaps. Provide the validation owner exact commands/input hashes; controller obtains scoped checks and one final review, and finalizes `docs/TODO.md` only against supported acceptance claims.

## Verification ownership and limits

Fast-generic owns no-edit baseline and scoped command validation, including changed-file YAML/available Ansible checks and static tests; it preserves commands, exits and hashes in ignored durable artifacts. Workers own implementation/self-review and provide command recommendations, not duplicate full-suite runs. One final reviewer assesses spec and quality from the combined diff and evidence. Controller reads artifacts, resolves findings, and commissions one final combined relevant static suite after both tasks; no unrelated role validation. Live execution and installed identity compatibility remain unverified unless read-only target evidence is obtained; neither is inferred from static success.
