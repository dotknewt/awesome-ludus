# Ansible Validation Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a thin skill and bundled script that run available Ansible/YAML static tools, report missing tools as explicit unverified warnings, and preserve complete deployment-artifact target coverage.

**Architecture:** The skill resolves the user's role/range/source/blueprint scope into explicit role, playbook, and data paths. A small standard-library Python script validates those paths with whichever of `ansible-playbook`, `ansible-lint`, and `yamllint` are on `PATH`, aggregates deterministic statuses, and never installs anything. `--all` supplies a simple whole-repository inventory using the same execution path.

**Tech Stack:** Python 3 standard library, `ansible-playbook`, `ansible-lint`, `yamllint`, `unittest`, Markdown/YAML configuration

**Spec:** `docs/superpowers/specs/2026-10-19-ansible-validation-design.md`

## Global Constraints

- Proposed script: `.opencode/skills/ansible-validation/scripts/validate.py`; exact CLI spelling remains an implementation choice.
- Discover all three tools independently through `PATH`; run every available tool and never install tools, roles, or collections.
- Verify and use `ansible-lint`'s current supported offline/no-dependency-install mode so child processes cannot install requirements.
- Missing tools are warning-only. Actual tool failures, malformed invocation/runtime errors, unresolved targets, nonexistent paths, and missing truthful harnesses are nonzero failures.
- If an available tool reports a missing role, collection, module, or other dependency, classify it as `FAIL`, not `NOT AVAILABLE`.
- A warning-only result is `PASS WITH WARNINGS — NOT VERIFIED`, never clean/verified `PASS`.
- Every included/referenced role and declared dependency in an evaluated range/source/blueprint belongs in the inventory; unrelated roles do not.
- No CI/pre-commit integration, fake harnesses, custom exception engine, dependency locks, managed bootstrap, remote action, commit, or deployment.

## Review Focus

- All, partial, and zero tool availability must produce the specified per-tool and overall statuses without suppressing available checks.
- An available tool failure plus another unavailable tool must remain nonzero `FAIL`.
- Missing target/harness and `--coverage-gap` must be coverage failures, not `NOT AVAILABLE`.
- Artifact data must reach only `yamllint`; role/playbook targets must reach the correct real tools without unrelated roles.
- The report must name missing packages, safe optional install commands, exact rerun command, unverified targets, and live-not-run status.
- The suggested rerun must activate the new virtual environment or prefix its `bin` directory onto `PATH`.

---

### Task 1: Build and test the bundled validator script

**Files:**
- Create: `.opencode/skills/ansible-validation/scripts/validate.py`
- Create: `.opencode/skills/ansible-validation/tests/test_validate.py`
- Create: `.ansible-lint`
- Create: `.yamllint.yml`

**Interfaces:**
- Consumes: proposed repeated `--role PATH`, `--playbook PATH`, `--data PATH`, `--coverage-gap TEXT`, or `--all`
- Produces: per-tool `ToolResult(tool: str, executable: str | None, status: str, targets: tuple[str, ...], detail: str)`, overall status/exit code, exact rerun command, and static/live report sections

- [ ] **Step 1: Write deterministic CLI and aggregation tests**

Test argument/path validation, explicit target classification, `--all` expansion, missing role harness, coverage gaps, and pure status aggregation for all/partial/no tools, tool failure plus missing tool, malformed invocation, and runtime error. Assert the shell-quoted rerun exposes the suggested venv on `PATH`, `ansible-lint` receives the verified offline/no-install option, and an available tool's missing-dependency error is `FAIL`. Only complete all-tool success says `PASS`; warning-only combinations say `PASS WITH WARNINGS — NOT VERIFIED`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest discover -s .opencode/skills/ansible-validation/tests -v`

Expected: FAIL because the script does not exist.

- [ ] **Step 3: Implement target validation and simple `--all` discovery**

Implement `parse_args(argv: Sequence[str])`, explicit path checks, and repository-specific `--all` expansion. Roles contribute role YAML, role lint paths, and existing `tests/syntax.yml`; playbooks contribute to all three checks; data contributes only to YAML lint. Missing harnesses and supplied coverage gaps remain distinct nonzero coverage errors. Never synthesize a harness.

- [ ] **Step 4: Implement independent real-tool execution**

Use `shutil.which` independently for `ansible-playbook`, `ansible-lint`, and `yamllint`. Before finalizing the `ansible-lint` invocation, verify its current officially supported offline/no-requirements-install option from primary documentation and installed `--help`, then always use it. Run each available binary with `subprocess.run`, shared lint config, explicit targets, and an `ANSIBLE_ROLES_PATH` derived only from supplied role parents; preserve its output and exit status. Mark only absent executables `NOT AVAILABLE`. Missing dependencies reported by an available executable are `FAIL`. Keep package mappings `ansible-playbook -> ansible-core`, `ansible-lint -> ansible-lint`, and `yamllint -> yamllint`; never invoke installers.

- [ ] **Step 5: Implement reporting and exit semantics**

Print target/coverage inventory, per-tool executable/status/check counts, unverified targets, optional isolated install commands containing only missing packages, and the exact rerun command. The rerun must activate the suggested environment or prefix its `bin` directory onto `PATH`. Keep native exceptions reasoned and visible in source/shared configuration rather than building a scanner. Print separate static and `Live verification: NOT RUN — requires separate authorization` sections. Implement the three overall states and failure precedence from the spec.

- [ ] **Step 6: Run deterministic tests**

Run: `python3 -m unittest discover -s .opencode/skills/ansible-validation/tests -v`

Expected: PASS for CLI/status mechanics. These tests verify the script, not Ludus runtime behavior.

- [ ] **Step 7: Exercise real tools that are currently available**

Run the script against a small valid checked-in role/harness and controlled malformed YAML/Ansible fixtures. Restrict `PATH` to subsets of the same real discovered executables to exercise partial/no-tool reporting; do not create fake tool executables. For every tool actually present, demonstrate a passing check and a real failing check. Confirm the real `ansible-lint` command uses its verified offline/no-install mode and does not modify dependency locations. Record unavailable integrations as unverified rather than claiming them tested.

Expected: real available tools produce their native PASS/FAIL outcomes; no-tool and partial-tool cases follow warning semantics; available failure plus missing peer remains nonzero.

### Task 2: Create the skill and deployment-scope workflow

**Files:**
- Create: `.opencode/skills/ansible-validation/SKILL.md`
- Modify: `.opencode/instructions/ansible.instructions.md:56-60`
- Modify: `docs/instructions/ludus-authoring.md:26-28`
- Modify: `.opencode/skills/ludus-blueprint/SKILL.md:10-27`
- Modify: `.opencode/skills/range-config/SKILL.md:33-41`
- Modify: `.opencode/skills/ludus-cli/SKILL.md:28-43`

**Interfaces:**
- Consumes: a requested role/range/source/blueprint scope, current official Ludus documentation, and locally inspectable files
- Produces: a human-readable complete target inventory plus one explicit script invocation; unresolved roles/dependencies become `--coverage-gap` entries

- [ ] **Step 1: Verify Ludus scope guidance before writing it**

Follow `docs/instructions/ludus-skill-documentation.md`: read affected skills fully and fetch current official source, blueprint, range configuration, requirements/dependency, role-development, and CLI/deployment pages. Record URLs, relevant exact guidance, redirects, unsupported assumptions, and conflicts. Distinguish repository workflow from official Ludus behavior; do not invent reference semantics.

- [ ] **Step 2: Write the thin skill**

Document how to inventory all included/referenced roles and declared dependencies, resolve source-local and already available external roles, identify truthful harnesses, classify artifact YAML as data, exclude unrelated roles, and represent every unresolved item as a prominent coverage gap. The skill supplies explicit paths to the script rather than implementing a dependency resolver or fetching/installing roles. Document `--all` for intentional repository-wide validation.

- [ ] **Step 3: Document status and authorization handling**

Require actual check failures and coverage errors to be fixed before requesting live authorization. Allow a missing-tool warning result to proceed only as `PASS WITH WARNINGS — NOT VERIFIED`, carrying forward each unavailable check and target. State that neither clean nor warning-only static output proves runtime readiness or authorizes deployment.

- [ ] **Step 4: Add minimal handoffs**

Point the Ansible instruction and Ludus authoring policy to the skill/script. In blueprint, range-config, and ludus-cli, require complete artifact target inventory while excluding unrelated roles. Preserve separate static/live evidence and do not add references to unrelated skills.

- [ ] **Step 5: Review documentation against official evidence**

Inspect changed regions and diff. Confirm factual Ludus guidance has firsthand current sources, exact commands/status words match the script, and no handoff says all tools must be installed or that warning-only output is verified/deployment permission. Report inaccessible sources and unresolved coverage.

### Task 3: Verify end-to-end behavior and scope

**Files:**
- Review: all files from Tasks 1-2

**Interfaces:**
- Consumes: completed script, tests, configs, skill, and handoffs
- Produces: final report separating script tests, real available-tool evidence, unavailable checks, artifact coverage, and live-not-run status

- [ ] **Step 1: Run the script test suite**

Run: `python3 -m unittest discover -s .opencode/skills/ansible-validation/tests -v`

Expected: PASS with deterministic all/partial/no-tool and failure-precedence coverage.

- [ ] **Step 2: Run explicit-role and `--all` smoke checks**

Run the finalized command against an existing role with a truthful harness, then run `--all`. Expected outcomes depend on installed tools and repository findings: missing tools are `NOT AVAILABLE`; available failures and whole-repository missing harnesses are nonzero; no unavailable check is described as verified.

- [ ] **Step 3: Run one range/blueprint inventory through explicit paths**

Use the skill to inventory a checked-in blueprint/range, list every referenced role/dependency and artifact data file, and invoke the script with explicit paths plus coverage gaps. Confirm unrelated roles are absent and unresolved targets prevent a clean result without being mislabeled as missing tools.

- [ ] **Step 4: Inspect final scope and report**

Run `git diff --check`, inspect the full diff, and confirm there are no installers, locks, caches/registries, generated harnesses, CI hooks, live commands, or unrelated role edits. Report exact commands, per-tool evidence, install suggestions, rerun command, target coverage, and `Live verification: NOT RUN — requires separate authorization`. Do not commit or deploy without separate instruction.
