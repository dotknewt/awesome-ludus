# GitLab Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Debian/Ubuntu Docker GitLab Runner role and opt-in, convergent CE demo-project/project-runner bootstrap.

**Architecture:** Keep installation, project/runner API operations, pipeline provisioning, and local runner configuration in a reusable `ludus_gitlab_runner` role. CE independently bootstraps a protected API credential; explicit range inputs authorize the runner to retrieve it through delegation. Use the modern project-runner API on the separately ordered runner VM.

**Tech Stack:** Ansible roles, Debian/Ubuntu packages, GitLab REST API, `community.general.gitlab_*`, Ludus range YAML, Docker executor.

**Spec:** `docs/superpowers/specs/2026-10-22-gitlab-runner-design.md`

## Global Constraints

- Install Runner from the approved GitLab package script URL and `gitlab-runner` package.
- Enable/start the service and render Docker executor configuration without a Docker socket mount or privileged containers.
- Use `POST /api/v4/user/runners` with `runner_type=project_type` and `project_id`; do not use `/projects/:id/runners` to create runners.
- Registration uses `--token`, never `--registration-token`.
- Bootstrap is opt-in, explicit, secret-safe, convergent, and preserves unrelated project content.
- Do not assume the Docker role's hardcoded `debian` identity.
- Static verification only; no live actions, simulations, stateful fakes, or mocks.

## File map and contracts

- Create `ansible/roles/ludus_gitlab_runner/{defaults/main.yml,meta/main.yml,tasks/main.yml,tasks/bootstrap.yml,templates/config.toml,README.md,tests/syntax.yml}`: exact `ludus_gitlab_runner_*` inputs, package installation, delegated token read, project/runner lifecycle, exclusively owned config, service lifecycle, metadata, and docs. Output is an enabled service with root-owned restrictive config.
- Modify `ansible/roles/linux_gitlab_ce/{defaults/main.yml,tasks/main.yml,tasks/bootstrap.yml,README.md}`: add `ludus_gitlab.bootstrap` and an independent include; CE creates and persists the scoped API credential, while the runner owns project/runner operations. No manual token is required when explicit bootstrap delegation is enabled.
- Create `docs/examples/gitlab-runner/range-config.yml`: separate server and runner VMs, `ludus_install_docker` plus `ludus_gitlab_runner`, explicit bootstrap host/URL/project/image inputs, and server-before-runner `depends_on`. No secret literal is added.

## Review Focus

1. Credential bootstrap/transport and task redaction: CE generates `api`+`create_runner` token under `no_log`, writes mode `0600`, and runner reads only via explicit host delegation or explicit token (static review; live handling unverified).
2. API semantics and scopes: project creation versus runner creation versus assignment, with `project_type` and `create_runner` (static request inspection; endpoint compatibility unverified).
3. Partial failure after remote runner creation: deterministic managed identity/reuse and no duplicate creation (static control-flow review; crash recovery unverified).
4. Idempotence/content preservation: no duplicate project or CI commit; fail closed for unrecoverable existing runner/config rather than destructive reset or TOML merge (static review; repeated convergence unverified).
5. Identity/security: explicit runner user, unprivileged Docker executor, no socket mount, correct service/config permissions (static template/range checks; actual container isolation unverified).

## Tasks

### Task 1: Define the reusable runner role

**Files:** Create the `ludus_gitlab_runner` files listed in the file map.

- [ ] Define defaults: URL, optional token, `bootstrap_from_server: false`, explicit `bootstrap_host`, name, tags, image, config path, and user; reject neither-token mode unless bootstrap is explicitly enabled.
- [ ] Add metadata with nonempty role name and author `dotknewt`.
- [ ] Implement repository script download/execution guarded by package/repository state, install `gitlab-runner`, and avoid unconditional changed commands.
- [ ] Read `/var/lib/ludus/gitlab/bootstrap-api-token` from the explicit delegated host under `no_log` when enabled; fail closed if unavailable.
- [ ] Create/find the configured project and call `POST /api/v4/user/runners` with `runner_type=project_type`; do not promise token recovery or use `/projects/:id/runners` for creation.
- [ ] Render exclusively managed `config.toml`; fail closed on non-managed preexisting content, then register with `--token` and enable/start the service.
- [ ] Run file-scoped YAML syntax and static checks; record package/runtime behavior as unverified.

### Task 2: Make CE bootstrap opt-in and convergent

**Files:** Modify CE defaults, `tasks/main.yml`, add `tasks/bootstrap.yml`, and update `README.md`.

- [ ] Add `ludus_gitlab.bootstrap.enabled: false` and exact project/token-file inputs; include bootstrap independently of groups/users.
- [ ] Generate the dedicated credential locally with `gitlab-rails`, scopes `api` and `create_runner`, under `no_log`, and write mode `0600`; never require manual token input for this path.
- [ ] Document that runner owns project creation, runner creation, and minimal `.gitlab-ci.yml`; avoid duplicate commits and preserve unrelated content.
- [ ] Fail closed when a remote runner exists but its authentication token is unavailable; require explicit operator recovery and never delete/reset it.
- [ ] Update README inputs, secret transport, opt-in behavior, and limitations; run scoped static checks.

### Task 3: Add the ordered range example

**Files:** Create `docs/examples/gitlab-runner/range-config.yml`.

- [ ] Add distinct GitLab server and runner VMs; assign CE to the server and Docker plus Runner to the runner.
- [ ] Wire explicit URL, `bootstrap_from_server: true`, `bootstrap_host` equal to the server inventory identity, project identity, and image; do not rely on hidden hostnames or Docker-role account behavior.
- [ ] Add `depends_on` containing the server VM name and installed CE role identity; retain repository range defaults `snapshot_with_RAM: true`, `stale_hours: 0`, and `timezone: Europe/Oslo`.
- [ ] Validate range YAML/schema and statically confirm no secret literals, socket mount, privileged container, or legacy registration flag.

### Task 4: Final static review and evidence report

**Files:** Changed files only; no implementation additions unless a check exposes a defect.

- [ ] Inspect the diff for scope, naming, role identity, input/output consistency, and preservation of unrelated content.
- [ ] Run changed-file YAML/Ansible syntax, role metadata, and range-schema checks available in the repository.
- [ ] Report static evidence separately from live-unverified claims; explicitly list unresolved selected-version/package/API compatibility and crash-recovery evidence.

## Self-review result

The approved installation, automatic CE credential bootstrap, explicit
delegation transport, API distinction, fail-closed recovery, range ordering,
security constraints, and five risk focuses each map to a task or review
focus. No live verification or mock/stateful fake is included. Official Ludus
documentation supports `depends_on` ordering but does not establish
cross-playbook `hostvars` persistence; the plan therefore uses explicit
delegation and records that limitation rather than claiming live readiness.
