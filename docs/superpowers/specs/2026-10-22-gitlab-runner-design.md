# GitLab Runner Design

## Goal and approved scope

Add a reusable `ludus_gitlab_runner` role for Debian/Ubuntu and extend
`linux_gitlab_ce` with opt-in bootstrap of a demo project and modern project
runner registration. The range example places the runner on a separate VM and
orders it after the GitLab server with `depends_on`.

## Interfaces

`ludus_gitlab_runner` consumes these exact inputs: `ludus_gitlab_runner_url`,
`ludus_gitlab_runner_auth_token` (or the explicit bootstrap delegation switch
below), `ludus_gitlab_runner_name`, `ludus_gitlab_runner_tags`,
`ludus_gitlab_runner_executor_image`, `ludus_gitlab_runner_config_path`, and
`ludus_gitlab_runner_user`. It installs the GitLab repository using
`https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh`,
installs `gitlab-runner`, renders Docker executor `config.toml`, and enables and
starts the service. It may reuse `ludus_install_docker`, but must not assume its
`debian` account; the runner user and permissions are explicit.

The CE opt-in block is `ludus_gitlab.bootstrap` and is included independently
from groups/users. CE creates a dedicated root-owned API credential with
`gitlab-rails` (scopes `api` and `create_runner`) under `no_log`, persists it at
`/var/lib/ludus/gitlab/bootstrap-api-token` mode `0600`, and never commits or
prints it. The runner role owns project and runner lifecycle: it reads that
file by explicit `ludus_gitlab_runner_bootstrap_host` delegation when
`ludus_gitlab_runner_bootstrap_from_server: true`, or accepts an explicit
`ludus_gitlab_runner_auth_token` instead. It creates/finds the named project,
then calls `POST /api/v4/user/runners` with `runner_type=project_type` and
`project_id=...`. `/projects/:id/runners` is assignment of an existing runner,
not creation, and is not used.

The design must be convergent: identify existing project/runner/configuration,
avoid duplicate projects, runners, and commits, and preserve unrelated project
content. Registration uses `gitlab-runner register --token`, never the legacy
`--registration-token`. Containers run unprivileged and do not mount the Docker
socket.

## Credential and failure decisions

The dedicated CE credential is generated only when bootstrap is enabled and
stored at the path above; optional externally supplied runner credentials remain
supported for operators who do not want delegation. Official Ludus docs confirm
`depends_on` ordering but do not guarantee `hostvars` persistence across
separate playbooks. Therefore the example uses server-before-runner ordering
and an explicit inventory host for Ansible delegated protected-file reading;
if Ludus executes roles in separate playbooks where delegation cannot share the
read, bootstrap delegation is unsupported and the operator must supply the
token explicitly. Missing token/file or an existing remote runner whose token
cannot be recovered is fail-closed: report operator recovery, never reset or
delete the remote runner automatically. Runner config is exclusively managed:
if a non-managed existing config is present, fail rather than merge or replace
unrelated entries.

## Verification boundary

Authorized evidence is static only: YAML/Ansible syntax, role metadata,
scoped lint/pattern checks, and range-schema validation for the example. No
live GitLab deployment, API call, runner registration, or stateful fake/mock is
authorized. Package/repository compatibility, GitLab version behavior, and
actual convergence remain unverified and must be reported as such.
