# ludus_gitlab_runner

Installs GitLab Runner on Debian/Ubuntu and configures an unprivileged Docker
executor. The role installs distribution `docker.io`, starts Docker, and adds
the configured runner account to the `docker` group; no particular login user
is assumed. Jobs receive only `/cache` and never the host Docker socket. Docker
executor jobs are not privileged.

## Inputs

| Variable | Default | Purpose |
| --- | --- | --- |
| `ludus_gitlab_runner_url` | `""` | GitLab instance URL (required) |
| `ludus_gitlab_runner_auth_token` | `""` | Existing runner authentication token; registers without provisioning projects/runners |
| `ludus_gitlab_runner_bootstrap_from_server` | `false` | Enable project and runner provisioning |
| `ludus_gitlab_runner_bootstrap_host` | `""` | Explicit Ansible inventory host from which to read the protected API token |
| `ludus_gitlab_runner_api_token` | `""` | Optional explicit API token for bootstrap instead of delegation |
| `ludus_gitlab_runner_name` | `ludus-docker-runner` | Runner description |
| `ludus_gitlab_runner_tags` | `[docker]` | Runner tags |
| `ludus_gitlab_runner_executor_image` | `alpine:latest` | Default Docker executor image and CI image |
| `ludus_gitlab_runner_config_path` | `/etc/gitlab-runner/config.toml` | Package-service path; other paths are rejected |
| `ludus_gitlab_runner_user` | `gitlab-runner` | Account added to the Docker group |
| `ludus_gitlab_runner_project_name` | `ludus-runner-demo` | Bootstrap project display name |
| `ludus_gitlab_runner_project_namespace` | `root` | Project namespace path |
| `ludus_gitlab_runner_project_path` | `root/ludus-runner-demo` | Full namespace/project path |
| `ludus_gitlab_runner_smoke_ci_enabled` | `true` | Manage the sample CI file; set `false` to provision only the project and runner |
| `ludus_gitlab_runner_ci_file` | `.gitlab-ci.yml` | CI configuration path in the project |
| `ludus_gitlab_runner_allow_ci_file_replace` | `false` | Explicitly permit replacing an existing CI file |
| `ludus_gitlab_runner_state_path` | `/var/lib/ludus/gitlab-runner/runner.json` | Protected runner credential recovery state |

Bootstrap delegates a protected read of
`/var/lib/ludus/gitlab/bootstrap-api-token` from the configured host. It
requires server-side `api` and `create_runner` scopes and reachable delegation
in the same Ansible execution context. If Ludus separates role execution so
delegation cannot read the server, provide an API token explicitly or provide
an existing runner auth token. The latter only registers; it cannot provision
the project, CI file, or runner through the API.

This role is intended for disposable lab credentials and data. Task inputs,
GitLab API responses, and failure details may appear in Ansible diagnostics,
output, and controller logs. Do not use it with production credentials or other
externally provisioned secrets.

The role calls `POST /api/v4/user/runners` with `runner_type=project_type`.
GitLab does not return existing runner authentication tokens; a matching
remote runner whose token is absent locally is intentionally not reset/deleted,
and results in an operator recovery error. The canonical config is root-owned
mode `0600`; unrelated pre-existing config is refused rather than merged.
The role installs `python3-toml` to parse runtime config and preserves the
selected runner's id and token rotation metadata. Requested tags are provisioned
through the API, not written as unsupported TOML fields. The bootstrap runner
is configured to accept untagged jobs so the included sample CI job is runnable.
Immediately after API creation the runner id and authentication token are saved
to the root-owned state file mode `0600`; config tokens take precedence over
state tokens so a locally rotated credential is not overwritten with stale data.

When the project is absent, bootstrap resolves the requested namespace with
`GET /api/v4/namespaces/:url_encoded_full_path` and the protected API token.
Nested namespace `/` separators are explicitly escaped as `%2F` in that path
parameter.
It fails closed unless GitLab returns HTTP 200, exact `full_path`, a `kind` of
`user` or `group`, and a positive namespace ID. Only that namespace ID is sent
when creating the project; user IDs are not substituted for namespace IDs.

Set `ludus_gitlab_runner_smoke_ci_enabled: false` to keep project and runner
provisioning enabled without managing the sample pipeline. In that mode the
role does not read or write the CI file and launches no pipeline. The default is
`true` for backward compatibility.

## Compatibility and references

Supported target families: Debian and Ubuntu with apt and systemd. This role
does not prove compatibility with a particular GitLab server release, runner
package release, executor image, or bootstrap delegation topology. Package
repository setup and actual registration require runtime validation; no live
GitLab operations are performed by static checks.

Official references:

- [GitLab Runner Linux installation](https://docs.gitlab.com/runner/install/linux-repository/)
- [Runner authentication token registration](https://docs.gitlab.com/runner/register/)
- [Create a runner API](https://docs.gitlab.com/api/runners/#create-a-runner)
- [Namespaces API](https://docs.gitlab.com/api/namespaces/)
- [Projects API](https://docs.gitlab.com/api/projects/)
- [Repository files API](https://docs.gitlab.com/api/repository_files/)
