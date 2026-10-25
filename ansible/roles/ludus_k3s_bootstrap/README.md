# ludus_k3s_bootstrap

Installs a pinned native K3s single-server prerequisite on Ubuntu 24.04 amd64.
K3s runs as a systemd service with its embedded containerd. The role neither
uses K3s's remote installer nor selects `--docker`, and it does not install,
remove, reconfigure, stop, or restart host Docker or system containerd packages.

## Fixed contract

- K3s `v1.37.1+k3s1` (`v1.37.1` Kubernetes), Helm `v3.20.0`, and helm-diff
  `3.15.15` are downloaded from the fixed upstream release URLs in
  `vars/artifacts.yml` and checked against fixed SHA-256 digests before use.
- Helm is installed at `/usr/local/bin/helm`. The verified helm-diff archive is
  extracted directly under the plugin directory reported by `helm env
  HELM_PLUGINS` for root; no downloaded install or update hook is executed.
  The installed Helm and diff binaries plus the diff plugin manifest are hashed
  against their members inside the retained, checksum-verified release archives
  on installation and every marked rerun.
- The root-owned kubeconfig is `/etc/rancher/k3s/k3s.yaml`, mode `0600`, with
  exact cluster, context, current-context, and user-entry name `default`.
  The context references cluster/user `default`; the API endpoint is
  `https://127.0.0.1:6443`. These are the pinned K3s exported admin kubeconfig
  names, not the `local`/`Default` names used by internal component configs.
- Kubernetes Python dependencies live in a `--system-site-packages` venv at
  `/opt/ludus-k3s/python`. This retains Ubuntu's `python3-apt` for normal
  Ansible modules while every pip-installed direct and transitive dependency is
  pinned and hash-locked in `files/kubernetes-requirements.txt`. Verification
  compares the complete venv-local distribution set and versions with that
  lock; only the intentional `pip` and optional `setuptools` bootstrap
  distributions are outside it. Ubuntu system-site distributions are visible
  but are not mistaken for venv-local pip installations.

The role publishes these same-host facts only after verification:

| Fact | Value |
| --- | --- |
| `ludus_k3s_kubeconfig_path` | `/etc/rancher/k3s/k3s.yaml` |
| `ludus_k3s_kube_context` | `default` |
| `ludus_k3s_cluster_name` | `default` |
| `ludus_k3s_python_interpreter` | `/opt/ludus-k3s/python/bin/python` |

It also sets `ansible_python_interpreter` to that dedicated interpreter for
later roles on the same host. Run any role that needs the system interpreter,
including the GitLab runner role, before this role.

Consumers with literal range inputs must also select context and cluster
`default`; changing the published facts does not update those inputs. Do not
rename the generated kubeconfig entries: K3s regenerates this file. The pinned
[exported kubeconfig writer](https://github.com/k3s-io/k3s/blob/v1.37.1%2Bk3s1/pkg/clientaccess/kubeconfig.go#L29-L48)
uses the [default export name](https://github.com/k3s-io/k3s/blob/v1.37.1%2Bk3s1/pkg/cli/cmds/server.go#L300-L305)
for all entries and references.

## Inputs and supported boundary

The artifact selections and owned paths are internal immutable variables, not
mirror or version inputs. Public inputs only bound readiness waits:

| Variable | Default | Allowed |
| --- | ---: | --- |
| `ludus_k3s_bootstrap_service_retries` | `60` | integer 1–120 |
| `ludus_k3s_bootstrap_service_delay` | `5` | integer seconds 1–10 |
| `ludus_k3s_bootstrap_api_retries` | `60` | integer 1–120 |
| `ludus_k3s_bootstrap_api_delay` | `5` | integer seconds 1–10 |

Only Ubuntu 24.04, amd64, and systemd are accepted. The role requires outbound
HTTPS to the pinned GitHub, Helm, and PyPI artifacts. It installs only
`ca-certificates` and `python3-venv` from Ubuntu; it never pip-installs into the
system interpreter.

## Ownership and lifecycle

Before any managed write, the role inventories the K3s binary, service,
configuration/state, kubeconfig, Helm binary, root diff plugin, Python venv,
and role cache. Existing destinations without the exact root-owned marker at
`/var/lib/ludus-k3s-bootstrap/ownership.yml` fail closed. Marked binaries,
service configuration, kubeconfig, plugin, and imports are checked against the
fixed contract before mutation; mismatches fail rather than being replaced or
adopted. Existing Docker and distro containerd state is not a collision.

Marked state must retain exact regular-file/directory types, root ownership,
and modes for every protected destination, including state/config/cache roots,
the `0600` kubeconfig, retained release archives, lock/verifier files, and tool
binaries. `/etc/rancher/k3s` may contain only the generated `k3s.yaml`;
`config.yaml`, `config.yaml.d`, and every other entry fail before mutation.
The exact service fragment must have no drop-ins, `Environment`, or
`EnvironmentFiles`, preventing alternate runtime injection around the reviewed
command. Drift is rejected rather than chmodded or repaired.

There is deliberately no reset, uninstall, migration, adoption, or cleanup path.
One narrowly defined recovery is supported: an exact marker-owned pre-service
partial state with all 13 verified bootstrap destinations present, exactly the
four service destinations absent, and an inactive, unfragmented systemd unit.
The role inspects the pip-only venv before resuming locked wheel installation.
This is not a general repair path: partial states outside that exact boundary
fail closed without cleanup. A failure after dependency installation but
before service setup also requires operator review and is not automatically
resumed on a later run. Omitting the role leaves service, cluster state, tools,
and credentials in place.

## Role-internal deployment prerequisite checks

Service restart/start requests are nonblocking and systemd has a finite
120-second startup timeout; explicit role retries bound the observed result.
Every retrying kubectl request has a 10-second request timeout. Bounded checks
require an active service, the API `/readyz` endpoint, exact kubeconfig names,
and then retry the complete predicate for exactly one Ready Linux/amd64 node
that is not unschedulable and has no `NoSchedule` or `NoExecute` taint. The
node's reported `containerRuntimeVersion` must be `containerd://...`, providing
runtime evidence in addition to the effective unit/config checks. They also
require exact K3s/Helm/diff versions, a consistent Python dependency graph, and
exact imports for
`kubernetes==37.0.1`, `PyYAML==6.0.3`, and `jsonpatch==1.36`.

The role creates no pod, deployment, job, event, or other synthetic workload.
Static checks establish source contracts only. Ubuntu, systemd, network,
release, cluster, convergence, and recovery behavior remain unverified until a
separately authorized deployment executes this actual role entrypoint.
