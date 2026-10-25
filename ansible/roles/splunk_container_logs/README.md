# splunk_container_logs

Collects existing container logs and sends logs only to an explicit Splunk
Platform HEC event endpoint. `mode: docker` installs one reviewed Splunk
OpenTelemetry Collector executable and dedicated service. `mode: kubernetes`
uses the reviewed official chart against an explicit existing cluster.

## Supported boundary

- Debian 12 or Ubuntu 22.04/24.04, amd64, systemd.
- Existing, explicit, readable regular `*-json.log` files. Each path is resolved
  and must be unique and visible through the service sandbox. A bounded first
  record must contain scalar `log`, `stream` (`stdout` or `stderr`), and a valid
  RFC3339 `time`; this does not prove every later record. Globs, Docker `local`,
  journald, rootless layouts, remote drivers, and Windows containers are
  unsupported.
- The caller confirms `splunk_container_logs_docker_logging_driver: json-file`.
  The role reads a representative envelope but does not contact Docker.
- No container runtime package, configuration, service, socket, group, source
  mode, or source ownership is changed. Source parent directories are exposed
  read-only in the service sandbox so a recreated active file remains visible;
  only the configured state directory is writable.
- Kubernetes mode requires an existing kubeconfig, exact context and cluster
  name, a nonempty node selector, and Linux/amd64 nodes. It does not create or
  reconfigure a cluster, runtime, workload, audit policy, or admission/RBAC
  exception. Unsupported hostPath or Pod Security policy fails normally.
- The execution host must already provide `kubernetes.core` 6.6.0 and its
  Python requirements, Helm 3.20.0, and helm-diff 3.15.15. The role validates
  tools but never installs them.

The internal `vars/artifacts.yml` fixes Collector 0.163.0, the archive SHA-256,
archive layout, executable entrypoint, chart/image/tool versions and digests,
and component IDs. The collector and chart URLs are normal caller overrides
only for mirrors whose bytes match their frozen digest. The Debian package and its
maintainer scripts are deliberately not used; only the reviewed `bin/otelcol`
raw member is extracted into protected staging, checked against its frozen
size/SHA-256, and then installed. The installed executable is hashed before
every collector execution; a same-size modified binary fails closed.

## Variables

| Variable | Default | Requirement |
| --- | --- | --- |
| `splunk_container_logs_mode` | `""` | Required scalar `docker` or `kubernetes` |
| `splunk_container_logs_owner_id` | `ludus-container-logs` | Stable ownership identity |
| `splunk_container_logs_hec_endpoint` | `""` | Exact `/services/collector/event` HTTP(S) URL |
| `splunk_container_logs_hec_index` | `""` | Required destination index |
| `splunk_container_logs_hec_token` | `""` | Required except in Kubernetes existing-Secret mode |
| `splunk_container_logs_tls_verify` | `true` | `false` maps only to TLS certificate skipping |
| `splunk_container_logs_allow_insecure_http` | `false` | Separate permission for plaintext HTTP |
| `splunk_container_logs_ca_file` | `""` | Optional readable CA bundle |
| `splunk_container_logs_start_at` | `end` | `end` or `beginning` for new files without offsets |
| `splunk_container_logs_docker_include` | `[]` | Required nonempty explicit source paths |
| `splunk_container_logs_docker_exclude` | `[]` | Optional explicit source paths |
| `splunk_container_logs_docker_state_dir` | `/var/lib/splunk-container-logs` | Writable persistent state root |
| `splunk_container_logs_docker_logging_driver` | `""` | Must explicitly equal `json-file` |
| `splunk_container_logs_collector_url` | reviewed release URL | Same-digest mirror may override |
| `splunk_container_logs_chart_url` | reviewed chart URL | Same-digest mirror may override |
| `splunk_container_logs_queue_size` | `1000` | Request count from 1 through 2147483647 |
| `splunk_container_logs_queue_max_disk_mib` | `512` | From 200 through 8796093022207 MiB; checked before conversion to bytes |
| `splunk_container_logs_kubeconfig` | `""` | Existing readable kubeconfig; required in Kubernetes mode |
| `splunk_container_logs_kube_context` | `""` | Exact existing context; never inferred from current context |
| `splunk_container_logs_k8s_cluster_name` | `""` | Exact cluster named by the context and stable ownership marker |
| `splunk_container_logs_k8s_namespace` | `splunk-logs` | Owned namespace; unmanaged existing destination is rejected |
| `splunk_container_logs_k8s_release` | `splunk-container-logs` | Owned Helm release name |
| `splunk_container_logs_k8s_existing_secret` | `""` | External Secret name, mutually exclusive with caller token |
| `splunk_container_logs_k8s_node_selector` | `{}` | Required label-valid positive selector; Linux/amd64 is enforced |
| `splunk_container_logs_k8s_tolerations` | `[]` | Explicit agent tolerations |
| `splunk_container_logs_k8s_log_paths` | `[/var/log/pods]` | Must include chart receiver source `/var/log/pods`; optional `/var/log/containers` is a supplemental read-only mount |
| `splunk_container_logs_k8s_checkpoint_path` | `/var/addon/splunk/otel_pos` | Stable normalized dedicated writable checkpoint host path |
| `splunk_container_logs_k8s_queue_path` | `/var/addon/splunk/exporter_queue` | Stable normalized dedicated writable exporter queue host path, disjoint from checkpoint path |

Role defaults retain normal Ansible precedence, so Ludus `role_vars` can set all
public inputs. Version, checksum, archive layout, binary path, and component IDs
are internal pins and are not public release-substitution inputs.

Both queue inputs accept integers or canonical ASCII decimal strings within
their bounds. Booleans, floats, signs, whitespace, leading zeroes, decimal points,
exponents, underscores, and non-ASCII digits are rejected. This supports numeric
inputs materialized as text without silently coercing malformed values.
The same strict filters validate the inputs and perform numeric conversion
inside each Docker or Kubernetes template expression, before multiplication or
rendering. Queue values remain unquoted YAML numbers; no global Jinja setting
change or intermediate scalar fact is required.

Shared and Kubernetes text inputs accept strings, including Ansible's YAML and
unsafe-text string subclasses, without converting non-string values. Existing
nonempty, URL, authority, identity, and path restrictions still apply.
If shared or bounded Kubernetes input validation fails, controller-side
diagnostics report only fixed condition names, booleans, type codes, or an
`evaluation_error` code. Input values and exception text remain hidden. These
diagnostics do not permit validation failure to continue into installation.

Helm application failures also produce a value-free error classification and,
when available, a post-failure controller loader snapshot with the selected
module path, collection version, and source hash. This snapshot is not a trace
of the earlier failed task's worker. Raw Helm output and credentials remain
hidden, the role still fails, and its protected workspace cleanup still runs.

## Kubernetes credentials and convergence

With `splunk_container_logs_k8s_existing_secret`, the role reads but never
updates that Secret. It strictly base64-decodes the nonempty
`splunk_platform_hec_token`; when `splunk_platform_hec_ca_file` is present it
also strictly decodes and parses its PEM trust data in memory. The chart receives
only the Secret name and a non-secret CA placeholder. Caller token and local CA
inputs must remain empty in existing-Secret mode. In caller-token mode the
role creates or updates only `<release>-hec`, marked by owner and cluster
annotations. An optional local `splunk_container_logs_ca_file` is parsed before
its bytes are put in that owned Secret. Secret-bearing tasks are redacted; token
and CA bytes are not command arguments or values-file content.

A SHA-256 marker derived from length-framed decoded token and CA bytes is placed
in the collector pod annotations; plaintext credentials are never placed there.
For the owned Secret, changing caller token or CA changes that marker and gives
Helm a pod-template diff for a bounded rollout. For an external existing Secret,
the role never watches or mutates the object: an operator rotates it, then reruns
this role so read-only validation recomputes the marker and Helm rolls pods when
the bytes changed. Rotation without a role rerun has no refresh guarantee.

The role requires Helm 3.20.0 and helm-diff 3.15.15, verifies the chart archive
against its frozen SHA-256, and sets three-way diff. Existing namespaces,
role-owned Secrets and releases must carry the expected ownership and cluster
identity; a release must be deployed chart/app 0.163.0. Pending, failed,
unmanaged, or wrong-lineage destinations fail without automatic recovery. A
clean module diff performs no upgrade; a real diff uses bounded wait. There is
no uninstall, force, replace, or cluster-recreation path.

The rendered values enable only container file logs to Splunk Platform. They
disable metrics, traces, Observability, cluster receiver/events/objects,
journald, gateway, operator/CRDs, instrumentation, OBI, target allocator,
remote management, logs-to-metrics, agent Service/host networking, all six
application listener ports, helper init containers, and the validation hook.
The collector image is the reviewed Linux/amd64 digest. Chart-native checkpoint
and persistent-queue values plus explicit merged collector configuration retain
stable IDs, bounded queue storage, retries and backpressure. The chart's log
mounts and explicit approved pod-log mounts are read-only; checkpoint and queue
mounts are the only requested writable host state.

The pinned chart receiver always tails `/var/log/pods/*/*/*.log`, so v1 requires
`/var/log/pods` and records the sorted mount/source identity in managed release
values. `/var/log/containers`, when selected alongside it, is only a supplemental
read-only mount; it is not an alternate receiver source. Changing this identity,
or changing normalized checkpoint/queue roots, fails existing-release preflight
pending explicit migration. Persistent paths reject dot segments, trailing or
duplicate separators, equality, and ancestor/descendant overlap. Each must be a
single `/var/addon/splunk/` basename containing only letters, digits, `.`, `_`,
or `-`; whitespace and YAML-sensitive punctuation are rejected because the
pinned chart interpolates these paths unquoted.

The Docker state root must already be normalized, contain no `.`/`..` components or
trailing slash, and be a dedicated descendant of `/var/lib`, `/srv`, `/mnt`, or
`/opt`. Before writes, the role checks every existing lexical ancestor without
following links, verifies nearest-ancestor resolution, and rejects overlap with
resolved sources or owned config/install/cache roots. Changing it later remains
an explicit migration. Resolved sources and custom CAs under paths hidden by
`ProtectHome` or private temporary directories are rejected.

## Persistence, lifecycle, and failures

Docker uses stable `file_storage/checkpoints` and `file_storage/exporter_queue`;
Kubernetes uses chart checkpoint `file_storage` and exporter
`file_storage/persistent_queue`. These survive collector restarts. Queue size counts
requests; disk size limits the queue database. Receiver retry and exporter
backpressure reduce immediate loss, but bounded storage, rotation, retention,
and outages can still lose or duplicate events. This role makes no exactly-once
claim. `start_at` applies only where no checkpoint exists.

Changing owner, source realpaths, state root, install/config identity, or stable
component IDs while managed state exists fails and requires an explicit scoped
migration. Omitting the role later does not stop the service, remove the binary,
delete offsets, or revoke credentials. There is no uninstall or destructive
retirement path.

Known unmanaged package/service/config or fixed-destination collisions fail
closed. Before any write, the role reads the manager's effective `UnitPath` and
inventories the same-name unit plus service aliases in every listed directory.
It also rejects manager-reported or on-disk name-specific, dash-prefix
(`splunk-container-.service.d`, `splunk-.service.d`), and type-wide
(`service.d`) drop-ins. `LoadState`, `FragmentPath`, `DropInPaths`, `Names`, and
`Transient` must show no unmanaged, shadowed, generated, transient, alias, or
override provenance. This includes a fresh drop-in without a base unit. An owned
installation permits only the exact `/etc/systemd/system/splunk-container-logs.service`
fragment and no external override.
Configuration and unit candidates are protected; collector validation
must pass before pending intent and active replacement. A failed validation
keeps the active files/service unchanged. Later installation, activation, or
service failures can leave clearly owned partial state or a pending marker and
are reported as failures, not rolled back or described as success.

Check mode performs read-only facts, source, format, collision, and ownership
checks. Docker does not download, extract, write, start, enable, or restart. Because
it does not write a secret-bearing candidate, candidate validation is explicitly
reported as unverified (and calls out an absent collector binary).
Kubernetes check mode may create and always removes a protected local temporary
chart/values workspace for an existing release so Helm can render and diff, but
it does not create a namespace or Secret or mutate a release. A missing namespace
or release fails explicitly because the pinned Helm module does not render/diff
fresh installs in check mode; that fresh-install plan remains unvalidated. Missing
required tools or context likewise fails instead of being described as validated.

Static validation cannot establish host compatibility, source readability over
time, systemd sandbox enforcement, HEC acceptance, indexing, rotation behavior,
offset continuity, retry recovery, or unchanged runtime state. Those require
separately authorized live acceptance.
