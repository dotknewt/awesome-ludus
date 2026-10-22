# splunk_container_logs

Installs one reviewed Splunk OpenTelemetry Collector executable and a dedicated
`splunk-container-logs` service to read existing Docker `json-file` logs and
send logs only to an explicit Splunk Platform HEC event endpoint. C3 supports
only `mode: docker`; `kubernetes` is rejected until C4.

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

The internal `vars/artifacts.yml` fixes Collector 0.163.0, the archive SHA-256,
archive layout, executable entrypoint, and component IDs. Only
`splunk_container_logs_collector_url` is a normal caller override, permitting a
mirror only when its bytes match the frozen digest. The Debian package and its
maintainer scripts are deliberately not used; only the reviewed `bin/otelcol`
raw member is extracted into protected staging, checked against its frozen
size/SHA-256, and then installed. The installed executable is hashed before
every collector execution; a same-size modified binary fails closed.

## Variables

| Variable | Default | Requirement |
| --- | --- | --- |
| `splunk_container_logs_mode` | `""` | Required scalar `docker` |
| `splunk_container_logs_owner_id` | `ludus-container-logs` | Stable ownership identity |
| `splunk_container_logs_hec_endpoint` | `""` | Exact `/services/collector/event` HTTP(S) URL |
| `splunk_container_logs_hec_index` | `""` | Required destination index |
| `splunk_container_logs_hec_token` | `""` | Required secret |
| `splunk_container_logs_tls_verify` | `true` | `false` maps only to TLS certificate skipping |
| `splunk_container_logs_allow_insecure_http` | `false` | Separate permission for plaintext HTTP |
| `splunk_container_logs_ca_file` | `""` | Optional readable CA bundle |
| `splunk_container_logs_start_at` | `end` | `end` or `beginning` for new files without offsets |
| `splunk_container_logs_docker_include` | `[]` | Required nonempty explicit source paths |
| `splunk_container_logs_docker_exclude` | `[]` | Optional explicit source paths |
| `splunk_container_logs_docker_state_dir` | `/var/lib/splunk-container-logs` | Writable persistent state root |
| `splunk_container_logs_docker_logging_driver` | `""` | Must explicitly equal `json-file` |
| `splunk_container_logs_collector_url` | reviewed release URL | Same-digest mirror may override |
| `splunk_container_logs_queue_size` | `1000` | Positive request count |
| `splunk_container_logs_queue_max_disk_mib` | `512` | At least 200 MiB; rendered as checked MiB-to-byte multiplication |

Role defaults retain normal Ansible precedence, so Ludus `role_vars` can set all
public inputs. Version, checksum, archive layout, binary path, and component IDs
are internal pins and are not public release-substitution inputs.

The state root must already be normalized, contain no `.`/`..` components or
trailing slash, and be a dedicated descendant of `/var/lib`, `/srv`, `/mnt`, or
`/opt`. Before writes, the role checks every existing lexical ancestor without
following links, verifies nearest-ancestor resolution, and rejects overlap with
resolved sources or owned config/install/cache roots. Changing it later remains
an explicit migration. Resolved sources and custom CAs under paths hidden by
`ProtectHome` or private temporary directories are rejected.

## Persistence, lifecycle, and failures

Stable `file_storage/checkpoints` offsets and a separate bounded
`file_storage/exporter_queue` survive collector restarts. Queue size counts
requests; disk size limits the queue database. Receiver retry and exporter
backpressure reduce immediate loss, but bounded storage, rotation, retention,
and outages can still lose or duplicate events. This role makes no exactly-once
claim. `start_at` applies only where no checkpoint exists.

Changing owner, source realpaths, state root, install/config identity, or stable
component IDs while managed state exists fails and requires an explicit scoped
migration. Omitting the role later does not stop the service, remove the binary,
delete offsets, or revoke credentials. There is no uninstall or destructive
retirement path in C3.

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
checks. It does not download, extract, write, start, enable, or restart. Because
it does not write a secret-bearing candidate, candidate validation is explicitly
reported as unverified (and calls out an absent collector binary).

Static validation cannot establish host compatibility, source readability over
time, systemd sandbox enforcement, HEC acceptance, indexing, rotation behavior,
offset continuity, retry recovery, or unchanged runtime state. Those require
separately authorized live acceptance.
