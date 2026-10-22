# Splunk container collection and HEC evidence

Research date: 2026-10-22. This is source and artifact inspection, not runtime
proof. No downloaded program was executed, no package was installed, and no
live Splunk, Docker, or Kubernetes endpoint was queried.

## Proposed C1 combination and public-default handoff

The source-backed candidate set awaiting the C1 review gate is recorded in
`ansible/roles/splunk_container_logs/vars/artifacts.yml`:

- Splunk OpenTelemetry Collector **0.163.0**, using the release's
  `linux/amd64` tar archive rather than its Debian package.
- Official Splunk OpenTelemetry Collector chart **0.163.0** and the chart's
  matching collector image, pinned to the Linux/amd64 manifest digest
  `sha256:e9f0b6afea725b5b6e2a516db64399d37437c09cbe1dac6a5ab0697d8f93a668`.
- Helm **3.20.0**, helm-diff **3.15.15**, and locally installed
  `kubernetes.core` **6.6.0**.
- Exporter queue size **1000** and a dedicated file-storage database cap of
  **512 MiB** (`max_size: 536870912`).

The manifest is internal immutable metadata in the role-vars lane. It deliberately
does **not** define caller-facing variables: Ansible role vars would override
Ludus `role_vars`. C3 must put this exact mapping in `defaults/main.yml`:

```yaml
splunk_container_logs_collector_version: "0.163.0"
splunk_container_logs_collector_package_url: "https://github.com/signalfx/splunk-otel-collector/releases/download/v0.163.0/splunk-otel-collector_0.163.0_amd64.tar.gz"
splunk_container_logs_collector_package_checksum: "sha256:bb44c773423c88392c7e27d309c43bfae937ce1b3b0b81831dbc07149a28ca49"
splunk_container_logs_chart_version: "0.163.0"
splunk_container_logs_chart_url: "https://github.com/signalfx/splunk-otel-collector-chart/releases/download/splunk-otel-collector-0.163.0/splunk-otel-collector-0.163.0.tgz"
splunk_container_logs_chart_checksum: "sha256:8f7a64a2c10583932c82dcb2f761c2daef748d4b29fb7440092df144a4b0f9d9"
splunk_container_logs_queue_size: 1000
splunk_container_logs_queue_max_disk_mib: 512
```

V1 supports only the reviewed Collector 0.163.0 archive SHA-256, chart 0.163.0
package SHA-256, and matching repository/platform image digest recorded in the
manifest. A caller may change either download URL to an arbitrary mirror only
when the downloaded bytes still match that artifact's fixed manifest SHA-256;
the version and checksum inputs must equal the reviewed values. A new release is
not a three-field runtime substitution: it requires a complete update and review
of the internal manifest, including archive layout/entrypoint, capabilities,
image, dependencies, chart values, and merge behavior. The two queue limits are
normal independent caller inputs, validated as positive integers and rendered
into both queue-size and byte-cap mappings; they do not change artifact identity.
Convert MiB to bytes with a checked integer multiplication by 1,048,576 and
reject values below the selected chart's 200 MiB rebound-needed threshold.

## Artifact provenance and safe inspection

Artifacts were downloaded to the unique directory
`/tmp/opencode/c1-artifacts.bx9Sxa`. Before extraction, Python `tarfile`
inspection checked absolute paths, `..` components, backslashes, link entries,
non-regular entries, entry count, and expanded size. No unsafe path, symlink,
hardlink, or special file was found. Archive contents were read but not run.

| Artifact | Bytes / entries / expanded bytes | SHA-256 provenance |
| --- | --- | --- |
| `collector.tar.gz` | 184,427,702 / 9 / 501,306,956 | Local `sha256sum` = `bb44c773423c88392c7e27d309c43bfae937ce1b3b0b81831dbc07149a28ca49`; matches the GitHub v0.163.0 release asset digest and `checksums.txt` |
| `chart.tgz` | 180,520 / 127 / 1,630,957 | Local `sha256sum` = `8f7a64a2c10583932c82dcb2f761c2daef748d4b29fb7440092df144a4b0f9d9`; matches the GitHub release asset digest |
| `helm-v3.20.0-linux-amd64.tar.gz` | 17,455,024 / 4 / 57,682,840 | Local `sha256sum` = `dbb4c8fc8e19d159d1a63dda8db655f9ffa4aac1b9a6b188b34a40957119b286`; matches `get.helm.sh` `.sha256sum` |
| `helm-diff-3.15.15-linux-amd64.tgz` | 34,673,986 / 6 / 82,793,954 | Local `sha256sum` = `504e99410611daa70702362e1b10dc74929df8a912cb3f6b5d21d1ee9d0cb7d9`; matches the GitHub v3.15.15 release asset digest |

The selected OCI tag was resolved through the Quay v2 registry and then fetched
again by immutable digest. Preserved response headers and JSON are:

- `/tmp/opencode/c1-artifacts.bx9Sxa/otel-image-index.{headers,json}`:
  `Docker-Content-Digest: sha256:e1192a0ef85a6094b939b873dbad099f5f926feae402f4ce949e435c3e5cc5a9`,
  media type `application/vnd.oci.image.index.v1+json`; the JSON's own SHA-256
  is the same index digest.
- `/tmp/opencode/c1-artifacts.bx9Sxa/otel-image-amd64.{headers,json}`:
  selected index child for `linux/amd64`, digest
  `sha256:e9f0b6afea725b5b6e2a516db64399d37437c09cbe1dac6a5ab0697d8f93a668`,
  size 3129 and media type `application/vnd.oci.image.manifest.v1+json`; the
  digest-addressed response header and local JSON SHA-256 both match.

The immutable requests were
`https://quay.io/v2/signalfx/splunk-otel-collector/manifests/sha256:e1192a0ef85a6094b939b873dbad099f5f926feae402f4ce949e435c3e5cc5a9`
with OCI-index Accept media type, followed by the same path using child digest
`sha256:e9f0b6afea725b5b6e2a516db64399d37437c09cbe1dac6a5ab0697d8f93a668`
and OCI-manifest Accept media type.

The image is mapped to the Collector repository commit and Apache-2.0 license
recorded in the manifest. This proves registry descriptor identity and source
mapping, not image execution or runtime contents.

The collector archive stores the selected executable as the unique regular raw
member `./splunk-otel-collector/bin/otelcol` (normalized
`splunk-otel-collector/bin/otelcol`), 449,040,714 bytes, streamed SHA-256
`bfd3de154091ff3449e7d9a346b8ad1f7795dcb0ce5bd366e10d1f704fc3cb4f`.
The same bounded inspection reconfirmed archive SHA-256
`bb44c773423c88392c7e27d309c43bfae937ce1b3b0b81831dbc07149a28ca49`.
Provenance is the controller-accepted streaming `tarfile` result in
`.superpowers/sdd/2026-10-22-splunk-container-hec/validation-C3-entry-hash.txt`;
the first literal normalized-name lookup found zero entries, while a bounded
`./` normalization found exactly one regular member and streamed all bytes.
It also contains executable `bin/otelcollauncher` (5,463,599),
`bin/opampsupervisor` (46,784,032), and non-executable sample
`config/{agent_config.yaml,gateway_config.yaml}` (10,328/8,283). All three
executables are statically linked x86-64 ELF files. C3 must install only
`bin/otelcol` at
`/opt/splunk-container-logs/collector/0.163.0/bin/otelcol`, write its owned
configuration to `/etc/splunk-container-logs/collector.yaml`, and use the direct
systemd entrypoint:

```text
/opt/splunk-container-logs/collector/0.163.0/bin/otelcol --config=/etc/splunk-container-logs/collector.yaml
```

The service identity is root for read-only Docker log access. The role does not
install or invoke the launcher, OpAMP supervisor, sample configs, vendor service,
or package scripts. This is a proposed install contract pending C1 acceptance;
actual service and sandbox behavior require later static and live gates.

The rejected Debian artifact is exactly
`splunk-otel-collector_0.163.0_amd64.deb`, 183,629,366 bytes, SHA-256
`8747774565f130e9c0a73366cda117e401357fff45eeb8fba5fa4d1c2f89a164`,
package architecture `amd64`, installed-size 489645 KiB, dependency
`libcap2-bin`. Its data includes `/usr/bin/{otelcol,otelcollauncher,opampsupervisor}`,
`/etc/otel/collector` conffiles, and
`/lib/systemd/system/splunk-otel-collector.service`; that unit runs
`/usr/bin/otelcollauncher $OTELCOL_OPTIONS` as `splunk-otel-collector`.
Preserved control-script hashes are `preinst`
`8f3f23599e3062afaabec3ccf19a21f319f600993cd64030ffb5484f527f1348`,
`postinst` `f3e5e97de4b1a03a59418afc2021705582333b136ef0d455890bfc9c17f57120`,
and `prerm` `f462654de73fc85fecd9d5b16b1d73d6da8c48d5d6255bfe9032d72324f005f`.
`preinst` creates the vendor account and stops/disables an active same-named
service. `postinst` sets capabilities, recursively chowns vendor config/state,
enables the unit, and restarts it if its environment file exists. Controller
ruling therefore selects the script-free archive; the package cannot preserve
the validation-first dedicated-service boundary on upgrades.

The release `go.mod` pins the distribution's filelog **receiver factory**,
file-storage **extension factory**, Splunk HEC **exporter factory**, stanza
package (which supplies `json_parser`, `time_parser`, and `move` operators), and
exporter helper to v0.163.0. Operators are not collector component factories.
Official Splunk Linux documentation supports Intel/AMD systemd systems including
Debian and Ubuntu; the selected archive is explicitly amd64. Debian 12 and Ubuntu
22.04/24.04 remain proposed v1 bounds whose actual host compatibility requires
live acceptance.

Primary artifacts and source refs:

- [Collector v0.163.0 release](https://github.com/signalfx/splunk-otel-collector/releases/tag/v0.163.0), source commit [`0a7df0e76f57c5b849b296619948f30e7e06594d`](https://github.com/signalfx/splunk-otel-collector/tree/0a7df0e76f57c5b849b296619948f30e7e06594d), Apache-2.0.
- [Chart 0.163.0 release](https://github.com/signalfx/splunk-otel-collector-chart/releases/tag/splunk-otel-collector-0.163.0), source commit [`619445cd7da7515d64002ecec36b38bc70d9e7c4`](https://github.com/signalfx/splunk-otel-collector-chart/tree/619445cd7da7515d64002ecec36b38bc70d9e7c4), Apache-2.0.
- [Helm v3.20.0](https://github.com/helm/helm/releases/tag/v3.20.0) and [helm-diff v3.15.15](https://github.com/databus23/helm-diff/releases/tag/v3.15.15), both Apache-2.0.
- [`kubernetes.core` 6.6.0 source](https://github.com/ansible-collections/kubernetes.core/tree/e91b3171ea9bb55f2fc0c3fc7ab06fb571f05ddc), GPL-3.0-or-later collection code.

## Transport, parser, and persistence contract

### Docker mode

The source is pre-existing Docker `json-file` files only. The role must use a
stable `filelog/docker_json` receiver ID, persistent `file_storage/checkpoints`,
and a separate `file_storage/exporter_queue`. The exact proposed queue mapping
for C3 is:

```yaml
extensions:
  file_storage/checkpoints:
    directory: /var/lib/splunk-container-logs/checkpoints
    fsync: true
  file_storage/exporter_queue:
    directory: /var/lib/splunk-container-logs/exporter_queue
    timeout: 0
    max_size: 536870912
    fsync: true
receivers:
  filelog/docker_json:
    storage: file_storage/checkpoints
    retry_on_failure:
      enabled: true
      initial_interval: 1s
      max_interval: 30s
      max_elapsed_time: 0s
exporters:
  splunk_hec/logs:
    retry_on_failure:
      enabled: true
      initial_interval: 5s
      max_interval: 30s
      max_elapsed_time: 0s
    sending_queue:
      enabled: true
      storage: file_storage/exporter_queue
      sizer: requests
      queue_size: 1000
      num_consumers: 10
      block_on_overflow: true
service:
  extensions: [file_storage/checkpoints, file_storage/exporter_queue]
```

Here `queue_size` counts exporter requests (serialized incoming batches), while
`max_size` is bytes for the dedicated queue's one bbolt database. Receiver retry
pauses file reading under downstream pressure; exporter overflow blocks the
caller rather than immediately rejecting while room might become available. A
full database or exhausted caller timeout can still reject data. The parser must
also explicitly configure:

1. `json_parser` from `body`, with embedded RFC3339 timestamp parsing from
   `attributes.time`;
2. move `attributes.log` to `body` while retaining `attributes.stream`;
3. stable source from the resolved file path and deterministic sourcetype
   `docker:json`;
4. caller-selected `start_at`, default `end`, and `delete_after_read: false`;
5. stable component/operator IDs so checkpoint and parser identity do not drift.

The v0.163.0 [filelog receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.163.0/receiver/filelogreceiver/README.md)
documents include/exclude globs, `start_at`, persistent offset storage, resolved
path attributes, operators, retries, and disabled-by-default deletion. The
v0.163.0 [JSON parser](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.163.0/pkg/stanza/docs/operators/json_parser.md)
supports embedded timestamp parsing. These are configuration capabilities, not
proof that a given host's files are readable or valid Docker JSON envelopes.

### Kubernetes mode

The selected chart natively tails `/var/log/pods/*/*/*.log`, uses the `container`
operator for CRI/containerd/Docker records, retains body/timestamp and runtime
attributes, adds Kubernetes metadata, derives `kube:container:<container>` as
sourcetype, moves the file path to `com.splunk.source`, and persists offsets at
`/var/addon/splunk/otel_pos`. Its default starts at `beginning`; the role must
override `agent.config.receivers.file_log.start_at` to the public default `end`.

Chart 0.163.0 ordinarily renders `queue_size: 1000` in request units, no
`block_on_overflow`, and a 300-second exporter retry window. Enabling
`featureGates.noDropLogsPipeline` would instead change the sizer to items and
raise 1000 to at least 10000, so it is explicitly **false**. C4 must apply the
manifest's full `chart_values_override`: persistent queue values create the
hostPath/mount and generated storage reference, while `agent.config` overrides
the generated `file_storage/persistent_queue`, `file_log`, and
`splunk_hec/platform_logs` maps. The resulting required contract is:

- checkpoint storage ID `file_storage`, directory
  `/var/addon/splunk/otel_pos`;
- exporter storage ID `file_storage/persistent_queue`, dedicated directory
  `/var/addon/splunk/exporter_queue/agent`, `max_size: 536870912`, `fsync: true`,
  and the chart's explicit online-compaction thresholds 200/100 MiB;
- exporter queue request units, `queue_size: 1000`, 10 consumers,
  `block_on_overflow: true`, and that storage ID;
- receiver retry 1s/30s/unlimited and exporter retry 5s/30s/unlimited
  (`max_elapsed_time: 0s`); receiver `start_at: end`.
- logs pipeline receivers exactly `[file_log]`, replacing the generated OTLP
  receiver so application OTLP listeners are not started.
- `agent.service.enabled: false`, `agent.hostNetwork: false`, and every selected
  chart application port key set to null: `otlp`, `otlp-http`, `zipkin`,
  `jaeger-thrift`, `jaeger-grpc`, and `opampforwarder`. Thus neither the chart's
  agent Service nor its application `containerPort`/`hostPort` entries should
  render.

The merge is source-verified at selected-ref `templates/configmap-agent.yaml`:
the rendered default agent config is parsed with `fromYaml`, then
`.Values.agent.config` is piped into
`mustMergeOverwrite $defaultConfig`. Helm pipeline argument order makes the
values map the rightmost argument, so its nested scalar/maps overwrite defaults
while unspecified generated endpoint/token/index fields remain. This is the
selected merge strategy, but its exact rendered result remains a required Helm
gate because Helm is absent here.

These port controls use the exact keys in selected-ref `values.yaml`. That file
defaults `agent.service.enabled` and `agent.hostNetwork` to true, defines host
ports for OTLP/OTLP-HTTP/Zipkin/Jaeger and a container port for the OpAMP
forwarder, and explicitly documents null as the way to disable a port. The
selected `templates/service-agent.yaml` gates the Service on
`agent.service.enabled`; `templates/daemonset.yaml` iterates `agent.ports` to
render enabled application ports and host ports. The explicit false/null values
are therefore source-backed proposed inputs, but the assertion that no Service,
application port, or host port remains is pending render acceptance.

The logs-only values contract must set at least: Splunk Platform logs true;
Platform metrics/traces false; Splunk Observability empty/disabled;
clusterReceiver, gateway, operator/operator CRDs, target allocator, OBI,
journald, events, objects, audit, OTLP application listeners, logs-to-metrics,
and remote management disabled. It must set an explicit positive node selector.
The manifest records the concrete source-backed values, digest rendering split,
and disabled dependency conditions. They are proposed inputs to the pending
schema/render gate, not proof of the rendered resources.
`agent.skipInitContainers: true` prevents the root host-permission-changing UBI
init container from rendering. `secret.validateSecret: false` prevents the
default untagged UBI validation hook; the role must instead preflight the named
Secret and its nonempty `splunk_platform_hec_token` key read-only. The intended
result is that only the pinned collector image renders; this is not established
until the pending render inspection confirms images, hooks, init containers,
mounts, and RBAC.

The chart builds an image as `repository:tag` and has no separate digest field.
To produce an immutable reference without changing the chart, set repository to
`quay.io/signalfx/splunk-otel-collector@sha256` and tag to the 64-hex digest;
the rendered result is the exact `repository@sha256:digest` recorded above.
This rendering still requires controller validation with Helm.

With an existing Secret, use `secret.create: false`, its exact `secret.name`, and
disable the hook as above. The selected chart mounts key
`splunk_platform_hec_token`. For a custom CA, the Secret must also contain PEM
content at `splunk_platform_hec_ca_file`, while `splunkPlatform.caFile` must be a
nonempty placeholder to cause the mount and `tls.ca_file` reference to render;
it is not a controller filesystem path. TLS verification maps to
`splunkPlatform.insecureSkipVerify`, default false. Before Helm comparison or
mutation, C4 must read the selected Secret only through the explicit
kubeconfig/context/namespace, strictly base64-decode both requested keys, assert
the token is nonempty, and—when custom CA is requested—assert the CA is nonempty
and parseable as PEM trust data using Python `ssl.SSLContext.load_verify_locations`
with in-memory `cadata`. The preflight is `no_log`; neither token nor CA is placed
on a command line, and no token is copied to disk.

### Bounded persistent queue

The v0.163.0 [exporter helper](https://github.com/open-telemetry/opentelemetry-collector/blob/v0.163.0/exporter/exporterhelper/README.md)
supports a persistent queue through `sending_queue.storage`, queue sizing and
overflow blocking. The v0.163.0 [file-storage extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.163.0/extension/storage/filestorage/README.md)
supports `max_size` in bytes and rejects a write that would grow its bbolt file
beyond that limit. The selected `536870912` byte cap exceeds the chart's 200 MiB
rebound-compaction threshold. Use a dedicated database only for this exporter;
the cap applies per bbolt database file, so sharing the extension would not be a
single aggregate disk bound. Queue rejection/drop and retry exhaustion remain
possible; persistence is not exactly-once delivery.

## Helm convergence contract

`kubernetes.core.helm` 6.6.0 supports a local packaged `chart_ref`, explicit
kubeconfig/context/namespace, values files, wait/timeouts, and check mode. Its
source warns that default idempotency can miss changes and selects helm-diff when
installed. Its helm-diff invocation treats nonempty diff output as change and
lets command errors fail the module.

Pin helm-diff 3.15.15 and set task environment
`HELM_DIFF_THREE_WAY_MERGE=true`; upstream documents this as equivalent to
`--three-way-merge`, so live drift participates in comparison. Use `no_log`, a
protected temporary values file, `force: false`, `replace: false`, and no
uninstall path. Preflight Helm release status separately and fail on pending,
failed, unknown-lineage, or ownership-mismatched releases. A clean diff means no
upgrade; errors are failures. Neither Helm nor helm-diff is currently installed,
so the integration and rendered output remain unverified locally.

The chart declares support for actively supported upstream Kubernetes versions,
not a fixed numeric range, and has no `kubeVersion` field. Therefore no universal
Kubernetes version is frozen. Static rendering must use the actual selected
cluster server version after read-only discovery; until then render compatibility
is **PASS WITH WARNINGS — NOT VERIFIED**.

Primary references:

- [`kubernetes.core.helm` 6.6.0 module source](https://github.com/ansible-collections/kubernetes.core/blob/6.6.0/plugins/modules/helm.py)
- [helm-diff 3.15.15 three-way merge and exit behavior](https://github.com/databus23/helm-diff/blob/v3.15.15/README.md)
- [Chart 0.163.0 `Chart.yaml`](https://github.com/signalfx/splunk-otel-collector-chart/blob/619445cd7da7515d64002ecec36b38bc70d9e7c4/helm-charts/splunk-otel-collector/Chart.yaml), [`values.yaml`](https://github.com/signalfx/splunk-otel-collector-chart/blob/619445cd7da7515d64002ecec36b38bc70d9e7c4/helm-charts/splunk-otel-collector/values.yaml), [agent config template](https://github.com/signalfx/splunk-otel-collector-chart/blob/619445cd7da7515d64002ecec36b38bc70d9e7c4/helm-charts/splunk-otel-collector/templates/config/_otel-agent.tpl), [agent Service template](https://github.com/signalfx/splunk-otel-collector-chart/blob/619445cd7da7515d64002ecec36b38bc70d9e7c4/helm-charts/splunk-otel-collector/templates/service-agent.yaml), [DaemonSet template](https://github.com/signalfx/splunk-otel-collector-chart/blob/619445cd7da7515d64002ecec36b38bc70d9e7c4/helm-charts/splunk-otel-collector/templates/daemonset.yaml), and [advanced configuration](https://github.com/signalfx/splunk-otel-collector-chart/blob/619445cd7da7515d64002ecec36b38bc70d9e7c4/docs/advanced-configuration.md)

## Splunk Enterprise 10.6.1.1 HEC contract

The role's selected Splunk release is 10.6.1.1. The version-matched official
`inputs.conf` reference says:

- global `[http]` defaults to `port=8088`, `disabled=1`, and `enableSSL=true`;
- HEC TLS is shared with the Splunk management server and cannot be enabled when
  management TLS is disabled;
- token stanzas are `[http://name]` with required `token`, default-enabled
  `disabled=0`, optional comma-separated `indexes`, and token default `index`.

The version-matched `indexes.conf` specification requires writable absolute
`homePath`, `coldPath`, and `thawedPath`; the recommended role-owned stanza form
is `$SPLUNK_DB/$_index_name/{db,colddb,thaweddb}` (the thawed path cannot use a
volume reference). Changes require restart.

`inputs.conf` and `indexes.conf` are global-context files. Official precedence
for a standalone instance is system/local, app/local, app/default,
system/default, highest to lowest. Cluster peers put peer-app/local above those.
Therefore `ludus_hec/local` can override vendor system/default (including the
disabled listener), but cannot override system/local and is not guaranteed to
win among app/local definitions by its name. Implementation must inventory all
definitions and use `btool <file> list --debug`; permit vendor defaults, prior
owned values, and compatible shared globals, but fail on incompatible or
shadowed administrator definitions and cluster-peer context.

The 10.6 HEC troubleshooting table maps response JSON code `0` to HTTP 200
Success, while codes 24 and 25 are also HTTP 200 capacity warnings. Validation
must therefore require both HTTP 200 and parsed JSON `code == 0`; this proves HEC
acceptance only, not searchability.

Primary official references (browser-readable on 2026-10-22; the legacy
`docs.splunk.com` URLs returned empty shells):

- [10.6.1 `inputs.conf`](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.1-configuration-file-reference/inputs.conf)
- [10.6.1 `indexes.conf`](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.1-configuration-file-reference/indexes.conf)
- [10.6 configuration precedence](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/administer-splunk-enterprise-with-configuration-files/configuration-file-precedence)
- [10.6 HEC troubleshooting and response codes](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.6/get-data-with-http-event-collector/troubleshoot-http-event-collector)

## Evidence disposition and remaining gates

Static inspection established artifact identity, archive shape, source-backed
configuration capabilities, the bounded-queue mechanism, package side effects,
HEC stanza semantics, and precedence. It did not establish installation,
configuration acceptance, service convergence, log readability/parsing,
delivery, indexed-event fields, selected-cluster API compatibility, Secret/RBAC
behavior, Helm live drift, or Splunk searchability. Those remain live acceptance
items and require separate authorization.

The Task C1 report's requested checks are historical: accepted artifact, YAML,
and source evidence was completed and subsequently reused as recorded below.
C5 requires only documentary scope, provenance, and formatting review; unchanged
implementation checks must not be rerun. Helm render/schema checking remains
unavailable because Helm is not installed, and no installation or execution of
the inspected Helm bytes is authorized.

## Accepted implementation evidence ledger

This section reconciles the C2–C4 authored static deliverable with the research
claims above. It does not upgrade source checks into runtime evidence. Commit
`b03cb9158b3ac80f449e48903c547bbbf22cb570` is the earlier implementation
checkpoint, not the final current overlap-corrected file state.

| Scope | Accepted commits and exact evidence | What it establishes | What it does not establish |
| --- | --- | --- | --- |
| HEC (C2) | `f84fe71283ba02d0861cfb4c7db02a97ae0cd602`, corrected by `2962558733fb3d7fd0cfbce2420eb25cf7e5d30d`; `validation-telemetry-phasefix1-shapes.txt`: Python AST exit 0, source contracts 17/17, parser examples 8/8 | The selected files parse as Python and encode the reviewed source and pure-data parser contracts. | Native role-entrypoint syntax, selected Splunk 10.6.1.1 `btool` shapes, pre-write listener detection, restart/convergence, authenticated acceptance, searchability, and preservation on a real server. Official listener references used for the correction were 10.0 references, not exact 10.6.1.1 runtime evidence. |
| Docker collector (C3) | `d8d78ec150d17b707fb70ecff1a92c16280d9933`; accepted streaming member evidence in `validation-C3-entry-hash.txt`; archive member `./splunk-otel-collector/bin/otelcol`, 449,040,714 bytes, SHA-256 `bfd3de154091ff3449e7d9a346b8ad1f7795dcb0ce5bd366e10d1f704fc3cb4f` | Exact archive/member identity and source-encoded Docker path, parser, ownership, sandbox, and service contracts. | Collector configuration acceptance, archive extraction on a target, systemd behavior, readable rotating logs, HEC delivery, offsets, outage recovery, or unchanged convergence. |
| Kubernetes collector (C4), historical pre-final-overlap checkpoint | `b03cb9158b3ac80f449e48903c547bbbf22cb570`; `validation-telemetry-phasefix1.txt`: source contracts 28/28, YAML and file-scoped lint exit 0 for three changed task files, Jinja and helper AST exit 0; `validation-telemetry-phasefix2.txt`: source contracts 28/28 and helper AST exit 0. Unchanged phase-fix-1 YAML/lint/Jinja evidence was reused after the helper/test/README-only phase-fix-2 correction. | At that checkpoint, source and pure-data checks encoded the reviewed Secret, source-path, persistence-path, chart-values, and Helm-task contracts. | Pinned-chart rendering/schema/resource output, Kubernetes API/admission/RBAC compatibility, fresh installation, check-mode behavior, Helm drift/revision convergence, Secret rotation, event delivery, or checkpoint continuity. |

The relevant final correction hashes are recorded rather than recomputed here:

- C2 correction: `hec-preflight.yml`
  `1c621a50ab4b048106e4562ac5d2695531979e2daf97c3aa325ebb926462b1b5`,
  `hec_config.py`
  `a0f3755b9a8f819f8f94935d3f11a34239da2f1c1e735026c02f3be8dfaa7114`,
  HEC source test
  `3e890de225df39977975e9566350509f63924218298f88e1b33fe9ebd9c46048`,
  and parser test
  `951010e92c731a2a21aa51bfd6c598799979a2130b5952b3c412f67091e0a18e`.
- C3 commit records the final internal manifest SHA-256 as
  `711a2989b03f0c1b0c18f0112cbe7832dd387bf2dedbbb7e6d14d9b8f88a0611`.
- C4's historical pre-final-overlap checkpoint records the Kubernetes helper SHA-256 as
  `677be74ab41bbd507ec80c6e85af6a1d636d614145aed589b4d43ceaaaa73a7e`
  and source-test SHA-256 as
  `b2d9bf467b0e1a9b67bd062502bdfcbe101c6070135122c1772d6ec7f0edbd1e`.

### Final same-namespace overlap correction

The final remediation replaces exact `intersect` matching for already-observed
same-namespace DaemonSet host paths with normalized equality/ancestor overlap
semantics. `final-fix-review-package.md` records the current exact hashes:

- `tasks/kubernetes/cluster-state.yml`:
  `48232ddd55eb2ee1aeb614fb593a9bb53642de0a90957f514792de1dec9230ec`
- `filter_plugins/kubernetes_contract.py`:
  `52dd5d3724c646ba2941ca2e11c11c095b9219ac79ffa7419e4839231d7dbf61`
- `tests/test_container_contract_static.py`:
  `a783b023bf994e31e30259e889799a4817f69e71408f60aae2d591485c08a279`

`final-fix-validation.txt` records source/pure-data contracts **29/29**, changed
task YAML and file-scoped lint exit 0, helper AST exit 0, and scoped diff checks
exit 0 for all three files. The YAML wrapper planned zero role-entrypoint checks.
This evidence does not prove Helm rendering, native role-entrypoint execution,
live Kubernetes behavior, delivery, or persistence. The original final reviewer
accepted the correction in the scoped rereview; no material finding remains.

Raw command argv, complete output, and status are preserved in the named
`validation-*` files above. In particular, the validator's zero playbook targets
and zero planned commands are not role-entrypoint syntax evidence. The recorded
`git diff --no-index --check /dev/null <file>` invocations exited **1** because
the compared files differ from `/dev/null`; they emitted no whitespace
diagnostic, but are not exit-0 whitespace checks. Commit proofs separately
record `git diff --cached --check` exit 0.

Helm and PowerShell were absent from the relevant static environments. They were
not installed, and their missing coverage remains a gap. C2–C4 implementation
review reused the pinned artifact/source research in this document while the
manifest and relevant dependencies remained unchanged. An earlier telemetry
oracle checkpoint reported no material blocker and retained a maintainability
advisory to split the long Docker task file plus a duplicated-public-URL concern.
The corrected final review subsequently required the same-namespace overlap fix
above, which passed scoped rereview for authored static acceptance. Docker task
decomposition remains a nonblocking follow-up; live readiness is not established.

## Live authorization and acceptance matrix

No live action was authorized for this work package. Every row below is
therefore **NOT RUN**; a future authorization must identify the target and scope
before executing the actual role entrypoint.

| Actual-entrypoint scope | Required evidence | Status |
| --- | --- | --- |
| HEC fresh enablement | Enable over vendor defaults; prove effective token/index/listener settings and preserve unrelated Splunk configuration. | **NOT RUN** |
| HEC convergence/update | Unchanged rerun causes no HEC write/restart; owned update and compatible shared globals converge. | **NOT RUN** |
| HEC failure paths | Winning/shadowed conflicts, wrong token/index/TLS, listener collision, interrupted pending state, and post-mutation failure disposition. | **NOT RUN** |
| HEC emitted/searchable event | Require HTTP 200 plus HEC JSON `code == 0`; separately search for event/index identity. Acceptance alone is not searchability. | **NOT RUN** |
| Docker fresh/convergence | Install against real existing `json-file` logs; second run has no restart; prove runtime package/config/service and container runtime remain as contracted. | **NOT RUN** |
| Docker delivery/persistence | Parse and search a representative event; exercise rotation, collector restart, HEC outage/recovery, bounded queue behavior, and offset continuity. | **NOT RUN** |
| Docker failure/preservation | Unsupported driver, unreadable source, ownership collision, invalid config, activation/restart failures; prove source/runtime state and unrelated resources are preserved. | **NOT RUN** |
| Kubernetes fresh/convergence | Use an existing supported cluster/context; inspect rendered/applied logs-only resources; second run has no Helm revision change. | **NOT RUN** |
| Kubernetes delivery/persistence | Search an actual pod event; verify selected nodes, existing/owned Secret paths, rollout offset continuity, credential rotation after role rerun, and managed drift behavior. | **NOT RUN** |
| Kubernetes failure/preservation | Bad context/TLS/Secret/namespace/ownership/pending release, admission/RBAC and outage failures; prove no cluster/runtime/audit mutation or unrelated-resource damage. | **NOT RUN** |

No deployment, check-mode guest probe, installation, cleanup, event generation,
or endpoint query was performed. Static source/parser checks do not establish
selected-version compatibility, native convergence, delivery, persistence, or
deployment readiness. Current disposition remains **PASS WITH WARNINGS — NOT
VERIFIED**.
