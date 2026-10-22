# Splunk Container Collection and HEC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in Linux HEC and independent collection-only Docker/Kubernetes log delivery, retaining an evidence-backed legacy collector comparison.

**Architecture:** Extend `linux_splunk_server` with an owned HEC app and create `splunk_container_logs` with one mode per invocation. Callers supply the same endpoint/index/token contract across separate server/workload hosts; neither role invokes the other. Artifact selection is frozen before implementation.

**Tech Stack:** Ansible, Splunk Enterprise configuration/HEC, Splunk OTel Collector, official Splunk OTel Helm chart, `kubernetes.core.helm`, helm-diff, systemd.

**Spec:** `docs/superpowers/specs/2026-10-22-portable-splunk-gpo-design.md` (user-approved; approval supersedes its historical proposed-status line).

## Global Constraints

- Follow `docs/instructions/ludus-authoring.md`: STATIC AND LIVE ONLY; no mocks, stateful fakes, simulated runtime evidence or whole-repository validation.
- SDD is selected; controller requests plan confirmation before execution. No live tests, guest probes, installation on live targets, runtime changes or destructive cleanup are authorized by this plan.
- Preserve `splunk_server_*`, shared `splunk_*`, directory `linux_splunk_server` and metadata identity `linux_splunk_enterprise`; installed Ludus identity remains unverified.
- One scalar mode, `docker` OR `kubernetes`; existing standard Kubernetes, never Minikube. Caller owns disjoint target sets; checks stay locally observable.
- Collection only: no runtime install/configuration/restart, Docker socket, host-log permission changes, cluster recreation/audit enablement, metrics/traces, test workloads or Helm uninstall/reinstall.
- Proposed Docker bounds: Debian 12, Ubuntu 22.04/24.04, amd64/systemd/json-file, conditional on C1 evidence; do not expand support.
- HEC subflow convergence only; unrelated license lifecycle stays out of scope. Secrets use `no_log` and restricted files; TLS verification defaults true.
- Preserve all legacy roles, `splunk_forwarder`, source/range/blueprint files, preexisting staged `.opencode/skills/range-config/SKILL.md` and untracked `blueprints/detection-engineering/`.

## Review Focus

1. Vendor-disabled HEC versus owned updates versus shadowed administrator conflicts: permit only the first two or compatible shared globals (C2).
2. Invalid TLS/index/token or post-write precedence failure: fail without a false success or premature restart; HTTP acceptance is not searchability (C2).
3. Docker symlink overlap, unreadable/non-json-file logs or unmanaged collector: reject bounded observable collisions without runtime mutation (C3).
4. Wrong context, missing Secret key, unowned/pending Helm release or no actual diff: fail safely or skip upgrade as appropriate (C4).
5. Check mode, removed invocation or changed state identity: no mutation/HTTP event/deletion; report unknown live state rather than fabricate convergence (C2–C4).

---

## Execution, validation and commit budget

Workers own exact file scopes and static interpretation; **fast-generic owns command execution**, captures argv/tool versions/output/exit status and reuses unchanged evidence. Controller reconciles scopes/results, assigns a **fresh reviewer per SDD task**, and oracle reviews each coherent phase: C1 research, C2–C4 implementation, C5 final evidence/docs. No nested agents from workers. Do not rerun passing checks without changed inputs or an unresolved failure.

Before checks, inventory each changed path, role directory/metadata identity, local provenance, available dependency bytes and harness suitability. Existing `linux_splunk_server/tests/syntax.yml` names `linux_splunk_enterprise`, not the source directory; do not assume local resolution. It also expands unchanged role content. New-role harness absence and server file-scoped syntax limitations are coverage gaps; **do not generate a generic harness or alter that existing harness**.

Commands below are requests to fast-generic, using explicit changed-file lists (not globs over whole roles):
- YAML only: `python3 .opencode/skills/ansible-validation/scripts/validate.py --data <changed.yml> [--data <changed.yml> ...]`. `--data` runs yamllint only; zero Ansible targets is not syntax/lint evidence. Never use `--role` or `--all` for completion.
- Where installed tooling supports exact scope: `ansible-lint --offline -c .ansible-lint <changed-task-or-handler.yml> ...`; first confirm dependency traversal does not widen completion scope. Otherwise report unavailable file-scoped Ansible lint. Missing referenced installed modules/collections are failures, not tool unavailability.
- Jinja syntax: `python3 -c 'import sys,jinja2; [jinja2.Environment().parse(open(p).read()) for p in sys.argv[1:]]' <changed.j2> ...`; no runtime claim. Missing Jinja/tooling is reported, not installed.
- Static contracts: `python3 <task-test.py> <explicit changed paths...>`; scripts accept only explicit paths and inspect source/schema/rendered configuration, never emulate services. Request the initial missing-contract failure, then one post-change run; no broad regression suite.
- Changed chart values: render with already-available pinned Helm using `helm template splunk-container-logs <verified-local-chart> --namespace splunk-logs --kube-version <C1-version> -f <protected-rendered-values>`; purely local rendering, no kube API. Record absent renderer/schema dependencies honestly.
- Preserve raw statuses. Blocking failures stop completion; optional Galaxy metadata absence alone is advisory, while nonempty role_name/author is mandatory. Tool gaps carry `PASS WITH WARNINGS — NOT VERIFIED`; static checks never establish runtime readiness.

At each task's commit checkbox, **only fast-generic** stages an explicit reviewed file list and commits using controller-approved path-scoped commit/index isolation. First inventory preexisting staged paths; never `git add .`, `git commit -a`, or a blanket commit of the current index. Preserve preexisting staged bytes/status. Workers provide the manifest/message, never run commit commands. No commit is authorized during this planning turn.

## Task C1: Freeze one supported artifact and transport contract (research gate)

**Files — create:** `ansible/roles/splunk_container_logs/vars/artifacts.yml` (single dependency manifest), `docs/research/2026-10-22-splunk-container-hec-evidence.md` (source decisions, evidence ledger, limitations).
**Consumes:** spec §§3–4/9, current server defaults/handlers and locally available collection/tool versions.
**Produces:** reviewed exact chart/package/image/tool/collection pins and digests; selected-version HEC stanza/precedence map; logs-only render/queue/parser/service contract consumed by C2–C4. Manifest entries contain immutable URL/ref, version, SHA-256 or image digest, source/license, supported platform and verified capability; never placeholders presented as pins.
**Manifest interface:** `splunk_container_logs_artifacts: {collector: {version, url, sha256, components, platforms}, chart: {version, url, sha256, images}, tooling: {helm, helm_diff, kubernetes_core}, queue: {size, max_disk_mib, implementation}, sources: []}`. Images record exact repository/digest; sources record URL/ref/license. C3/C4 derive pinned defaults from this accepted manifest, not independent version selections.

- [ ] Inspect `https://github.com/signalfx/splunk-otel-collector-chart/releases` artifacts and `helm-charts/splunk-otel-collector/{Chart.yaml,values.yaml,templates/}`, `docs/advanced-configuration.md` at the selected immutable ref. Candidate **0.163.0 from main is unverified**, not a chosen default. Safely download into a unique `/tmp/opencode` directory, check paths/types/symlinks/size before extraction, never execute archive contents.
- [ ] Inspect `https://github.com/signalfx/splunk-otel-collector/releases`, selected-ref `docs/getting-started/linux-manual.md`, distribution components/package scripts and the matching upstream `receiver/filelogreceiver/README.md` / `exporter/splunkhecexporter/README.md` under `open-telemetry/opentelemetry-collector-contrib`. Freeze actual package availability, json-file operators, file_storage, persistent queue limits and non-runtime-touching install behavior for proposed OS targets.
- [ ] Verify exact Helm/helm-diff/`kubernetes.core.helm` source/docs (`https://docs.ansible.com/ansible/latest/collections/kubernetes/core/helm_module.html`, `https://github.com/databus23/helm-diff`) for values comparison, three-way drift, exit/error handling and unsupported release states. Use locally installed collection versions as minimum unless evidence requires raising them; no tool installs or live API probes.
- [ ] Verify selected Splunk release `inputs.conf`/`indexes.conf` specifications, precedence and HEC response codes from official entry points `https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf`, `https://docs.splunk.com/Documentation/Splunk/latest/Admin/Indexesconf`, `https://docs.splunk.com/Documentation/Splunk/latest/Admin/Wheretofindtheconfigurationfiles`, `https://docs.splunk.com/Documentation/Splunk/latest/Data/TroubleshootHTTPEventCollector`. Resolve version-matched pages; inaccessible/ambiguous sources remain a gate, not inferred semantics.
- [ ] Freeze manifest plus public pin/queue values: `splunk_container_logs_collector_version`, `splunk_container_logs_collector_package_url`, `splunk_container_logs_collector_package_checksum`, `splunk_container_logs_chart_version`, `splunk_container_logs_chart_url`, `splunk_container_logs_chart_checksum`, `splunk_container_logs_queue_size`, `splunk_container_logs_queue_max_disk_mib`. Checksums use `sha256:<hex>`; overrides require a reviewed consistent pin set, never version-only fallback. Verify disk-limit enforcement in selected exporter/storage; stop for controller resolution if required bounds cannot be represented without scope expansion.
- [ ] Ask fast-generic for manifest YAML check, available local render/schema checks and `sha256sum <exact downloaded artifacts>`; record digest provenance and capability evidence. Acceptance: one immutable supported combination, no implicit latest images, reviewed service scripts, explicit Secret/TLS behavior and HEC precedence rules. Unsupported live claims stay unverified.
- [ ] Obtain fresh reviewer + controller + oracle approval of C1 artifacts/interfaces before implementation; submit exact C1 file list to fast-generic for scoped commit `docs: freeze container telemetry dependencies and HEC contract`.

## Task C2: Owned HEC configuration, ordered restart and optional validation

**Files — modify:** `ansible/roles/linux_splunk_server/{defaults/main.yml,tasks/main.yml,handlers/main.yml,README.md}`.
**Create:** same role's `tasks/{hec,hec-preflight,hec-validate}.yml`, `templates/{hec-inputs,hec-indexes}.conf.j2`, `tests/test_hec_contract_static.py`.
**Interfaces:** all spec §3 `splunk_server_hec_*` variables verbatim: enabled/validate false, app `ludus_hec`, port 8088, ssl_enabled/validate_certs true, token_name `ludus-container-logs`; token, server_cert, default_index, validation_endpoint, ca_path empty; indexes `[]`. Preserve existing shared/server vars. Produce an owned app under `{{ splunk_server_home }}/etc/apps/{{ splunk_server_hec_app }}` and handler topic **`splunk_server_hec_restart`**, not exported credentials/facts. Callers map endpoint/index/token explicitly to collector variables.

- [ ] Add static contracts for default opt-out, conflicting validation switches, no password debug, no_log/permissions, and restart notification only after effective on-disk checking; request a targeted initial failure. Treat these as source assertions, not tests of Splunk behavior.
- [ ] Implement preflight of types/token/index membership/TLS paths and the C1 precedence map: vendor defaults, previous owned app, compatible shared globals, administrator conflicts including shadowed definitions. Reject unowned paths/token reuse/index ownership conflicts and identity changes; classify rather than overwrite unrelated configuration.
- [ ] Implement change-aware app writes with actual service-identity ownership, 0600 secrets and compatible 0700 directories; check effective files before notification. Partial failures remain fatal and named; never schedule the HEC restart for a failed update. Skip legacy creation only for indexes now owned by this HEC path, preserving legacy availability; remove admin-password output, leave license lifecycle untouched.
- [ ] Implement the HEC handler topic with mutually exclusive systemd/manual paths using existing `splunk_server_enable_boot_start`/home; flush before readiness and optional validation. Validate via authenticated `ansible.builtin.uri`: HTTP 200 **and JSON code 0**, explicit endpoint/index/token/trust, no_log and fatal errors. Validation sends an event, not a searchability proof.
- [ ] Implement HEC check mode as read/plan only: no app writes, restart, CLI mutations or HTTP test; never claim effective state for a not-yet-created app. Document false switches as cessation of management, not teardown; no automatic token rotation/index deletion.
- [ ] Ask fast-generic for exact changed-file YAML/Jinja/contracts checks; inspect C1 classification and check-mode paths. Record deferred real-entrypoint cases: fresh/default-disabled HEC, owned change, shadowed conflict, incompatible TLS/token/index, post-write failure and unchanged HEC rerun. Update README with HEC-only convergence and unrelated license limitation.
- [ ] Fresh reviewer gate; fast-generic scoped commit after controller acceptance: `feat: add owned opt-in Splunk HEC subflow`.

## Task C3: Shared collector contract and Docker json-file mode

**Files — create:** `ansible/roles/splunk_container_logs/{defaults/main.yml,meta/main.yml,LICENSE,README.md,tasks/main.yml,tasks/preflight.yml,tasks/docker.yml,handlers/main.yml,templates/docker-otel.yaml.j2,templates/splunk-container-logs.service.j2,tests/test_container_contract_static.py}`. Consume C1 `vars/artifacts.yml` without changing its accepted pins.
**Interfaces:** spec §4 common vars exactly, under `splunk_container_logs_`: mode required scalar; owner_id `ludus-container-logs`; hec_endpoint/index/token empty; tls_verify true; allow_insecure_http false; ca_file empty; start_at `end`. `splunk_container_logs_docker_include/exclude` default `[]`, `splunk_container_logs_docker_state_dir` `/var/lib/splunk-container-logs`; include nonempty. C1 freezes package and queue fields. Handler topic **`splunk_container_logs_restart`** affects only owned collector service `splunk-container-logs`; config `/etc/splunk-container-logs/collector.yaml`, persistent state in configured state_dir. C3 owns shared defaults/main/README; C4 amends them sequentially.

- [ ] Add static contracts asserting one mode, explicit transport, scheme/TLS separation, required include paths, read-only log mounts/sandbox, filelog storage wiring, and absence of Docker/socket/runtime-mutating tasks; request initial failure on missing implementation.
- [ ] Implement shared assertions/dispatch and Docker-local bounded ownership/realpath/driver/readability checks. Reject unsupported mode/format/platform, conflicting package/service/config or identity changes. Never infer global disjointness; callers own inventory boundaries. Use `ansible.builtin` package/template/systemd integrations with C1-reviewed package behavior and no unrelated collector adoption.
- [ ] Implement pinned package installation and readable filelog-only pipeline parsing `log`/`stream`/`time`; HEC index/TLS/token binding, deterministic source mapping, persistent offsets/export queue, finite C1 limits and retry/backpressure. Stable component IDs; default start_at end; no exact-once promise. Template systemd sandbox with log sources read-only, state writable; no chmod/chown of source logs.
- [ ] Validate candidate config before replacing/restarting the running collector; restart only after changed validated configuration/package. Protect secret files/staging, no_log/diff suppression; report partial package/service failure honestly. Check mode performs no download/install/write/restart; if config validation needs absent binaries, report that gap rather than execute fetched contents.
- [ ] Document variables, verified bounds, queue/rotation limitations, omission-not-uninstall and explicit migration for state/root changes; metadata role_name `splunk_container_logs`, author `dotknewt`, required available collections and project license. No generic syntax harness.
- [ ] Request exact-file checks plus available pinned-config static validation; distinguish configuration structure from actual delivery. Deferred live cases: unreadable/unsupported logs and collisions, fresh/repeat entrypoint, actual Docker event/rotation/restart/outage recovery and unchanged runtime state.
- [ ] Fresh reviewer gate; fast-generic scoped commit after controller acceptance: `feat: collect existing Docker json-file logs with OTel`.

## Task C4: Existing Kubernetes logs-only Helm mode

**Files — modify:** C3 `defaults/main.yml`, `tasks/main.yml`, `README.md`, `tests/test_container_contract_static.py`; **create:** `tasks/kubernetes.yml`, `templates/kubernetes-values.yaml.j2` in `ansible/roles/splunk_container_logs/`.
**Interfaces:** under `splunk_container_logs_`, explicit kubeconfig/kube_context/k8s_cluster_name required; k8s_namespace `splunk-logs`, k8s_release `splunk-container-logs`, k8s_existing_secret empty and exclusive with token; key `splunk_platform_hec_token`. k8s_node_selector must be nonempty; k8s_log_paths per verified chart. Expose `splunk_container_logs_k8s_tolerations: []`, `splunk_container_logs_k8s_checkpoint_path: /var/addon/splunk/otel_pos`, `splunk_container_logs_k8s_queue_path: /var/addon/splunk/exporter_queue`. Consume C1 chart/tools and C3 transport contract; no new host-discovery interface.

- [ ] Extend static contracts for Secret exclusivity/key/CA mapping, explicit context/selector, readonly log mounts, persistent state and disabled metrics/traces/cluster receiver/operator/listeners/hooks; request the targeted initial failure before implementing this mode.
- [ ] Implement bounded context/namespace/release/Secret preflight with `kubernetes.core.k8s_info`/Helm info and C1-verified integration. Reject unmanaged destination, invalid selector, missing key, pending/failed release and known conflicting sources; never relax cluster admission/RBAC or expose Secret values.
- [ ] Fetch chart with pinned SHA-256 and TLS verification, then render values with container logs only, helper images pinned or disabled, no permission-changing init containers, stable checkpoints/queue. Existing Secret remains untouched; caller-token mode creates only an owned Secret. Use verified CA-file-content contract, protected values files and cleanup on success/failure.
- [ ] Implement C1-approved Helm diff/upgrade path using `kubernetes.core.helm` where supported: no diff means no upgrade, real diff means bounded wait/update, errors fatal. Check mode is read/local-render/diff only, no namespace/Secret/release mutation or HTTP event; absent tools/context must not be reported as a validated plan.
- [ ] Request changed-file checks and local pinned `helm template`; inspect rendered images/pipelines/mounts/RBAC. Document deferred actual-entrypoint cases for bad Secret/context/TLS, managed drift, unchanged Helm revision, real log/index delivery and offsets across rollout; no cluster/runtime/audit changes.
- [ ] Fresh reviewer + controller gate, then implementation-phase oracle review of C2–C4 and reused evidence; fast-generic scoped commit: `feat: collect logs from existing Kubernetes with pinned Helm release`.

## Task C5: Durable comparison and scoped acceptance handoff

**Files — create:** `docs/research/2026-10-22-splunk-collector-comparison.md`; **update:** C1 evidence document and the two touched role READMEs only for factual coverage/usage corrections.
**Consumes/produces:** inspection report `.slim/deepwork/portable-splunk-gpo/gpo-collector-analysis.md` §§3/5 and recorded artifact hashes → durable standalone Task 4 comparison, not collector implementation or implied parity.

- [ ] Transfer exact inspected URLs/digests/versions, active inputs, disabled scripts, props/transforms/PSTree placement, license evidence and non-equivalence into durable docs; include CERTER/WIN11A/WIN11V/Linuxv differences, XML/filter gaps, Laurel index/sourcetype/service differences and missing PowerShell/transcript collection. Preserve evidence provenance, not only `.slim` links; unavailable changed artifacts make equivalence unknown.
- [ ] Reconcile minimal evidence per claim in C1 ledger: pin/schema/parse evidence vs unverified native convergence/delivery. Record command outputs/status locations, changed-file hashes, reused evidence, tool gaps and no live authorization. Do not rerun unchanged passing checks or turn documentary comparison into `splunk_forwarder` edits.
- [ ] Document separate authorization matrix for actual role entrypoints from spec §8: fresh/convergence/failure paths, actual emitted/searchable events, persistence and preservation of unrelated state. All live rows remain **NOT RUN**; no deployment, check-mode guest probing or cleanup now.
- [ ] Fresh reviewer, controller scope reconciliation and final-phase oracle gate; fast-generic stages exact approved docs/corrections with index isolation and commits `docs: record collector comparison and scoped verification limits`.

## Dependency and approval handoff

C1 → C2 → C3 → C4 → C5; C2/C3 share transport intent, not filesystem ownership, but keep this initial sequence to minimize interface churn. Windows W1–W3 is independent and may proceed in parallel under controller scheduling. Each task requires its reviewer before successors consume it. Controller self-reviews both plans against the spec, requests plan confirmation, then uses the already-selected SDD method; planning completion is not execution authorization.
