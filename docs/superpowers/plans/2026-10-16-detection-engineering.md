# Detection Engineering Range Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a five-VM, infrastructure-only Ludus detection-engineering range whose required Linux, GitLab, runner, Docker, Kubernetes, Splunk, and packet telemetry can be proven without enabling CI jobs or exposing integration secrets.

**Architecture:** Add one isolated blueprint and range-specific Ansible roles while leaving `constructing-defense` and existing shared roles unchanged. A first factual-gate task records compatible templates and pinned product inputs; independent role lanes build the range before integration and authorization-gated live acceptance. A separate default-off maintenance entrypoint can remove only a verified Splunk Enterprise package while preserving required state; normal deploy/redeploy never invokes it.

**Tech Stack:** Ludus blueprint YAML, Ansible, Debian Linux, GitLab CE, GitLab Runner, Splunk Enterprise 60-day trial with separately gated future Free/maintenance paths, Splunk Universal Forwarder, Docker, Minikube, Kubernetes audit logging, Splunk OpenTelemetry Collector, Malcolm, pytest, PyYAML, jsonschema

**Spec:** `docs/superpowers/specs/2026-10-16-detection-engineering-design.md`

## Global Constraints

- This plan does **not** authorize implementation, deployment, uninstall, restoration, or Free conversion; each remains blocked pending its applicable explicit user approval.
- Preserve the requested execution method: use subagent-driven development after approval; do not ask the user to choose an execution method again.
- Create five distinct VMs only: GitLab 8 GB/4 vCPU, runner 8 GB/4 vCPU, Malcolm 64 GB/8 vCPU, Splunk 12 GB/4 vCPU, workload 16 GB/6 vCPU (108 GB/26 vCPU total; 20 GB nominal host/router RAM headroom; no other ranges).
- Inherit template disks without adequacy claims. Do not add retention, capacity caps, or disk-sizing promises; disk exhaustion remains a documented risk.
- V1 has no CI jobs, executor activation, registry, pipeline, application, interaction simulation, sample workload, or multi-node cluster.
- Keep GitLab, Splunk, and runtime bootstrap automatic. Fixed lab credentials must be documented as isolated-lab-only; scoped generated tokens must never appear in logs, process arguments, rendered evidence, or world-readable files.
- Keep services lab/VPN-only with outbound installation allowed, no public ingress, narrowly scoped traffic, and no global firewall shutdown. Document accepted plaintext exposure; do not add a universal CA/TLS redesign.
- Do not use `role_linux_logging`, copy `role_k8s_telemetry_collection`, use Windows Splunk roles as Linux solutions, or change shared roles/`constructing-defense` without a separately approved bounded change and regression evidence.
- Pin every installed product, shared-role input, and Malcolm source after verifying primary vendor/upstream sources. Do not invent Splunk download, account, HEC, Free-mode, or licensing claims, and never reset a trial.
- The user approved V1 beginning with the 60-day Enterprise trial. Record that as user confirmation, not independent terms/package evidence; unknown future Free compatibility does not by itself block initial verified trial deployment.
- Splunk uninstall is a separate, explicitly authorized operator maintenance action: never automatic at expiry, on a timer, or during normal deploy/redeploy. It preserves required data/configuration in place but creates no backup/archive/storage/transfer and automates no reinstall, trial renewal/reset, or Free conversion.
- `/opt/splunk` must remain present. Never purge, explicitly delete files/trees, remove required index/config/auth/encryption/instance state or custom paths, autoremove packages, or delete accounts needed by retained ownership. Package-owned removal is allowed only after evidence proves those files are not required; uncertainty is `BLOCKED`.
- Keep vendor disk, retention, capacity, and audit queue/backlog defaults unchanged; do not add tuning while claiming to preserve defaults.
- `no_log` is not secret sanitization: bootstrap avoids argv/query/stdout exposure; audit filtering removes bounded process fields before durable storage; producer/OTEL contracts remove named sensitive fields. Canary tests cover those exact paths, not arbitrary-secret DLP.
- Use the existing `README.md` host-bridge procedure after the range bridge exists; do not create replacement bridge automation. Same-VLAN placement is not packet-visibility evidence.
- Static/schema/syntax tests are necessary but never substitute for authorized live deployment, service readiness, paused/no-job/no-privilege checks, per-class Splunk searches, body-free Kubernetes audit, actual packet capture, reboot, or redeploy evidence.
- Every acceptance criterion uses `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN`. A mandatory `BLOCKED`, `FAIL`, or `NOT_RUN` criterion prevents a whole-range `PASS`; known GitLab CE product gaps are reported separately from implementation failures.

## Review Focus

1. **Missing or incompatible factual inputs:** tests in Task 1 reject blank/unpinned templates/products/checksums and unverified trial HEC/search/auth before initial install; future Free and uninstall-preservation gates remain separately visible without blocking an otherwise verified initial trial.
2. **Secret-bearing runtime values:** canary tests in Tasks 2–7 and 9 must prove planned bootstrap/runtime credentials and bounded sensitive fields are absent from argv, queries, selected producer/audit/OTEL outputs, collected events, and evidence—not merely hidden by `no_log`.
3. **Duplicate or over-broad telemetry:** tests in Tasks 4 and 7 must prove exactly one owner per Docker/Kubernetes source, metadata-only audit policy, and no request/response bodies or indiscriminate file globs.
4. **Runner accidentally able to execute:** tests in Task 6 and live checks in Task 10 must prove paused-from-creation identity, matching minimum local registration, masked/inactive service before and after registration, zero jobs/polls, and no Docker socket, privileged group, or sudo access.
5. **False acceptance under missing infrastructure or maintenance:** Task 9/10 convert missing prerequisites to `BLOCKED`/`NOT_RUN`; Task 11 reports Splunk `ABSENT` downtime and prevents whole-range PASS until explicit restore/conversion and repeated live acceptance.

---

## File Responsibility Map

| Path | Responsibility |
|---|---|
| `blueprints/detection-engineering/blueprint.yml` | Ludus manifest metadata and minimum version. |
| `blueprints/detection-engineering/range-config.yml` | Five-VM topology, exact resources, role order/dependencies, narrow network rules, and non-secret role inputs. |
| `blueprints/detection-engineering/requirements.yml` | Pinned Ansible collections only; no unreviewed role dependency. |
| `blueprints/detection-engineering/verified-inputs.yml` | Source-controlled, non-secret factual decisions: templates, versions, URLs, SHA-256 values, license/mode/HEC findings, sources, and verification date. |
| `blueprints/detection-engineering/telemetry-matrix.yml` | Canonical host/source/index/sourcetype ownership and required search classes. |
| `blueprints/detection-engineering/README.md` | Credentials retrieval, lab-only/plaintext risks, prerequisites, deployment order, bridge handoff, and acceptance instructions. |
| `blueprints/detection-engineering/tests/{conftest.py,support.py}` | One shared production-include harness used by all role tests. |
| `blueprints/detection-engineering/tests/requirements.txt` | Exact Task-1-verified pins for pytest, PyYAML, jsonschema, ansible-core, ansible-lint, and yamllint. |
| `blueprints/detection-engineering/tests/` | Integrated manifest, schema, security, dependency, matrix, and evidence-contract tests. |
| `ansible/roles/ludus_detection_guest_firewall/` | Dedicated guest input/forward isolation for all five VMs, including Malcolm, without replacing unrelated nftables/Docker tables. |
| `ansible/roles/ludus_detection_linux_logging/` | Audited common Linux host baseline without downloaded scripts. |
| `ansible/roles/ludus_detection_splunk/` | Pinned Linux Splunk install, indexes/HEC/listener, local-only Splunk host inputs, and protected bootstrap artifacts. |
| `ansible/roles/ludus_detection_forwarder/` | Pinned Linux Universal Forwarder and host-specific monitored inputs for GitLab, runner, and workload hosts. |
| `ansible/roles/ludus_detection_gitlab/` | Range-local pinned GitLab CE install/bootstrap/configuration adapted from, without changing, `ludus_gitlab_ce`. |
| `ansible/roles/ludus_detection_runner/` | Paused-from-creation API identity plus local minimum registration while the V1 runner service remains masked/inactive. |
| `ansible/roles/ludus_detection_workload/` | Non-root-user Minikube, metadata-only audit, least-privilege OTEL, Docker/Kubernetes source ownership, and reboot-safe service. |
| `blueprints/detection-engineering/acceptance/` | Authorization guard, live checks/searches, redaction, status schema, and operator inventory example. |
| `blueprints/detection-engineering/maintenance/` | Default-off, operator-triggered Splunk package-removal entrypoint, inventory example, and maintenance documentation; never part of normal deployment. |
| `/tmp/detection-engineering-evidence/<run-id>/` | Generated secret-safe evidence and `summary.json`; never committed. |

## Stable Interfaces and Selected Builder Choices

- Every identity derives from `range_id`: `"{{ range_id }}-{gitlab,runner,malcolm,splunk,workload}"`; Minikube is `"{{ range_id }}-minikube"`. VLAN 10 octets are 11–15. Tests render `alpha` and `bravo` and require disjoint VM/host/cluster identities.
- Indexes are `de_linux`, `de_gitlab`, `de_runner`, `de_runtime`; Splunk service events remain in `_internal`. Fixed isolated-lab passwords are documented defaults; generated HEC, temporary GitLab API bootstrap, and runner manager tokens are distinct and never manually created in ordinary deployment.

### `verified-inputs.yml` schema

The root is `{schema_version: 1, verified_at: RFC3339, user_supplied_candidates: map, templates: map, capacity: Gate, network: Gate, apt: map, downloads: map, git: map, charts: map, capabilities: map, test_tools: Gate}`. Every factual leaf is a `Gate[T]`: `{status: VERIFIED|BLOCKED, source: {url: str, observed_at: RFC3339}, observed: T|null, limitation: str, stops: list[int]}`. `FutureGate[T]` is `{status: UNVERIFIED|VERIFIED|INCOMPATIBLE, source, observed, limitation}` and never blocks initial trial deployment merely because it is `UNVERIFIED`.

| Exact key | `observed` type / required fields | Stops |
|---|---|---|
| `templates.<gitlab|runner|malcolm|splunk|workload>` | `{name: str, inherited_disk_gb: int}` | 8–10 |
| `capacity` | `{ram_gb: int, physical_cpus: int, logical_cpus: int, current_allocations: object, free_storage_gb: int}` | 8–10 |
| `network` | `{management_cidrs: list[str], vpn_cidrs: list[str], lab_cidr: str, public_probe_source: str, guest_interface: str, docker_bridge_interfaces: list[str], service_ports: map[profile,list[int]]}` | 2, 8–10 |
| `user_supplied_candidates.splunk_10_6_1_1` | `{provenance: USER_SUPPLIED_UNVERIFIED, version: "10.6.1.1", build: "b2ae2962645c", enterprise_deb_url, forwarder_deb_url, forwarder_tgz_reference_url, windows_msi_reference_url}`; values must equal the canonical table in the [design spec](../specs/2026-10-16-detection-engineering-design.md#user-supplied-splunk-10611-candidate-urls) | none; feeds verification |
| `apt.<gitlab|runner|docker|containerd|docker_plugins>` | `{repository_url: https-url, signing_key_url: https-url, signing_key_fingerprint: str, packages: list[{name: str, version: str}]}` | owning role, 8–10 |
| `downloads.<splunk|forwarder|minikube|kubectl|helm>` | `{version: str, build: str|null, url: https-url, sha256: 64-hex, download_auth_required: bool}` | owning role, 8–10 |
| `git.malcolm` / `charts.otel` | `{repository: https-url, tag: str, commit: 40-hex}` / `{repository: https-url, chart: str, version: str, digest: str}` | 7–10 / 8–10 |
| `capabilities.splunk` | `{initial_mode: ENTERPRISE_60_DAY_TRIAL, trial_days_user_confirmed: 60, terms_confirmation: USER_CONFIRMED_NOT_INDEPENDENTLY_VERIFIED, expiry_behavior: str, hec: bool, search_api: bool, auth_behavior: str}` | 3–4, 7–10 |
| `capabilities.splunk_free` | `FutureGate[{version: str, perpetual_free: bool, hec: bool, search_api: bool, auth_behavior: str}]` | future conversion only; never initial Tasks 3–10 solely when UNVERIFIED |
| `capabilities.splunk_uninstall` | `{package_name: splunk, version: str, build: str, architecture: amd64, package_sha256: 64-hex, metadata_reviewed: true, maintainer_script_sha256s: map[str,64-hex], remove_argv: [dpkg,-r,splunk], required_preserve_paths: list[str], disposable_preservation_test: {passed: true, fixture_manifest_sha256: 64-hex}}` | 11 only |
| `capabilities.gitlab_ce_logs` | `{paths: map[class,path], producer_safe_fields: map[class,list[str]], query_and_auth_excluded: bool, unavailable_classes: list[str]}` | 4–6, 8–10 |
| `capabilities.runner_api` | `{bootstrap_auth: {credential_type: str, minimum_scope: str, creation_argv: list[str], stdin_operation: str, protected_path: /etc/detection-engineering/secrets/runner-api-bootstrap.token, mode: "0600", revoke_endpoint: str, revoke_method: str}, manager: {runner_type: str, create_endpoint: str, create_method: str, lookup_endpoint: str, lookup_method: str, update_endpoint: str, update_method: str, request_fields: list[str], response_token_field: str, local_verify_command: list[str], pause_at_create: bool}}` | 5–6, 8–10 |
| `capabilities.audit_dispatch` | `{package_version: str, plugin_protocol: str, write_logs_false: bool, fail_closed: bool}` | 2, 8–10 |
| `capabilities.otel` | `{secret_file_provider: bool, audit_path: str, node_log_inputs: list[str], required_rbac: map[str,list[str]]}` | 7–10 |
| `test_tools` | `map[name, exact_version]` for pytest/PyYAML/jsonschema/ansible-core/ansible-lint/yamllint | 1–9 |

`telemetry-matrix.yml` is exactly `{schema_version: 1, sources: list[Source]}` where `Source` is `{id: str, boundary: host|node, vm_role: gitlab|runner|splunk|workload, class: str, path_or_input: str, reader: forwarder|splunk_local|otel_host|otel_cluster, index: str, sourcetype: str, safe_fields: list[str], negative_fields: list[str], required: true, capability_gate: str|null}`. Required rows are never removed; a BLOCKED capability is reported as a gap and prevents overall PASS.

### Exact manifest-to-role variables

| Consumer | Exact variables (type) |
|---|---|
| guest firewall | `detection_firewall_profile: gitlab|runner|malcolm|splunk|workload`; `detection_firewall_lab_ip: str`; `detection_firewall_management_cidrs`, `detection_firewall_vpn_cidrs`, `detection_firewall_docker_bridges: list[str]`; `detection_firewall_allowed_tcp: list[{sources:list[str], ports:list[int]}]` |
| Linux logging | `detection_linux_host_id: str`; `detection_audit_dispatch: {package_version,plugin_protocol,write_logs_false,fail_closed}` |
| Splunk | `detection_splunk_artifact: {version,build,url,sha256,download_auth_required}`; `detection_splunk_download_auth_path: str|null`; `detection_splunk_license: capabilities.splunk.observed`; `detection_splunk_hec_supported`, `detection_splunk_search_api_supported: bool`; `detection_splunk_bind_ip: str`; `detection_splunk_admin_password: str`; `detection_splunk_restore_authorized: bool=false`; `detection_splunk_maintenance_state_path: /var/lib/detection-engineering/splunk-maintenance-state.json` |
| forwarder | `detection_forwarder_artifact: {version,build,url,sha256,download_auth_required}`; `detection_forwarder_download_auth_path: str|null`; `detection_forwarder_profile: gitlab|runner|workload`; `detection_forwarder_inputs: list[{path,index,sourcetype,safe_fields}]`; `detection_splunk_receiver_host: str`; `detection_splunk_receiver_port: 9997` |
| GitLab | `detection_gitlab_packages: list[{name:str,version:str}]`; `detection_gitlab_repository_url`, `detection_gitlab_signing_key_url`, `detection_gitlab_signing_key_fingerprint: str`; `detection_gitlab_log_contract: capabilities.gitlab_ce_logs.observed`; `detection_runner_api_contract: capabilities.runner_api.observed`; `detection_gitlab_root_password: str` |
| runner | `detection_runner_packages: list[{name:str,version:str}]`; `detection_runner_repository_url`, `detection_runner_signing_key_url`, `detection_runner_signing_key_fingerprint: str`; `detection_runner_description: "{{ range_id }}-runner"`; `detection_gitlab_host: str`; `detection_runner_api_contract: capabilities.runner_api.observed` |
| workload | `detection_docker_packages: list[{name:str,version:str}]`; `detection_docker_repository_url`, `detection_docker_signing_key_url`, `detection_docker_signing_key_fingerprint: str`; each `detection_{minikube,kubectl,helm}_artifact: {version:str,url:str,sha256:str,download_auth_required:bool}`; `detection_otel_chart: {repository:str,chart:str,version:str,digest:str}`; `detection_otel_contract: capabilities.otel.observed`; `detection_workload_user: deworkload`; `detection_cluster_name: "{{ range_id }}-minikube"`; `detection_splunk_hec_url: str`; `detection_runtime_token_state: present|absent` |
| Malcolm | existing full `ludus_install_malcolm_*` variables plus verified template/firewall vars; role defaults retain its verified tag/commit contract |

Task 8 maps `templates.*.observed.name` to each VM `template`, fixed resources to `ram_gb/cpus`, network service ports/CIDRs to firewall variables, product records to the named role objects above, and asserts the existing Malcolm defaults equal `git.malcolm.observed`; `test_range_role_vars_equal_verified_inputs` checks every leaf. Tokens originate mode 0600 at `/etc/detection-engineering/secrets/{hec-workload,runner-auth}.token`, transfer by delegated SSH `slurp` under `no_log` into non-cacheable facts, and are immediately cleared. `summary.json` uses mandatory `PASS|FAIL|BLOCKED|NOT_RUN` and `maintenance_status: null|HEALTHY|PREPARED|REMOVE_FAILED|POSTCHECK_FAILED|ABSENT|RESTORED_PENDING_ACCEPTANCE`; `null` is allowed only before the first `finalize`, and any unavailable required source or non-`HEALTHY` final state prevents overall PASS.

`detection_splunk_maintenance_state_path` is the single durable maintenance authority. Its schema is `{schema_version: 1, range_id: str, state: HEALTHY|PREPARED|REMOVE_FAILED|POSTCHECK_FAILED|ABSENT|RESTORED_PENDING_ACCEPTANCE, operation_id: UUID|null, package: {name,version,build,architecture,sha256}, startup_paths: list[str], baseline: null|{captured_at: RFC3339, writers_stopped: true, paths: list[{path,type,owner,group,mode,content_sha256}]}, journal: list[{at: RFC3339, from: str|null, to, result, limitation}], acceptance: {run_id: str|null, summary_sha256: 64-hex|null, accepted_at: RFC3339|null}}`. The first complete Task 10 acceptance creates `HEALTHY` with `baseline: null`; Task 11 freezes the baseline before removal. Writes use a same-directory temporary file, `fsync`, and atomic rename. The baseline/journal are validation metadata, never a data backup or archive.

## Concrete Telemetry Ownership

| Hosts | Class and production input | Read owner | Index / sourcetype |
|---|---|---|---|
| GitLab, runner, workload, Splunk | auth + sudo `/var/log/auth.log`; system `/var/log/syslog`; sanitized audit/process `/var/log/detection-engineering/audit-safe.jsonl` | Forwarder on first three; local Splunk input on Splunk | `de_linux` / `linux:auth`, `linux:system`, `linux:audit:safe` |
| GitLab | producer-safe `/var/log/gitlab/nginx/gitlab_access.log`; application/audit paths exactly from VERIFIED `capabilities.gitlab_ce_logs.observed.paths` (raw defaults are not presumed safe) | Forwarder | `de_gitlab` / `gitlab:access`, `gitlab:application`, `gitlab:audit` |
| Runner | system input filtered to `gitlab-runner`; `/var/log/detection-engineering/runner-registration.jsonl` | Forwarder | `de_runner` / `gitlab:runner`, `gitlab:runner:registration` |
| Splunk | `$SPLUNK_HOME/var/log/splunk/*.log` | Splunk local input only | `_internal` / native sourcetypes |
| Workload outer host | system input filtered to `dockerd`; `/var/lib/docker/containers/*/*-json.log` | Forwarder for daemon; host OTEL service for outer-container JSON | `de_runtime` / `docker:daemon`, `docker:container` |
| Minikube node/cluster | API audit file, node service logs, `/var/log/containers/*.log` inside node | In-cluster OTEL only, adding range-scoped host/node/pod/container fields | `de_runtime` / `kube:audit`, `kube:node`, `kube:container` |

GitLab paths remain required rows but become explicit CE gaps if the verified installed version cannot emit the class; they are never deleted. Host OTEL cannot claim in-node paths and in-cluster OTEL cannot claim outer Docker JSON. Acceptance requires at least one safe event per row, one sudo and one useful process record per baseline host, exact range-scoped attribution, and zero canary-secret/request-body fields.

## Dependency and Parallel-Lane Map

1. Task 1 is the factual and contract gate for all work.
2. After Task 1, Tasks 2–3 may run in parallel: they write separate role trees.
3. Task 4 depends on Tasks 1–3; Task 5 depends on Task 1; Task 6 starts only after Task 5 produces GitLab readiness plus the protected runner token source; Task 7 depends on Tasks 1 and 3. Tasks 4, 5, and 7 have disjoint write scopes and may run in parallel; Task 6 cannot share Task 5's lane.
4. Task 8 depends on Tasks 2–7 and alone modifies the blueprint root files after Task 1.
5. Task 9 depends on Task 8 and alone owns `acceptance/` plus integrated acceptance tests.
6. Task 10 depends on Task 9 and explicit deployment authorization; it writes only the external evidence directory. No concurrent lane may modify a shared path.
7. Task 11's maintenance implementation depends on Tasks 3, 8, and 9; executing it additionally requires explicit uninstall authorization and a VERIFIED uninstall-preservation gate. It is never called by Tasks 8–10, normal role dependencies, timers, handlers, reboot, or redeploy.

### Task 1: Factual Gates and Blueprint Contract

**Dependencies:** None.

**Files:**
- Create: `blueprints/detection-engineering/blueprint.yml`
- Create: `blueprints/detection-engineering/range-config.yml`
- Create: `blueprints/detection-engineering/requirements.yml`
- Create: `blueprints/detection-engineering/verified-inputs.yml`
- Create: `blueprints/detection-engineering/telemetry-matrix.yml`
- Create: `blueprints/detection-engineering/tests/conftest.py`
- Create: `blueprints/detection-engineering/tests/support.py`
- Create: `blueprints/detection-engineering/tests/test_contract.py`
- Create: `blueprints/detection-engineering/tests/requirements.txt`

**Interfaces:**
- Consumes: design, official schema, target template/capacity/network inventory, primary vendor release/download/license/API docs, and reviewed `curi0usJack/ludus_splunk` candidate.
- Produces: typed verified inputs, concrete telemetry rows, range-scoped identities, verified runner paused-creation/registration semantics, exact test-tool pins, and `run_production_include(role, includes, variables, fake_bin) -> CompletedProcess[str]` that invokes real production includes in a temporary Ansible play.

- [ ] **Step 1: Pin and bootstrap test tooling before RED**

  Verify Python 3.14-compatible exact versions from package metadata, write `requirements.txt`, `conftest.py`, and `support.py`, then run: `python3 -m venv /tmp/opencode/detection-engineering-tests/venv && /tmp/opencode/detection-engineering-tests/venv/bin/pip install --requirement blueprints/detection-engineering/tests/requirements.txt && /tmp/opencode/detection-engineering-tests/venv/bin/python -c "import ansible,jsonschema,pytest,yaml"`. Expected: exit 0; dependency failure is `BLOCKED` setup, not RED evidence.

- [ ] **Step 2: Write failing contract and gate tests**

  Add `test_two_range_ids_render_disjoint_identities`, `test_exact_resource_totals`, `test_gate_records_have_source_status_limitation_and_stops`, `test_every_manifest_value_maps_to_exact_role_var`, `test_every_matrix_input_has_one_reader`, `test_splunk_candidate_record_matches_spec_urls_verbatim`, `test_initial_trial_does_not_require_verified_free_gate`, and `test_uninstall_gate_stops_only_task_11`. Assert candidate provenance is user-supplied/unverified, `.deb` files alone are V1 candidates, no guessed checksum, trial terms are user confirmation, and `.tgz`/MSI never become required artifacts.

- [ ] **Step 3: Run the focused test and observe RED**

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/pytest -q blueprints/detection-engineering/tests/test_contract.py`

  Expected: FAIL because the blueprint/manifests and verified pins do not exist.

- [ ] **Step 4: Resolve facts and create the minimal blueprint contract**

  Resolve existing gates and verify the candidate Enterprise/forwarder `.deb` accessibility/auth, SHA-256, package identity/scripts, OS compatibility, trial HEC/search/auth behavior, and expiry behavior. Preserve user confirmation separately from evidence. `splunk_free=UNVERIFIED` does not stop initial trial; uninstall metadata/preservation uncertainty stops only Task 11. Never guess hashes or promote `.tgz`/MSI into V1.

- [ ] **Step 5: Run contract, YAML, and official schema checks**

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/pytest -q blueprints/detection-engineering/tests/test_contract.py`

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/python -c "import json,urllib.request,yaml; from jsonschema.validators import validator_for; p='blueprints/detection-engineering/range-config.yml'; d=yaml.safe_load(open(p,encoding='utf-8')); s=json.load(urllib.request.urlopen('https://docs.ludus.cloud/schemas/range-config.json',timeout=30)); validator_for(s)(s).validate(d); print('schema passed')"`

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/yamllint -d '{extends: default, rules: {line-length: disable}}' blueprints/detection-engineering`

  Expected: all three checks PASS. Missing network/server/tooling is `BLOCKED`; Task 1 cannot complete on partial contract-only evidence.

- [ ] **Step 6: Commit the factual gate checkpoint after approval**
  Run: `git add blueprints/detection-engineering && git commit -m "feat: define detection engineering blueprint contract"`

### Task 2: Five-Guest Isolation and Four-Host Linux Logging

**Dependencies:** Task 1.

**Files:**
- Create: `ansible/roles/ludus_detection_guest_firewall/defaults/main.yml`
- Create: `ansible/roles/ludus_detection_guest_firewall/tasks/main.yml`
- Create: `ansible/roles/ludus_detection_guest_firewall/templates/nftables-detection.nft.j2`
- Create: `ansible/roles/ludus_detection_guest_firewall/handlers/main.yml`
- Create: `ansible/roles/ludus_detection_guest_firewall/tests/test_role.py`
- Create: `ansible/roles/ludus_detection_guest_firewall/tests/syntax.yml`
- Create: `ansible/roles/ludus_detection_linux_logging/defaults/main.yml`
- Create: `ansible/roles/ludus_detection_linux_logging/tasks/main.yml`
- Create: `ansible/roles/ludus_detection_linux_logging/templates/audit.rules.j2`
- Create: `ansible/roles/ludus_detection_linux_logging/templates/audit-dispatch.conf.j2`
- Create: `ansible/roles/ludus_detection_linux_logging/templates/rsyslog-detection.conf.j2`
- Create: `ansible/roles/ludus_detection_linux_logging/files/audit_sanitize.py`
- Create: `ansible/roles/ludus_detection_linux_logging/handlers/main.yml`
- Create: `ansible/roles/ludus_detection_linux_logging/tests/test_role.py`
- Create: `ansible/roles/ludus_detection_linux_logging/tests/syntax.yml`

**Interfaces:**
- Consumes: exact firewall and logging variables from the mapping table.
- Produces: all five guests get dedicated `table inet ludus_detection` input/forward hooks; only GitLab/runner/Splunk/workload get auth/system and sanitized `/var/log/detection-engineering/audit-safe.jsonl`. The firewall role never flushes rulesets or edits Docker/other tables; its forward chain drops unallowlisted new DNAT traffic to verified Docker bridges while allowing established/related and required egress.

- [ ] **Step 1: Write failing behavioral tests against production includes**

  Add `test_audit_canary_is_removed_but_process_identity_survives`; `test_malcolm_profile_allows_only_management_vpn_and_verified_ui_ports`; `test_role_replaces_only_its_named_table`; and `test_docker_dnat_bypass_is_dropped`. The last test runs rendered rules in a disposable network namespace with a DNAT/forward path representing a published container port: allowed peer succeeds, unlisted/public peer drops, outbound and established replies succeed, and sentinel non-owned/Docker tables remain byte-identical. Lack of root/nft namespace capability is `BLOCKED`, not skipped.

- [ ] **Step 2: Verify the tests fail for the missing role**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_guest_firewall/tests ansible/roles/ludus_detection_linux_logging/tests`

  Expected: FAIL because the role files do not exist.

- [ ] **Step 3: Implement the audited baseline**

  Implement the firewall as a separate role assigned to all five VMs and the logging role only to the required four. Validate and atomically replace only the named table, preserve Docker forwarding/NAT, and handle DNAT traffic explicitly. Configure verified fail-closed audit dispatch before durable storage; never persist raw EXECVE/PROCTITLE or alter vendor storage/backlog defaults.

- [ ] **Step 4: Run behavioral and syntax checks**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_guest_firewall/tests ansible/roles/ludus_detection_linux_logging/tests`

  Run: `for role in ludus_detection_guest_firewall ludus_detection_linux_logging; do /tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook --syntax-check -i localhost, ansible/roles/$role/tests/syntax.yml || exit; done && /tmp/opencode/detection-engineering-tests/venv/bin/ansible-lint -x 'var-naming,yaml[line-length]' ansible/roles/ludus_detection_guest_firewall ansible/roles/ludus_detection_linux_logging && /tmp/opencode/detection-engineering-tests/venv/bin/yamllint -d '{extends: default, rules: {line-length: disable}}' ansible/roles/ludus_detection_guest_firewall ansible/roles/ludus_detection_linux_logging`

  Expected: every command PASS. Unrun Ansible-dependent behavior/syntax/lint blocks Task 2 completion.

- [ ] **Step 5: Commit the baseline checkpoint after approval**
  Run: `git add ansible/roles/ludus_detection_guest_firewall ansible/roles/ludus_detection_linux_logging && git commit -m "feat: isolate detection guests and add safe linux logging"`

### Task 3: Dedicated Linux Splunk Server

**Dependencies:** Task 1.

**Files:**
- Create: `ansible/roles/ludus_detection_splunk/defaults/main.yml`
- Create: `ansible/roles/ludus_detection_splunk/tasks/main.yml`
- Create: `ansible/roles/ludus_detection_splunk/templates/indexes.conf.j2`
- Create: `ansible/roles/ludus_detection_splunk/templates/inputs.conf.j2`
- Create: `ansible/roles/ludus_detection_splunk/templates/web.conf.j2`
- Create: `ansible/roles/ludus_detection_splunk/templates/hec-input.conf.j2`
- Create: `ansible/roles/ludus_detection_splunk/templates/install-provenance.yml.j2`
- Create: `ansible/roles/ludus_detection_splunk/handlers/main.yml`
- Create: `ansible/roles/ludus_detection_splunk/tests/test_role.py`
- Create: `ansible/roles/ludus_detection_splunk/tests/syntax.yml`

**Interfaces:**
- Consumes: verified candidate `.deb` identity/SHA and Enterprise-trial HEC/search/auth behavior, fixed admin password, range host, indexes/binds, exact role input `detection_splunk_restore_authorized: bool=false`, and the durable maintenance manifest contract.
- Produces: enabled Enterprise-trial Splunk, endpoints/local inputs, scoped HEC token, and non-secret `/etc/detection-engineering/splunk-install-provenance.yml` recording package/version/build/architecture/SHA and license decision. Any manifest state other than `HEALTHY` refuses desired-state-present unless restoration authorization is true and state is `ABSENT|RESTORED_PENDING_ACCEPTANCE`; successful full configuration appends `ABSENT -> RESTORED_PENDING_ACCEPTANCE`, while an authorized idempotent pending-state reapply retains `RESTORED_PENDING_ACCEPTANCE`, baseline, operation ID, and journal history. It never writes `HEALTHY`.

- [ ] **Step 1: Write failing install/configuration tests**

  Add bootstrap/local-input/token tests plus `test_user_approved_trial_with_verified_expiry_is_allowed_when_free_unknown`, `test_install_provenance_matches_verified_deb`, `test_nonhealthy_maintenance_state_blocks_ordinary_redeploy`, `test_restore_requires_absent_and_explicit_intent`, `test_successful_restore_sets_pending_without_claiming_healthy`, and `test_authorized_pending_reapply_is_idempotent_and_stays_pending`. Assert pending reapply without restoration authorization refuses; authorized pending reapply changes no baseline/operation ID/history and performs no trial reset/renewal, Free conversion, automatic uninstall, unrelated app, manifest deletion, or state bypass.

- [ ] **Step 2: Verify failure before implementation**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_splunk/tests`

  Expected: FAIL because the role is absent.

- [ ] **Step 3: Implement pinned, idempotent Splunk installation**

  Install the checksum-verified Enterprise `.deb` for the approved 60-day trial, write provenance, and configure verified trial HEC/search/auth. Future Free unknown is documented but does not block. Enforce the manifest guard before package mutation: authorized `ABSENT` may reinstall and records pending only after complete configuration; authorized `RESTORED_PENDING_ACCEPTANCE` may converge idempotently and remains pending; all other non-`HEALTHY` paths refuse. Never mark `HEALTHY`, delete or rewrite prior history/baseline, uninstall, reset/renew a trial, claim Free support, or add apps/firewall changes in this role.

- [ ] **Step 4: Run behavioral, rendered-config, and syntax verification**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_splunk/tests`

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook --syntax-check -i localhost, ansible/roles/ludus_detection_splunk/tests/syntax.yml`

  Expected: both PASS; either unrun blocks this task. Task 8 runs lint for all changed roles.

- [ ] **Step 5: Commit the Splunk checkpoint after approval**
  Run: `git add ansible/roles/ludus_detection_splunk && git commit -m "feat: add dedicated linux splunk role"`

### Task 4: Host-Aware Linux Forwarding

**Dependencies:** Tasks 1–3.

**Files:**
- Create: `ansible/roles/ludus_detection_forwarder/defaults/main.yml`
- Create: `ansible/roles/ludus_detection_forwarder/tasks/main.yml`
- Create: `ansible/roles/ludus_detection_forwarder/templates/outputs.conf.j2`
- Create: `ansible/roles/ludus_detection_forwarder/templates/inputs.conf.j2`
- Create: `ansible/roles/ludus_detection_forwarder/handlers/main.yml`
- Create: `ansible/roles/ludus_detection_forwarder/tests/test_role.py`
- Create: `ansible/roles/ludus_detection_forwarder/tests/syntax.yml`

**Interfaces:**
- Consumes: exact `detection_forwarder_*` variables from the mapping table and only Task-1-approved producer-safe files.
- Produces: enabled `SplunkForwarder` service, deterministic host identity, TLS/plaintext risk documentation matching the selected transport, and only the profile-owned file inputs.

- [ ] **Step 1: Write failing profile/rendering tests**

  Add `test_rendered_profiles_match_matrix_and_range_host`, `test_workload_forwarder_reads_daemon_not_container_or_kube_paths`, and `test_uf_has_no_parsing_or_redaction_configuration`. Parse `inputs.conf`; assert every monitored file has a VERIFIED producer-safe contract, and no UF props/transforms/SEDCMD, unsafe GitLab path, duplicate owner, `dc:9997`, Laurel-only setup, or Splunk loop exists.

- [ ] **Step 2: Run tests and observe the missing-role failure**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_forwarder/tests`

  Expected: FAIL because the role is missing.

- [ ] **Step 3: Implement data-driven forwarder configuration**

  Install pinned Universal Forwarder only to monitor/forward allowlisted safe files. Per Splunk's official forwarder and route/filter documentation (`https://help.splunk.com/en/splunk-enterprise/forward-and-process-data/forwarding-and-receiving-data/10.0/perform-advanced-configuration/route-and-filter-data` and `https://help.splunk.com/en?resourceId=Splunk_Forwarding_Typesofforwarders`), do not propose arbitrary-text parsing/filtering (`props`/`transforms`/SEDCMD), a heavy-forwarder tier, sixth VM, or extra app. GitLab must produce query/auth-free logs before UF reads them; selected-version proof must show useful allowlisted fields (method, query-free path, status, timestamp, and stable identity where available) or that source is `BLOCKED`.

- [ ] **Step 4: Verify profiles, convergence, and syntax**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_forwarder/tests`

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook --syntax-check -i localhost, ansible/roles/ludus_detection_forwarder/tests/syntax.yml`

  Expected: both PASS; unrun behavior/syntax blocks completion.

- [ ] **Step 5: Commit the forwarding checkpoint after approval**
  Run: `git add ansible/roles/ludus_detection_forwarder && git commit -m "feat: add host-aware linux telemetry forwarding"`

### Task 5: GitLab CE Bootstrap and Capability Reporting

**Dependencies:** Task 1.

**Files:**
- Create: `ansible/roles/ludus_detection_gitlab/defaults/main.yml`
- Create: `ansible/roles/ludus_detection_gitlab/tasks/main.yml`
- Create: `ansible/roles/ludus_detection_gitlab/templates/gitlab-detection.rb.j2`
- Create: `ansible/roles/ludus_detection_gitlab/templates/gitlab-safe-nginx.conf.j2`
- Create: `ansible/roles/ludus_detection_gitlab/tests/test_role.py`
- Create: `ansible/roles/ludus_detection_gitlab/tests/syntax.yml`

**Interfaces:**
- Consumes: verified GitLab apt repository/signing-key fingerprint/package version, root password, lab URL/address, and Task 1 CE capability findings.
- Produces: producer-safe GitLab logs; factual capability JSON; temporary `/etc/detection-engineering/secrets/runner-api-bootstrap.token` mode 0600; and stable `/etc/detection-engineering/secrets/runner-auth.token` mode 0600.

**Runner bootstrap transaction (all tasks `no_log`):** Task 5 creates a short-lived API credential by the verified Rails-stdin method/minimum scope; looks up `(runner_type, description="{{ range_id }}-runner")`; rejects duplicates; creates paused or pauses/re-reads the match; and persists the one-time manager token only on first identity creation. On a retry after registration failure, Task 5 mints a new temporary bootstrap credential but must preserve the paused identity and byte-identical stable manager token. Task 6 alone owns delegated revocation in its `always` path, so Task 5 never waits on a later role. Missing auth, pause, token recovery, or revocation capability is `BLOCKED`.

- [ ] **Step 1: Write failing production-include tests**

  Add `test_producer_safe_logs_exclude_query_auth_and_unapproved_fields`; creation/scope tests for exact endpoint/method/fields, Authorization header, minimum scope, duplicate rejection, pause-before-handoff, and mode-0600 temporary credential; and `test_retry_mints_new_bootstrap_but_preserves_identity_and_manager_token`. Task 5 has no revocation assertion. Canary values stay absent while approved method/path/status/identity fields survive.

- [ ] **Step 2: Verify failure for the missing role**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_gitlab/tests`

  Expected: FAIL because production includes are missing.

- [ ] **Step 3: Implement the range-specific layer**

  Adapt the shared role without changing it; use verified apt inputs. Configure producer-side nginx/access format with no query string or auth header and only collect application/audit files whose selected-version safe-field contract is VERIFIED—UF cannot sanitize them. Execute the bootstrap transaction through protected stdin/files and render factual CE/log capability status.

- [ ] **Step 4: Verify behavior and syntax**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_gitlab/tests`

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook --syntax-check -i localhost, ansible/roles/ludus_detection_gitlab/tests/syntax.yml`

  Expected: both PASS; unrun checks block completion.

- [ ] **Step 5: Commit the GitLab checkpoint after approval**
  Run: `git add ansible/roles/ludus_detection_gitlab && git commit -m "feat: configure detection range gitlab telemetry"`

### Task 6: Registered Runner Manager, Paused and Dispatch-Disabled

**Dependencies:** Tasks 1 and 5.

**Files:**
- Create: `ansible/roles/ludus_detection_runner/defaults/main.yml`
- Create: `ansible/roles/ludus_detection_runner/tasks/main.yml`
- Create: `ansible/roles/ludus_detection_runner/tasks/revoke-bootstrap.yml`
- Create: `ansible/roles/ludus_detection_runner/templates/runner-config.toml.j2`
- Create: `ansible/roles/ludus_detection_runner/templates/policy-rc.d.j2`
- Create: `ansible/roles/ludus_detection_runner/tests/test_role.py`
- Create: `ansible/roles/ludus_detection_runner/tests/syntax.yml`

**Interfaces:**
- Consumes: verified runner package/API facts, range-scoped description, GitLab readiness, and runner token delegated from the GitLab 0600 source.
- Produces: one paused GitLab runner-manager identity plus matching local config and successful version-gated manager verification handshake. **Builder choice for user review:** V1 keeps `gitlab-runner.service` masked/inactive before and after registration rather than polling; this satisfies no-execution intent but is not silently treated as a user-fixed service-state decision.

**Task 6 lifecycle truth table:** markers are mode 0644 under `/var/lib/detection-engineering/`; the temporary credential remains mode 0600 on GitLab.

| Registration | Revocation | Credential / markers / result | Retry precondition |
|---|---|---|---|
| succeeds | succeeds | Delete credential; remove `runner-registration-failed` and `runner-bootstrap-cleanup-failed`; PASS. | None. |
| fails | succeeds | Delete credential; create only `runner-registration-failed`; keep service masked; FAIL. | Rerun Task 5 to mint a new temporary credential while preserving paused identity/manager token, then rerun Task 6. |
| succeeds or fails | fails after 3 tries | Retain protected credential; create only `runner-bootstrap-cleanup-failed` containing registration outcome/status/timestamp; keep service masked; FAIL. | Rerun Task 6 in cleanup-first mode before any registration. If cleanup succeeds, delete credential/cleanup marker; PASS when prior registration succeeded, or create `runner-registration-failed` and follow the preceding retry when it failed. |

An already revoked credential is always deleted; Task 6 never regenerates the stable manager token.

- [ ] **Step 1: Write failing identity and privilege tests**

  Add `test_package_install_cannot_autostart_runner`, `test_new_identity_is_paused_before_local_registration`, `test_preexisting_unpaused_identity_is_paused_before_transfer`, `test_second_run_preserves_identity_and_manager_token`, `test_verified_cli_handshake_precedes_bootstrap_revocation`, `test_success_success_deletes_credential_and_markers`, `test_registration_failure_cleanup_success_deletes_credential_and_marks_registration`, `test_revocation_failure_retains_only_protected_credential_and_cleanup_marker`, and cleanup-first retry tests for both recorded registration outcomes. Assert Task 6 never creates/replaces the manager token and never proceeds to registration while cleanup is pending.

- [ ] **Step 2: Verify the tests fail before implementation**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_runner/tests`

  Expected: FAIL because the role does not exist.

- [ ] **Step 3: Implement package, service, and paused API identity**

  Before registration, detect `runner-bootstrap-cleanup-failed`; if present, run only delegated cleanup and apply the table's transition. Otherwise prevent auto-start, consume the existing paused identity/token without regenerating it, render config, execute `detection_runner_api_contract.manager.local_verify_command`, and recheck pause/zero jobs. In `always`, `revoke-bootstrap.yml` delegates to GitLab, slurps the protected credential, calls the contract revoke endpoint/method, accepts 200/204/404, and retries three times. Confirmed revocation always deletes the credential regardless of registration result; failed revocation always retains it. Apply exactly the marker/result transitions above and keep the service masked. Unsupported handshake remains `BLOCKED` for user decision.

- [ ] **Step 4: Run behavior, negative privilege, and syntax tests**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_runner/tests`

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook --syntax-check -i localhost, ansible/roles/ludus_detection_runner/tests/syntax.yml`

  Expected: both PASS; unrun checks block completion.

- [ ] **Step 5: Commit the runner checkpoint after approval**
  Run: `git add ansible/roles/ludus_detection_runner && git commit -m "feat: register paused dispatch-disabled runner"`

### Task 7: Docker, Minikube, and Least-Privilege Telemetry

**Dependencies:** Tasks 1 and 3.

**Files:**
- Create: `ansible/roles/ludus_detection_workload/defaults/main.yml`
- Create: `ansible/roles/ludus_detection_workload/tasks/main.yml`
- Create: `ansible/roles/ludus_detection_workload/templates/audit-policy.yaml.j2`
- Create: `ansible/roles/ludus_detection_workload/templates/otel-values.yaml.j2`
- Create: `ansible/roles/ludus_detection_workload/templates/otel-rbac.yaml.j2`
- Create: `ansible/roles/ludus_detection_workload/templates/otel-host.yaml.j2`
- Create: `ansible/roles/ludus_detection_workload/templates/minikube-detection.service.j2`
- Create: `ansible/roles/ludus_detection_workload/templates/otel-host.service.j2`
- Create: `ansible/roles/ludus_detection_workload/handlers/main.yml`
- Create: `ansible/roles/ludus_detection_workload/tests/test_role.py`
- Create: `ansible/roles/ludus_detection_workload/tests/syntax.yml`

**Interfaces:**
- Consumes: non-root `deworkload`, verified exact Docker/containerd/plugin apt versions plus Minikube/kubectl/Helm/OTEL pins, range-scoped cluster, Splunk HEC endpoint, and delegated HEC token.
- Produces: pinned Docker; Minikube started with `--driver=docker --extra-config=apiserver.audit-policy-file=/etc/kubernetes/audit-policy.yaml --extra-config=apiserver.audit-log-path=/var/log/kubernetes/audit/audit.log`; all-Metadata audit; host and in-cluster OTEL; protected host/Kubernetes token handoffs; reboot services.

**Audit/collector contract:** stage policy at `/home/deworkload/.minikube/files/etc/kubernetes/audit-policy.yaml` before first start so it appears in the node at `/etc/kubernetes/audit-policy.yaml`. The OTEL DaemonSet mounts node hostPaths `/var/log/kubernetes/audit` (audit), `/var/log/containers` and `/var/log/pods` (container logs), all read-only; node telemetry uses only the Task-1-verified `node_log_inputs` and `required_rbac` (`get/list/watch` resources exactly as recorded). The outer-host collector runs as `deotel`, gets read/traverse ACLs only on `/var/lib/docker/containers`, has no Docker group/socket, and systemd hardening includes `NoNewPrivileges=true`, `ProtectSystem=strict`, and read-only source paths.

**HEC handoff:** create `/etc/detection-engineering` and its `secrets` child root:`deotel` mode 0750, then transfer the scoped token to `secrets/hec-workload.token` root:`deotel` mode 0640. Verify readability by executing as `deotel`, not root. Create/update Kubernetes Secret `otel-system/splunk-hec` key `token` under `no_log`, then clear the fact; mount it read-only mode 0400 at `/var/run/secrets/detection/hec/token` for the verified file-provider. `detection_runtime_token_state: absent` deletes the host token, Kubernetes Secret, transient facts, and empty role-owned directories and revokes the Splunk token; tests prove `deotel` parent traversal/read and post-cleanup absence. Cluster administrators can read Kubernetes Secrets. Unsupported file-provider behavior is `BLOCKED`, never changed to argv/environment exposure.

- [ ] **Step 1: Write failing first-run, policy, and convergence tests**

  Add named tests for exact Minikube flags/staged policy; DaemonSet read-only hostPaths; RBAC equality to the verified contract; hardened `deotel` ACL/service; Secret mode/path/file-provider; absent-state revocation; and disjoint outer/node paths. Render production manifests and assert no Request/Response bodies, argv/env token, sample pod, overbroad mount/RBAC, uninstall/reinstall, or token churn; second run is unchanged.

- [ ] **Step 2: Run tests and observe missing-role failure**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_workload/tests`

  Expected: FAIL because the workload role is absent.

- [ ] **Step 3: Implement durable workload infrastructure**

  Install verified Docker/tool versions locally; prove fresh group access; stage policy then start/update Minikube with the exact flags without unconditional stop; render exact mounts/RBAC/host ACLs; and execute the HEC lifecycle above. Bounded OTEL processors drop named auth/token/password fields and Kubernetes bodies while retaining attribution metadata; they are not a general DLP claim.

- [ ] **Step 4: Verify rendered policy, first-run path, convergence, and syntax**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_workload/tests`

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook --syntax-check -i localhost, ansible/roles/ludus_detection_workload/tests/syntax.yml`

  Expected: both PASS; unrun checks block completion.

- [ ] **Step 5: Commit the workload checkpoint after approval**
  Run: `git add ansible/roles/ludus_detection_workload && git commit -m "feat: add durable minikube telemetry host"`

### Task 8: Integrate the Five-VM Blueprint and Malcolm Handoff

**Dependencies:** Tasks 2–7.

**Files:**
- Modify: `blueprints/detection-engineering/range-config.yml`
- Modify: `blueprints/detection-engineering/requirements.yml`
- Modify: `blueprints/detection-engineering/telemetry-matrix.yml`
- Create: `blueprints/detection-engineering/README.md`
- Modify: `blueprints/detection-engineering/tests/test_contract.py`

**Interfaces:**
- Consumes: every role interface above and exact existing variables `ludus_install_malcolm_admin_username`, `ludus_install_malcolm_admin_password`, `ludus_install_malcolm_capture_enabled`, and `ludus_install_malcolm_capture_interface`.
- Produces: fully wired role order/dependencies, exact traffic policy, Malcolm VM contract, operator prerequisites, and deployment documentation.

- [ ] **Step 1: Extend integration tests before wiring roles**

  Assert range-scoped names, exact resources/IPs, the firewall role on all five VMs, logging only on the four required hosts, verified-input-to-role-var equality, dependencies, and Malcolm at 64 GB/8 vCPU with capture enabled. Parse all five rendered guest rules/binds for this policy (CIDRs/Malcolm ports are verified facts, not guessed):

  | Source | Destination | TCP service |
  |---|---|---|
  | management CIDR | all guests | 22 |
  | VPN CIDR | GitLab / Splunk / Malcolm | 80 / 8000,8089 / verified Malcolm UI ports |
  | runner | GitLab | 80 |
  | GitLab, runner, workload | Splunk | 9997 |
  | workload | Splunk | 8088 |

  Require established/related and loopback, default-drop guest inbound, unrestricted required outbound installation traffic, and live-peer source IPs derived from `range_second_octet`. Router/bridge defaults remain untouched; no invalid per-host Ludus network-rule fields are proposed.

- [ ] **Step 2: Run integration tests and observe role-order failures**

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/pytest -q blueprints/detection-engineering/tests/test_contract.py`

  Expected: FAIL because the skeleton is not fully wired/documented.

- [ ] **Step 3: Wire roles and write operator documentation**

  Wire roles as specified and document the user-approved 60-day trial, the spec's canonical candidate URL table, unverified checksum/package/Free facts, expiry/disk/collector queue-or-drop risks, and no reset/renewal promise. Document Task 11 as default-off maintenance, not backup or normal redeploy behavior; absence blocks healthy status, and explicit restore/conversion requires repeated Task 10 acceptance. Retain token, firewall, runner, and bridge documentation unchanged.

- [ ] **Step 4: Run integrated contract/schema/syntax checks**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q blueprints/detection-engineering/tests ansible/roles/ludus_detection_*/tests`

  Run: official schema command from Task 1; `for syntax in ansible/roles/ludus_detection_*/tests/syntax.yml; do /tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook --syntax-check -i localhost, "$syntax" || exit; done`; then `/tmp/opencode/detection-engineering-tests/venv/bin/ansible-lint -x 'var-naming,yaml[line-length]' ansible/roles/ludus_detection_* blueprints/detection-engineering` and `/tmp/opencode/detection-engineering-tests/venv/bin/yamllint -d '{extends: default, rules: {line-length: disable}}' ansible/roles/ludus_detection_* blueprints/detection-engineering`.

  Expected: all commands PASS. Any unrun Ansible/schema/lint check blocks integration completion.

- [ ] **Step 5: Commit the integrated blueprint checkpoint after approval**
  Run: `git add blueprints/detection-engineering && git commit -m "feat: integrate detection engineering range"`

### Task 9: Secret-Safe Live Acceptance Harness

**Dependencies:** Task 8.

**Files:**
- Create: `blueprints/detection-engineering/acceptance/inventory.example.yml`
- Create: `blueprints/detection-engineering/acceptance/live-acceptance.yml`
- Create: `blueprints/detection-engineering/acceptance/searches.yml`
- Create: `blueprints/detection-engineering/acceptance/render_summary.py`
- Create: `blueprints/detection-engineering/tests/test_acceptance_contract.py`
- Modify: `blueprints/detection-engineering/README.md`

**Interfaces:**
- Consumes: inventory groups `detection_guests`, `allowed_probe`, `denied_probe`; `detection_acceptance_phase: preflight|postdeploy|packet|reboot|redeploy|finalize`; `detection_acceptance_range_id`, `detection_acceptance_run_id`, `detection_acceptance_evidence_dir`, explicit boolean `detection_acceptance_authorized`, `detection_acceptance_restoration_authorized: bool=false`, and the exact `detection_splunk_maintenance_state_path`; credentials are slurped from existing protected paths.
- Produces: `/tmp/detection-engineering-evidence/<run-id>/{facts,services,searches,security,pcap,recovery,summary.json}` with the stable status schema and redacted outputs. `finalize` creates the initial `HEALTHY` manifest after first acceptance or atomically appends `RESTORED_PENDING_ACCEPTANCE -> HEALTHY` after a newly complete restoration run; it retains all prior journal/baseline evidence.

- [ ] **Step 1: Write failing evidence-contract tests**

  Add `test_missing_mandatory_source_prevents_pass`, `test_canary_rejected_from_all_evidence`, `test_absent_or_failure_state_prevents_healthy_summary`, `test_pending_restore_requires_restoration_authorization`, `test_restore_intent_or_old_pass_cannot_finalize`, `test_failed_or_incomplete_new_run_stays_pending`, and `test_complete_new_run_transitions_pending_to_healthy_without_erasing_history`. Reject absent authorization/local guest aliases; require exact search evidence. Initial trial preflight requires verified trial behavior but not verified future Free. `PREPARED|REMOVE_FAILED|POSTCHECK_FAILED|ABSENT` cannot run healthy acceptance; `RESTORED_PENDING_ACCEPTANCE` may run only with restoration authorization and never yields overall PASS before `finalize`.

- [ ] **Step 2: Verify tests fail before the harness exists**

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/pytest -q blueprints/detection-engineering/tests/test_acceptance_contract.py`

  Expected: FAIL because acceptance files are absent.

- [ ] **Step 3: Implement guarded checks and searchable-evidence matrix**

  Implement these guarded actions: every phase rejects false authorization, bad range/run IDs, and missing prerequisites; guest/probe plays reject localhost/local connections, while only the controller-targeted `preflight` play may use `connection: local`:

  | Phase/action | Target and exact mechanism | Evidence / stop behavior |
  |---|---|---|
  | `preflight` | controller validates verified gates and queries only the existing Ludus server/host for capacity, templates, storage, CIDRs, outbound/product prerequisites; no guest inventory contact or mutation | `facts/preflight.json`; any mandatory non-VERIFIED gate => `BLOCKED`, stop before deploy |
  | `postdeploy.services_runner` | `detection_guests` service/fingerprint checks; GitLab API via `uri` with protected auth; runner local config/service/group/socket checks | `services/*.json`, `security/runner.json`; mismatch/duplicate/unpaused/job/poll/privilege => `FAIL`, stop later mutation |
  | `postdeploy.network` | `allowed_probe` runs `nc -zvw3` for every allow row; `denied_probe` runs the same against listed services and Docker-published paths expecting failure; guests capture binds and owned nft table hashes | `security/network.json`; unavailable denied source => `BLOCKED`, unexpected allow/deny => `FAIL` |
  | `postdeploy.telemetry` | harmless `true CANARY_acceptance_47`, header-only failed GitLab request, and natural system activity; Splunk local REST export on 8089 executes every `searches.yml` query | `searches/<source-id>.json`; count <1, wrong host/source, canary/body/argv field => `FAIL`; unavailable CE class => explicit gap and no overall PASS |
  | `packet` | workload runs unauthenticated `curl --max-time 5 --output /dev/null --write-out '%{http_code}' http://<splunk-lab-ip>:8088/services/collector/health`; HTTP 200/400/401/403 proves the allowlisted TCP path without a token; Malcolm checks timestamp/source/destination/interface | `pcap/visibility.json`; connect error/untolerated status/absent packet => `FAIL`, absent bridge/query => `BLOCKED` |
  | `reboot` | `ansible.builtin.reboot` serially on five guests, wait, then automatically rerun services/runner/network/telemetry/packet actions | `recovery/reboot.json`; any regression => `FAIL` |
  | `redeploy` | validation only after separately recorded operator reapply; compare pre/post config/token/input/identity hashes and rerun all checks | `recovery/redeploy.json`; missing reapply marker => `NOT_RUN`, drift/duplicate => `FAIL` |
  | `finalize` | controller verifies every mandatory entry in the candidate summary is PASS for preflight, postdeploy, packet, reboot, and redeploy from the same new run; hash that candidate, then on the Splunk guest compare range/package identity, atomically store its hash/update the durable manifest, and rerender the final summary | missing/stale/mixed-run evidence => `BLOCKED`; initial accepted install creates `HEALTHY`; pending restoration requires `detection_acceptance_restoration_authorized=true` and appends `RESTORED_PENDING_ACCEPTANCE -> HEALTHY` without deleting history |

  Store only counts, times, attribution, safe IDs, hashes, and limitations—not raw events/secrets. The playbook performs probes/checks and guest reboot; it does **not** apply/reapply the blueprint or configure the host bridge.

- [ ] **Step 4: Run offline harness and redaction tests**

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/pytest -q blueprints/detection-engineering/tests/test_acceptance_contract.py`

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/python blueprints/detection-engineering/acceptance/render_summary.py --self-test`

  Expected: PASS and `self-test passed`; no live target is contacted.

- [ ] **Step 5: Commit the acceptance-harness checkpoint after approval**
  Run: `git add blueprints/detection-engineering/acceptance blueprints/detection-engineering/tests blueprints/detection-engineering/README.md && git commit -m "test: add detection range acceptance harness"`

### Task 10: Authorized Live Deployment, Recovery, Search, and Capture Gate

**Dependencies:** Task 9, explicit user authorization, target/server access, passed capacity/template/license/download gates, and operator bridge availability.

**Files:**
- Generate locally: `/tmp/detection-engineering-evidence/<run-id>/...`
- Modify on the authorized Splunk target only: `/var/lib/detection-engineering/splunk-maintenance-state.json` during Task 3 restoration/reapply and Task 9 `finalize`; these are explicit remote-state writes, not repository changes.
- Do not modify repository files unless a failure returns to its owning implementation task with a new failing regression test.

**Interfaces:**
- Consumes: approved integrated blueprint and acceptance harness plus `detection_splunk_maintenance_state_path`; for restoration, `detection_splunk_restore_authorized=true` during reinstallation and `detection_acceptance_restoration_authorized=true` for the new acceptance run.
- Produces: one secret-safe `summary.json` plus referenced evidence for controller/user review; a complete PASS initializes or transitions the durable maintenance manifest to `HEALTHY`; no source commit.

**Authorization boundary:** this plan and its review do not authorize any command below. Obtain a new explicit user authorization naming the target range/server before deployment, bridge change, probes, reboot, restoration role-var injection, or maintenance-manifest write; otherwise every step remains `NOT_RUN`.

For a restoration run, the operator creates mode-0600 `/tmp/detection-engineering-acceptance/restoration-vars.yml` containing exactly `detection_splunk_restore_authorized: true` and `detection_acceptance_restoration_authorized: true`. Before **both** the initial restore apply and required convergence reapply, the authorized controller loads the first value into the Splunk VM's `role_vars` through a verified Ludus-supported protected role-variable injection mechanism; because `ludus blueprint apply` has no documented `-e` flag, do not invent one. Every acceptance phase loads the same file with `-e @/tmp/detection-engineering-acceptance/restoration-vars.yml`. If protected role-var injection is unavailable or unverified, restoration is `BLOCKED`; never weaken the role default of `false` or persist authorization in the blueprint.

- [ ] **Step 1: Record pre-deployment gates without changing the target**

  After authorization, set `RUN_ID=<UTC-run-id>`, `EVIDENCE=/tmp/detection-engineering-evidence/$RUN_ID`, and run `PHASE=preflight`. It is read-only and records infrastructure and verified Enterprise-trial/package/HEC/search/auth gates; `splunk_free=UNVERIFIED` alone does not block. `ABSENT` permits only an explicitly authorized restoration flow; `RESTORED_PENDING_ACCEPTANCE` permits only a restoration-authorized new run; `PREPARED|REMOVE_FAILED|POSTCHECK_FAILED` block. Ordinary deployment/redeploy requires `HEALTHY` (or no manifest before the initial accepted deployment). Restoration preflight also verifies the protected role-var injection mechanism and vars-file mode/content before any remote mutation.

- [ ] **Step 2: Deploy once and capture startup/negative-security evidence**

  Operator runs from repository root: `ludus blueprint apply awesome-ludus-sauce/detection-engineering --target-range <range-id>`. For restoration, first load `detection_splunk_restore_authorized: true` from the protected restoration vars file through the verified role-var injection mechanism; Task 3 may then change only `ABSENT -> RESTORED_PENDING_ACCEPTANCE`. After successful return, run acceptance with `PHASE=postdeploy` and, for restoration, `-e @/tmp/detection-engineering-acceptance/restoration-vars.yml`; the playbook owns the Task 9 evidence actions. Failure stops bridge/reboot/redeploy.

- [ ] **Step 3: Configure the existing host bridge and prove packet visibility**

  Operator runs on the single-node Ludus/Proxmox host from the repository root: `sudo ansible-playbook ludus-configure-bridge.yaml -e range_second_octet=<1-254>`. Then run acceptance with `PHASE=packet`; same-VLAN/bridge state without the Malcolm-observed Task 9 probe is not PASS.

- [ ] **Step 4: Reboot and rerun all acceptance actions**

  Run acceptance with `PHASE=reboot`; the playbook serially reboots the five guests and reruns runner pause/mask/jobs, token hashes, services, allowed/denied probes, every search/host attribution, and packet proof. It never reboots the Ludus host/router.

- [ ] **Step 5: Reapply once, then validate convergence**

  Operator repeats exactly `ludus blueprint apply awesome-ludus-sauce/detection-engineering --target-range <range-id>`, then runs `mkdir -p "$EVIDENCE/recovery" && printf '%s\n' "$RUN_ID" > "$EVIDENCE/recovery/reapply-complete"`; run acceptance with `PHASE=redeploy`. For restoration, load the same protected `detection_splunk_restore_authorized: true` role-var input before this apply and pass the vars file to acceptance. Task 3 must converge idempotently while retaining `RESTORED_PENDING_ACCEPTANCE` and all baseline/history; omission or false authorization makes this reapply refuse. Require unchanged identity/token/input/baseline/history hashes, no duplicates, and all postdeploy/packet checks PASS.

- [ ] **Step 6: Render and review the final claim map**

  For each ordinary phase run: `PHASE=<phase>; /tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook -i /tmp/detection-engineering-acceptance/inventory.yml blueprints/detection-engineering/acceptance/live-acceptance.yml -e @/tmp/detection-engineering-acceptance/vars.yml -e detection_acceptance_authorized=true -e detection_acceptance_range_id=<range-id> -e detection_acceptance_phase="$PHASE" -e detection_acceptance_run_id="$RUN_ID" -e detection_acceptance_evidence_dir="$EVIDENCE"`. For every restoration phase use the same command with exact additional argument `-e @/tmp/detection-engineering-acceptance/restoration-vars.yml` immediately after the ordinary vars file.

  Run summary: `/tmp/opencode/detection-engineering-tests/venv/bin/python blueprints/detection-engineering/acceptance/render_summary.py --evidence-dir "$EVIDENCE"`

  If every mandatory criterion in this same run is `PASS`, run the harness once with `PHASE=finalize` and the same IDs; set `detection_acceptance_restoration_authorized=true` only for a separately authorized pending-restoration run. `finalize` verifies and hashes the new summary before creating initial `HEALTHY` or appending `RESTORED_PENDING_ACCEPTANCE -> HEALTHY`. Any failure, incomplete phase, stale/older PASS, or mismatched run leaves pending restoration unchanged. Expected: exit 0 only after finalization; otherwise nonzero with explicit `FAIL`, `BLOCKED`, or `NOT_RUN`. Inspect evidence for secrets and do not commit it.

### Task 11: Operator-Triggered Splunk Enterprise Uninstall with Preservation

**Dependencies:** Implement after Tasks 3, 8, and 9. Execution additionally requires explicit maintenance authorization and `capabilities.splunk_uninstall.status=VERIFIED`; it is independent of normal Task 10 deployment/redeploy.

**Files:**
- Create: `blueprints/detection-engineering/maintenance/splunk-uninstall.yml`
- Create: `blueprints/detection-engineering/maintenance/inventory.example.yml`
- Create: `blueprints/detection-engineering/maintenance/README.md`
- Modify: `blueprints/detection-engineering/README.md`
- Create: `ansible/roles/ludus_detection_splunk/tasks/maintenance-preflight.yml`
- Create: `ansible/roles/ludus_detection_splunk/tasks/maintenance-uninstall.yml`
- Create: `ansible/roles/ludus_detection_splunk/tests/test_maintenance_uninstall.py`
- Modify: `ansible/roles/ludus_detection_splunk/defaults/main.yml`
- Modify: `ansible/roles/ludus_detection_splunk/tests/syntax.yml`

**Interfaces:**
- Consumes: `detection_splunk_maintenance_authorized: bool=false`, `detection_splunk_maintenance_action: none|uninstall_enterprise_preserve` (default `none`), `detection_splunk_maintenance_range_id: str`, `detection_splunk_maintenance_state_path: /var/lib/detection-engineering/splunk-maintenance-state.json`, exact expected host `"{{ detection_splunk_maintenance_range_id }}-splunk"`, remote inventory, `capabilities.splunk_uninstall.observed`, install provenance, protected admin access for path discovery, operator-selected evidence directory, and the durable manifest in state `HEALTHY|PREPARED|REMOVE_FAILED|POSTCHECK_FAILED|ABSENT`.
- Produces: package `splunk` absent, all discovered startup paths stopped/disabled, required retained artifacts matching the frozen pre-removal baseline, the same manifest in `ABSENT`, and secret-safe `maintenance.json` with `maintenance_status: ABSENT`. It produces no second marker, archive/backup/transfer, reinstall, trial reset, Free conversion, or healthy-range claim.

- [ ] **Step 1: Write failing guard, preservation, and idempotence tests**

  Using the shared production-include harness with fake `dpkg-query`, `dpkg`, `systemctl`, init/process discovery, and filesystem fixtures, add `test_default_action_is_none_and_normal_paths_never_include_uninstall`, `test_wrong_host_local_connection_or_unverified_package_blocks_before_mutation`, `test_package_identity_and_install_provenance_must_match_gate`, `test_unreviewed_maintainer_script_or_owned_preserve_path_blocks`, `test_discovers_stops_disables_and_verifies_all_startup_paths`, `test_only_dpkg_remove_argv_is_allowed`, `test_required_paths_hash_owner_mode_survive_removal`, `test_baseline_is_frozen_after_all_writers_stop_before_remove`, `test_remove_failure_records_remove_failed_and_retry_reuses_baseline`, `test_postcheck_failure_records_postcheck_failed_and_retry_reuses_baseline`, `test_interrupted_prepared_with_absent_package_finishes_against_original_baseline`, `test_absent_without_trusted_manifest_is_blocked`, `test_already_absent_requires_matching_absent_manifest`, and `test_nonhealthy_state_blocks_ordinary_redeploy`. Assert defaults make no mutation; wrong host/local connection/gate/package/provenance blocks before stop/remove; every discovered startup path is disabled, stopped, and process-free before baseline/removal; the only removal argv is exactly `[dpkg,-r,splunk]`; required paths retain fingerprint/owner/group/mode and `/opt/splunk`; retries never recapture/rebase; and no purge, autoremove, account deletion, archive/copy transfer, explicit deletion, timer, second marker, or Task 11 call from normal Tasks 8–10 exists.

- [ ] **Step 2: Run tests to observe RED**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_splunk/tests/test_maintenance_uninstall.py`

  Expected: FAIL because the guarded maintenance entrypoint/tasks do not exist.

- [ ] **Step 3: Implement preflight, refusal, stopped-state removal, and reporting**

  Guard authorization/action, one exact remote Splunk host, package name/version/build/architecture and install SHA provenance. A new uninstall starts only from a trusted `HEALTHY` manifest. While Splunk is present, resolve actual index paths with the pinned local CLI/config inspection; include `$SPLUNK_HOME/etc`, local apps/config, auth, `splunk.secret`, encryption/instance/runtime state, default index data, and every custom/external path. Compare `dpkg-query -L` plus reviewed `prerm/postrm` behavior to required paths; any possible required-artifact removal is `BLOCKED`.

  Discover startup paths from installed systemd unit `ExecStart` values, SysV scripts, boot-start configuration, and live executables rooted under the verified Splunk home; stop/disable each and require no matching process. Only then fingerprint every required path and atomically persist the operation ID, stopped-state baseline, startup paths, and `HEALTHY -> PREPARED` journal entry before invoking verified argv `dpkg -r splunk`. Package-owned files may be removed only when the gate proves they are not required. Removal failure atomically records `REMOVE_FAILED`; absent package or success proceeds to postchecks. Recheck `/opt/splunk`, every baseline fingerprint/ownership/mode, package absence, stopped state, and no unapproved archive/deletion; mismatch records `POSTCHECK_FAILED`, match records `ABSENT`.

  Retries in `PREPARED|REMOVE_FAILED|POSTCHECK_FAILED` use the same operation ID and immutable baseline. If the package remains present and required state matches, append a transition back to `PREPARED` before retrying removal; if absent, skip removal and rerun postchecks against that baseline. A failed removal records `REMOVE_FAILED`; a failed absent-state comparison records or retains `POSTCHECK_FAILED`; only a full match records `ABSENT`. Already-absent is idempotent success only when the trusted manifest is already `ABSENT` and current retained state/provenance match; absent with no manifest, `HEALTHY`, mismatched identity, missing baseline, or changed retained state is `BLOCKED|FAIL`. Never recapture a baseline after attempted removal.

- [ ] **Step 4: Document operator invocation, downtime, and restoration boundary**

  Document `/tmp/detection-engineering-maintenance/vars.yml` as mode 0600 with required `detection_splunk_maintenance_range_id: <range-id>`, `detection_splunk_maintenance_state_path: /var/lib/detection-engineering/splunk-maintenance-state.json`, `detection_splunk_maintenance_evidence_dir: /tmp/detection-engineering-evidence/<run-id>/maintenance`, verified `capabilities.splunk_uninstall.observed`, and protected admin-access input. The exact future authorized command is `/tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook -i /tmp/detection-engineering-maintenance/inventory.yml blueprints/detection-engineering/maintenance/splunk-uninstall.yml -e @/tmp/detection-engineering-maintenance/vars.yml -e detection_splunk_maintenance_authorized=true -e detection_splunk_maintenance_action=uninstall_enterprise_preserve`. State that ingestion/search stop, collectors may queue/drop, disk risk remains, and baseline/journal metadata are not a backup. Normal deploy/redeploy refuses non-`HEALTHY`; authorized pending reapply remains pending; Task 3 alone owns authorized `ABSENT -> RESTORED_PENDING_ACCEPTANCE`, and Task 9 `finalize` alone owns pending-to-healthy after one complete new Task 10 run. Failed/incomplete reacceptance stays pending, and no lifecycle step deletes prior evidence.

- [ ] **Step 5: Run focused and integrated verification**

  Run: `PYTHONPATH=blueprints/detection-engineering/tests /tmp/opencode/detection-engineering-tests/venv/bin/pytest -q ansible/roles/ludus_detection_splunk/tests/test_maintenance_uninstall.py ansible/roles/ludus_detection_splunk/tests/test_role.py blueprints/detection-engineering/tests/test_acceptance_contract.py`

  Run: `/tmp/opencode/detection-engineering-tests/venv/bin/ansible-playbook --syntax-check -i localhost, ansible/roles/ludus_detection_splunk/tests/syntax.yml && /tmp/opencode/detection-engineering-tests/venv/bin/ansible-lint -x 'var-naming,yaml[line-length]' ansible/roles/ludus_detection_splunk blueprints/detection-engineering/maintenance && /tmp/opencode/detection-engineering-tests/venv/bin/yamllint -d '{extends: default, rules: {line-length: disable}}' ansible/roles/ludus_detection_splunk blueprints/detection-engineering/maintenance`

  Expected: all checks PASS; any unrun behavioral/syntax/lint check blocks maintenance enablement.

- [ ] **Step 6: Commit the maintenance checkpoint after approval**
  Run: `git add ansible/roles/ludus_detection_splunk blueprints/detection-engineering/maintenance blueprints/detection-engineering/README.md && git commit -m "feat: add guarded Splunk uninstall maintenance path"`

## Claim-to-Evidence Ownership

| Claim | Acceptance owner | Contributing tasks | Minimal evidence / limitation |
|---|---|---|---|
| Five range-scoped VMs, capacity, services, and isolation | Task 10 | 1, 2, 8 | Server facts, service state, allowed/denied probes; offline config is insufficient. |
| Every baseline/product/runtime row searchable once | Task 10 | 2–5, 7, 9 | Per-row count and attribution; safe observations are not attack simulation. |
| GitLab CE coverage is truthful | Task 10 | 1, 5, 9 | Capability source + searches + explicit gaps; CE may lack a class and then overall coverage is not PASS. |
| Runner is locally registered, paused, masked, idle, unprivileged | Task 10 | 1, 5, 6, 9 | API/local fingerprint, service state, zero jobs/polls, negative privileges. |
| Kubernetes audit/OTEL and Docker boundaries are safe | Task 10 | 4, 7, 9 | Active policy/RBAC, body-negative searches, owner/attribution checks. |
| Bootstrap/runtime credentials and bounded sensitive fields are absent from telemetry/evidence | Task 10 | 2–7, 9 | Canary zero-results and process/log/evidence inspection; no general DLP claim, and root can read protected files. |
| Malcolm sees packets before and after reboot | Task 10 | 8, 9, operator | Malcolm-observed probes plus persistent bridge hook; requires host action. |
| Reboot and redeploy preserve pause, tokens, packets, hosts, and convergence | Task 10 | 2–9 | Before/after hashes, searches, packet proof, and changed/failed counts. |
| Manual Enterprise uninstall is guarded and preserves required state | Task 11 | 1, 3, 8, 9 | Durable stopped-state baseline/journal, deterministic failure retry, and matching postchecks; `ABSENT` is downtime, not healthy or backup. |
| Overall status is not overstated | Task 10 | 9 | Aggregated mandatory statuses; any missing prerequisite/source prevents PASS. |
