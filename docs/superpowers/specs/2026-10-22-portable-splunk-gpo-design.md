Use separate collection-only container telemetry and readable Windows policy roles, with opt-in Linux HEC; verify artifact pins before use and live compatibility before readiness claims.

# Portable Splunk collection and Windows policy design

Date: 2026-10-22. Status: user-approved design after two scoped review passes; implementation plan confirmation pending, with no live deployment authorization. Controller owns design review and validation. Repository authoring/verification policy: `docs/instructions/ludus-authoring.md`.

## 1. Intent and decision provenance

Deliver independently reusable components that collect existing container logs into Splunk and author three understandable Windows policies without distributing an opaque, foreign-domain GPO backup. Keep role configuration explicit enough for standalone Ansible and Ludus `role_vars` callers.

**User requirements established by this work package:**

- Recreate the three custom policies from readable, configurable settings. Defender disabling is explicit lab opt-in, never a logging dependency.
- Use existing standard Kubernetes, not Minikube, with container workloads and Splunk on separate hosts. Collection-only may manage collectors but never install, reconfigure, or restart container runtimes, recreate clusters, or enable audit logging.

**Controller/repository scope and engineering decisions (not additional end-user requirements):** preserve legacy roles; Task 4 is comparison only; do not edit existing blueprints/ranges or staged/untracked work. Extend HEC with opt-in defaults, a separate validation switch, existing `splunk_server_*`/shared `splunk_*` namespaces, TLS verification, restricted secrets and fatal failures. Repository verification uses static and live evidence only. No live authorization has been granted; that is the current execution boundary, not a prerequisite for writing code after design approval.

**Assistant-selected implementation choices, incorporating controller refinements; subject to design review:**

- New directories/metadata role names `splunk_container_logs` and `windows_logging_policy`; modify directory `linux_splunk_server` without renaming its existing metadata identity `linux_splunk_enterprise`.
- Official Splunk OTel chart for Kubernetes; a pinned Splunk OTel Linux collector with a filelog-only configuration for Docker `json-file`. No Universal Forwarder dependency for these feeds.
- All Windows policies default disabled; explicit links default empty. New names are `Ludus-Logging`, `Ludus-CertEnroll`, and `Ludus-DisableDefender`; legacy policies are not automatically adopted.
- Native GroupPolicy cmdlets for registry policy and links, with one bounded protocol-backed advanced-audit helper. No general GPO importer, arbitrary migration engine, or generalized transaction framework.
- One telemetry mode per invocation: Docker or Kubernetes. The caller owns disjoint host/node target sets across invocations; the role checks explicit inputs and locally observable collisions, not global exclusivity.
- Initial host packaging targets Debian 12 and Ubuntu 22.04/24.04, amd64/systemd, **conditional on exact package/component verification**. These are proposed targets, not tested support claims.

### Goals and non-goals

Goals: explicit ownership; repeat-run convergence; meaningful failure reporting; portable domain discovery; readable settings; no unexpected workload/runtime management; trustworthy provenance and bounded live acceptance criteria.

Non-goals: replacing legacy collectors, wholesale existing-install migration, AD CS/template provisioning, arbitrary GPO import/export, changing default domain policies, provisioning Splunk add-ons/search capabilities, enabling Windows event producers beyond the three policies, collecting Windows transcripts automatically, container metrics/traces, Kubernetes events/audit collection in v1, Minikube, container runtime repair, or any new blueprint/range.

## 2. Components, interfaces, and ownership

| Component | Owns | Requires from caller / does not own |
| --- | --- | --- |
| `linux_splunk_server` extension | One marked HEC app, its configured token and index stanzas, applicable Splunk restart and explicit validation | Existing server installation workflow/license acceptance; TLS material and network access. No collectors, Docker, Kubernetes, or unrelated Splunk configuration |
| `splunk_container_logs` | Dedicated host collector package/config/service/state, or one marked Helm release and its collector objects; optional role-created Kubernetes Secret | Existing runtime/cluster and readable logs, HEC destination/index/credentials, existing kubeconfig/context. No runtime daemon, cluster lifecycle, log permission changes, or Splunk server installation |
| `windows_logging_policy` | Three selected, marked GPOs; enumerated registry values/audit rows and explicit direct links | Existing joined AD management host, writable DC and delegated rights; AD CS/templates if enrollment is wanted; endpoint log storage/permissions and downstream collection |

Roles do not include each other or obtain credentials from sibling facts. The caller maps the same index/token contract to server and collectors. Each telemetry invocation selects exactly one mode: Kubernetes on an explicit Ansible management host with Helm/kubeconfig, or Docker on explicit inventory log-source hosts. Windows runs once per domain on one documented designated management host/DC holding its protected state, never once per member VM. These boundaries must be documented in role READMEs, not hidden delegation to an inferred inventory host.

Every new role has nonempty `meta/main.yml` `role_name`/`author`, narrow platform prerequisites, a license for project-authored code, and complete namespaced defaults. Repository directory, metadata identity, source identity, and installed Ludus identity are distinct: **no installed role name has been verified**. Check the actual installed identity before any future deployment selection; do not edit metadata merely to make a guessed identity work.

## 3. Linux Splunk HEC contract

Keep existing shared `splunk_version`, `splunk_build`, `splunk_accept_license`, and `splunk_receiver_port`; retain existing `splunk_server_*` installation variables. Add:

| Variable | Default / contract |
| --- | --- |
| `splunk_server_hec_enabled` | `false`; no HEC mutation when false |
| `splunk_server_hec_validate` | `false`; true requires HEC enabled and performs an authenticated ingestion check after configuration/restart |
| `splunk_server_hec_app` | `ludus_hec`; marked role-owned app under `{{ splunk_server_home }}/etc/apps/`; existing unmarked path fails |
| `splunk_server_hec_port` | `8088`; validate range and listener conflicts |
| `splunk_server_hec_ssl_enabled` | `true`; false is an explicit plaintext-lab choice |
| `splunk_server_hec_server_cert` | Empty means do not override Splunk's existing/default certificate selection; explicit path must exist and be readable by Splunk. No PKI provisioning; actual certificate trust is independently required |
| `splunk_server_hec_token_name` | `ludus-container-logs`; one token stanza owned by this role |
| `splunk_server_hec_token` | Empty; explicit secret required when enabled, no generated token silently changed between runs |
| `splunk_server_hec_indexes` | `[]`; explicit nonempty list of index names to create/manage when enabled; no adoption of existing unrelated definitions |
| `splunk_server_hec_default_index` | Empty; required member of the above list; token allowed-index list must match |
| `splunk_server_hec_validation_endpoint` | Empty; explicit full reachable `/services/collector/event` URL required when validation is enabled, with scheme consistent with server TLS |
| `splunk_server_hec_validate_certs` | `true`; explicit false permits an untrusted certificate only for validation, not an implicit collector override |
| `splunk_server_hec_ca_path` | Empty = validation host's trust store; otherwise existing CA bundle on the validation execution host |

Use owned `local/inputs.conf` for managed HEC settings/token and `local/indexes.conf` for configured indexes. Review the selected Splunk version's configuration specification and precedence before implementation. Do not append into `system/local`, overwrite another app, or infer precedence from an app name. Preflight both winning values/provenance (`btool ... --debug`) and relevant on-disk definitions, including shadowed stanzas; effective output alone is not a duplicate-definition inventory. Classify settings as follows:

- **Vendor defaults:** may be overridden, including default disabled HEC. Fresh enablement must not fail merely because defaults differ.
- **Previous role-owned configuration:** may be updated in place after ownership validation; compare desired values rather than rejecting legitimate changes.
- **Compatible administrator-managed shared globals:** may be used without claiming exclusive ownership or replacing their files. A later incompatible desired change fails for explicit coordination.
- **Administrator-owned conflicts:** incompatible globals, token name/value reuse, or requested indexes defined outside the owned app fail before mutation. Do not silently take ownership because a shadowed definition currently loses precedence.

Perform configuration/precedence checks before writing/restarting where possible. After writing, verify on-disk effective values before restart; a failed check leaves an identified partial owned-app update, does not clear its failure, and must not flush a restart handler for that failed update. After a successful restart, verify effective running behavior. Preserve unrelated tokens/indexes throughout; report post-write/restart failures and recovery scope rather than success.

Restrict app/config and staging permissions to the actual Splunk service identity; secret-bearing files mode 0600, directories 0700 where compatible with that identity. Use `no_log` on all token/password/secret-bearing command outputs, templates, comparisons, HTTP calls and diffs. Do not print the existing admin password in the role's final debug message. Retain no plaintext diagnostic summary or secret-bearing backup in a permissive directory.

Only changed, successfully checked HEC files notify a restart dispatcher that works for both existing systemd and manual-start modes. Flush handlers before running-state checks and optional validation. HEC authentication, certificate, restart, config and HTTP failures are fatal; do not conceal mutations with ignored errors or unconditional `changed_when: false`.

**Acceptance covers HEC subflow convergence, not whole-server convergence.** An unchanged HEC rerun performs no HEC config write or HEC-triggered restart. The existing license installation (`tasks/main.yml:152–159`) runs whenever a license file is supplied and swallows failures; that unrelated lifecycle limitation remains out of scope. Narrow integration changes remove admin-password debug output and correct legacy index handling only where it interferes with HEC ownership/validation (including duplicate creation of a requested HEC index), preserving intended legacy index availability. Do not turn this extension into a whole-role lifecycle cleanup.

Validation sends a small identified event to the configured default index with the configured token, checks HTTP 200 **and parsed JSON `code == 0`**, and redacts the request. This establishes authenticated HEC acceptance, **not searchability, parsing correctness, or end-to-end collection**. Do not use an unauthenticated health request as a substitute. Validation is disabled by default because it writes an event. Network/firewall opening and searchable-event verification require separately scoped authorization.

False switches are not uninstall requests. Disabling HEC management later does not silently delete indexes/data, revoke a previously created token, or stop another user's listener. Document this lifecycle explicitly; removal/rotation is a separately specified operation. Changing configured ownership (app/index/token name) with old owned state present fails pending explicit migration rather than orphaning/replacing resources.

## 4. `splunk_container_logs` contract

### Shared inputs and transport

| Variable | Default / requirement |
| --- | --- |
| `splunk_container_logs_mode` | Empty; required scalar `docker` or `kubernetes` on invocation; reject lists, both modes, or missing selection |
| `splunk_container_logs_owner_id` | `ludus-container-logs`; stable installation identity, required to match existing managed state |
| `splunk_container_logs_hec_endpoint` | Empty; explicit full HEC event endpoint required for either mode; no inferred `DC` hostname |
| `splunk_container_logs_hec_index` | Empty; explicit nonempty index provisioned/allowed on the destination |
| `splunk_container_logs_hec_token` | Empty; explicit secret required for Docker and for Kubernetes unless an existing Secret is selected |
| `splunk_container_logs_tls_verify` | `true`; false explicitly maps to the collector's insecure-skip-verification option |
| `splunk_container_logs_allow_insecure_http` | `false`; separate explicit permission required for HTTP; TLS-skip alone does not authorize plaintext |
| `splunk_container_logs_ca_file` | Empty = system trust; otherwise existing CA bundle on execution/source host, supplied to the collector. Kubernetes existing-Secret CA content follows the pinned chart's Secret contract |
| `splunk_container_logs_start_at` | `end`; applies only to newly discovered files without a checkpoint; explicit `beginning` requests historical ingestion |

Both modes produce only logs to the configured Splunk Platform HEC destination. Explicitly disable metrics/traces pipelines, Observability destinations, application OTLP listeners and unnecessary agent services/host ports; chart defaults are not an adequate logs-only contract. Collector internal operational logs may remain local; do not export an unrequested metrics pipeline. Preserve timestamps/body/stream and stable source attributes; Docker need not claim Kubernetes-equivalent label enrichment. Define deterministic sourcetype/source mapping in readable templates and validate it against actual indexed events later.

Offsets use persistent `file_storage`/chart checkpoint storage with stable component IDs. Enable a bounded persistent exporter queue and retry/backpressure using options supported by the selected distribution; separate writable state from read-only logs. Defaults: host state `/var/lib/splunk-container-logs`, Kubernetes host checkpoint `/var/addon/splunk/otel_pos`, exporter queue `/var/addon/splunk/exporter_queue`; expose paths and queue/disk limits as role variables. Never delete checkpoints on rerun, upgrade or restart. Receiver offsets alone do not guarantee delivery; bounded disks, retention and retry windows can lose events, and retry can duplicate events. No exactly-once claim.

### Docker mode

- Inputs: `splunk_container_logs_docker_include: []` (explicit nonempty list required), `splunk_container_logs_docker_exclude: []`, `splunk_container_logs_docker_state_dir: /var/lib/splunk-container-logs`, and an exact reviewed collector package version/URL/SHA-256. No `latest`, mutable install script, or unverified automatic version fallback.
- Support only preexisting Docker **json-file** logs on the proposed Debian/Ubuntu amd64/systemd matrix after package verification. Require valid accessible log roots and operator confirmation of the logging driver; inspect representative files read-only. Fail on unsupported driver/format or missing permissions. No Docker socket access, daemon JSON edit, restart, runtime package installation, Docker group membership, or host-log chmod/chown. Docker `local`, journald, remote drivers, rootless layouts, Windows containers and non-Debian packaging are outside v1 unless separately qualified.
- Install/manage only the collector and its normal package dependencies. Inspect the exact package maintainer scripts/service behavior first; reject a package path that overwrites or autostarts an unrelated existing collector. An existing unmanaged service/config/package collision fails rather than being adopted. If the vendor package cannot coexist safely, constrain v1 to clean collector hosts; do not silently add a second competing instance.
- Use a dedicated collector configuration and systemd unit. Proposed default is a root collector with a read-only filesystem sandbox except its owned state/config lifecycle paths, since Docker logs often require privileged reads; never grant runtime control. If a nonroot identity is supported, existing read ACLs are a prerequisite. Log sources are always read-only; file deletion is disabled. Pin supported sandbox directives against each target OS.
- Parse the Docker JSON envelope (`log`, `stream`, `time`) using the pinned collector's supported operators. Explicit includes/excludes prevent duplicate ingestion of the same file/symlink target. No assertion that an extension merely being present upstream means it is included in the vendor distribution.
- Compare actual owned configuration, package version and service state; restart the collector only when required. Configuration validation must succeed before restart; failed validation preserves the running configuration. Failure after a package/service mutation is reported as partial failure; do not claim automatic rollback.

### Kubernetes mode

| Variable | Default / requirement |
| --- | --- |
| `splunk_container_logs_kubeconfig` / `splunk_container_logs_kube_context` | Empty; both explicitly required, existing readable kubeconfig and exact existing context; never silently use current context |
| `splunk_container_logs_k8s_cluster_name` | Empty; explicit stable cluster identity |
| `splunk_container_logs_k8s_namespace` | `splunk-logs`; may create this collector namespace only, never repurpose/delete an unrelated namespace |
| `splunk_container_logs_k8s_release` | `splunk-container-logs`; existing release requires matching owner identity and supported chart lineage |
| `splunk_container_logs_k8s_existing_secret` | Empty; mutually exclusive with a supplied token; otherwise names an existing Secret in the selected namespace with nonempty `splunk_platform_hec_token` key |
| `splunk_container_logs_k8s_node_selector` | `{}` default is invalid for an enabled invocation: require an explicit nonempty positive selector defining collector nodes; expose tolerations for those nodes |
| `splunk_container_logs_k8s_log_paths` | Standard existing pod-log roots (`/var/log/pods`, with `/var/log/containers` only where required by pinned chart); override explicit; read-only mounts, resolve symlink targets into approved read-only roots |
| Chart/tool pins | Exact chart version/archive SHA-256, collector/helper image digests, Ansible Helm integration, Helm and helm-diff versions in one concise dependency manifest; no approved default pin yet |

Use official `signalfx/splunk-otel-collector-chart`. Research on mutable `main` found chart/app version **0.163.0** on 2026-10-22; **the exact release artifact, schema, image contents/digests and dependencies have not been independently pinned-source verified**. Phase 0 must fetch/verify the actual artifact and review its templates/defaults; do not treat `main` as a verified release or make up checksums. Render against the actual existing cluster API version, using only a verified chart-supported Kubernetes version range. No generic claim that every Kubernetes distribution/version or Windows node is supported.

Pin and configure the chart to enable container file logs and Splunk Platform logs only; disable cluster receiver, events/objects/audit logs, journald, gateway, metrics/traces, operator/CRD installation, auto-instrumentation, target allocator and unrelated optional agents. Disable permission-fixing init containers rather than allowing host-log chmod/chown. Review every rendered host mount, init container, hook and RBAC rule. Do not rely on an implicit `latest` Secret-validation/helper image: disable the optional hook in favor of role read-only Secret preflight or pin/review it. Read-only log mounts may coexist with explicitly owned writable checkpoint/queue mounts; unsupported hostPath/Pod Security admission fails, not automatic cluster-policy relaxation.

With existing Secret, configure `secret.create=false` and its exact name; do not copy the token back to disk or replace the Secret. If the caller supplies a token, create only the marked role-owned Secret with restricted handling and documented cluster RBAC expectations. For custom CA with existing Secret, verify the pinned chart's `splunk_platform_hec_ca_file` contract and required value to enable mounting; never assume a local path is equivalent to PEM content. No token in command-line values, logs or world-readable values files; protected temporary files are removed on success and failure.

**Helm convergence:** prefer the existing `kubernetes.core.helm` integration with pinned, verified helm-diff support over a bespoke release engine. Verify the chosen versions' values/chart comparison and actual live-drift coverage; require verified three-way drift checking for the managed resources rather than assuming it. Suppress secrets and use `no_log`. No diff means no upgrade; a documented diff triggers a bounded install/update with wait; comparison errors fail. Use the verified local chart and explicit context/namespace. Do not run an upgrade every play or hide it with `changed_when: false`; do not uninstall/reinstall, force replacement or automatically recover pending/failed releases. Unsupported release/diff states fail explicitly. Phase 0 verifies this integration; missing prerequisites do not justify an always-changing fallback.

### Duplicate ownership and lifecycle

The caller selects disjoint Docker inventory hosts and Kubernetes nodes across separate invocations, including excluding Docker-source hosts from the Kubernetes selector and coordinating other collectors. This is a caller prerequisite, not a guarantee proved by this role. There is no global node mapping, cross-invocation registry or collector discovery framework.

Preflight only the selected mode before its writes: validate explicit paths/selectors and detect collisions observable in the current host's known collector service/config paths or the selected Kubernetes release/resources. Reject an unmanaged object at an owned destination, duplicate resolved source paths in the invocation, or readable known configuration showing a competing source owner. Fail on an observed contradiction; do not claim absence of unknown agents or cross-host overlap from these bounded checks.

Changing roots/component IDs/state paths/release identity can replay or orphan data: fail on such ownership changes while previous managed state exists and require scoped migration. Omitting a former role invocation does not uninstall its collector or clear offsets; it continues until explicitly retired. This phase does not implement destructive decommissioning. Locally observed competing old ownership is rejected pending retirement; coordinating remote or unknown collectors remains the caller's responsibility.

## 5. `windows_logging_policy` contract

### Inputs and supported boundary

| Variable | Default / semantics |
| --- | --- |
| `windows_logging_policy_domain` | Empty = `Get-ADDomain -Current LocalComputer`; use returned DNSRoot/DN/ObjectGUID/SID, not string-built DN. Explicit override must resolve and match the intended joined-domain boundary |
| `windows_logging_policy_server` | Empty = discovered PDC emulator; use the same verified writable target-domain DC for GroupPolicy, LDAP and SYSVOL operations |
| `windows_logging_policy_owner_id` | `ludus-windows-logging-policy`; stable marker in GPO description plus a small protected ownership record keyed by domain/GPO GUID |
| `windows_logging_policy_management_host` | Required designated inventory host; assert this is the executing host. One writer per domain; no automatic delegation/failover |
| `windows_logging_policy_state_dir` | `C:\ProgramData\Ludus\WindowsLoggingPolicy`; configurable protected local path on that host, restricted to the role execution identity, SYSTEM and local administrators |
| `windows_logging_policy_logging_enabled` | `false` |
| `windows_logging_policy_enrollment_enabled` | `false` |
| `windows_logging_policy_defender_disable_policy_enabled` | `false`; the single explicit opt-in to the Defender-disabling lab policy; true does not mean protection is enabled |
| `windows_logging_policy_names` | Map of `logging`, `enrollment`, `defender` to the new names above; unique, nonempty, never built-in Default Policy names/GUIDs |
| `windows_logging_policy_links` | Map of those policy IDs to lists, each default `[]`; items `{target: domain_root or explicit domain/OU DN, enabled: true, enforced: false, order: optional positive integer}` |
| Logging settings | Readable `windows_logging_policy_audit_subcategories` list plus `windows_logging_policy_powershell` map described below; no binary defaults |
| Enrollment settings | `windows_logging_policy_enrollment` map: `renew_update_revoke: true`, `update_templates: true`, offline expiration 10 percent, store `MY`; computer policy only. Controller refinement for v1: when enrollment is enabled the two booleans are coupled and both must be true; reject every other combination before mutation |

Initial authoring target: Windows Server 2022 management host with Windows PowerShell 5.1, GroupPolicy/GPMC and ActiveDirectory modules, reachable writable AD/SYSVOL, and delegated create/edit/link rights. Initial recipient targets: Windows Server 2022 and Windows 11, specific builds recorded during live acceptance. Other versions are not declared supported merely because a documentation page lists them. The role may install appropriate management features only if that capability is explicitly included in its reviewed prerequisite tasks; it does not promote/join DCs or create the domain. Cross-forest administration, user-policy variants, WMI/security-filter management and arbitrary custom extensions are outside v1.

**Windows credential prerequisite:** the actual execution session must authenticate to both LDAP and the selected DC's SYSVOL over SMB, not merely have nominal AD permissions. WinRM to a separate management host introduces a second hop; a default nondelegating session is insufficient. The caller supplies a documented working credential/delegation arrangement (for example, appropriately configured Kerberos delegation or an explicit domain execution identity) and verifies access under that same session. The role does not enable CredSSP/delegation, change account policy or silently fall back to another DC/identity. Read-only LDAP/SYSVOL access checks precede writes; failed access is fatal. Actual write permissions and application remain live-verification items.

Discovery failure, mismatch with supplied Ludus domain facts, missing modules/rights, cross-domain links, an RODC, ambiguous names or malformed settings fail before creation. Pass structured PowerShell parameters, not executable string interpolation. Empty links create an unlinked enabled policy, never implicit domain-wide application. Default filtering comes from a newly created target-domain GPO; do not copy source DACLs.

### Readable policy contents

**Logging:** configure exact registry values with `Get/Set/Remove-GPRegistryValue`, explicit domain/server/GUID, preserving unrelated values and using additive semantics where lists require it. Settings default, when this policy is enabled, to the legacy custom logging intent:

- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=1`.
- Under `HKLM\Software\Policies\Microsoft\Windows\PowerShell`: ModuleLogging enabled with configurable module-name list default `['*']`; ScriptBlockLogging and script-block invocation logging enabled; Transcription enabled, invocation headers enabled, output directory configurable with default `C:\Transcripts`.
- Expose each switch in `windows_logging_policy_powershell`, including `transcription_directory`. Validate absolute local/UNC path syntax, never infer a foreign share. Endpoint directory/share availability, least-privilege ACLs and retention are prerequisites owned elsewhere; writing a GPO path does not establish those. Do not claim PowerShell 7 policy parity without its separate template/version evidence.
- Default advanced audit entries: the following 15 subcategories, success and failure. Use GUID identity rather than translated display names; remaining suffix is `-69ae-11d9-bed3-505054503030`.

| GUID prefix | Subcategory | GUID prefix | Subcategory |
| --- | --- | --- | --- |
| `0cce9242` | Kerberos Authentication Service | `0cce9240` | Kerberos Service Ticket Operations |
| `0cce9236` | Computer Account Management | `0cce9237` | Security Group Management |
| `0cce9235` | User Account Management | `0cce923e` | Detailed Directory Service Replication |
| `0cce923b` | Directory Service Access | `0cce923c` | Directory Service Changes |
| `0cce923d` | Directory Service Replication | `0cce9215` | Logon |
| `0cce921c` | Other Logon/Logoff Events | `0cce921b` | Special Logon |
| `0cce9221` | Certification Services | `0cce9244` | Detailed File Share |
| `0cce9227` | Other Object Access Events | | |

Each list entry supplies GUID and success/failure booleans; the helper derives documented setting flags. Validate unique supported GUIDs/flags before writes. No process-creation audit is claimed by this default. Directory/object audit policies can still require appropriate object SACLs to generate events; this role does not silently add them. GPO logging is producer configuration, not Splunk collection.

**Certificate enrollment:** configure the computer AutoEnrollment registry policy (`AEPolicy=7` for the verified enabled all-options bundle; `OfflineExpirationPercent=10`, `OfflineExpirationStoreNames=MY`) from named readable options. **Controller refinement, not an original user request:** the bounded official-source search did not establish independent `AEPolicy` bit representation, so v1 supports enrollment enabled only when both `renew_update_revoke` and `update_templates` are true. Reject either false value, including mixed combinations, before mutation with a clear unsupported-v1-combination error; do not calculate or invent other numeric values. Retirement removes all three owned values rather than writing a disabled numeric value. Use the joined target domain's ordinary Active Directory enrollment policy; do **not** emit a `Cryptography\PolicyServers` tree, source domain GUID, hashed server key, or `**DeleteKeys` instruction. No custom CEP/CES server mode in v1. AD CS enterprise CA, published template and enrollment permissions are external prerequisites; policy creation does not prove issuance. An existing competing enrollment-server policy requires explicit review rather than deletion. `Set-CertificateAutoEnrollmentPolicy` configures local policy, not a domain-GPO target, so it is not a substitute setter.

**Defender lab policy:** only when `windows_logging_policy_defender_disable_policy_enabled=true`, set the two readable, independently exposed legacy intent values `DisableAntiSpyware=1` and `Real-Time Protection\DisableRealtimeMonitoring=1` under `HKLM\Software\Policies\Microsoft\Windows Defender`. This single opt-in requests a lab policy, not guaranteed protection disablement. Current Defender versions, onboarding and tamper protection can ignore or change these effects; no tamper-protection bypass or additional endpoint changes are authorized. Default no links and no enforcement; domain-root scope requires an explicit link.

### Advanced audit: concrete protocol-backed implementation boundary

Microsoft's GroupPolicy module has no advanced-audit setting cmdlet. `Set-GPRegistryValue` changes registry policy, and `auditpol /set` or `/restore` changes local policy; neither authors a domain GPO's advanced audit payload. The documented route is the **MS-GPAC audit policy file plus MS-GPOL extension update**, not just copying a CSV into SYSVOL. [M1–M7]

A small dedicated PowerShell helper may operate **only on the role-owned logging GPO**:

1. Acquire the designated host's per-domain writer lock and inspect protected state **before normal comparison**. Any unresolved pending record blocks ordinary convergence, even if CSV and AD/GPT versions appear to match. Serialize native registry changes and audit publication under this lock; after native cmdlets finish, reread authoritative AD/GPT versions and extension registrations from the selected DC. Fail on inconsistency, malformed CSV, concurrent mutation or unexpected ownership. Require no other administrative writer during the update; the lock is not a distributed transaction guarantee.
2. Render `Machine\Microsoft\Windows NT\Audit\audit.csv` as documented UTF-8/CRLF with header `Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`. Follow MS-GPAC field/flag grammar, not locale-dependent `auditpol` display output. Compare semantic rows and avoid rewriting unchanged settings. Preserve unrelated valid rows; own only the configured/previously recorded GUIDs.
3. Before any audit-file/version/extension mutation, atomically persist and flush a compact **pending audit publication** in the protected record: domain/GPO/DC identity, prior AD/GPT versions and extension tuples, prior payload hash/backup location, intended payload hash (or deletion), intended versions and owned GUIDs. Recheck the prior state immediately before publication; failure to persist pending state prohibits mutation. Then publish the file and prescribed extension update: audit CSE `{f3ccc681-b74c-4060-9f26-cd84525dca2a}`, tool `{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}`; preserve other tuples. Follow the combined LDAP replacement of `versionNumber`/`gPCMachineExtensionNames` and GPT update rules; increment the computer half in AD and `GPT.INI`, preserving user half and nonzero wrap semantics. Register/unregister the tuple only as appropriate for all remaining audit data; check every result.
4. Read back payload, extension membership and versions; commit ownership state and clear pending only after all match. Any error or interruption retains pending and blocks new links and ordinary reruns. Scoped operator recovery inspects the recorded prior/intended/current states on the same DC, then explicitly completes publication or restores the affected prior state after checking for intervening edits; only verified reconciliation permits clearing pending. In particular, a CSV already matching desired content with unchanged matching AD/GPT versions is **not** convergence when pending exists. Updating a linked GPO is not atomic; retain the protected backup and report partial state. No automatic rollback, blind retry/version bump or generalized transaction framework.

This is a **documented protocol route**, not a claim of a single high-level supported cmdlet or proven implementation. Complete MS-GPAC/MS-GPOL clause review precedes code implementation. Authorized fresh/apply/convergence/failure tests on real AD and a client gate **compatibility/readiness claims, not permission to implement and statically validate code**. Do not substitute local `auditpol` or claim unverified logging parity. Native `IGroupPolicyObject::Save` documents registry-policy persistence; it alone does not prove arbitrary audit CSV edits receive the required update.

### Ownership, convergence and retirement

- The designated host's protected record and matching domain/GPO marker/GUID jointly establish ownership. Missing, mismatched or unreadable records for an existing marked GPO fail closed; do not reconstruct ownership from names or descriptions. Moving the writer/path requires explicit protected state transfer and reconciliation before writes; no automatic failover.
- Before creation or any setting/link addition, change or retirement, durably record compact pending intent (resource identity, prior ownership and intended owned keys/GUIDs/links). Create new GPOs unlinked with the exact ownership marker supplied atomically to the documented `New-GPO -Comment` call, then durably record the returned GUID before content changes. Newly managed settings/links enter pending intent **before** mutation and committed ownership only after successful readback; interrupted additions therefore remain tracked. Any unresolved pending intent stops ordinary reruns for scoped recovery. A crash before recording a new GPO GUID is a collision for review, not adoption permission. No implicit adoption of legacy or built-in policies; no general receipt framework.
- On rerun, compare actual registry values, audit rows, and direct links. Converge documented owned settings; preserve unrelated values, audit rows, links, ACLs and user policy. An unexpected setting at an owned key can be reconciled because ownership was explicit; an invalid/ambiguous ownership record or structural drift fails. Never delete a registry subtree or replace the whole GPO.
- Use native New/Set-GPLink only for explicit targets; preserve unrelated links. New links follow successful content readback. Optional link order is an explicit request that may shift relative order; report that effect and do not otherwise reorder links. Removing an owned link from the desired list disables that recorded link rather than deleting unrelated links. No automatic enforcement inferred from old backup reports.
- An enabled policy becoming disabled removes only its recorded owned setting values/rows and disables its recorded owned links; retain the marked GPO and unrelated content. A never-managed disabled policy is a no-op. Thus `windows_logging_policy_defender_disable_policy_enabled=false` retires this role's disabling intent without claiming effective Defender restoration; there is no second acknowledgment switch.
- No broad gpupdate/reboot, automatic adoption, policy deletion, security-filter rewrite, or source-domain credential/account migration. Check mode reads/plans without creating a GPO or incrementing versions. Every task reports actual changes; unchanged reruns leave settings, links and GPO versions unchanged.

## 6. Provenance and explicit migration/functionality differences

Detailed evidence: `.slim/deepwork/portable-splunk-gpo/gpo-collector-analysis.md` (sections 1–3, 5 and verification disposition), `.slim/deepwork/portable-splunk-gpo/gpo-archive.md`, and `.slim/deepwork/portable-splunk-gpo/progress.md`. The prior report's section 4 generic `windows_gpo` importer proposal is **superseded** by the user's readable-policy decision; its archive inspection and collector comparison remain applicable to the recorded bytes.

Archive: `/tmp/opencode/portable-splunk-gpo/inspection-rkB8fx/CondefGPO.zip`; extracted root `/tmp/opencode/portable-splunk-gpo/inspection-rkB8fx/extracted/CondefGPO`; 47,340 bytes; SHA-256 `d401b570866537774f8825ebf7c4e389d9aadbcb8482b6099d17edc1c6036058`. Independently matched commit-pinned upstream `0cefe62755eebba7b226e611ece75160706e22f6` bytes. Five backups exist; legacy `role_gpo_deploy` imports only GPO-Logging, GPO-CertEnroll and GPO-DisableDefender. The Default Domain and Default Domain Controllers backups are excluded. Inspection corrected the inventory to four INF and four registry.pol files; UTF-16 XML/INF and binary policy records were read, not executed/imported.

Foreign-domain material includes condef.local/DC/DNs and source SID/DACL metadata; old SYSVOL UNC strings were backup provenance rather than discovered active UNC consumers. Substantive exceptions include CertEnroll's foreign PolicyServers GUID/deletion directive and the unused Default Domain Policy's embedded EFS Administrator certificate/identity. No named certificate template or CA provisioning was present. Readable recreation omits those identities instead of pretending a migration table maps arbitrary registry GUIDs/certificates. No backup download, migration-table input or archive extraction belongs in the new role.

Upstream had no repository/archive license statement and GitHub reported `license: null`; the downloader role's GPL license does not establish archive redistribution permission. A commit-pinned URL plus checksum improves reproducibility without republishing bytes but does not settle rights; project release hosting and vendoring require established redistribution permission and provenance. The approved approach authors readable project settings and avoids bundling the archive; still use original project-authored documentation/code and appropriate attribution rather than copying an unlicensed binary bundle. No release asset was published.

Differences from legacy GPO behavior are intentional: no built-in policies imported; new names and no auto-adoption; explicit domain discovery/links; no default domain-wide application; CertEnroll not automatically enforced; the Defender-disabling policy is off by default; target AD enrollment instead of a source PolicyServers blob. Transcription/audit generation is not automatically collected into Splunk. Running old and new policies together can create conflicting precedence: operators must inventory effective links/settings and separately approve retiring legacy links before enabling overlapping new policy links. This design does not edit the legacy deployment to do that automatically.

**Task 4 remains evaluation only.** Safely inspected ZIP inventories/digests/license records are under `/tmp/opencode/portable-splunk-gpo/collector-inspection-tuysl242`; the comparison report records exact URLs and SHA-256 values. Findings:

| Legacy collector | Confirmed differences from current `splunk_forwarder` |
| --- | --- |
| `role_splunk_collector_certer` | Windows TA 9.0.1 Security → `winlogs`; XML, AD resolution, history/checkpoint and 5145 share-filter details are not representable by the generic template |
| `role_splunk_collector_win11a` | Above plus Sysmon TA 4.0.2 XML/source handling and PSTree 2.0.0 search command; generic role delivers no corresponding apps/transforms/scripts |
| `role_splunk_collector_win11v` | Windows/Sysmon apps plus SILK channel → `etw`/`json`; no PSTree. Channel/index can be configured generically, but app/XML/filter parity is absent |
| `role_splunk_collector_linuxv` | Laurel path is representable, but UF 9.3.2 vs 10.6.1.1, `linux` vs `main` index, unset vs `laurel:json` sourcetype and install/service ownership differ; no automatic takeover |

Windows TA's shipped inventory scripts/WMI stanzas were disabled, not active-feed requirements. Props/transforms/lookups and PSTree need correct indexer/search-head placement; ZIP presence on a UF does not prove execution there. Neither path automatically collects PowerShell Operational/transcripts. Legacy Windows firewall disabling, hardcoded credentials/service identity and unpinned downloads are not behavior to reproduce. Splunk add-on licenses and mixed PSTree dependency notices do not establish blanket redistribution rights. **No collector is declared a drop-in equivalent and none is changed by this work.**

## 7. Implementation file scopes and phases

Allowed future implementation scopes (subject to design approval):

- `ansible/roles/splunk_container_logs/`: defaults, tasks split preflight/Docker/Kubernetes, handlers, readable OTel/chart templates, metadata, README/license, artifact manifest. No runtime provisioning helpers.
- `ansible/roles/windows_logging_policy/`: defaults/readable settings, preflight and policy/link tasks, one bounded audit helper and CSV template, metadata, README/license. No bundled GPO ZIP.
- `ansible/roles/linux_splunk_server/`: defaults, isolated HEC tasks, required handlers/templates/README, removal of admin-password output and only necessary legacy-index integration. Preserve shared namespace/metadata identity; unrelated license lifecycle and whole-role convergence are out of scope.
- Scoped documentation/static verification artifacts only where the controller approves their location. This design phase writes this document only.

Excluded: `role_gpo_deploy`, `role_k8s_telemetry_collection`, `role_splunk_hec_validate`, all four `role_splunk_collector_*`, `splunk_forwarder`, existing sources/blueprints/range configuration, `.opencode/skills/range-config/SKILL.md`, and untracked `blueprints/detection-engineering/`. No package/source registration, source identity rewrite, commit or installed-role assumption follows from this design.

1. **Resolve source-research gates:** independently verify immutable chart/package/tool/image artifacts, exact schema/components, package service scripts/OS support and Helm diff behavior; verify selected Splunk HEC stanza specification/precedence, enrollment flag mapping and complete advanced-audit protocol. Record provenance in one concise dependency manifest. Unknown support is not claimed. Controller reviews these artifacts; live evidence later gates readiness, not code implementation.
2. **HEC extension:** owned app/index/token contract, true change detection, restart ordering, effective config and optional authenticated test. Review shared input/output shapes and ownership before any parallel implementation.
3. **Container collectors:** Docker mode and Kubernetes mode against the approved transport contract; include ownership preflight and strict runtime boundary. They may be implemented independently only after interfaces are agreed. This document does not authorize agents or live actions.
4. **Readable Windows policies:** registry/settings/link ownership first; bounded audit publication helper with explicit partial-failure handling. Do not advertise logging parity until audit delivery is verified on a real client.
5. **Review/static acceptance:** controller reviews scoped diff and evidence, then obtains separate live authorization if desired. Document migration prerequisites and unresolved readiness. Collector comparison remains a report, not a fourth implementation stream.

## 8. Verification and acceptance

### Static evidence required

- YAML/Ansible syntax and scoped lint, Jinja parsing/rendering, PowerShell parser checks, metadata/default/README consistency and namespaced variable coverage. No fake AD/Helm/Splunk service standing in for runtime verification.
- Verify chart/package digests against recorded artifacts; render the **pinned** chart and inspect actual pipelines, mounts, images, hooks, RBAC and secrets. Review package scripts without executing archive contents during research. Verify actual filelog/exporter/storage components in the selected distribution's pinned manifest. Reject unpinned implicit dependencies.
- Check advanced-audit CSV encoding/grammar/GUIDs and code paths against MS-GPAC/MS-GPOL; confirm serialized native/audit updates, durable pre-mutation pending state, fail-closed recovery, version halves, extension preservation and no writes on unchanged/check-mode paths. Static review cannot establish client application/replication.
- Inspect every changed failure path, secret-bearing output and owned-file write. Demonstrate that collector tasks have no container runtime package/service/config mutation, cluster creation, test pod creation, audit enablement, or Helm uninstall.
- Record source tree/artifact hashes, scoped diff, exact commands/tool versions/results and reused evidence provenance. Reuse only while relevant artifacts/dependencies are unchanged. Static results alone do not establish selected-version compatibility or readiness.

### Live acceptance, only after separate authorization

| Scope | Required real-system evidence |
| --- | --- |
| HEC subflow only | Fresh enablement over vendor defaults, unchanged HEC rerun without HEC-triggered restart, owned config update, compatible shared globals, winning/shadowed administrator conflicts and partial-failure handling; effective token/index/listener settings, preserved unrelated config, wrong token/index/TLS failures; HTTP 200 + HEC code 0 after handler flush. Search separately establishes event/index identity; this does not establish whole-server/license convergence |
| Docker | Real existing json-file workload, fresh install, second run with no restart, actual parsed log delivery/index identity, rotation and collector restart with persistent offsets, HEC outage/recovery and bounded-state behavior; unsupported driver/unreadable path/ownership collision failures. Prove runtime config/package/service state unchanged |
| Kubernetes | Existing supported cluster/context; correct selected nodes, rendered/applied logs-only pipeline, existing-Secret and role-created-Secret paths, actual source event delivery, second run with no Helm revision change, managed drift reconciliation, credential/TLS/namespace/ownership/pending-release failures; persistent offsets through collector rollout. Prove no runtime/cluster/audit mutation |
| Windows | Fresh creation with explicit links; actual client application and `auditpol` subcategories, PowerShell events/transcripts, AD enrollment/issuance separately; unchanged rerun with no version increment. Verify actual session LDAP/SMB access/second hop, state loss/transfer failure, unmanaged collisions, missing rights and malformed CSV. Interrupt after CSV publication but before either version update: rerun must fail on pending even with matching old AD/GPT versions; verify scoped recovery and serialized registry/audit changes. Preserve unrelated settings/links. Defender opt-in/retirement and effective endpoint state are separate observations |

Use authorized existing workload events or separately approved test event generation; installing collectors is not authorization to create workloads or force endpoint refresh. Failures before/after mutation must report actual resource/service/credential/marker disposition; no manufactured success receipts. For any claimed sanitization, send representative canary-bearing events through production processing and inspect output; configuration alone proves nothing. This design makes no sanitization claim.

**Current disposition:** static source/archive inspection and primary-document research only; no implementation checks, live operations, deployment, AD writes, archive execution or endpoint probes. Reused archive/collector evidence is identified in section 6 and its report; newly researched facts are cited below. Exact artifact compatibility, audit-helper behavior, enrollment mapping and end-to-end delivery remain unverified. Deployment readiness: **PASS WITH WARNINGS — NOT VERIFIED**. Controller must distinguish static executed, live executed, reused evidence and outstanding gaps in every subsequent review.

## 9. Primary research references

Retrieved/read 2026-10-22 unless the prior evidence report supplies provenance. Mutable-source links establish design possibilities only; they are not immutable artifact verification.

- **M1:** [GroupPolicy cmdlet inventory](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2025-ps), [Set-GPRegistryValue](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpregistryvalue?view=windowsserver2025-ps), [auditpol](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol).
- **M2:** [MS-GPAC audit CSV format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/6494a0f2-8a16-40e2-b87d-328be7d732e0), [GUID rather than display-name semantics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d).
- **M3:** [MS-GPAC extension GUIDs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/ac9c8234-d2e8-455d-be76-f84244dd1e58), [administrative update requirement](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/1efc1e40-1e7e-44fd-87ce-c09627c6c511).
- **M4:** [MS-GPOL extension-update processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/3b027be3-62ac-4b85-9334-37f79c83bfea), [LDAP update message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/5dacf4c4-07aa-4870-a7ee-1306b58392e1), [extension-update task](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/325337d8-d567-462c-80fa-18e30d8f9e87).
- **M5:** [Computer/user version increment](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/70fd86b1-926a-4dcf-9ce7-6f9d2149c20d), [GPT.INI version halves](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/59bb540a-64f4-4c52-9c55-5ca2fd2c0270).
- **M6:** [MS-GPAC client application](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/eda6a094-5d0a-4516-a3ab-7ee2d38b12b6), [IGroupPolicyObject::Save scope](https://learn.microsoft.com/en-us/windows/win32/api/gpedit/nf-gpedit-igrouppolicyobject-save).
- **M7:** [Domain discovery](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomain?view=windowsserver2025-ps), [native certificate auto-enrollment configuration/prerequisites](https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-server-certificate-auto-enrollment), [local certificate policy cmdlet](https://learn.microsoft.com/en-us/powershell/module/pki/set-certificateautoenrollmentpolicy?view=windowsserver2025-ps).
- **M8:** [Tamper-protection caveat](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview); additional Defender and archive/import references are in the inspection report.
- **S1:** Official chart mutable [Chart.yaml](https://raw.githubusercontent.com/signalfx/splunk-otel-collector-chart/main/helm-charts/splunk-otel-collector/Chart.yaml), [values.yaml](https://raw.githubusercontent.com/signalfx/splunk-otel-collector-chart/main/helm-charts/splunk-otel-collector/values.yaml), [advanced configuration / existing Secret](https://raw.githubusercontent.com/signalfx/splunk-otel-collector-chart/main/docs/advanced-configuration.md). Candidate 0.163.0 still requires exact released-artifact verification.
- **S2:** [Upstream filelog receiver configuration, offset persistence and retry limitations](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/receiver/filelogreceiver/README.md). Mutable main includes features newer than a selected vendor release; use only capabilities verified in the pinned distribution.
- **S3:** [Vendor Linux manual-install source pointer](https://github.com/signalfx/splunk-otel-collector/blob/main/docs/getting-started/linux-manual.md); its linked Splunk documentation returned HTTP 403 during this research. Consequently package/OS capability verification is explicitly outstanding, not inferred from old role metadata.
- **L1:** [Official Ludus role structure/provided variables](https://docs.ludus.cloud/docs/developers/ansible-roles), as verified in the inspection report. Proposed names/ownership/defaults here are repository design choices, not claims of Ludus-enforced behavior.
