# Detection Engineering Range Design

**Status:** Design only; implementation is not authorized by this document.
**Date:** 2026-10-16; V1 forwarding scope amended 2026-10-17

> **2026-10-18 validation-lifecycle supersession:** Initial provisioning uses
> the reviewed selected-product static contract plus genuine target/template,
> capacity, role-content, network, identity, and protected inputs. Static
> readiness routes, Runner jobs routes, and forwarder bootstrap shapes are
> contracts—not claims that guests are ready, job-free, started, or accepted.
> Guest installation/bootstrap/readiness checks occur during provisioning;
> external APIs, paused/zero-job state, telemetry/packet delivery, cleanup, and
> final service state are post-provisioning acceptance. Missing runtime evidence
> cannot block creation of a `NEVER_DEPLOYED` range or be labeled verified.

> **2026-10-19 operator-policy supersession:** The user explicitly waived
> installed role-version and role-content comparison as a provisioning gate.
> Required role and collection names remain dependency contracts, but contents
> stay `USER_WAIVED_NOT_VERIFIED`; no verified-content claim is made. GitLab's
> package-generated `/etc/gitlab/initial_root_password` is preserved: the role
> must not reset, delete, copy, or expose it. Protected application defaults are
> limited to Splunk admin and Malcolm admin credentials; Runner and HEC tokens
> remain role-owned lifecycles.

> **2026-10-18 firewall scope supersession:** Guest OS and guest Docker
> firewall rules are outside the detection-engineering V1 scope. Historical
> guest-firewall wiring, variables, ingress/probe inputs, isolation claims, and
> allow/deny acceptance requirements below are superseded and are not active
> requirements. Preserve Ludus/host networking, VLAN 10, host bridge `vmbr3`,
> user-managed promiscuous mode, service endpoint configuration, and Malcolm's
> automatic guest capture-interface discovery. The standalone
> `ludus_detection_guest_firewall` role is retained for possible other consumers
> but is not wired by this blueprint.

> **2026-10-17 user supersession:** V1 forwards only the common Linux host
> sources from GitLab, runner, and workload hosts, plus the explicit
> runner-registration record from the runner. GitLab access/application/audit
> forwarding, runner-service forwarding, and Docker-daemon forwarding are not
> optional V1 features: they are outside V1. Their producer formats, adapters,
> capability gates, searches, and acceptance obligations are removed. This does
> not remove Splunk local collection, host/container/Kubernetes OpenTelemetry,
> or the paused-runner bootstrap and security lifecycle. A future V2 may revisit
> service-specific forwarding only under a separate design and authorization;
> this document creates no V2 backlog commitment.

> **2026-10-17 Laurel baseline supersession:** Common host audit telemetry uses
> the existing ConstructingDefense architecture—native auditd to Laurel JSONL at
> `/var/log/laurel/audit.log`—adapted only in private detection-engineering
> roles. The original `role_linux_logging`, `role_splunk_collector_linuxv`,
> `role_k8s_telemetry_collection`, and ConstructingDefense blueprint are
> read-only guidance. V1 does not sanitize native audit fields, exclude audit
> record types, or promise credential/argv/environment redaction. This isolated
> threat-hunting lab contains no real or production secrets/data. Routine
> bootstrap credential handling remains protected, and Kubernetes audit remains
> metadata-only as a collection-scope choice.

## Purpose and scope

This document describes an infrastructure-only Ludus blueprint for a detection-engineering lab. GitLab is a lab service and host whose Linux telemetry can be investigated; V1 does not forward GitLab-specific access, application, or audit logs. GitLab is **not** the detection CI platform. The first version establishes services, bounded collection, and a place to examine telemetry; it does not deliver a build/deploy exercise or an application under test.

The design is based on confirmed user requirements. The sections below distinguish those decisions from builder choices and facts that still need verification. It is not evidence that the range has been deployed or that the integrations work.

## Confirmed user decisions and boundaries

- The range has five separate VMs: GitLab CE (8 GB RAM, 4 vCPU), a GitLab Runner (8 GB, 4 vCPU), Malcolm for PCAP analysis (64 GB, 8 vCPU), dedicated Linux Splunk (12 GB, 4 vCPU), and a single-node Minikube workload host using Docker (16 GB, 6 vCPU).
- The VMs total **108 GB RAM and 26 vCPU**. The host has 128 GB RAM; plan for 20 GB nominal headroom for the host and router, with no other ranges running. CPU capacity on the intended host is not verified. Existing template disk sizes are inherited, not validated; do not imply they are sufficient. Capacity caps, retention tuning, and disk sizing are deferred. Vendor defaults remain in place, so disk exhaustion is a known operational risk.
- V1 starts Minikube and Docker and enables logging. The runner is installed, automatically registered, and paused. It accepts no jobs. No sample build/deploy pipeline, registry setup, app interactions, or active executor are in V1. Minimal executor metadata may be needed to register a runner; that is a builder implementation choice, not permission to unpause it or enable job execution. Build/deploy and clustering are V2.
- GitLab, Splunk, and runtime tokens are bootstrapped automatically using fixed, documented lab credentials. This does not mean every token is fixed: scoped runtime tokens may be generated as needed. Do not print secrets in logs. All fixed lab credentials are for isolated lab use and must never be used in production.
- Interfaces are lab/VPN-only, with no public ingress. Outbound internet access for installation is allowed. The runner gets no privileged host access. Existing transport defaults may use HTTP/plaintext; no new CA is required. Document this risk. Do not disable firewalls globally.
- Logging is required on GitLab, runner, Splunk, and the Minikube/Docker host. Malcolm is the packet-analysis platform and is not included in the four-VM host-log baseline. Universal Forwarder V1 profiles are exact: GitLab and workload receive only `/var/log/auth.log`, `/var/log/syslog`, and `/var/log/laurel/audit.log`; runner receives those three plus `/var/log/detection-engineering/runner-registration.jsonl`. Splunk ingests its own Laurel file locally without a Universal Forwarder loop.
- The user accepts V1 starting with the 60-day Splunk Enterprise trial and later choosing either an operator-run uninstall/reinstall path or conversion to perpetual Free licensing. This is the user's confirmed licensing decision, not independent evidence that the candidate package, Free mode, HEC, search, or authentication behavior is compatible.
- Splunk uninstall is operator-triggered only, never automatic at expiry or during ordinary deploy/redeploy. It preserves required indexed data and configuration in place for possible later backup; it does not create a backup, archive, storage target, transfer, reinstall, trial reset, or Free conversion.
- The acceptance criteria in this document are required. A static/schema check alone is not acceptance, and no live deployment or access to the target Ludus server has yet been established.

## Topology and workload

| VM | V1 role | RAM / vCPU | V1 behavior |
|---|---|---:|---|
| GitLab CE | Lab service plus Linux host telemetry | 8 GB / 4 | GitLab CE available on lab/VPN interfaces; V1 does not configure or forward GitLab-specific log formats or files. |
| GitLab Runner | Registered runner identity plus Linux and registration telemetry | 8 GB / 4 | Installed and registered automatically, then left paused; no jobs run and no runner-service stream is forwarded. |
| Malcolm | PCAP analysis | 64 GB / 8 | Adapt the existing Malcolm VM definition from `blueprints/constructing-defense/range-config.yml`. |
| Linux Splunk | Dedicated single-node event search | 12 GB / 4 | Receives the selected lab telemetry; also retains its own OS and internal service logs locally. |
| Minikube/Docker | Single-node Kubernetes and workload telemetry | 16 GB / 6 | Docker installed; Minikube running; Kubernetes audit policy is metadata-only. |

These are separate machines; do not consolidate roles to address resource pressure. Range names and VM names must be range-scoped to avoid collisions. Actual template disk capacities, storage availability, and CPU headroom are unresolved and must be checked before deployment.

### V1 exclusions

V1 does not run CI jobs, create a registry, build or deploy an application, simulate GitLab interactions, enable the runner executor, configure GitLab-specific forwarding, or create runner-service/Docker-daemon forwarding adapters. It runs a single-node Minikube cluster but does not implement multi-node clustering. V2 may add build/deploy behavior, multi-node clustering, or service-specific forwarding, but those changes require a separate design and authorization and are not promised here. Do not alter `constructing-defense` behavior through shared-role changes without regression evidence for that blueprint.

## Logging coverage and acceptance

Logging should be sufficient to exercise detection engineering without collecting every possible log or CI job body. Select appropriate indexes, sourcetypes, and host identities as builder choices. Map each source to the correct machine identity; do not use one generic host identity for the whole lab.

| Source | Required V1 coverage | Notes / boundary |
|---|---|---|
| GitLab VM | OS authentication, sudo, system logs, and native Laurel audit/process telemetry | No GitLab access/application/audit forwarding or GitLab-specific log-format configuration in V1. |
| Runner VM | OS authentication, sudo, system logs, native Laurel audit/process telemetry, and explicit runner-registration metadata | No runner-service or job logs in V1. Routine registration credentials retain their existing protected lifecycle. |
| Minikube/Docker VM | OS authentication, sudo, system logs, native Laurel audit/process telemetry; outer-container logs; Kubernetes audit, node, and container telemetry | No Docker-daemon forwarding in V1. Existing host and in-cluster OTEL scope remains required. Kubernetes audit is metadata-only as a source-scope decision. |
| Splunk VM | OS authentication, sudo, service/system logs, audit and process telemetry; Splunk internal/service logs | Keep local ingestion for Splunk's own logs; do not send them back through an unnecessary loop. |
| Malcolm VM | PCAP analysis through the existing Malcolm deployment | Packet capture visibility is established separately via the host bridge procedure, not by assuming same-VLAN placement is enough. |

Acceptance requires representative events from **each of the four non-Malcolm VMs** and from each in-scope V1 log class to be searchable in Splunk, with correct source and host identity. The runner-registration record is required; GitLab-specific, runner-service, and Docker-daemon classes are not V1 gaps and must not be included in V1 completeness claims. The collector and search should make each retained source and class evident. Kubernetes audit records must demonstrate metadata-only coverage, not request or response bodies.

Do not collect every log by default or CI bodies. Native Laurel audit content,
including command arguments and configured environment fields, is intentionally
preserved; telemetry redaction, secret-canary absence, and sanitized-output
guarantees are not V1 goals or acceptance blockers. This does not authorize new
secret-dumping behavior or weaken routine bootstrap credential handling. No
retention or storage-capacity promise is made in V1.

## Bootstrap, identity, and credentials

The builder should make GitLab, Splunk, and runtime integrations ready without requiring manual secret creation for ordinary deployment. Use documented fixed lab credentials for the agreed bootstrap accounts and document where operators retrieve them. Runtime integrations should use scoped credentials and may generate distinct tokens as necessary; do not force all services to share a token merely for convenience. Do not log credentials, token values, or secret-bearing command output.

The runner must be registered automatically and left paused after deployment. If the registration API requires executor metadata, supply only the minimum registration fields and keep job execution disabled. Verify its paused state and prove that no job ran. No runner privilege escalation or host socket access is permitted. Fixed lab credentials and plaintext transport are acceptable only within the isolated lab boundary and are not production-safe.

## Network and transport security

Expose services only on lab/VPN interfaces. The range can reach the internet outbound to install packages and products; there must be no public inbound exposure. Retain Ludus and host firewall protections, and express narrowly scoped required traffic rather than globally disabling firewalls. Existing plain HTTP or other plaintext defaults are accepted for this lab, but document that credentials and telemetry may be exposed to observers on the relevant network paths. A new CA or universal TLS redesign is not a V1 requirement.

## Malcolm and packet capture

Use the Malcolm PCAP definition in `blueprints/constructing-defense/range-config.yml` as the starting point and adapt its names to the new range if required. Live capture setup is deliberately separate from the range blueprint. Follow the repository's **Configure the host packet capture bridge** instructions in `README.md`, using `ludus-configure-bridge.yaml` and `ansible/roles/ludus_configure_bridge` on the Ludus/Proxmox host after the range bridge exists. Do not design a new capture bridge in this blueprint.

Acceptance requires demonstrating actual packet visibility in Malcolm after the operator has manually configured the host bridge. Sharing a VLAN, interface, or range is not proof of capture visibility. The bridge setup is an external operational prerequisite and must be reported as such if unavailable.

## Reuse and implementation direction

Existing roles and their limits should guide implementation, but are not proof of suitability without validation:

- `ludus_gitlab_ce` is the starting point for GitLab CE.
- `ludus_install_docker` and `ludus_install_minikube` provide the workload-host tooling. There is a known first-deploy Docker group propagation issue; validate first deployment and subsequent runs rather than assuming Docker access is ready immediately.
- `role_k8s_telemetry_collection` is read-only guidance for the private workload role. Adapt its architecture without modifying it: remove the user assumption, keep the already-approved host and cluster OTEL ownership, deliver credentials without Helm argv or summaries, and enforce metadata-only Kubernetes audit.
- `role_linux_logging`, `role_splunk_collector_linuxv`, and the ConstructingDefense auditd/Laurel setup are read-only guidance for private detection-engineering roles. Vendor the reviewed versioned Laurel configuration and plugin mechanics idempotently rather than executing the floating TLS-verification-disabled script. Configure native `read-users` only after the actual reader account exists (`splunkfwd` on UF hosts and the existing Splunk account locally), and reuse native size `5000000`/generations `10` without adding schedules or tuning.
- `role_splunk_install` is a Windows MSI installation role that directly downloads Splunk 9.3.2 and accepts the EULA. It does not demonstrate a Free-license switch or sustainable licensing.
- The Windows-only `ludus_splunk_universalforwarder` companion is not a Linux forwarder solution.
- `ludus_splunk` at `https://github.com/curi0usJack/ludus_splunk` is a suitable candidate for a pinned/adapted Linux installation, subject to reviewing its exact behavior, version, and licensing/download requirements. Do not add unrelated Splunk applications.

Keep all implementation in private `ludus_detection_*` roles. The original roles and ConstructingDefense configuration must not be modified. Laurel v0.6.3 is only the baseline script's starting version; installation remains blocked until an immutable artifact URL, checksum, layout, and target compatibility are verified rather than fabricated.

## Splunk licensing and installation gate

V1 intentionally begins with the user-approved 60-day Splunk Enterprise trial. Do not block that initial deployment solely because future perpetual Free compatibility is unknown. Do not silently reset or renew the trial, automate reinstall at expiry, or represent user-confirmed terms as independently verified licensing evidence. The later operator choice is either manual uninstall/reinstall or conversion to perpetual Free **after** the exact selected version's Free, HEC, search, and authentication behavior is verified. Neither path promises uninterrupted compatibility.

### User-supplied Splunk 10.6.1.1 candidate URLs

These URLs and version/build (`10.6.1.1` / `b2ae2962645c`) are user-supplied candidates and were not downloaded or independently verified during design. The Debian `.deb` files are the intended all-Linux V1 paths. The `.tgz` is a reference alternative, not an additional install; the Windows MSI is reference-only and outside V1.

| Purpose | V1 status | Candidate URL |
|---|---|---|
| Linux Enterprise Debian amd64 | Intended V1 candidate | https://download.splunk.com/products/splunk/releases/10.6.1.1/linux/splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb |
| Linux Universal Forwarder Debian amd64 | Intended V1 candidate | https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb |
| Linux Universal Forwarder tarball amd64 | Reference alternative only | https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.tgz |
| Windows Universal Forwarder MSI x64 | Reference only; outside V1 | https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi |

Before installation, verify candidate accessibility/account requirements, cryptographic checksums, exact package metadata and maintainer scripts, target OS compatibility, trial behavior, and selected-mode HEC/search/authentication behavior. Do not guess checksums or require the `.tgz`/MSI. Future Free support remains a separate factual gate, not a condition for initial trial deployment.

### Operator-run Enterprise uninstall with in-place preservation

The requested uninstall path is a separately authorized maintenance action, never a normal blueprint side effect or timer. Before enabling it, inspect the pinned `.deb` metadata and maintainer scripts and run a disposable representative preservation test. Prior guidance for Splunk 10.4 says to stop first and that `dpkg -r splunk` removes the package while non-package data/configuration may remain; `dpkg -P` purges and recursive deletion is destructive. The guidance URL is `https://help.splunk.com/en/splunk-enterprise/administer/install-and-upgrade/10.4/uninstall-splunk-enterprise/uninstall-splunk-enterprise`; a controller fetch returned HTTP 403, and the exact 10.6.1.1 package/scripts have not been inspected. This is research guidance, not proof of current package behavior.

Maintenance must identify and stop/disable every discovered Splunk startup path, then verify stopped before package removal. It may use only the validated stopped-state removal action; `/opt/splunk` must remain present. Never purge, explicitly delete files/trees, run autoremove, delete the Splunk account while retained files depend on it, or delete index data, resolved custom/external index paths, local apps/configuration, authentication material, `splunk.secret`, encryption/instance configuration, or other state needed to recover preserved data. Package-manager removal of owned files is acceptable only when prior metadata/script and disposable-fixture evidence proves they are not required retained artifacts; otherwise the action is `BLOCKED`.

One durable, secret-safe maintenance manifest at `/var/lib/detection-engineering/splunk-maintenance-state.json` is the authority for this lifecycle. It retains package provenance, an operation ID, an append-only transition journal, acceptance references, discovered startup paths, resolved required index/config/auth paths, and path existence/type/owner/group/mode plus content fingerprints without secret contents. Path discovery may begin before shutdown, but the authoritative fingerprint baseline is frozen and durably written only after every discovered writer is verified stopped and before `dpkg -r splunk`. The state transitions are `HEALTHY -> PREPARED -> ABSENT`, with `REMOVE_FAILED` when removal fails and `POSTCHECK_FAILED` when package absence or preservation checks fail. Failure retries reuse the original operation ID and stopped-state baseline; they never establish a new baseline. If the package is already absent, only `ABSENT` with matching trusted baseline/provenance is idempotent success; `PREPARED`, `REMOVE_FAILED`, or `POSTCHECK_FAILED` may reach `ABSENT` only by completing postchecks against that same baseline. Absence without this durable evidence is `BLOCKED`/`FAIL`, never fresh success.

While `ABSENT`, Splunk ingestion/search are unavailable; collectors may queue or drop, disk use may grow, and there is no zero-loss promise. The manifest is validation metadata, not a backup: no archive/new storage/transfer is created. The first complete acceptance creates the initial `HEALTHY` manifest; Task 11 cannot run without it. Normal deploy/redeploy refuses every non-`HEALTHY` maintenance state. Separately authorized restoration/reinstall or verified Free conversion may transition only `ABSENT -> RESTORED_PENDING_ACCEPTANCE` after the product is fully configured; restore intent alone cannot claim health. The same explicit restoration authorization may permit the required convergence reapply while already `RESTORED_PENDING_ACCEPTANCE`, but that reapply must be idempotent, retain all baseline/history, and leave the state pending; an ordinary pending-state reapply still refuses. A new, complete live acceptance run may inspect the pending state and transitions it to `HEALTHY` only when every required phase passes, recording the run ID and summary hash in the same manifest. Failed or incomplete acceptance leaves `RESTORED_PENDING_ACCEPTANCE`; history and prior baseline evidence are retained rather than deleted.

## Deployment and validation criteria

The required live acceptance run must establish all of the following:

1. The range deploys with all five VMs and services ready at the specified resource assignments, subject to confirmed host capacity. GitLab CE, Docker, Minikube, Splunk, and Malcolm start successfully.
2. The runner is automatically registered and demonstrably paused, with no jobs executed and no privileged host access.
3. Representative events from every in-scope V1 log class on GitLab, runner, Splunk, and Minikube/Docker are searchable in Splunk and show the correct host and source. This includes native Laurel JSONL at `/var/log/laurel/audit.log`, auth/syslog on all four hosts, explicit runner-registration telemetry, Splunk-local ingestion without a UF loop, and existing OTEL host/container/Kubernetes scope. Native audit arguments/environment are not redaction failures.

Native command arguments/environment are not redaction failures and must not
block V1 acceptance.
4. Kubernetes audit output is metadata-only; richer request/response bodies are not collected.
5. After the separate manual host bridge configuration, Malcolm demonstrably receives actual packets. Same-VLAN membership alone does not satisfy this criterion.
6. The range recovers after reboot and a repeated deployment converges without duplicate, broken, or unsafe configuration. Validate Docker group readiness in the first deployment path.

If the separately authorized uninstall has run, `PREPARED`, `REMOVE_FAILED`, `POSTCHECK_FAILED`, and `ABSENT` cannot satisfy healthy/searchable acceptance. A restored system in `RESTORED_PENDING_ACCEPTANCE` may run the complete acceptance suite but remains non-healthy until that new run passes and records the transition to `HEALTHY`; restore intent, reinstall success, partial evidence, or an older PASS cannot make that transition.

Static YAML/schema and role syntax checks are necessary, but not sufficient; they cannot substitute for live-service, searchable-event, capture, reboot, and repeat-deploy evidence. Report unavailable user/server access, templates, roles, CPU/disk resources, outbound access, bridge setup, and Splunk download/licensing access as external prerequisites. Never report those checks as passed without evidence.

## Builder choices, unresolved facts, and deferred work

**Builder choices (not user-approved fixed values):** range name (suggested `detection-engineering`), range-scoped VM/host naming, compatible Linux templates based on repository practice, IP assignments, pinned product/role versions, exact index and sourcetype names, host identity convention, and implementation details for scoped generated runtime tokens. Keep them consistent with the repository's actual Ludus range schema and naming patterns. In particular, do not blindly use `linux: true` if the repository's schema and examples require the `linux.packages` mapping; validate the real schema.

**Unresolved factual gates:** target-server access and available host CPU; actual inherited template disk sizes and free storage; Laurel immutable artifact URL/checksum/layout and target compatibility; private Linux role compatibility; Docker group propagation behavior; candidate Splunk/forwarder checksums, access/auth requirements, package metadata/scripts and OS compatibility; selected trial HEC/search/auth behavior; exact-version perpetual Free compatibility; preservation behavior of stopped-state package removal; and proof that the separately configured bridge presents packets to Malcolm. Resolve or clearly report each gate during implementation or maintenance acceptance. Removed service-specific forwarding and telemetry redaction do not require V1 factual gates.

**Deferred:** disk caps, disk sizing, retention policy tuning, application interactions, sample build/deploy pipeline, registry, runner activation, multi-node clustering, and any GitLab-specific, runner-service, or Docker-daemon forwarding. Keep vendor defaults until separately authorized, and retain the disk-full risk statement. Deferral is noncommittal and creates no implementation backlog.

## Authorization boundary

This is a design document only. It does not authorize changes to range files, roles, templates, firewall policy, shared blueprint behavior, product installation, uninstall, restoration, or Free conversion. A builder may propose implementation details for review, but implementation and every maintenance execution require separate explicit authorization. User approval of the licensing decision and candidate URLs is not live/package validation.
