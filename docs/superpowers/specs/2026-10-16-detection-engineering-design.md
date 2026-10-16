# Detection Engineering Range Design

**Status:** Design only; implementation is not authorized by this document.
**Date:** 2026-10-16

## Purpose and scope

This document describes an infrastructure-only Ludus blueprint for a detection-engineering lab. GitLab is the lab's telemetry source: its users, access, and interactions can generate events to investigate. GitLab is **not** the detection CI platform. The first version establishes services, collection, and a place to examine telemetry; it does not deliver a build/deploy exercise or an application under test.

The design is based on confirmed user requirements. The sections below distinguish those decisions from builder choices and facts that still need verification. It is not evidence that the range has been deployed or that the integrations work.

## Confirmed user decisions and boundaries

- The range has five separate VMs: GitLab CE (8 GB RAM, 4 vCPU), a GitLab Runner (8 GB, 4 vCPU), Malcolm for PCAP analysis (64 GB, 8 vCPU), dedicated Linux Splunk (12 GB, 4 vCPU), and a single-node Minikube workload host using Docker (16 GB, 6 vCPU).
- The VMs total **108 GB RAM and 26 vCPU**. The host has 128 GB RAM; plan for 20 GB nominal headroom for the host and router, with no other ranges running. CPU capacity on the intended host is not verified. Existing template disk sizes are inherited, not validated; do not imply they are sufficient. Capacity caps, retention tuning, and disk sizing are deferred. Vendor defaults remain in place, so disk exhaustion is a known operational risk.
- V1 starts Minikube and Docker and enables logging. The runner is installed, automatically registered, and paused. It accepts no jobs. No sample build/deploy pipeline, registry setup, app interactions, or active executor are in V1. Minimal executor metadata may be needed to register a runner; that is a builder implementation choice, not permission to unpause it or enable job execution. Build/deploy and clustering are V2.
- GitLab, Splunk, and runtime tokens are bootstrapped automatically using fixed, documented lab credentials. This does not mean every token is fixed: scoped runtime tokens may be generated as needed. Do not print secrets in logs. All fixed lab credentials are for isolated lab use and must never be used in production.
- Interfaces are lab/VPN-only, with no public ingress. Outbound internet access for installation is allowed. The runner gets no privileged host access. Existing transport defaults may use HTTP/plaintext; no new CA is required. Document this risk. Do not disable firewalls globally.
- Logging is required on GitLab, runner, Splunk, and the Minikube/Docker host. Malcolm is the packet-analysis platform and is not included in the four-VM host-log baseline.
- The acceptance criteria in this document are required. A static/schema check alone is not acceptance, and no live deployment or access to the target Ludus server has yet been established.

## Topology and workload

| VM | V1 role | RAM / vCPU | V1 behavior |
|---|---|---:|---|
| GitLab CE | Source of user, access, and application telemetry | 8 GB / 4 | GitLab CE available on lab/VPN interfaces; actual CE event and audit coverage must be checked. |
| GitLab Runner | Registered runner identity and service telemetry | 8 GB / 4 | Installed and registered automatically, then left paused; no jobs run. |
| Malcolm | PCAP analysis | 64 GB / 8 | Adapt the existing Malcolm VM definition from `blueprints/constructing-defense/range-config.yml`. |
| Linux Splunk | Dedicated single-node event search | 12 GB / 4 | Receives the selected lab telemetry; also retains its own OS and internal service logs locally. |
| Minikube/Docker | Single-node Kubernetes and workload telemetry | 16 GB / 6 | Docker installed; Minikube running; Kubernetes audit policy is metadata-only. |

These are separate machines; do not consolidate roles to address resource pressure. Range names and VM names must be range-scoped to avoid collisions. Actual template disk capacities, storage availability, and CPU headroom are unresolved and must be checked before deployment.

### V1 exclusions

V1 does not run CI jobs, create a registry, build or deploy an application, simulate GitLab interactions, or enable the runner executor. It runs a single-node Minikube cluster but does not implement multi-node clustering. V2 may add build/deploy behavior and multi-node clustering, but those changes require a separate design and authorization. Do not alter `constructing-defense` behavior through shared-role changes without regression evidence for that blueprint.

## Logging coverage and acceptance

Logging should be sufficient to exercise detection engineering without collecting every possible log or CI job body. Select appropriate indexes, sourcetypes, and host identities as builder choices. Map each source to the correct machine identity; do not use one generic host identity for the whole lab.

| Source | Required V1 coverage | Notes / boundary |
|---|---|---|
| GitLab VM | OS authentication, sudo, service/system logs, audit and process telemetry; relevant GitLab access and application events | Confirm which access, application, and audit events are available in the installed CE edition/version. Do not promise paid-tier audit features. Collect only appropriate, useful events. |
| Runner VM | OS authentication, sudo, service/system logs, audit and process telemetry; runner service and registration metadata | No job logs in V1 because no jobs execute. Do not expose registration credentials or tokens. |
| Minikube/Docker VM | OS authentication, sudo, service/system logs, audit and process telemetry; Docker daemon and container logs; Kubernetes audit, node, and container telemetry | Kubernetes audit is metadata-only. An existing richer audit policy must be changed for this range. Avoid indiscriminate collection of workload bodies. |
| Splunk VM | OS authentication, sudo, service/system logs, audit and process telemetry; Splunk internal/service logs | Keep local ingestion for Splunk's own logs; do not send them back through an unnecessary loop. |
| Malcolm VM | PCAP analysis through the existing Malcolm deployment | Packet capture visibility is established separately via the host bridge procedure, not by assuming same-VLAN placement is enough. |

Acceptance requires representative events from **each of the four non-Malcolm VMs** and from each required log class to be searchable in Splunk, with correct source and host identity. The collector and search should make the source and class evident. Kubernetes audit records must demonstrate metadata-only coverage, not request or response bodies. A missing CE event class must be reported as a gap rather than represented as available.

Do not collect every log by default, CI bodies, or secrets. Define a practical event selection and mapping appropriate to the use case; index names, sourcetypes, and exact host naming are builder choices. No retention or storage-capacity promise is made in V1.

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
- `role_k8s_telemetry_collection` starts the cluster, installs OTEL, and currently has a hardcoded Debian user and a richer Kubernetes audit policy. Adapt those behaviors for this range: remove the user assumption and enforce metadata-only audit. Validate least privilege and repeat-deploy convergence.
- `role_linux_logging` is an existing Linux logging candidate, but the existing Linux Splunk collector covers only `/var/log/laurel/audit.log` and destination `dc:9997`; that is insufficient for this design. Extend/adapt the collection approach to the required sources and dedicated Linux Splunk destination.
- `role_splunk_install` is a Windows MSI installation role that directly downloads Splunk 9.3.2 and accepts the EULA. It does not demonstrate a Free-license switch or sustainable licensing.
- The Windows-only `ludus_splunk_universalforwarder` companion is not a Linux forwarder solution.
- `ludus_splunk` at `https://github.com/curi0usJack/ludus_splunk` is a suitable candidate for a pinned/adapted Linux installation, subject to reviewing its exact behavior, version, and licensing/download requirements. Do not add unrelated Splunk applications.

Keep range-specific changes isolated where possible. Changes to shared roles must not alter `constructing-defense` behavior without regression evidence. Pin role and product versions where the repository and Ludus support it; exact compatible versions and Linux templates are builder choices subject to repository conventions and factual validation.

## Splunk licensing and installation gate

The preferred outcome is no recurring registration or developer renewal requirement and a sustainable lab deployment. A clearly labeled, expiring Splunk Enterprise trial is acceptable temporarily, but is not a sustainable final answer. Do not silently reset trials or imply that trial renewal is automated or supported. Document the expiry behavior and any feature limitations.

Before selecting the installer, verify the exact Linux installer version, download URL, account/authentication requirement, and license behavior. Do not claim Free-mode support, its limits, or HEC support unless verified against the chosen version and role. Support for a user-supplied license is an optional builder choice, not a mandatory user requirement. If there is no verified sustainable mode, record the limitation and the temporary-trial decision explicitly instead of fabricating a licensing solution.

## Deployment and validation criteria

The required live acceptance run must establish all of the following:

1. The range deploys with all five VMs and services ready at the specified resource assignments, subject to confirmed host capacity. GitLab CE, Docker, Minikube, Splunk, and Malcolm start successfully.
2. The runner is automatically registered and demonstrably paused, with no jobs executed and no privileged host access.
3. Representative events from every required log class on GitLab, runner, Splunk, and Minikube/Docker are searchable in Splunk and show the correct host and source. Document any GitLab CE audit/access coverage gap.
4. Kubernetes audit output is metadata-only; richer request/response bodies are not collected.
5. After the separate manual host bridge configuration, Malcolm demonstrably receives actual packets. Same-VLAN membership alone does not satisfy this criterion.
6. The range recovers after reboot and a repeated deployment converges without duplicate, broken, or unsafe configuration. Validate Docker group readiness in the first deployment path.

Static YAML/schema and role syntax checks are necessary, but not sufficient; they cannot substitute for live-service, searchable-event, capture, reboot, and repeat-deploy evidence. Report unavailable user/server access, templates, roles, CPU/disk resources, outbound access, bridge setup, and Splunk download/licensing access as external prerequisites. Never report those checks as passed without evidence.

## Builder choices, unresolved facts, and deferred work

**Builder choices (not user-approved fixed values):** range name (suggested `detection-engineering`), range-scoped VM/host naming, compatible Linux templates based on repository practice, IP assignments, pinned product/role versions, exact index and sourcetype names, host identity convention, and implementation details for scoped generated runtime tokens. Keep them consistent with the repository's actual Ludus range schema and naming patterns. In particular, do not blindly use `linux: true` if the repository's schema and examples require the `linux.packages` mapping; validate the real schema.

**Unresolved factual gates:** target-server access and available host CPU; actual inherited template disk sizes and free storage; Linux role and installer compatibility; CE-specific event availability; Docker group propagation behavior; exact Splunk Linux installer download/account requirements and sustainable license options; and proof that the separately configured bridge presents packets to Malcolm. Resolve or clearly report each gate during implementation and live acceptance.

**Deferred:** disk caps, disk sizing, retention policy tuning, application interactions, sample build/deploy pipeline, registry, runner activation, and multi-node clustering. Keep vendor defaults until separately authorized, and retain the disk-full risk statement.

## Authorization boundary

This is a design document only. It does not authorize changes to range files, roles, templates, firewall policy, or shared blueprint behavior. A builder may propose implementation details for review, but implementation requires separate authorization. A fresh builder review was completed; its remaining questions concern the documented temporary-trial allowance, builder-owned version selection, and factual deployment prerequisites. These remain checks for planning and deployment, not claims of live validation.
