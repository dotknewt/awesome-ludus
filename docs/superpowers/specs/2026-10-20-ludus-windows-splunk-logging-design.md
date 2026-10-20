# Windows Splunk logging extension design

## Status and decisions

This is a design and research gate, not an implementation or deployment approval.

**User decisions:** add Windows collector support using the logging configured by `ludus_install_sysmon`; include Windows Security events and the legacy SilkService-Log input; use the legacy `role_splunk_collector_win11v` as a reference; prioritize modern Windows and defer legacy support; use separate `winlogs`, `sysmon`, and `etw` indexes and extend the server role to create configured indexes.

**Proposed assistant defaults (not approvals):** extend `ludus_splunk_collector` rather than create a new role; target Windows 11 x64 and Server 2019/2022/2025 x64; preserve Linux behavior and the Debian 13 server scope; leave `ludus_install_sysmon` unchanged; XML inputs; Security history `oldest` with `current_only = 0` and the effective legacy exclusions below; Sysmon role-owned filters; collect (but do not install, start, configure, or alter policy for) SilkService-Log; no unrelated TA scripts, firewall changes, or TLS work; standalone illustrative integration rather than migrate the legacy roles/blueprint. The selected Windows artifact, service account/bootstrap method, and checksum must be established from primary sources before implementation. No invented MSI properties or fallback installer path.

## Goals and non-goals

Goals are a reusable, platform-dispatched collector with explicit Windows inputs, safe ownership, validated artifacts, idempotent convergence, and config-only restart behavior. Installation and configuration must fail before mutation when the platform, version, checksum, path, ACL, or existing ownership is incompatible. Windows collection prerequisites and supported Ansible/PowerShell versions must be explicit; no automatic reboot, upgrade, or password rotation.

Non-goals are changing Linux behavior, expanding server OS support, migrating the legacy blueprint, implementing optional Splunk TAs/CIM normalization, inventing TLS, or adding hidden Sysmon sibling-role execution. Raw XML plus indexes does not guarantee CIM dashboards.

## Contract and ownership

The collector dispatches by platform; existing Linux tasks are confined to Linux, while Windows receives separately named Security, Sysmon, and SilkService-Log inputs plus shared receiver/license/admin inputs. Inputs use role-prefixed variables, bounded identifiers, documented Windows paths, and explicit URL/version/checksum values. Installed identities and role names must be verified rather than inferred from source directories; examples must show explicit source/role ordering and `depends_on` (`vm_name` and `role`) where applicable.

The Security contract is XML/history/index `winlogs` with exactly these effective exclusions: `blacklist1 = $XmlRegex="<EventID>5145<\/EventID>.*<Data Name='ShareName'>\W\W\W\WC\W"`; inherited `blacklist2 = EventCode="566" Message="Object Type:(?!\s*groupPolicyContainer)"`. The legacy local `blacklist2` ADMIN$ line remains commented and must not be activated; the overridden inherited default `blacklist1` EventCode4662 must not be accidentally restored. Matching this intended reference configuration is only a static config target, not proof that rendered XML filtering works; native canary/event testing is required later.

SilkService-Log is `[WinEventLog://SilkService-Log]`, `disabled=0`, `index=etw`, `sourcetype=json`. This is collection only: the collector must not install, start, configure, or alter SilkService or its producer/audit policy, must not add XML-specific Security flags, and must not promise data when the channel is absent. Channel availability is a producer prerequisite; the collector must not create it.

The collector owns its app/configuration and safe Windows paths/ACLs. `ludus_install_sysmon` owns Sysmon installation and filtering. Do not duplicate filters or execute an implicit sibling role. The server index role owns a separate app and accepts `ludus_splunk_server_indexes: []` for backward compatibility. `[]` on a never-managed server is a true no-op. Once managed, removal (including changing to `[]`) fails; definitions are append-only and never silently drop data, retention, or indexes. Reject unmanaged conflicting definitions, reparse points/symlinks, injection, and unbounded identifiers.

Illustrative contract:

```yaml
ludus_splunk_server_indexes: [winlogs, sysmon, etw]
# Windows collector: Security -> winlogs; Sysmon -> sysmon; SilkService-Log -> etw
```

The server remains Debian 13. No server OS expansion is in scope.

Additional assistant decisions after builder review:

- Prefer the vendor-supported virtual service account with explicitly verified Security/Sysmon read access. Do not silently fall back to LocalSystem or introduce a managed-account/password lifecycle. If primary sources cannot establish this route, stop and present the alternative for approval.
- Prefer the existing 10.6.1.1 release only if its Windows artifact and target support can be established. A separately pinned Windows release is acceptable if official evidence covers the full modern target set and receiver compatibility. Do not silently drop a target or advertise unsupported combinations; unresolved compatibility blocks the affected implementation and is reported for a decision.
- Support fresh installation and convergence of an installation owned by this role. Reject existing unmanaged installations, even at the desired version; automatic adoption/migration is out of scope. Use an explicit ownership marker and inspect service path, identity, version, and managed configuration rather than trusting the marker alone.

## Lifecycle and failure expectations

Fresh install validates platform and artifact, creates only owned paths/service configuration, configures inputs, and starts the service with the selected documented identity. A converged rerun is idempotent and does not restart for unchanged configuration. A configuration change restarts only when rendered managed configuration changes. Conflicting versions, checksums, unmanaged files, unsafe paths/ACLs, missing credentials, unsupported collections, or incompatible platforms fail before mutation and preserve unrelated data. Reboots and upgrades are never automatic.

Later authorized native tests must cover fresh install, no-op rerun, config-change restart, Security/Sysmon/SilkService-Log arrival in the correct indexes, both effective Security exclusions (including canary events), absent-channel behavior, service identity/access, version conflicts, credential failures, and preservation of unrelated data. Live tests are **not authorized now**.

## Evidence and verification plan

Static-only work now: review role metadata/tasks/templates/defaults, run repository Ansible validation for the selected roles/dependencies, and add static tests for dispatch, ownership, append-only indexes, validation, and restart conditions. Do not add simulations, stateful fakes, or runtime mocks. Static results do not establish native compatibility or deployment readiness.

Evidence to preserve: legacy ZIP URL `https://github.com/Antonlovesdnb/ConstructingDefense/raw/refs/heads/main/splunkappswin11v.zip`, repository HEAD `0cefe62755eebba7b226e611ece75160706e22f6`, blob `0d4a9cd8d6e071d2ecbc42264689b4f8e45ba673`, SHA256 `5ae6b8741e91211b80e386d3cf97e8f3f4a19b360bc0960444906c4b9004cea2` at `/tmp/opencode/splunkappswin11v.zip`. Safe ZIP reading found local Security XML (`oldest`, `current_only=0`, effective blacklist1 `$XmlRegex="<EventID>5145<\/EventID>.*<Data Name='ShareName'>\W\W\W\WC\W"`; inherited blacklist2 `EventCode="566" Message="Object Type:(?!\s*groupPolicyContainer)"`; commented local ADMIN$ blacklist and overridden EventCode4662 default not activated), Sysmon exact `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` to `sysmon`, and SilkService-Log ETW/JSON to `etw`; no `outputs.conf` was present.

Primary references: [Ansible win_package](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_package_module.html), [win_service](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_service_module.html), [Ludus configuration](https://docs.ludus.cloud/docs/configuration), [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Splunk 9.2 removals](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/9.2/deprecated-features/deprecated-and-removed-in-version-9.2), [support policy](https://www.splunk.com/en_us/legal/splunk-software-support-policy.html), [forwarder compatibility](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/compatibility-matrix/splunk-products-version-compatibility/compatibility-between-forwarders-and-splunk-enterprise-indexers).

Known gaps: the rolling Sysmon page is not version-specific proof; exact Windows Splunk 10.6.1.1 MSI URL/checksum and MSI bootstrap/service properties remain unverified (direct help pages returned 403); selected-version service-account/bootstrap design is mandatory research. Splunk 9.2 removed Server 2012/R2 and 9.1 was the last documented line; older targets remain deferred and unverified. Compatibility claims are not native evidence.

## Tracked plan

- [ ] Research primary-source Windows artifact, checksum, service identity, bootstrap, and supported collections.
- [x] Review this contract and legacy evidence; resolve ownership and failure semantics.
- [x] Parent reads this design and the research note; fresh builder-review agent checks it.
- [ ] Obtain explicit approval, then implement only the scoped roles/tasks/tests/docs.
- [ ] Run static repository/Ansible validation and report gaps separately.
- [ ] Request separate authorization for native live lifecycle and ingestion tests; none is granted here.
