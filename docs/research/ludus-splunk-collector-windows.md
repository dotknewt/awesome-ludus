# Research: Windows Splunk collector

## Scope

This note supports extending `ludus_splunk_collector` to Windows 11 x64 and Server 2019/2022/2025 x64. Windows 10 and Server 2012–2016 are deferred after compatibility review. The existing Debian 13 receiver, Linux collector behavior, and `ludus_install_sysmon` remain unchanged.

## Legacy evidence

The legacy role `role_splunk_collector_win11v` and its blueprint are references, not migration targets. Safe ZIP inspection used `/tmp/opencode/splunkappswin11v.zip` (no execution/extraction): source URL `https://github.com/Antonlovesdnb/ConstructingDefense/raw/refs/heads/main/splunkappswin11v.zip`; repo HEAD `0cefe62755eebba7b226e611ece75160706e22f6`; blob `0d4a9cd8d6e071d2ecbc42264689b4f8e45ba673`; SHA256 `5ae6b8741e91211b80e386d3cf97e8f3f4a19b360bc0960444906c4b9004cea2`.

The Security local input uses XML rendering, `oldest`, `current_only=0`, index `winlogs`, and effective blacklists `blacklist1 = $XmlRegex="<EventID>5145<\/EventID>.*<Data Name='ShareName'>\W\W\W\WC\W"` plus inherited `blacklist2 = EventCode="566" Message="Object Type:(?!\s*groupPolicyContainer)"`. The local ADMIN$ blacklist2 line is commented and must remain inactive; the overridden default EventCode4662 blacklist1 must not be restored. Sysmon reads channel `Microsoft-Windows-Sysmon/Operational`, sets source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, and uses index `sysmon` with no extra event filters. SilkService-Log is `[WinEventLog://SilkService-Log]`, `disabled=0`, `index=etw`, `sourcetype=json`. Collection must not install/start/configure SilkService or alter producer/audit policy; an absent channel is a producer prerequisite, not something the collector creates. No `outputs.conf` was found. These observations are design evidence, not proof of current Splunk compatibility.

## Compatibility and installer gaps

The current Sysmon page lists Windows 11+ and Server 2019+, but is rolling and not version-specific proof. Splunk 9.2 documents removal of Server 2012/R2; Splunk 9.1 was the last documented line, and full support ended 2025-06-28 (P3 through 2028). The modern 10.0 requirements page has a search excerpt mentioning 2025 Universal Forwarder, but the exact 10.6.1.1 OS table was unavailable.

Existing Linux/server artifacts pin 10.6.1.1. The design may aim at the same Windows version, but implementation must not default it until a publisher-verified Windows MSI URL, version, and checksum are recorded. Exact MSI bootstrap and service-account properties are not established; direct help pages returned 403. Do not fabricate them or use an insecure generic fallback. If primary documentation cannot establish a safe route, stop at the research gate.

References: [modern requirements](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.0/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises), [9.2 removals](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/9.2/deprecated-features/deprecated-and-removed-in-version-9.2), [support policy](https://www.splunk.com/en_us/legal/splunk-software-support-policy.html), [forwarder/indexer compatibility](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/compatibility-matrix/splunk-products-version-compatibility/compatibility-between-forwarders-and-splunk-enterprise-indexers).

## Implementation research gates

Confirm supported Windows collections, Ansible and PowerShell prerequisites, a documented service account/bootstrap design, safe paths and ACLs, and artifact verification. Use [win_package](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_package_module.html) and [win_service](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_service_module.html) only after selected-version behavior is confirmed. No automatic reboot, upgrade, or password rotation.

The collector should render separate Security (`winlogs`), Sysmon (`sysmon`), and SilkService-Log (`etw`) inputs. Optional Splunk TAs are not collection prerequisites and are outside scope; raw XML/indexes do not promise CIM dashboards. Server index management is append-only: `[]` is a no-op only when never managed; after opt-in, removal fails. Matching the reference exclusions is a static configuration target, not proof of rendered-XML filtering; later native canary/event testing must verify both exclusions.

## Verification status

Static repository and Ansible validation are the next evidence. No simulated runtime tests and no live actions are authorized. Later native authorization must independently verify fresh installation, convergence without restart, configuration-change restart, Security/Sysmon/SilkService-Log arrival in `winlogs`/`sysmon`/`etw`, both Security exclusions with canary events, absent-channel behavior, service identity/access, conflict and credential failures, and unrelated-data preservation.
