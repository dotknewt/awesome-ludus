# Research: Windows Splunk collector

## Scope

This note supports extending `ludus_splunk_collector` to Windows 11 x64 and Server 2019/2022/2025 x64. Windows 10 and Server 2012–2016 are deferred after compatibility review. The existing Debian 13 receiver, Linux collector behavior, and `ludus_install_sysmon` remain unchanged.

## Legacy evidence

The legacy role `role_splunk_collector_win11v` and its blueprint are references, not migration targets. Safe ZIP inspection used `/tmp/opencode/splunkappswin11v.zip` (no execution/extraction): source URL `https://github.com/Antonlovesdnb/ConstructingDefense/raw/refs/heads/main/splunkappswin11v.zip`; repo HEAD `0cefe62755eebba7b226e611ece75160706e22f6`; blob `0d4a9cd8d6e071d2ecbc42264689b4f8e45ba673`; SHA256 `5ae6b8741e91211b80e386d3cf97e8f3f4a19b360bc0960444906c4b9004cea2`.

Historically, the Security local input uses XML rendering, `oldest`, `current_only=0`, index `winlogs`; its local `blacklist1` is the 5145 C$ regex while the TA's `blacklist1` is the 4662 filter, so collision/inheritance behavior must be preserved as historical evidence, not copied. The local ADMIN$ `blacklist2` is commented. Sysmon reads channel `Microsoft-Windows-Sysmon/Operational`, sets source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, and uses index `sysmon` with no extra event filters. SilkService-Log is `[WinEventLog://SilkService-Log]`, `disabled=0`, `index=etw`, `sourcetype=json`. Collection must not install/start/configure SilkService or alter producer/audit policy; an absent channel is a producer prerequisite, not something the collector creates. No `outputs.conf` was found. These observations are design evidence, not proof of current Splunk compatibility.

The new desired baseline is zero Security exclusions. Optional, disabled candidates use unique keys: `blacklist1 = EventCode="4662" Message="Object Type:(?!\s*groupPolicyContainer)"`, `blacklist2 = EventCode="566" Message="Object Type:(?!\s*groupPolicyContainer)"`, and `blacklist3 = $XmlRegex="<EventID>5145<\/EventID>.*<Data Name='ShareName'>\W\W\W\WC\W"`. The ADMIN$ candidate remains outside the set. EventCode/Message behavior versus XML matching must be checked before any future application; no filter effectiveness is promised.

## Compatibility and installer gaps

The current Sysmon page lists Windows 11+ and Server 2019+, but is rolling and not version-specific proof. Splunk 9.2 documents removal of Server 2012/R2; Splunk 9.1 was the last documented line, and full support ended 2025-06-28 (P3 through 2028). The modern 10.0 requirements page has a search excerpt mentioning 2025 Universal Forwarder, but the exact 10.6.1.1 OS table was unavailable.

Existing Linux/server artifacts pin 10.6.1.1. The design may aim at the same Windows version, but implementation must not default it until a publisher-verified Windows MSI URL, version, and checksum are recorded. A primary Splunk Cloud Universal Forwarder 10.6 Windows installation page (HTTP 200, scrape ID `01a15855-68e6-728c-9c56-b6fdcc50c4b2`, metadata version `10.6.0`) documents `LAUNCHSPLUNK` (default `1`) and `SERVICESTARTTYPE` (default `auto`). It also states that quiet installation with `/quiet`, without `SPLUNKPASSWORD`/`SPLUNKUSERNAME`, and with `GENRANDOMPASSWORD=0`, installs without a user; a user must then be created through `user-seed.conf`. A safe candidate route is `AGREETOLICENSE=Yes`, `LAUNCHSPLUNK=0`, `GENRANDOMPASSWORD=0`, omit username/password, and create a protected seed before first start. Exact seed syntax and the selected MSI URL/checksum remain unverified.

The same source recommends a least-privileged virtual service account in EventLogReaders; `SeSecurityPrivilege` can modify/delete the Security log and is not an automatic substitute. Its domain-controller exception requires separate verification: do not assume a Server OS is not a DC, grant unsupported domain roles, or fall back to LocalSystem. Task 0 must verify a DC-safe least-privilege read route or record an explicit blocker/approval.

Source: [Splunk Windows Universal Forwarder installation](https://help.splunk.com/en/splunk-cloud-platform/forward-and-process-data/universal-forwarder-manual/10.6/install-the-universal-forwarder/install-a-windows-universal-forwarder), HTTP 200 scrape metadata version `10.6.0`, scrape ID `01a15855-68e6-728c-9c56-b6fdcc50c4b2`. Exact MSI URL/checksum, seed syntax, and selected collection pins remain open.

References: [modern requirements](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.0/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises), [9.2 removals](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/9.2/deprecated-features/deprecated-and-removed-in-version-9.2), [support policy](https://www.splunk.com/en_us/legal/splunk-software-support-policy.html), [forwarder/indexer compatibility](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/compatibility-matrix/splunk-products-version-compatibility/compatibility-between-forwarders-and-splunk-enterprise-indexers).

## Implementation research gates

Confirm supported Windows collections, Ansible and PowerShell prerequisites, a documented service account/bootstrap design, safe paths and ACLs, and artifact verification. Use [win_package](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_package_module.html) and [win_service](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_service_module.html) only after selected-version behavior is confirmed. No automatic reboot, upgrade, or password rotation.

The collector should render separate Security (`winlogs`), Sysmon (`sysmon`), and SilkService-Log (`etw`) inputs with an unfiltered Security baseline. Optional Splunk TAs are not collection prerequisites and are outside scope; raw XML/indexes do not promise CIM dashboards. Server index management is append-only: `[]` is a no-op only when never managed; after opt-in, removal fails. Future exclusion evaluation is tracked in [TODO SPLUNK-001](../TODO.md); it requires explicit opt-in/authorization and representative native events.

## Verification status

Static repository and Ansible validation are the next evidence. No simulated runtime tests and no live actions are authorized. Later native authorization must independently verify fresh installation, convergence without restart, configuration-change restart, Security/Sysmon/SilkService-Log arrival in `winlogs`/`sysmon`/`etw`, the unfiltered baseline, and any explicitly approved candidate exclusions with keep/drop canaries, absent-channel behavior, service identity/access, conflict and credential failures, and unrelated-data preservation.
