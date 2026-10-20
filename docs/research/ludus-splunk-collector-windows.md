# Research: Windows Splunk collector

**Documentary reconciliation: 2026-10-20.** This note is limited to the Task 0
pre-live gate. It is evidence for planning, not evidence of installation,
authentication, ACL correctness, ingestion, or selected-version runtime support.

## Primary-source conclusions

- The pinned artifact remains the publisher URL
  `https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi`, with SHA-512
  `980658ef29a964e430ee7b601b170324185a2d93fcee83f55d992a522d20355dc784f2947839690b12265ba775f861810d610244c7cc978c65e20f588147f693`.
  Its sidecar URL is
  `https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi.sha512`;
  parent HTTP 200 and an independent local SHA-512 match were recorded for
  `/tmp/opencode/uf106.msi` (386322432 bytes). Offline MSI inspection recorded
  ProductVersion `10.6.1.1`, x64, and `GENRANDOMPASSWORD=1`; this is native
  file inspection, not execution.
- Splunk's Windows UF 10.6 installation page (retrieved 2026-10-20; page
  metadata 10.6.0) documents `LAUNCHSPLUNK` default `1` and
  `SERVICESTARTTYPE` default `auto`. It documents the no-user quiet route as
  omitting `SPLUNKUSERNAME`/`SPLUNKPASSWORD` and using `GENRANDOMPASSWORD=0`.
  The selected implementation's `AGREETOLICENSE=Yes LAUNCHSPLUNK=0
  GENRANDOMPASSWORD=0` is therefore a documented bootstrap shape; the page
  does not prove this exact 10.6.1.1 MSI's behavior.
- Splunk's `user-seed.conf` reference (9.3 reference, retrieved 2026-10-20)
  defines `[user_info]` with `USERNAME` and `PASSWORD`, and also documents
  `HASHED_PASSWORD`. The repository template uses the documented plaintext
  `PASSWORD` form, writes it only after restrictive ACLs, and removes it after
  successful loopback authentication. No source establishes that this
  sequence works on the selected MSI; native authentication remains open.
- Microsoft documents virtual accounts as automatically managed local accounts
  named `NT SERVICE\<service-name>` with no administrator-managed password.
  Ansible `ansible.windows.win_service` 3.8.0 independently documents
  `username: NT SERVICE\service name`. These sources support the requested
  identity and reject a LocalSystem fallback, but do not grant Event Log read
  access automatically.
- Microsoft `wevtutil` documentation says event-log access is controlled by an
  SDDL security descriptor (`/ca`) and that `get-log` exposes log
  configuration. It does not document that adding a local virtual-account SID
  is equivalent to membership in `Event Log Readers`, nor provide a
  domain-controller-specific recipe. The role's `Translate()` lookup of
  `NT SERVICE\SplunkForwarder` and additive per-channel READ ACE is a plausible
  local-preservation strategy, but DC-safe lookup and effective access require
  live verification. `SeSecurityPrivilege` is not established as required and
  must not be substituted automatically.
- Official Ansible docs retrieved 2026-10-20 identify `ansible.windows` 3.8.0;
  previously recorded Galaxy metadata also pins `community.windows` 3.3.0
  (depending on `ansible.windows >=3.0,<4`) and Core >=2.16. The local
  validator recorded Core 2.21.5/Python 3.14.8 without installing collections.
  `win_package` documents MSI arguments, return code 3010 as
  `reboot_required`, and checksum support; `win_service` documents virtual
  accounts and `auto`/`disabled`/`started` states. These facts support the
  module choices and reboot stop/fail path, not Splunk compatibility.

## Role reconciliation and implementation mismatches

- `install.yml` uses the documented no-user properties and does not set
  `SERVICESTARTTYPE`; it later explicitly starts the service and sets `auto`.
  That is internally intentional, but the exact MSI default/property behavior
  is not proven by the retrieved Splunk page.
- `configure.yml` checks the service identity, adds READ ACEs to Security and
  Sysmon, and conditionally SilkService-Log. It protects the seed with SYSTEM,
  Administrators, and service-account READ ACLs. This is documentary design
  evidence only; `SecurityDescriptor`/`SaveChanges` preservation, deny ACE
  behavior, and effective reads are live-only gates, including on DCs.
- `inspect.yml` requires Security and Sysmon channels and treats Silk as
  optional, matching the intended producer boundary. **Static correction made:**
  PowerShell variable names are case-insensitive; `$home` is the automatic
  `$HOME` variable, documented by Microsoft as the executing user's home
  directory (normally `C:\Users\<UserName>`), not an undefined variable. The
  executable-version path guard and lookup now use the established
  `$splunkHome`, with a focused static regression assertion. This is source/test
  evidence only: PowerShell execution and installation/runtime behavior remain
  unverified. Source: [Microsoft about_Automatic_Variables](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables)
  (retrieved 2026-10-20).
- `validate.yml` pins Windows 11/Server 2019/2022/2025 x64, PowerShell >=5.1,
  and UF 10.6.1.1. The official sources collected here do not provide the
  exact 10.6.1.1 OS support table. The selected-version applicability gate is
  therefore unresolved, not failed and not closed.
- **Static API corrections (2026-10-20):** the installed `ansible.windows`
  3.8.0 `win_get_url` contract accepts `checksum_algorithm: sha512` and requires
  the checksum argument as bare hexadecimal, so the task now strips the
  `sha512:` prefix while retaining the algorithm. The `win_uri` result exposes
  `status_code`; the retry condition now reads that field. The task still sends
  `status_code: 200` as its accepted-response argument. These source corrections
  and static tests do not establish runtime download/authentication behavior.
  Sources: [Ansible `win_get_url` 3.8.0](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_get_url_module.html)
  and [Ansible `win_uri` 3.8.0](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_uri_module.html).
- Fresh-install phase transition now requires a non-skipped package result and
  re-reads a pending marker before advancing; existing initialized markers are
  not advanced by a skipped registered result. Seed ACL management now
  restricts parent and file DACLs before rendering secret content and refuses
  unsafe ownership/reparse state or unrelated files in the shared `system/local`
  parent. This is a source-level fail-closed correction only; ACL effectiveness,
  seed authentication, and preservation/runtime behavior remain unverified.

## Gates / status

**Documentary prerequisites established:** artifact identity/checksum,
installer flag meanings at the cited Splunk-page version, seed key syntax,
virtual-account naming, Ansible module capability, and intended target matrix.

**Blockers before claiming Task 0 closed:** obtain primary documentation that
applies specifically to UF 10.6.1.1 (or record the limitation explicitly), and
obtain an authoritative, DC-safe account/ACL procedure or keep the role's local
SID approach explicitly as an unverified design. The `$home` source mismatch is
corrected, but the static regression assertion does not establish runtime
behavior.

**Live-only gaps (not documentary blockers):** fresh install and convergence;
MSI return/reboot behavior; seed authentication and seed removal; service
identity; effective Security/Sysmon access; optional Silk channel behavior;
forwarding and event arrival; and preservation of unrelated ACLs/configuration.
No install, deployment, guest probe, or target-server query was performed.

## Sources (retrieved 2026-10-20)

- [Splunk Windows UF installation](https://help.splunk.com/en/splunk-cloud-platform/forward-and-process-data/universal-forwarder-manual/10.6/install-the-universal-forwarder/install-a-windows-universal-forwarder)
- [Splunk `user-seed.conf` reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.3/configuration-file-reference/9.3.0-configuration-file-reference/user-seed.conf)
- [Microsoft service accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts)
- [Microsoft `wevtutil`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [Ansible `win_package` 3.8.0](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_package_module.html)
- [Ansible `win_service` 3.8.0](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_service_module.html)
- [Ansible `win_get_url` 3.8.0](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_get_url_module.html)
- [Ansible `win_uri` 3.8.0](https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_uri_module.html)
- [Splunk system requirements](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.0/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises)
