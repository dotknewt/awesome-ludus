# Windows logging policy protocol and evidence ledger

Date: 2026-10-22. Scope: source/protocol research only. No archive content was imported or executed, no AD/guest operation was performed, and no native-version compatibility claim is made.

## Frozen implementation contract

### Native execution and prerequisites

- Initial management boundary remains Windows Server 2022, Windows PowerShell 5.1, the GroupPolicy/GPMC and ActiveDirectory modules, and one selected writable target-domain DC. Every GroupPolicy call uses the owned GPO `-Guid`, discovered DNS domain via `-Domain`, and the same DC via `-Server`; names are discovery/display inputs, never mutation identity. `Get-ADDomain -Current LocalComputer` returns the joined computer's domain and exposes `DNSRoot`, `DistinguishedName`, `DomainSID`, `ObjectGUID`, and `PDCEmulator`. An explicit domain uses `-Identity`; an explicit server must belong to that domain. [R1-R6]
- `Get/Set/Remove-GPRegistryValue` select computer policy through `HKLM`, support explicit GUID/domain/server, and operate at value scope. `Remove-GPRegistryValue -Key ... -ValueName ...` removes that policy value without deleting the client registry value; key-only removal is prohibited here because it can remove all first-level policy values and fails when subkey policy exists. `Set-GPRegistryValue -Disable` is also prohibited for retirement because it authors a client-side deletion directive rather than removing this role's GPO setting. [R1-R3]
- `Set-GPRegistryValue -Additive` applies only to list values. Use it for owned module-name entries so applying the policy does not erase client-side list values; never use non-additive key-wide list replacement. For all scalar settings use exact `DWord` or `String` types below. Read back each exact value after mutation. [R2]
- `New-GPLink` creates an enabled, non-enforced link by default and accepts target LDAP DN, order, domain and server; code nevertheless supplies `LinkEnabled`, `Enforced`, `Domain`, and `Server` explicitly. `Set-GPLink` changes only requested enabled/enforced/order properties. Order is 1 through current-link-count+1; a lower number has higher precedence and requesting an order can shift unrelated links. [R4-R5]
- The running WinRM/PSRP session must already authenticate to LDAP and `\\<selected-dc>\SYSVOL` over SMB. Most WinRM authentication modes do not delegate credentials; Kerberos with delegation or CredSSP can, while NTLM cannot. The role performs same-session read-only LDAP and selected-DC SYSVOL access preflight before mutation and never enables CredSSP/delegation, changes credentials, or falls back to another DC. CredSSP sends reusable credentials to the server and is not a default recommendation. [R15]
- `ansible.windows.win_powershell` is frozen to collection 3.8.0 source. Pass data through `parameters`, not script interpolation; set `error_action: stop`. The script must define `[CmdletBinding(SupportsShouldProcess)]` or the module skips it in check mode. With that declaration, the module passes `-WhatIf` from check mode; the script must put every mutation behind `ShouldProcess` and still perform read/plan logic. Set `$Ansible.Changed = $false` initially and true only after a verified mutation; use `$Ansible.Result` for the structured plan/result and `$Ansible.Failed = $true` or a terminating exception for failure. Non-terminating errors only fail automatically with `error_action=stop`. The module defaults changed to true, result to `{}`, and serialization depth to 2. Local `path` scripts must be UTF-8. [R16-R19]
- Locally evidenced baselines are `ansible-core 2.21.5`, `ansible.windows 3.8.0`, and `community.windows 3.3.0`; both collection runtime manifests require ansible-core `>=2.16.0`, and community.windows 3.3.0 requires ansible.windows `>=3.0.0,<4.0.0`. This establishes dependency-range consistency only. `pwsh` is absent; there is no PowerShell parse or Windows PowerShell 5.1 runtime evidence and no selected Server 2022/Windows 11 compatibility claim. [R17-R19]

### Exact owned registry values

All paths are computer policy (`HKLM`). Values are individually read, set, and retired; no subtree deletion is allowed.

| Policy | Key | Value name | Type | Enabled value / source disposition |
| --- | --- | --- | --- | --- |
| logging | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `SCENoApplyLegacyAuditPolicy` | `DWord` | `1`; MS-GPSB says this makes the client ignore legacy category policy and indicates advanced audit policy is present. [R7] |
| logging | `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging` | `EnableModuleLogging` | `DWord` | `1`. [R8-R9] |
| logging | `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames` | one value per requested module; default value name `*` | `String` | data equals module name; default `*`. Treat each name/data pair as independently owned and additive. The archived GPO records wildcard module logging; no unrelated entry may be replaced. [A1, R8-R9] |
| logging | `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` | `EnableScriptBlockLogging` | `DWord` | `1`. [R9] |
| logging | same | `EnableScriptBlockInvocationLogging` | `DWord` | `1`; high-volume start/stop logging. [R9] |
| logging | `HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription` | `EnableTranscripting` | `DWord` | `1`. [R8-R9] |
| logging | same | `EnableInvocationHeader` | `DWord` | `1`. [R9] |
| logging | same | `OutputDirectory` | `String` | exact validated configured path, default `C:\Transcripts`; the policy does not create/protect/retain that location. [A1, R8-R9] |
| enrollment | `HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment` | `AEPolicy` | `DWord` | default requested bundle `7`; see the flag gate below. [A1, R10-R12] |
| enrollment | same | `OfflineExpirationPercent` | `DWord` | `10`. [A1, R10] |
| enrollment | same | `OfflineExpirationStoreNames` | `String` | `MY`. `MY` is always monitored by the native local-policy cmdlet; this value records the archived/domain-GPO representation, not use of that local setter. [A1, R10] |
| defender | `HKLM\Software\Policies\Microsoft\Windows Defender` | `DisableAntiSpyware` | `DWord` | `1`, only under the explicit disabling-policy opt-in. This legacy setting is ignored on Defender for Endpoint-onboarded devices at platform 4.18.2108.4+ and can be blocked by tamper protection. [A1, R13] |
| defender | `HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection` | `DisableRealtimeMonitoring` | `DWord` | `1`, only under the same opt-in. Microsoft maps the policy to this key/value, but tamper protection can ignore it. [A1, R14] |

`Set-CertificateAutoEnrollmentPolicy` is not a domain-GPO setter: Microsoft documents it as configuring local user/computer policy. It does, however, name the semantics: `EnableMyStoreManagement` means renew expired certificates, update pending certificates, and remove revoked certificates; `EnableTemplateCheck` updates template-based certificates; `EnableAll` sets all options and expiration to 10%; and `StoreName` adds monitored stores while `MY` is always monitored. Ordinary AD enrollment is therefore represented only by the three `AutoEnrollment` values above. Do **not** serialize `Cryptography\PolicyServers`, a source-domain GUID/hash, `**DeleteKeys`, CEP/CES configuration, or certificate-store placeholders. Issuance still requires an enterprise CA, a published template, and read/enroll/autoenroll permissions. [R10-R12]

**AEPolicy gate and controller refinement.** One bounded search of Microsoft-authored official material found the archived Microsoft TechNet Wiki troubleshooting page [R12]: in its documented enabled-policy example it says `AEPolicy` should be `7`. Together with the native cmdlet's descriptions [R10] and the inspected archive [A1], this proves the approved all-options bundle, but it is not an independent representation of the numeric bits and does not prove other combinations. No source reviewed for this task establishes the previously reported `0`/`1`/`6`/`0x8000` mapping, so those unsupported numbers are withdrawn. The controller therefore refined, rather than the original user requesting, the v1 interface: when enrollment is enabled, `renew_update_revoke` and `update_templates` MUST both be `true`; write `AEPolicy` as `DWord 7`. Reject either false value (including mixed combinations) before any mutation with an error that v1 supports only the verified all-options bundle. Retirement removes `AEPolicy`, `OfflineExpirationPercent`, and `OfflineExpirationStoreNames`; it does not serialize a disabled numeric value. Never infer separately named bits from decimal 7. [A1, R10-R12]

### Advanced-audit CSV grammar

The namespace identity is `\\<domain-dns-root>\SYSVOL\<domain-dns-root>\Policies\{<canonical-gpo-guid>}`. LDAP `gPCFileSysPath` MUST, after case-insensitive comparison and normalization of slash direction/trailing slash only, equal that identity; reject a different server/domain, share, policy GUID, or additional path. It is validation evidence, not the I/O route. Construct the only publication path independently as `\\<selected-dc-fqdn>\SYSVOL\<domain-dns-root>\Policies\{<canonical-gpo-guid>}\Machine\Microsoft\Windows NT\Audit\audit.csv` (and GPT as the same selected-DC root plus `\GPT.INI`). Require the selected DC to be the already verified target-domain FQDN. Never use the domain DFS hostname, `gPCFileSysPath` hostname, referral result, or fallback DC for I/O. [R20, R27-R29]

- Encode UTF-8 with no preamble and CRLF after every line, including the last. MS-GPAC requires UTF-8 and grammar begins directly with the exact header, so a BOM is not part of the accepted grammar. Header, exactly: `Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`. [R20-R21]
- The complete file production is `Header SubcategorySettings AuditOptions GlobalObjectAccessAuditSettings`; rows therefore form three contiguous class segments in exactly that order: all system and per-user subcategory rows, then audit-option rows, then global-SACL rows. Each physical row has exactly seven comma-delimited fields and ends CRLF. Preserve unrelated row order within its existing class segment; insert owned system rows at the end of the subcategory segment in approved input order. A row after a later-class segment has begun, an unclassifiable row, an extra/missing field, bare LF, or non-UTF-8 input is malformed and fails closed. [R21, R31-R37]
- The shared lexical ABNF is: `MachineName = String / QuotedString`; `Subcategory = StringWithSpaces / QuotedString`; `SubcategoryGUID = GUID`; `String = *(ALPHANUM / "/" / "-" / ":" / ";")`; `StringWithSpaces = String / String Wsp StringWithSpaces`; `QuotedString = DQUOTE *(%x20-21 / %x23-7E) DQUOTE`; `Wsp = *WSP`; and brace-delimited `GUID` contains the standard 8-4-4-4-12 hexadecimal groups. Only MachineName and Subcategory admit `QuotedString`; quotes are not general CSV quoting, embedded DQUOTE is forbidden, and there is no doubled-quote escape. Parse fields according to this protocol grammar, not a permissive CSV library dialect. Empty MachineName is valid `String`. [R21-R23, R31]
- **System subcategory:** `MachineName,System,Subcategory,{GUID},Inclusion,,SettingValue`. Inclusion is exactly `Success`, `Failure`, `Success and Failure`, `No Auditing`, or `Not Specified`; exclusion is empty; setting is respectively decimal `1`, `2`, `3`, `4`, or `0` for role-authored rows. Protocol semantics make the number authoritative and display text user-only; accept an unrelated existing row when both fields are independently lexical-valid even if they disagree, and preserve it unchanged. Emit empty MachineName, canonical English Subcategory, and matching text/value. Semantic key: `(system-subcategory, GUID case-insensitive)`. [R22-R24]
- **Per-user subcategory:** `MachineName,UserSID,Subcategory,{GUID},Inclusion,Exclusion,SettingValue`, where UserSID is a valid standard `S-R-I-S...` SID string; each display setting is one of the same five texts; numeric setting is `0` unchanged, `16` none, or decimal `1..15` combining `0x01` include-success, `0x02` exclude-success, `0x04` include-failure, and `0x08` exclude-failure (include wins over exclude for the same outcome). The number is authoritative; lexical-valid display mismatch is preserved. Semantic key: `(per-user-subcategory, canonical SID, GUID case-insensitive)`. The role never creates this class. [R22-R23, R32]
- **Audit option:** `MachineName,,Option:AuditOptionType,,AuditOptionValueText,,AuditOptionValue`; type is exactly one of `CrashOnAuditFail`, `FullPrivilegeAuditing`, `AuditBaseObjects`, `AuditBaseDirectories`; text is `Enabled` or `Disabled`; numeric value is `1` or `0`. The number is authoritative and text is user-only. Semantic key: `(audit-option, type case-insensitive)`. The role never creates this class. [R33-R35]
- **Global object-access SACL:** `MachineName,,ResourceGlobalSaclType,,,,GlobalSACL`; type is exactly `FileGlobalSacl` or `RegistryGlobalSacl`; GlobalSACL MUST be an SDDL encoding of a SACL. In addition to the seven-field/class check, require the Windows security-descriptor parser at execution time to accept the field as an SDDL SACL; this is a fail-closed validation requirement, not local runtime evidence. Semantic key: `(global-sacl, type case-insensitive)`. The role never creates this class. [R36-R38]
- Reject duplicate semantic keys in every class, including duplicates with different settings/text/case; do not choose first/last. Validate every GUID against MS-GPAC's supported subcategory table, every SID/type/value against its class rules, and every row before comparison or mutation. Only setting/GUID (plus SID for per-user, option type, or resource type) determines applied semantics; display fields remain preserved user-reference data. [R22-R25, R31-R38]
- Own exactly these 15 brace-delimited GUIDs (case-insensitive identity), all setting 3 by default: `{0cce9242-69ae-11d9-bed3-505054503030}`, `{0cce9240-69ae-11d9-bed3-505054503030}`, `{0cce9236-69ae-11d9-bed3-505054503030}`, `{0cce9237-69ae-11d9-bed3-505054503030}`, `{0cce9235-69ae-11d9-bed3-505054503030}`, `{0cce923e-69ae-11d9-bed3-505054503030}`, `{0cce923b-69ae-11d9-bed3-505054503030}`, `{0cce923c-69ae-11d9-bed3-505054503030}`, `{0cce923d-69ae-11d9-bed3-505054503030}`, `{0cce9215-69ae-11d9-bed3-505054503030}`, `{0cce921c-69ae-11d9-bed3-505054503030}`, `{0cce921b-69ae-11d9-bed3-505054503030}`, `{0cce9221-69ae-11d9-bed3-505054503030}`, `{0cce9244-69ae-11d9-bed3-505054503030}`, `{0cce9227-69ae-11d9-bed3-505054503030}`. MS-GPAC names match approved spec section 5. Process creation (`0cce922b`) is not included. [R22]
- Semantic comparison of owned system rows uses normalized GUID and setting value, not machine/display text or row order. A deletion removes only previously committed owned GUID rows. If valid audit rows remain, keep the file and tuple; if no rows of any supported class remain, delete the file and unregister only the audit tuple. [R21-R25]

### Combined audit publication and versions

The audit CSE/tool tuple is exactly `[{f3ccc681-b74c-4060-9f26-cd84525dca2a}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]`. `gPCMachineExtensionNames` is a concatenation of bracketed CSE/tool pairs sorted case-insensitively ascending by CSE GUID; processing terminates at the first out-of-order CSE. Normalize an absent LDAP attribute to the empty tuple sequence for parsing/planning. Preserve every unrelated complete tuple exactly, reject malformed or duplicate-CSE content, add this tuple only when audit data remains, and remove only this exact tuple when all audit data is gone. [R26-R28]

Under the per-domain writer lock, publication order is:

1. Read/validate owned marker and protected state first; any pending record blocks normal comparison. Read audit CSV, LDAP `versionNumber` and `gPCMachineExtensionNames`, and selected-DC `GPT.INI` from the same DC. AD and GPT 32-bit versions must agree before mutation. Parse every CSV row and tuple before planning.
2. Compute the desired CSV and extension string without writes. For machine policy version `V`, user half is `(V >> 16) & 0xffff`, machine half is `V & 0xffff`; increment only machine. If increment wraps to 0, use 1. Intended combined version is `(user << 16) | next_machine` for both AD and GPT. [R27-R29]
3. Atomically write-and-flush pending state including the exact prior/intended values and protected prior CSV backup. Re-read all prior authoritative values on the same DC; mismatch means concurrent mutation and no publication.
4. Create/replace/delete `audit.csv` first using a same-directory temporary file and atomic replacement where the filesystem supports it; close/flush and verify bytes/hash. MS-GPAC requires the extension-update task after every audit-file creation, modification, or deletion. [R25]
5. Send one LDAP modify request to the GPO DN with two replace changes: `versionNumber` has exactly one decimal intended-version value; `gPCMachineExtensionNames` has exactly one complete preserved/sorted string when tuples remain, or **zero values** when the resulting sequence is empty (LDAP replace-with-no-values removes the attribute; never write an empty-string value). Require result code 0 for the one combined request. This retains the verified CSV → combined LDAP → GPT sequence and is never an append or per-tuple LDAP delete. [R27-R28, R39]
6. Open selected-DC `GPT.INI`, require `[General]` and unique `Version`, recheck its prior value, write the same intended version, close, and verify. MS-GPOL specifies LDAP extension update followed by the GPT filesystem version update. [R27-R29]
7. Read back CSV bytes/semantics, extension membership/order, AD version, and GPT version. Only an exact match permits committed state replacement and atomic pending clear. New links remain blocked until this succeeds.

Failure windows are intentionally fail-closed: after pending/before CSV, prior state can be explicitly abandoned only after proving all authoritative values remain prior; after CSV/before LDAP, payload is intended but both versions/extensions are prior; after LDAP/before GPT, AD/extensions are intended and GPT is prior; after GPT/before state commit, authoritative state can be fully intended while local pending remains. Every window retains pending. Recovery is an explicit operator choice to (a) complete only missing prescribed steps when current state exactly equals a recorded prior/intended combination, or (b) restore the recorded prior CSV, complete a new prescribed extension/version publication, and verify it. Any third state or intervening edit blocks recovery. A desired CSV with old matching AD/GPT versions is never convergence while pending exists. There is no blind retry, automatic rollback, or version bump without payload/extension publication. [R25-R29]

`auditpol /set` and `/restore` configure local policy, not this GPO payload. `IGroupPolicyObject::Save` documents registry-policy save scope and does not establish publication of arbitrary audit CSV changes. Neither is a substitute for the sequence above. [R30]

## Protected ownership state schema and transitions

Canonical JSON is one protected, atomically replaced file on the designated host:

```json
{
  "schema_version": 1,
  "owner_id": "ludus-windows-logging-policy",
  "domain_guid": "<canonical GUID>",
  "writer_host": "<designated inventory hostname>",
  "policies": {
    "logging": {
      "gpo_guid": "<canonical GUID or null while create is pending>",
      "registry": [{"key":"...","value_name":"...","type":"DWord|String"}],
      "audit_guids": ["<canonical brace GUID>"],
      "link_targets": ["<canonical target DN>"],
      "pending": null
    }
  }
}
```

`policies` is keyed only by stable IDs `logging`, `enrollment`, and `defender`. A committed policy record contains its `gpo_guid`, committed registry identifiers (`key`, `value_name`, `type`; not secrets or merely desired values), committed audit GUIDs, and committed direct-link target DNs. `pending` is nullable and, when non-null, has:

```text
operation: create|registry_add|registry_update|registry_remove|audit_publish|audit_delete|link_add|link_update|link_disable
target: {policy_id, target_name, gpo_guid?, registry_identifier?, audit_guids?, link_target?}
prior_ownership: exact committed identifiers relevant to the operation
intended_ownership: exact post-operation identifiers
audit?: {dc, prior_ad_version, intended_ad_version, prior_gpt_version, intended_gpt_version,
         prior_machine_extensions, intended_machine_extensions, prior_hash, prior_backup_path,
         desired_hash, desired_deletion}
```

All GUIDs/DNs are canonicalized only after authoritative resolution. A new-object pending record is persisted before `New-GPO` with `target_name` and null GUID; once creation returns, update/flush pending with that GUID before marker/content/link mutation. A crash before GUID recording causes an unmanaged-name collision requiring review, never adoption. Every registry/audit/link addition, update, removal or disable persists prior and intended ownership before mutation; commit replaces owned identifiers only after authoritative readback. Missing/moved state, owner/domain/writer mismatch, unknown schema, malformed pending, existing unmanaged name, marker/GUID replacement, or any pending/current state outside its bounded transition fails closed. State transfer to a new writer is an explicit operator procedure, not reconstruction.

Check mode acquires/read-checks the lock and state, performs discovery/comparison/planning, and writes nothing: no state, GPO, registry, CSV, LDAP, GPT or link mutation. Disabled previously owned policies retire only their committed values/rows and disable committed links; a disabled never-managed policy is a no-op. Unrelated settings, audit rows, tuples, links, ACLs and user policy are immutable from this role's perspective.

## Archive provenance and copied findings

Reused static inspection evidence [A1], not re-executed: `/tmp/opencode/portable-splunk-gpo/inspection-rkB8fx/CondefGPO.zip`, 47,340 bytes, SHA-256 `d401b570866537774f8825ebf7c4e389d9aadbcb8482b6099d17edc1c6036058`; immutable upstream ref `0cefe62755eebba7b226e611ece75160706e22f6` independently matched. The archive was read/decoded, never imported. Upstream repository/archive redistribution permission is unestablished (`license: null` and no archive license); no bytes are bundled here.

There are five backups, but the legacy role imports only three: GPO-Logging, GPO-CertEnroll and GPO-DisableDefender. Default Domain Policy and Default Domain Controllers Policy are not imported and remain excluded. Correct physical inventory is four INF and four `registry.pol` files: DisableDefender has no INF and Default Domain Controllers Policy has no `registry.pol`. The three selected backups record the logging, `AEPolicy=7`/10/`MY`, and two Defender values represented above. The CertEnroll backup also contains foreign `condef.local` PolicyServers identity/deletion material; readable recreation deliberately omits it. [A1]

## Evidence matrix and unresolved gates

| Claim | Static primary/reused evidence | Live evidence | Disposition |
| --- | --- | --- | --- |
| Native cmdlet/domain/link contract | R1-R6 | None | Source-backed syntax/semantics; permissions/runtime unverified |
| Registry mapping | R7-R14 + A1 | None | Exact approved defaults frozen; AEPolicy independent combinations gated |
| CSV grammar/GUIDs | R20-R25 + R31-R38 | None | Four row classes, quoting, semantic keys/order frozen; client application unverified |
| LDAP/GPT tuple/version protocol | R26-R29 | None | Frozen; crash/concurrency behavior unverified |
| Ansible module contract/dependencies | R15-R19 | None | Version-matched source-backed; no parser/runtime execution |
| Archive provenance/inventory | A1 | None | Reused static bytes evidence; redistribution unresolved, archive not bundled |

Outstanding gates: fresh reviewer/controller/oracle acceptance of the controller-refined constrained `AEPolicy=7` v1 interface; Windows PowerShell 5.1 parsing; authorized real AD fresh/convergence/failure-window/recovery checks; selected Windows Server 2022/Windows 11 client application; LDAP/SMB credential path, replication, effective audit/PowerShell/enrollment/Defender behavior. Static evidence does not establish deployment readiness.

## Primary references

Retrieved 2026-10-22 unless the page metadata above records a later publication/update.

- **R1** Get-GPRegistryValue, Windows Server 2022 view: https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpregistryvalue?view=windowsserver2022-ps
- **R2** Set-GPRegistryValue, Windows Server 2022 view: https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpregistryvalue?view=windowsserver2022-ps
- **R3** Remove-GPRegistryValue, Windows Server 2022 view: https://learn.microsoft.com/en-us/powershell/module/grouppolicy/remove-gpregistryvalue?view=windowsserver2022-ps
- **R4** New-GPLink, Windows Server 2022 view: https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gplink?view=windowsserver2022-ps
- **R5** Set-GPLink, Windows Server 2022 view: https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gplink?view=windowsserver2022-ps
- **R6** Get-ADDomain, Windows Server 2022 view: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomain?view=windowsserver2022-ps
- **R7** MS-GPSB SCENoApplyLegacyAuditPolicy semantics: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/506f97dd-00f9-49dc-b3ba-bb041328cafb
- **R8** PowerShell ADMX registry mappings: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-powershellexecutionpolicy
- **R9** Windows PowerShell 5.1 policy semantics: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-5.1
- **R10** Set-CertificateAutoEnrollmentPolicy, Windows Server 2022 view: https://learn.microsoft.com/en-us/powershell/module/pki/set-certificateautoenrollmentpolicy?view=windowsserver2022-ps
- **R11** Microsoft certificate auto-enrollment procedure/prerequisites: https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-server-certificate-auto-enrollment
- **R12** Microsoft-hosted auto-enrollment troubleshooting (`AEPolicy=7`): https://learn.microsoft.com/en-us/archive/technet-wiki/3048.active-directory-certificate-services-ad-cs-troubleshooting-certificate-autoenrollment
- **R13** DisableAntiSpyware legacy/removal behavior: https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-disableantispyware
- **R14** Defender `DisableRealtimeMonitoring` mapping and tamper caveat: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowrealtimemonitoring
- **R15** Ansible WinRM authentication/delegation limitations: https://docs.ansible.com/ansible/latest/os_guide/windows_winrm.html
- **R16** win_powershell 3.8.0 rendered docs: https://docs.ansible.com/ansible/latest/collections/ansible/windows/win_powershell_module.html
- **R17** win_powershell 3.8.0 module source: https://raw.githubusercontent.com/ansible-collections/ansible.windows/3.8.0/plugins/modules/win_powershell.py
- **R18** ansible.windows 3.8.0 runtime manifest: https://raw.githubusercontent.com/ansible-collections/ansible.windows/3.8.0/meta/runtime.yml
- **R19** community.windows 3.3.0 manifests: https://raw.githubusercontent.com/ansible-collections/community.windows/3.3.0/galaxy.yml and https://raw.githubusercontent.com/ansible-collections/community.windows/3.3.0/meta/runtime.yml
- **R20** MS-GPAC audit path/admin event: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/06eee0c7-1f03-4383-ad1c-5c85156a9abc
- **R21** MS-GPAC UTF-8/CSV/CRLF grammar: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/6494a0f2-8a16-40e2-b87d-328be7d732e0
- **R22** MS-GPAC GUID authority/table: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
- **R23** MS-GPAC policy target and machine-name semantics: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/babbf4f2-5790-41d5-b633-09d489c7ba59 and https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/c76f6418-d4b7-4a8a-bc07-001af61d2ea8
- **R24** MS-GPAC system setting values: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/21ad2e80-3011-48ef-be13-cc11ff7bfeb1
- **R25** MS-GPAC client processing and mandatory update after file mutation: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/eda6a094-5d0a-4516-a3ab-7ee2d38b12b6 and https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/1efc1e40-1e7e-44fd-87ce-c09627c6c511
- **R26** MS-GPAC extension GUID assignments: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/ac9c8234-d2e8-455d-be76-f84244dd1e58
- **R27** MS-GPOL extension update/message: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/3b027be3-62ac-4b85-9334-37f79c83bfea and https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/5dacf4c4-07aa-4870-a7ee-1306b58392e1
- **R28** MS-GPOL extension tuple syntax/order and GPT grammar: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/b0e5c9e8-e858-4a7a-a94a-4a3d0a9d87a2
- **R29** MS-GPOL version increment/GPT update: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/70fd86b1-926a-4dcf-9ce7-6f9d2149c20d and https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/59bb540a-64f4-4c52-9c55-5ca2fd2c0270
- **R30** IGroupPolicyObject::Save: https://learn.microsoft.com/en-us/windows/win32/api/gpedit/nf-gpedit-igrouppolicyobject-save
- **R31** MS-GPAC subcategory row production: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/6932bdb2-e008-40aa-a774-edf6e1a68acd
- **R32** MS-GPAC per-user text/value bits and precedence: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/149ae116-a48f-4335-8cc8-c7e364f93dc0
- **R33** MS-GPAC audit-option row production: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/63011ea8-69be-46c6-acf0-d1837ea1c7ec
- **R34** MS-GPAC audit-option types: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/262a2bed-93d4-4c04-abec-cf06e9ec72fd
- **R35** MS-GPAC audit-option values: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/db56a605-4305-4302-b3ad-59112ae66425
- **R36** MS-GPAC global-object-access row production: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/0ffdef31-37a9-4f0c-bec0-75450a80a8a9
- **R37** MS-GPAC global-SACL resource types: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/c7b5dc6f-0088-4a3f-908e-8a7c40e7806a
- **R38** MS-GPAC GlobalSACL SDDL requirement: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/0b369429-3d83-49bd-9f08-ea83a74505d5
- **R39** LDAP replace semantics (replace with no values deletes the attribute), RFC 4511 §4.6: https://www.rfc-editor.org/rfc/rfc4511#section-4.6
- **A1** Reused archive inspection: `.slim/deepwork/portable-splunk-gpo/gpo-collector-analysis.md`, sections 1-3 and verification disposition; bytes/path/digest fixed above.
