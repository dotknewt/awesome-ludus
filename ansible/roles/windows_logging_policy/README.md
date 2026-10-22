# windows_logging_policy

Authors three optional, readable Windows domain policies without importing a
foreign GPO backup. All policies are disabled and unlinked by default. The role
uses native GroupPolicy cmdlets for value-scoped registry policy and direct
links, plus one bounded MS-GPAC/MS-GPOL audit publisher for its logging GPO.

## Supported boundary and prerequisites

The initial authoring target is Windows Server 2022 with Windows PowerShell
5.1, the GroupPolicy/GPMC and ActiveDirectory modules, a joined target domain,
and access to one selected writable DC. The actual WinRM/PSRP execution session
must already authenticate to LDAP and `\\<selected-dc>\SYSVOL`; a nominally
privileged account in a nondelegating second-hop session is insufficient. This
role does not enable CredSSP or delegation, change credentials, choose a
fallback DC, join/promote a host, or alter account policy.

`windows_logging_policy_management_host` is required and must equal the
inventory host executing the helper. Run once per domain on that designated
host. The installed Ludus role identity has not been verified; use the identity
reported by the target Ludus server rather than inferring it from this folder.

## Inputs

| Variable | Default | Contract |
| --- | --- | --- |
| `windows_logging_policy_domain` | empty | Joined domain; an override must resolve to the joined domain |
| `windows_logging_policy_server` | empty | Joined domain PDC; an override must be a writable DC in that domain |
| `windows_logging_policy_owner_id` | `ludus-windows-logging-policy` | Stable state and description-marker owner |
| `windows_logging_policy_management_host` | empty | Required designated inventory host |
| `windows_logging_policy_state_dir` | `C:\ProgramData\Ludus\WindowsLoggingPolicy` | Protected local state directory; UNC and reparse paths are rejected |
| `windows_logging_policy_logging_enabled` | `false` | Manage `Ludus-Logging` when true |
| `windows_logging_policy_enrollment_enabled` | `false` | Manage `Ludus-CertEnroll` when true |
| `windows_logging_policy_defender_disable_policy_enabled` | `false` | The single explicit opt-in for the Defender-disabling lab policy |

`windows_logging_policy_names` contains the three names above.
`windows_logging_policy_links` contains `logging`, `enrollment`, and `defender`
lists, empty by default. Each item has a `target` (`domain_root` or an explicit
target-domain/OU DN), boolean `enabled`/`enforced`, and optional positive
integer `order`. Empty links never imply a domain-root link.

The logging settings expose the 15 GUID-keyed advanced-audit subcategories and
the `module_logging_enabled`, `module_names`, `script_block_logging_enabled`,
`script_block_invocation_logging_enabled`, `transcription_enabled`,
`transcription_invocation_header`, and `transcription_directory` values under
`windows_logging_policy_powershell`. The role does not create, protect, retain,
or collect the transcription destination. The enrollment map defaults to the
only verified v1 bundle:
`renew_update_revoke: true`, `update_templates: true`, expiration 10, store
`MY`. Enabling enrollment with either boolean false is rejected; no other
`AEPolicy` bit mapping is inferred. The Defender map contains the two readable
legacy intent switches, but has no effect without the single policy opt-in.

`windows_logging_policy_audit_subcategories` items contain `guid`, `success`,
and `failure`. `windows_logging_policy_enrollment` also exposes
`offline_expiration_percent` and the v1-fixed `offline_expiration_store: MY`.
`windows_logging_policy_defender` exposes `disable_antispyware` and
`disable_realtime_monitoring`; these values are considered only when the single
Defender-disabling-policy opt-in is true.

## Execution and helper contract

`tasks/main.yml` validates the designated inventory host and input container
types, then includes `tasks/policy.yml`. The latter passes one structured,
lowercase `Configuration` hashtable to `ansible.windows.win_powershell`; input
values are not interpolated into executable PowerShell. The inline wrapper is
assembled by controller-side lookups of the three project-owned function files,
sets Ansible changed/result explicitly, and does not remotely stage scripts.

`Invoke-LoggingPolicy([hashtable] Configuration, [bool] PlanOnly,
[hashtable] Progress)` returns
`changed`, `planned_changes`, and `policies`. It obtains a read-only context,
acquires the per-domain writer, rereads the authoritative context under that
lock, reconciles GPOs and registry settings, publishes audit state, then changes
links only after content readback. The writer is always disposed in `finally`.
`Progress` is an optional invocation-local carrier created by the task wrapper;
on a terminating failure the wrapper reports the affected policy, phase and
state path plus completed and uncertain mutations, sets changed when either may
have occurred, and still terminates the task. It is not durable recovery state.

`Publish-LoggingAudit([hashtable] Context, [hashtable] State,
[string] DesiredCsv, [bool] PlanOnly)` returns `changed` and `state`. It is not
an importer or public migration API; it requires the caller-held lock and the
already verified role-owned logging GPO.

`files/LoggingPolicyState.ps1` exports:

- `Get-LoggingPolicyContext([hashtable] Configuration)`: validates settings,
  resolves and verifies the joined domain and selected writable DC, tests LDAP
  and selected-DC SYSVOL access in the current session, loads protected state,
  and reconciles state GUIDs with exact role markers. It is read-only.
- `Enter-LoggingPolicyWriter([hashtable] Context, [bool] PlanOnly)`: acquires a
  fileless per-domain named mutex and returns an `IDisposable`. Plan/check mode
  creates no directory or state/lock file.
- `Write-LoggingPolicyState([hashtable] Context, [hashtable] State)`: validates
  identity/schema, writes a same-directory temporary file, flushes it, applies
  a protected ACL, atomically replaces state, and verifies the result.

Configuration uses the public names with the prefix removed and additionally
contains `execution_inventory_host` and `desired_audit_csv`. Context returns
`domain_dns`, `domain_dn`, `domain_guid`, `dc`, `sysvol_root`, `state_path`,
`writer_host`, `owner_id`, and `state`. Before any mutation, the caller must
hold the writer handle and call `Get-LoggingPolicyContext` again; the earlier
read-only view is not authoritative.

### Pending ownership shape

Every pending record has `operation`, `target`, `prior_ownership`, and
`intended_ownership`; only audit operations additionally have `audit` with the
W1 version/extension/hash/backup fields. The operation discriminator fixes the
remaining shape:

| Operations | Exact target-specific field | Exact prior/intended field |
| --- | --- | --- |
| `create` | `gpo_guid` (nullable before creation) | `gpo_guid` |
| `registry_add`, `registry_update`, `registry_remove` | one `registry_identifier` | full policy-scoped `registry` identifier lists |
| `audit_publish`, `audit_delete` | nonempty policy-scoped `audit_guids` plus W1 audit publication state | full `audit_guids` lists |
| `link_add`, `link_update`, `link_disable` | one canonical `link_target` DN | full canonical `link_targets` lists |

Every target also contains `policy_id`, `target_name`, and, except for the
pre-creation phase, a nonnull `gpo_guid`. Add/update/remove transitions must
match the prior and intended ownership lists. Irrelevant operation fields,
duplicate identifiers, foreign policy registry values/audit GUIDs, and stored
links outside the selected domain fail closed. Logging module-name identifiers
remain configurable values under the one owned `ModuleNames` key; ownership
validation does not restrict them to the default wildcard.

For every audit operation, `desired_deletion` is true exactly when
`desired_hash` is null; a non-deletion carries a nonnull SHA-256. An
`audit_publish` never requests deletion. `audit_delete` means removal of owned
audit rows, not unconditional removal of `audit.csv`: it may carry a nonnull
desired hash when valid unrelated rows remain, or request file deletion only
when no supported rows remain. This preserves unrelated CSV content while
keeping recovery intent unambiguous.

## Native policy and link lifecycle

New GPO intent is persisted before `New-GPO`; the GPO is created unlinked with
its exact owner marker supplied through `New-GPO -Comment`, its returned GUID is
then persisted before content mutation, and committed state is written only
after marker readback. Every registry operation uses the committed
GPO GUID and explicit discovered domain and selected DC. Retirement uses
`Remove-GPRegistryValue` with an exact `ValueName`; it never removes a key,
authors a client-side deletion directive, replaces a whole GPO, or changes user
policy. A desired registry identifier that already exists without committed
ownership fails closed even when its type/value matches and even in check mode;
owned value drift remains reconcilable. Module-name entries use additive native
list semantics. Enrollment
writes only `AEPolicy=7`, `OfflineExpirationPercent`, and
`OfflineExpirationStoreNames=MY`; it never writes a `PolicyServers` tree.

Only configured direct links are considered. `domain_root` resolves to the
discovered domain DN; explicit DNs must resolve in that same domain. Empty links
create no implicit link. New links follow successful content readback, and an
optional order is sent only when requested. Omitted previously owned links are
disabled and remain recorded; unrelated links are neither reordered nor
deleted. A disabled never-managed policy is a no-op. Disabling a previously
managed policy removes only its committed registry/audit settings, disables its
committed links, and retains the marked GPO.

## Bounded advanced-audit publication

The Jinja template describes only the configured role-owned system-subcategory
rows. The publisher reads strict BOM-less UTF-8/CRLF `audit.csv`, validates all
seven fields and the system, per-user, audit-option, and global-SACL row classes,
rejects duplicate semantic keys or malformed class order, and preserves valid
unrelated rows in their class segments. It compares owned rows by GUID and
numeric setting, so display-only differences do not force a rewrite. Validation
accepts the complete explicit subcategory GUID table in the cited MS-GPAC
section for unrelated-row preservation, while role ownership remains limited to
the configured 15 GUIDs. Per-user targets are parsed by the native Windows
`SecurityIdentifier` type and keyed by its canonical `Value`; their original CSV
rows remain byte-for-byte preserved when republished.

All authoritative reads and writes use the selected DC. The publisher validates
the domain-form `gPCFileSysPath` identity but independently constructs the
selected-DC SYSVOL path. After native registry operations it freshly reads CSV,
LDAP `versionNumber`/`gPCMachineExtensionNames`, and `GPT.INI`, requiring AD and
GPT versions to agree. A changed publication persists a protected prior backup
and exact pending prior/intended state, rechecks prior state, then writes CSV,
verifies the payload hash or deletion before any version mutation, sends one
LDAP modify with replacement values for both attributes, updates GPT, and reads
everything back again before clearing pending. Only the machine half is
incremented; zero wrap becomes one and the user half is preserved. Unrelated
extension tuples are preserved and sorted. Removing the final tuple uses an LDAP
replace with zero values, not an empty string.

`audit_delete` removes committed owned rows. If unrelated valid rows remain it
publishes their nonnull resulting hash and retains the file/tuple; it requests
file deletion only when no supported rows remain. No semantic payload or
extension change means no version increment. Mixed removal/addition is handled
as bounded delete then publish transitions, each with its own pending state and
readback.

## Ownership, state loss, and recovery

State is one JSON file per domain under the configured directory. Schema 1
binds `owner_id`, domain GUID, designated writer, and policy records to exact
GPO GUIDs. A GPO description marker and matching protected state are both
required. An unmanaged name, marker/GUID replacement, moved or missing marked
GPO, owner/domain/writer mismatch, unknown schema, malformed pending record, or
any unresolved pending operation fails closed. Names/descriptions are never
used to reconstruct or adopt ownership.

The state directory and file reject reparse points and use a non-inherited ACL
limited to the execution identity, SYSTEM, and local Administrators. Moving the
writer or state path requires an explicit protected state transfer and
authoritative reconciliation. Pending recovery is an operator-reviewed bounded
procedure; there is no blind retry, automatic rollback, or generalized journal.
With all policies disabled and no prior state/marker, invocation is a read-only
no-op and creates no state. Check mode still performs authorized discovery and
comparison and acquires the fileless mutex, but creates no GPO/state/backup,
changes no registry/link/CSV/LDAP/GPT value, and increments no version.

An interruption after pending persistence deliberately blocks an ordinary
rerun, including when CSV already matches desired while old AD/GPT versions
still agree. Recovery is not implemented as a blind command. An operator must
compare the protected prior/intended record with CSV, extensions, AD version,
and GPT version on the recorded DC, reject any third/intervening state, then
explicitly complete the missing prescribed steps or restore the protected prior
payload through a new versioned publication. Clear pending only after complete
authoritative readback.

## Provenance and behavior differences

The readable mappings and protocol are derived from the primary references in
`docs/research/2026-10-22-windows-logging-policy-evidence.md` plus reused static
inspection of the recorded commit-pinned legacy archive; no archive bytes are
bundled or imported and redistribution permission for that archive remains
unestablished. Unlike the legacy import, this role does not touch built-in
policies, copy source-domain ACL/SID/PolicyServers material, enforce domain-root
links by default, provision AD CS/templates, or make Defender disabling a
logging dependency. Running old and new overlapping policies requires separate
operator inventory and retirement decisions.

## Verification status

Static checks can inspect defaults, metadata, interfaces, source ordering,
template grammar, and obvious forbidden commands only. No Windows PowerShell
5.1 parser/runtime, LDAP/SMB permissions,
second-hop path, real lock contention, ACL enforcement, state loss/transfer,
RODC/wrong-domain failure, crash recovery, replication, client application, or
effective audit/PowerShell/enrollment/Defender behavior has been verified.
Implementation and static checks do not establish deployment readiness. Live
operations require separate authorization.
