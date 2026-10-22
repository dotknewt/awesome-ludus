# windows_logging_policy

Authors three optional, readable Windows domain policies without importing a
foreign GPO backup. All policies are disabled and unlinked by default. This W2
delivery contains defaults and the state/preflight helper only; the Ansible
entrypoint, native registry/link operations, and advanced-audit publisher are
assembled in W3. It is not deployable by itself.

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
the PowerShell module/script-block/transcription settings in
`defaults/main.yml`. The helper validates their shape but does not publish
them. The enrollment map defaults to the only verified v1 bundle:
`renew_update_revoke: true`, `update_templates: true`, expiration 10, store
`MY`. Enabling enrollment with either boolean false is rejected; no other
`AEPolicy` bit mapping is inferred. The Defender map contains the two readable
legacy intent switches, but has no effect without the single policy opt-in.

## Helper contract

`files/LoggingPolicyState.ps1` exports:

- `Get-LoggingPolicyContext([hashtable] Configuration)`: validates settings,
  resolves and verifies the joined domain and selected writable DC, tests LDAP
  and selected-DC SYSVOL access in the current session, loads protected state,
  and reconciles state GUIDs with exact role markers. It is read-only.
- `Enter-LoggingPolicyWriter([hashtable] Context, [bool] PlanOnly)`: acquires a
  fileless per-domain named mutex and returns an `IDisposable`. W3 must dispose
  it in `finally`. Plan/check mode creates no directory or state/lock file.
- `Write-LoggingPolicyState([hashtable] Context, [hashtable] State)`: validates
  identity/schema, writes a same-directory temporary file, flushes it, applies
  a protected ACL, atomically replaces state, and verifies the result.

Configuration uses the public names with the prefix removed and additionally
contains `execution_inventory_host` and `desired_audit_csv`. Context returns
`domain_dns`, `domain_dn`, `domain_guid`, `dc`, `sysvol_root`, `state_path`,
`writer_host`, `owner_id`, and `state`. Before any W3 mutation, the caller must
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
With all policies disabled and no prior state/marker, the eventual W3 invocation
is a read-only no-op and creates no state.

## Verification status

Static checks can inspect defaults, metadata, interfaces, and obvious forbidden
commands only. No Windows PowerShell 5.1 parser/runtime, LDAP/SMB permissions,
second-hop path, real lock contention, ACL enforcement, state loss/transfer,
RODC/wrong-domain failure, crash recovery, replication, client application, or
effective audit/PowerShell/enrollment/Defender behavior has been verified.
Implementation and static checks do not establish deployment readiness. Live
operations require separate authorization.
