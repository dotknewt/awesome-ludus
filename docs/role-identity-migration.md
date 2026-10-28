# Linux role identity migration

This repository standardizes source-local directory names and
`galaxy_info.role_name`. It does not migrate an installed Ludus server or
change role variable APIs.

## Historical identities

| Previous identity or directory | Canonical identity and directory |
| --- | --- |
| Metadata identity `linux_splunk_enterprise` | `linux_splunk_server` |
| Metadata identity `ludus_gitlab_ce` | `linux_gitlab_ce` |
| Metadata identity `ludus_linux_logging` | `linux_logging` |
| Directory and metadata identity `ludus_gitlab_runner` | `linux_gitlab_runner` |
| Directory and metadata identity `ludus_k3s_bootstrap` | `linux_k3s_bootstrap` |
| Directory `linux_docker`; metadata identity `ludus_install_docker` | `linux_install_docker` |

Legacy tokens in variable prefixes remain supported inputs, not role aliases.
Persisted ownership markers also retain their historical values: Runner's
`managed by ludus_gitlab_runner`, K3s's `owner: ludus_k3s_bootstrap`, and
Linux logging's `Managed by ludus_linux_logging`. These identify files already
managed on deployed guests; renaming them would break safe convergence.
Existing author attribution is preserved. Historical specifications and
incident records describe the identities used at their recorded time; they
are not current installation instructions. No compatibility-wrapper roles
are provided.

## Staged operator migration

These are future operator steps, not actions performed by this change.

1. Record the target Ludus version, source revision/catalog, installed role
   identities, and effective user/global scope. Inventory every deployed and
   saved range that references the old identities, including dependency pairs
   and internal role calls. Keep the original range configuration and source
   revision available for rollback; do not commit private configuration.
2. Compare the target version's official documentation or source against its
   actual catalog and installed-role listing. Resolve any naming discrepancy
   before changing a deployed range. Matching repository directory and
   metadata names alone does not establish the installed identity.
3. With separate installation authorization, install the canonical roles from
   a reviewed immutable source revision in the required scope. Retain legacy
   installations for ranges not yet migrated; verify the reported canonical
   identities before switching their references. Do not assume refreshing a
   source catalog has replaced installed bytes.
4. Update each selected range's role assignments and exact `depends_on` role
   references together. Preserve its variable values and executor/telemetry
   choices. With separate deployment/probe authorization, verify installation
   and convergence. A repository static check is not that verification.
5. Retire legacy installations only after all affected ranges and saved
   configurations have migrated and rollback requirements permit it. Removal
   requires separate authorization. Until then, keep them untouched.

## Official guidance and compatibility boundary

Reviewed on 2026-10-28: the current [Ludus 2 sources documentation](https://docs.ludus.cloud/docs/using-ludus/sources)
describes source-local roles under `ansible/roles/<name>/`, references by
directory name, per-user installation with an optional global scope, and
additive installation. It distinguishes a refreshed source catalog from
installed artifacts and notes that removing a source registration leaves
installed roles on disk. These are current documentation statements, not
evidence of behavior on a particular target version.

Target version/catalog and installed-role evidence have **not** been captured
for this migration. Server identity compatibility, installation, convergence,
and retirement remain **NOT VERIFIED**. No server role installation/removal,
live deployment, or guest probe is authorized by this document.
