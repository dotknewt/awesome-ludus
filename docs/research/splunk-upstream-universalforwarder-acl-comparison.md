# Upstream UF role ACL comparison

**Repository inspected:** `curi0usJack/ludus_splunk_universalforwarder`  
**Pinned commit:** `bbe6a31adddf72f0c7ecee2edaa5f4ebb7ba332e` (the `main` tree
API returned this commit; retrieved 2026-10-20).  Source review only: no guest
probe, deployment, mutation, upload, or local role edit.

**Implementation update — 2026-10-20:** The collector's custom Windows
filesystem ACL policy discussed below has since been removed at the user's
direction that no stricter requirement was intended. The comparison remains
historical research: it does not establish the current role's effective
installer/inherited permissions, prove file access, or alter the separate
Event Log READ ACE behavior.

## Answer

This role does not explicitly solve the `etc/system/local` ACL problem. It
avoids the bootstrap-seed path entirely: there is no `user-seed.conf` template
or task, no `icacls`, `win_acl`, `win_acl_inheritance`, ownership, deny ACE, or
service-account ACL task in the pinned tree. It creates/configures only
`inputs.conf` and (when an indexer is set) `outputs.conf`, then starts the
service. Absence of an ACL task does not prove the effective MSI ACL or service
identity.

## Retrieved source evidence

* [Pinned tree](https://api.github.com/repos/curi0usJack/ludus_splunk_universalforwarder/git/trees/bbe6a31adddf72f0c7ecee2edaa5f4ebb7ba332e)
  lists only `tasks/main.yml`, `defaults/main.yml`, two config templates, and
  metadata/README. No Windows service script, ACL script, or seed template is
  present.
* [`tasks/main.yml` (raw, pinned)](https://raw.githubusercontent.com/curi0usJack/ludus_splunk_universalforwarder/bbe6a31adddf72f0c7ecee2edaa5f4ebb7ba332e/tasks/main.yml)
  exact excerpts: it builds MSI arguments beginning `AGREETOLICENSE=yes`
  followed by `SPLUNKUSERNAME`, `SPLUNKPASSWORD`, `RECEIVING_INDEXER`, and
  optionally `DEPLOYMENT_SERVER`; it does not set `LAUNCHSPLUNK` or
  `SERVICESTARTTYPE`. Later tasks create `...\etc\system\local`, render
  `inputs.conf` and `outputs.conf`, stop an existing service, and use
  `win_service` with `start_mode: auto` and `state: started`.
* [`defaults/main.yml` (raw, pinned)](https://raw.githubusercontent.com/curi0usJack/ludus_splunk_universalforwarder/bbe6a31adddf72f0c7ecee2edaa5f4ebb7ba332e/defaults/main.yml)
  sets an admin username/password input and `splunk_uf_start_service: true`.
  The credential value is intentionally not reproduced here. Defaults also
  pin UF `9.3.2`/`d8bb32809498`, while the README table states different
  `9.4.0`/`6b4ebe426ca6` values; this is an upstream consistency issue, not ACL
  evidence.
* [`README.md` (raw, pinned)](https://raw.githubusercontent.com/curi0usJack/ludus_splunk_universalforwarder/bbe6a31adddf72f0c7ecee2edaa5f4ebb7ba332e)
  describes Windows installation and admin credentials, but does not describe
  service identity, ACL hardening, seed cleanup, or credential-file cleanup.

## Comparison to the known failure

The failure described here came from the collector's now-removed custom
filesystem ACL policy; it is historical and not a current role prerequisite.

The upstream design does not create a credential seed and does not attempt to
change the shared directory DACL. Therefore it cannot encounter the custom
collector's seed-parent conflict (`FullControl2032127` versus expected
read/execute `1179817`, flags `3`) through its own code; that is avoidance, not
a demonstrated fix. It also does not establish whether the MSI-created files
are writable by the service, whether the service runs as LocalSystem or another
identity, or whether credentials remain exposed in MSI arguments/configuration.
The source contains no cleanup task for MSI arguments, credentials, or seed
files. Effective runtime permissions and credential disposition remain
unverified.

## Provenance limits

All source URLs above are pinned raw/API GitHub URLs and returned HTTP 200.
Line numbers are omitted because GitHub raw retrieval is unnumbered; the cited
file paths and commit SHA make the excerpts independently addressable. No
Splunk installer behavior is inferred from this role's omissions.
