# Splunk Windows UF bootstrap file provenance

**Research date:** 2026-10-20  
**Artifact scope:** Splunk Universal Forwarder `10.6.1.1`, build
`b2ae2962645c`, Windows x64 MSI.  This is documentary research only.  It is
not evidence of installation, service startup, ACL effectiveness, or runtime
forwarding.

## Findings

### Message-file classification: **NOT ESTABLISHED from primary source**

This bounded pass did not produce a readable official `messages.conf` page or
an exact official excerpt for per-filename semantics. It also did not produce
an official excerpt establishing the `inputs.conf`/`outputs.conf` claims.
No exact official excerpt defining `TCPOUT` or
`TCPOUT:FORWARDING_BLOCKED__S_S_S_LD` was obtained. Those exact names
came from the read-only guest/default-tree observation, not retrieved web
evidence; their semantics are therefore not asserted here as primary-source
fact.

Candidate references (not retrieved in this pass):

* [About configuration files](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/about-configuration-files)
  — candidate previously recorded; not retrieved in this pass.
* [`inputs.conf`](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/inputs.conf)
  — candidate previously recorded; not retrieved in this pass.
* [`outputs.conf`](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/outputs.conf)
  — candidate previously recorded; not retrieved in this pass.
* Candidate [`messages.conf`](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/messages.conf)
  URL; unavailable to the retrieval tool and not treated as retrieved evidence.

The candidate URLs are Splunk URLs previously recorded here, but the
retrieval tool returned HTTP 403 for these pages in this pass. Titles, versions,
and redirect chains could not be independently confirmed. The 9.4 path is
version context, not a verified excerpt. A generic `*.conf` scanner must not
classify a stanza as forwarding from its name alone.

### Installer-created files and runtime writability

The previously recorded [Windows UF installation procedure](https://help.splunk.com/en/splunk-cloud-platform/forward-and-process-data/universal-forwarder-manual/10.6/install-the-universal-forwarder/install-a-windows-universal-forwarder)
and [configuration-file reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/about-configuration-files)
remain candidate references. This pass obtained no exact-build manifest of
files created between MSI completion and first service start; unavailable
pages do not establish whether such documentation exists.

In particular, no retrieved official source proves all of the following
claims: that a fresh MSI necessarily creates `etc/system/local/authentication.conf`,
`server.conf`, and `README` before the first service start; which keys it
writes in each file; or that those files must remain writable by the service
 at runtime. The earlier read-only MSI-database inspection recorded product
 identity and installer-table observations for `/tmp/opencode/uf106.msi`; its
 artifact and checksum are recorded in
 `docs/research/ludus-splunk-collector-windows.md` (lines 9–17). It was not a
 guest filesystem/service probe and cannot answer these lifecycle questions.
 These remain live or exact-installer-source evidence gaps.

### ACL scope supported by the evidence

The available documentation does **not** establish a safe universal
inheritable read-only ACL for the shared `etc/system/local` directory, nor
that the service never writes `authentication.conf`, `server.conf`, or other
local files. Any seed-file-only scope is a research boundary for the parent to
assess, not an approved safety decision; parent permissions and existing
SYSTEM/administrative access must remain part of that assessment.

No ACL scope is approved by this document. Any seed-file, parent-directory,
service-account, inheritance, or write-denial change needs parent approval and
fresh-install/runtime verification on the selected Windows target.

## Version and evidence limits

The installation page is under the Splunk 10.6 documentation tree (page
metadata previously observed as 10.6.0), while the requested artifact is
10.6.1.1.  The configuration references linked above are 9.4 references.
They are **not established evidence in this pass** and do not prove exact
patch-build installer behavior. No guest access, package execution, service start,
ACL mutation, or live validation was performed.  No secrets are recorded.

## Unresolved questions for the parent safety decision

1. Does the exact MSI create the three named files before first service start,
   and with what contents?
2. Which of those files are subsequently written by the UF service, and under
   which service identity?
3. Does seed-file protection preserve required installer/service behavior on a
   fresh install and during convergence?
4. What is the effective ACL and inheritance behavior on the target Windows
   versions?  Official documentation found here does not answer this.
