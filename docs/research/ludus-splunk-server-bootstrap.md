# Ludus Splunk server bootstrap research

**Research date:** 2026-10-19  
**Purpose:** Findings for a possible future, minimal Ludus role that bootstraps a native Splunk Enterprise server. This is research, not an approved implementation plan.  
**Methods:** Static inspection of official Splunk Ansible source at immutable commit [`efc2012d02ac2220920ae452a683376549166bfd`](https://github.com/splunk/splunk-ansible/tree/efc2012d02ac2220920ae452a683376549166bfd) and fetched official Ansible `get_url` documentation. No package binaries or commands were run. Splunk Help documentation returned HTTP 403 to the researcher; OS support information below is user-supplied.

## Findings from official Splunk Ansible source

Use the pinned commit links below as source evidence; these are not proof that the same behavior or compatibility applies to Splunk Enterprise 10.6.

### First-run admin authentication and seed handling

In [`roles/splunk_common/tasks/enable_admin_auth.yml`](https://github.com/splunk/splunk-ansible/blob/efc2012d02ac2220920ae452a683376549166bfd/roles/splunk_common/tasks/enable_admin_auth.yml), the `first_run` block runs `splunk hash-passwd PASSWORD` (`no_log` is controlled by `hide_password`), then writes `etc/system/local/user-seed.conf` with `[user_info]`, `USERNAME`, and `HASHED_PASSWORD`, owned by the `splunk` OS account/group. The OS service account `splunk` is distinct from the Splunk application admin username.

The source demonstrates a hashed-password seed value. It does **not** establish a supported plaintext `PASSWORD` field in the seed file: the relevant 10.0 specification could not be verified (403). A pre-hashed input is therefore an evidence-backed option, but its generation and input interface remain a design choice needing further evidence. Do not require a particular operator hash-generation tool or secrets-management system based on this research.

`no_log` protects Ansible task output; it does not hide a secret passed in a process argument. Do not copy the source's `splunk hash-passwd PASSWORD` argv-secret pattern into a new role. A candidate implementation should avoid secrets in argv, protect any generated seed (for example mode `0600`), and remove only a seed it created after successful bootstrap. Preserve existing `etc/passwd` and do not reseed on reruns. The source's `first_run` variable is not evidence that an arbitrary installed package is a fresh native instance; fresh-install detection semantics remain unresolved.

Repository policy in [`docs/instructions/ludus-authoring.md`](../instructions/ludus-authoring.md) governs any later Ludus role. Its disposable username/password defaults and optional `role_vars` overrides do not imply mandatory Vault integration or rotation. Real external download tokens must not be committed.

### Source task sequence and service startup

[`roles/splunk_common/tasks/main.yml`](https://github.com/splunk/splunk-ansible/blob/efc2012d02ac2220920ae452a683376549166bfd/roles/splunk_common/tasks/main.yml) orders fact gathering and upgrade/configuration-change checks before installation, then calls admin authentication, service enablement on first run when enabled for Linux, Splunk start, and seed cleanup. This is a useful sequence reference, not a validated 10.6 native Debian 13 procedure.

The source's [`enable_service.yml`](https://github.com/splunk/splunk-ansible/blob/efc2012d02ac2220920ae452a683376549166bfd/roles/splunk_common/tasks/enable_service.yml) uses this command for versions `>= 7.2.2`:

```text
/opt/splunk/bin/splunk enable boot-start -systemd-managed 1 -user splunk --accept-license --answer-yes --no-prompt
```

This is a root-privileged enablement operation with intent to run the daemon as the non-root `splunk` user. The source uses `Splunkd.service.j2` only as a fallback for versions `< 7.2.2`; do not infer 10.6 unit content from that legacy template. No unverified `-group` argument is implied.

[`start_splunk.yml`](https://github.com/splunk/splunk-ansible/blob/efc2012d02ac2220920ae452a683376549166bfd/roles/splunk_common/tasks/start_splunk.yml) uses the configured service name with service state `started`. Its non-service CLI branch runs `start --accept-license --answer-yes --no-prompt` with five retries and ten-second delay, then waits for the management port. A listening management port is not proof of successful authenticated admin login.

The enablement tasks contain a cgroup v1 guard when a v2 controllers file exists. Do not copy historical cgroup workarounds as universal requirements. Actual unit name/content, user ownership, generated service behavior, and cgroup v2 compatibility on Debian 13 must be inspected during separately authorized native 10.6 validation. The source's enablement/start command flags do not settle native 10.6 General Terms acceptance. Docker's `SPLUNK_GENERAL_TERMS` environment variable is not evidence that the same mechanism works for native installation. No terms were accepted during this research.

### Candidate flow (derived, not validated)

For a future minimal server role, evidence suggests investigating this order: establish the OS `splunk` account; verify/install the selected package; ensure appropriate ownership; seed admin credentials only for a known-fresh instance; enable boot-start/systemd before first start; reload/enable/start systemd; perform bounded health and authenticated-login checks; then remove only the role-owned seed. A failed bootstrap must not be reported as success, trigger destructive credential reset, or blindly delete/recreate existing `etc/passwd` state. Exact first-run detection and recovery semantics need resolution before implementation.

All package/license lifecycle commands are contingent on the operator accepting applicable Splunk terms beforehand. Do not add HEC, telemetry, forwarding, apps, or logging configuration to a bare-server bootstrap unless separately required.

## Package acquisition and integrity

The exact Enterprise `.deb` URL/build and publisher checksum/algorithm remain unresolved. The [Splunk Enterprise download page](https://www.splunk.com/en_us/download/splunk-enterprise.html) is an acquisition reference, not a verified artifact URL or authentication-flow specification. Confirm product is Enterprise (not Universal Forwarder), target architecture is amd64, and version/build metadata before install. No package was downloaded.

Official Ansible [`get_url`](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/get_url_module.html) documents `checksum` as either `algorithm:digest` or `algorithm:checksum-url`. For a fixed release, prefer an explicit trusted publisher-provided checksum; use SHA-256 or SHA-512 only when the publisher evidence confirms the applicable algorithm. Locally computing a digest does not authenticate publisher provenance. Do not invent `.sha256` / `.sha512` endpoints or claim a pin without artifact evidence.

For authenticated `get_url`, the module documents `url_username` / `url_password`; by default redirects forward headers. `unredirected_headers: ['Authorization']` can mitigate forwarding an Authorization header. Compatibility with Splunk's actual download/auth flow is untested. Keep HTTPS certificate validation enabled. These are acquisition findings, not a selected download implementation.

## Operating system evidence

The user supplied a Splunk 10.6 support-table entry listing Debian 13, Ubuntu 24.04, and Ubuntu 26.04 x86_64 as supported for Splunk Enterprise. The cited [10.6 system requirements page](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.6/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises?pdfdownload=true) returned 403 to the researcher, so the table is recorded as user-supplied evidence, not independently fetched or verified here. Retain Debian 13 as the default host preference; the supplied table gives no unsupported-OS reason to switch to Docker. This OS row does not prove package, service, or bootstrap compatibility for a selected 10.6 build.

## Open evidence and decisions

| Open item | Current status |
|---|---|
| Selected 10.6 `.deb` URL and publisher checksum | URL and `.sha512` sidecar fetched 2026-10-19; see selected-artifact update below. Package binary remains undownloaded and its Debian metadata uninspected. |
| Native 10.6 license and General Terms acceptance mechanism | Unresolved; no terms accepted. Docker environment variable is not transferable evidence. |
| Seed generation/input contract and fresh-instance detection | Hashed seed value is evidenced in source; safe generation mechanism, plaintext support, and first-run semantics are unresolved. |
| Actual 10.6 systemd unit/service behavior, ownership, and Debian 13 cgroup v2 | Must inspect in authorized native validation; not established by legacy template or source commands. |

The initial research proposed a `ludus_splunk_server_`-prefixed input interface and left plaintext versus hashed admin credentials unresolved. The authored role now uses a plaintext fresh-instance seed and pins a selected package URL, expected version, and publisher checksum in its defaults; see the implementation README. Runtime compatibility remains unverified.

## Verification boundary

Static review for a later implementation can inspect syntax, interfaces, and source logic, including checksum-validation and install ordering; it cannot demonstrate actual checksum rejection before installation. Only authorized live testing on a disposable native target can establish selected-version behavior, including a checksum-mismatch case that confirms installation does not proceed; fresh bootstrap with non-root daemon and authenticated health check; convergence preserving credentials; reboot with service enabled; and failure paths that neither claim success nor reset credentials destructively. Simulations or stateful fakes are not evidence of live role behavior. No code, role, blueprint, install, deployment, or live test was performed for this note.

## Verified official Splunk 10.6 documentation update (2026-10-19)

The earlier HTTP 403 limitation above is superseded for the references in this
section: the researcher retrieved these official Help pages through Firecrawl
on 2026-10-19. This verifies documented behavior, not compatibility of a
selected package on a target.

- [Splunk 10.6 `user-seed.conf` reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/user-seed.conf): `USERNAME`, plaintext `PASSWORD`, and `HASHED_PASSWORD` are documented under `[user_info]`. If a plaintext password ends in `\\`, append a space for parsing (the space is not part of the password). An existing `etc/passwd` means the seed is ignored.
- [Run Splunk Enterprise as a systemd service](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/start-splunk-enterprise-and-perform-initial-tasks/run-splunk-enterprise-as-a-systemd-service): Splunk's `enable boot-start` generates `/etc/systemd/system/Splunkd.service` by default; `-systemd-unit-file-name Splunkd`, `-user`, and `-group` are documented. Use the vendor-generated unit rather than a copied legacy template. The generated service runs non-root; its memory limit reflects memory at unit generation and does not automatically track later host sizing changes.
- [Start Splunk Enterprise for the first time](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.6/start-using-splunk-enterprise/start-splunk-enterprise-for-the-first-time): documents `--accept-license --answer-yes --no-prompt` and the plain-text seed example. This does not remove the operator's responsibility to accept applicable terms before enabling the role input.
- [Install Splunk Enterprise on Linux](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.6/install-splunk-enterprise-on-linux-or-macos/install-on-linux): documents root installation of `.deb` and requires `/opt/splunk` to be a regular directory, not a symlink. It also warns about Debian's default `dash` shell and recommends considering Bash; this role does not change `/bin/sh`. The selected build's behavior remains a live-verification item.
- [About Splunk Free](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configure-splunk-licenses/about-splunk-free): trial initially runs for 60 days; changing to Free is a manual Settings/Licensing operation and restart. Free removes authentication/users/alerts. Therefore this server role must not automate a trial-to-Free switch.

Implementation decision based on these references: the role's fresh seed uses
documented plaintext `PASSWORD`, is protected as mode `0600`, and is not
rewritten after `etc/passwd` exists. It rejects passwords ending in a
backslash rather than silently changing their value. It requests the documented
vendor-generated systemd unit with explicit non-root user and group before
first start, and does not change `/bin/sh`. Debian 13 amd64 remains the only
role target; Ubuntu 24.04/26.04 user-supplied support information is not
translated into role support without implementation verification.

Target-side behavior remains unverified. No package binary was downloaded, no
terms accepted, and no target Ansible, installation, or deployment was run.

## Selected package URL and publisher digest update (2026-10-19)

The selected URL was supplied as:
[`splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb`](https://download.splunk.com/products/splunk/releases/10.6.1.1/linux/splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb).
The official HTTPS URL and its
[`sha512` sidecar](https://download.splunk.com/products/splunk/releases/10.6.1.1/linux/splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb.sha512)
were fetched on 2026-10-19; both returned status 200 without redirects. The
sidecar response was `text/plain`, Last-Modified `Thu, 15 Oct 2026 20:52:40
GMT`, and reported:

```text
SHA512(splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb)= f3f67f699fcd893ffd280b602a47215f5e7eb9b481cb242b08705a4db8ada489febb3fa49cb90f9bd1397603d9207ea5ac9bf59eec62f99d030c3f2ff738eb89
```

The role uses this publisher-reported digest and currently expects Debian
package Version `10.6.1.1`, but neither the binary nor its package metadata was
inspected to confirm that value. The published hash has not been compared
against a downloaded binary. Selected-build compatibility and live readiness
remain unverified; no package download, terms acceptance, or deployment
occurred.
