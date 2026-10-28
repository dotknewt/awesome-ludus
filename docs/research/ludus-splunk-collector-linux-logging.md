# Debian amd64 Splunk Universal Forwarder collector research

**Research date:** 2026-10-20. **Scope:** primary-source research for a
minimal, independently reusable `ludus_splunk_collector` role. This is design
evidence, not runtime compatibility evidence; no package was downloaded and no
deployment was performed.

## Artifact and platform

The requested publisher artifact is:

```
https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb
```

The publisher sidecar was fetched successfully (HTTP 200, `Last-Modified:
Thu, 15 Oct 2026 20:52:18 GMT`) without downloading the package:

```
SHA512(splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb)=
2172ed26173b4f29e3ffb051800dce3b21701f8fa202466063a535dd9e7c2cac03714e5db026c4a5dd37249a23be017661a80b4969a339e1d653a16622180c31
```

Use `sha512:<digest>` with Ansible `get_url`; retain HTTPS certificate
verification and reject credentials in URLs. The sibling server role documents
Debian 13 amd64/systemd as its intended scope, but that is not evidence that
this Universal Forwarder build supports that OS. The role must assert the
declared platform and state that selected-version compatibility remains
unverified until an authorized native test.

## Recommended v1 contract

* Install only the Universal Forwarder package and own its configuration; do
  not automatically invoke `ludus_splunk_server` or any logging sibling.
* Expose namespaced inputs for package URL, `sha512:` checksum, exact version,
  license acceptance, collector service user/group, receiver endpoint
  (`host:port`), and opt-in input paths. Require an explicit nonempty endpoint;
  do not infer a VM name, IP, or sibling role.
* Require explicit license opt-in. A user seed should be created only for a
  fresh instance, mode 0600, owned by the service account, and removed only
  after an authenticated initialization check. Preserve an existing
  authentication database and refuse an unmanaged seed. The exact UF
  10.6.1.1 seed-file syntax was not confirmed in version-specific primary docs;
  validate it in an authorized native test rather than asserting compatibility.
* Generate/enable boot-start with the vendor systemd procedure, explicitly
  selecting a non-root `splunk` identity, then inspect the effective unit and
  application-tree ownership before starting. Verify readable log paths for
  that identity; do not weaken permissions broadly. The existing server role's
  generated-unit checks are a useful repository contract, not proof for UF.

Suggested minimal forwarder configuration (only when enabled by role inputs):

```ini
[tcpout]
defaultGroup = primary_indexers
[tcpout:primary_indexers]
server = <receiver-host>:9997

[monitor:///var/log/syslog]
sourcetype = syslog
[monitor:///var/log/auth.log]
sourcetype = linux_secure
```

Treat `/var/log/audit/audit.log` as opt-in and use `sourcetype=auditd` only
when auditd is installed and the file exists. “Sysmon for Linux” is not a
universal Debian input: do not monitor a guessed path by default; expose an
opt-in path and document that the Sysmon-for-Linux deployment supplies it.
Avoid recursive `/var/log` by default to prevent duplication/secrets. Splunk's
official `inputs.conf` reference says custom inputs belong in
`$SPLUNK_HOME/etc/system/local/`, default files must not be modified, and a
restart is required. It also defines `monitor` and explicit `sourcetype`.

On the Enterprise server, the paired receiver configuration is the matching
Splunk cooked-data listener:

```ini
[splunktcp://9997]
disabled = 0
```

The server role currently intentionally does not configure forwarding or
receiving, so this must be a separate explicit server-side contract/change.

## Ludus ordering and reuse

The official Ludus role-development page requires standard role structure and
`meta/main.yml`. The official range configuration documents that roles on one
VM run in listed order and that an object-form role can use `depends_on` with a
`vm_name` and `role`; dependencies can override list order. Therefore a
blueprint that uses a separate server role should explicitly order the server
before the collector (and use the installed role identity), while the collector
itself remains independently reusable and has no hidden `include_role`.

Example design (names are illustrative; server and collector are separate VMs):

```yaml
roles:
  - name: ludus_splunk_collector
    depends_on:
      - vm_name: "{{ range_id }}-splunk-server"
        role: ludus_splunk_server
```

Do not copy this into the role defaults: topology belongs in the blueprint.

## Primary sources and gaps

* [Splunk `inputs.conf` reference](https://help.splunk.com/en/?resourceId=Splunk_Admin_Inputsconf), accessed 2026-10-20: local `inputs.conf`, monitor syntax, sourcetype behavior, and restart requirement; its example includes TCP 9997.
* [Splunk `outputs.conf` reference](https://help.splunk.com/en/?resourceId=Splunk_Admin_Outputsconf), accessed 2026-10-20: forwarder destinations are configured in `outputs.conf`.
* [Splunk configuration-file forwarder guide](https://help.splunk.com/en/data-management/onboard-data-to-splunk-enterprise/forwarding-and-receiving-data/10.2/configure-forwarders/configure-the-universal-forwarder-using-configuration-files), accessed 2026-10-20: identifies `inputs.conf` and `outputs.conf` as UF configuration files.
* [Splunk enable-a-receiver guide](https://help.splunk.com/en/splunk-enterprise/forward-and-process-data/universal-forwarder-manual/10.4/configure-the-universal-forwarder), accessed 2026-10-20: receiver setup; Splunk search documentation identifies 9997 as the standard forwarder receiving port.
* [Ludus Ansible roles](https://docs.ludus.cloud/docs/developers/ansible-roles/), accessed 2026-10-20: standard structure, mandatory meta file, role testing.
* [Ludus range configuration](https://docs.ludus.cloud/docs/configuration/), accessed 2026-10-20: role order and `depends_on` shape.
* [Repository server role README](../../ansible/roles/linux_splunk_server/README.md) and tasks: repository-specific non-root systemd, seed, checksum, and license conventions. Link updated for the canonical directory; this research records the findings at its original date.

No official 10.6.1.1-specific page was found establishing Debian 13 support,
Universal Forwarder package metadata, exact boot-start invocation, seed syntax,
or permissions for the selected build. General documentation must not be
represented as 10.6.1.1 compatibility. Static validation can check the role
contract; only a separately authorized native Debian target can establish
installation, boot persistence, readable inputs, forwarding, and receiver
interoperability.

## ConstructingDefense audit/Laurel source review

The upstream script is [linux_logging.sh at commit
`ff544ce02aa30e7bb792724d15a43f86581a77e8`](https://raw.githubusercontent.com/Antonlovesdnb/ConstructingDefense/ff544ce02aa30e7bb792724d15a43f86581a77e8/linux_logging.sh)
(the repository `main` file was also observed on 2026-10-20). It installs
`auditd`, deletes `/etc/audit/rules.d/audit.rules`, downloads the repository
rules with `--no-check-certificate`, downloads Laurel v0.6.3, creates `_laurel`
with home `/var/log/laurel`, downloads `config.toml`, downloads the Laurel
plugin from the moving `master` branch, watches `/usr/local/bin/kubectl`, and
HUPs auditd. These destructive/unpinned operations are not suitable as-is.

The exact referenced files are:

* [`audit.rules` at ConstructingDefense commit
  `0cefe62755eebba7b226e611ece75160706e22f6`](https://raw.githubusercontent.com/Antonlovesdnb/ConstructingDefense/0cefe62755eebba7b226e611ece75160706e22f6/audit.rules),
  27,422 bytes. It begins with `-D`, `-b 8192`, `-f 1`, and `-i`; includes
  broad watches for audit/configuration, identity, SSH, systemd, package
  managers, shells, suspicious tools, `/usr/local/bin/kubectl`, and many
  syscall rules; and ends with `##-e 2` commented out. It is a broad policy,
  not a Debian-minimal default, and contains paths that may not exist.
* [`config.toml` at ConstructingDefense commit
  `0cefe62755eebba7b226e611ece75160706e22f6`](https://raw.githubusercontent.com/Antonlovesdnb/ConstructingDefense/0cefe62755eebba7b226e611ece75160706e22f6/config.toml),
  5,625 bytes. Exact operational defaults are `directory = "/var/log/laurel"`,
  `user = "_laurel"`, `statusreport-period = 0`, `input = "stdin"`,
  `[auditlog] file = "audit.log"`, `size = 5000000`, `generations = 10`, and
  `read-users = [ "debian" ]`. It enriches PID/container/script/user-group
  context, records `LD_PRELOAD` and `LD_LIBRARY_PATH`, outputs array-form
  execve arguments, and drops filtered events (`filter-action = "drop"`).
  The configured ACL reader `debian` does not match the intended Splunk
  service identity and must not be copied without an explicit permission
  decision. The config has no explicit mode/owner for rotated files; verify
  Laurel's actual defaults on a native target.
* [`laurel.conf` at the upstream `master` path](https://raw.githubusercontent.com/threathunters-io/laurel/master/etc/audit/plugins.d/laurel.conf)
  (not immutable) is exactly `active = yes`, `direction = out`,
  `type = always`, `format = string`, `path = /usr/local/sbin/laurel`,
  `args = --config /etc/laurel/config.toml`. Vendor this file at a pinned
  Laurel commit/tag rather than consuming `master`.

### Safer Ansible rework

Preserve the policy as a separately named managed rules fragment under
`/etc/audit/rules.d/` (or a clearly documented role-owned file), never delete
or replace `audit.rules`, and let `augenrules` merge all fragments. Before
loading, validate syntax and preserve unrelated files; handle audit's immutable
state explicitly rather than silently forcing a reload. Make the kubectl rule
conditional on an explicit variable and path existence, since the upstream
rule is only meaningful when `/usr/local/bin/kubectl` exists. Use a pinned
Laurel release and checksum, package-owned/plugin-owned paths, a dedicated
system user, restrictive config/log permissions, and a handler for the
authorized auditd reload. Do not assume the Splunk user can read Laurel output:
grant only the selected collector identity access, preferably through a
dedicated group/ACL, and document the resulting mode/ACL.

The v0.6.3 GitHub release is [tagged at commit
`f552ee5c0bba949649355b566463fee8d60257bc`](https://github.com/threathunters-io/laurel/releases/tag/v0.6.3).
Its release API exposes the x86_64-musl archive (2,419,809 bytes) but no
publisher digest (`digest: null`). A safe, non-executed download on 2026-10-20
produced SHA-256
`ee7704e87c831bbfcac8cf8741e92eb56b49b3c6d64629d4730c98d97568ec53`; this is
an observed transport hash, not a publisher-provided checksum, so it must not
be treated as sufficient authenticity evidence without an approved upstream
verification source. Laurel's pinned source [LICENSE](https://raw.githubusercontent.com/threathunters-io/laurel/v0.6.3/LICENSE)
is GPL-3.0-or-later. Debian provides a `laurel` package in bookworm and trixie
([package search](https://packages.debian.org/laurel)); prefer the Debian
package when its version/features meet the role contract, rather than
vendoring an unverified archive, but do not claim equivalence without testing.

### Splunk identity caveat

The general Splunk systemd documentation gives the vendor command
`splunk enable boot-start -systemd-managed 1 -user <username> -group
<groupname>` and shows `User=`/`Group=` in the generated unit. The repository
server role uses `splunk`; Debian UF packaging may create/use `splunkfwd`.
The exact UF 10.6.1.1 identity, package-created account, user-seed behavior,
and readable-path requirements were not established by a version-10.6.1.1
primary source. Therefore the collector must discover/assert the package's
actual supported identity (or explicitly configure one), inspect the generated
unit, and verify access to selected log files during authorized native testing;
it must not hardcode the server role's `splunk` identity or claim UF support
from Enterprise documentation.

Additional primary references: [Splunk systemd boot-start procedure](https://docs.splunk.com/Documentation/Splunk/8.2.12/Admin/RunSplunkassystemdservice),
accessed 2026-10-20 (general systemd behavior, version-mismatched); [Laurel
INSTALL.md](https://github.com/threathunters-io/laurel/blob/v0.6.3/INSTALL.md),
accessed 2026-10-20 (plugin/config setup); [Debian Laurel package details](https://packages.debian.org/trixie/laurel),
accessed 2026-10-20.

## Final source-verification corrections (2026-10-20)

The ConstructingDefense commit used above is the verified signed `main` head
`0cefe62755eebba7b226e611ece75160706e22f6`; GETs of both raw files at that
commit returned HTTP 200 and the same contents previously summarized. The
repository API root listing showed no `LICENSE`, `COPYING`, or other root
license file, and neither `audit.rules` nor `config.toml` contains a license
notice. The repository file comments attribute the audit rules to third-party
sources (including Gov.uk, linux-audit, and others), but that is not a license
grant. The repository's contents therefore have **no verified redistribution
license** in the inspected sources. Do not vendor or redistribute these files
under this repository's GPL license; obtain permission or author replacement
rules/configuration, and preserve attribution if merely referencing them.

Laurel v0.6.3 source inspection resolves the rotation/permission behavior. In
[`src/rotate.rs` at commit
`f552ee5c0bba949649355b566463fee8d60257bc`](https://raw.githubusercontent.com/threathunters-io/laurel/f552ee5c0bba949649355b566463fee8d60257bc/src/rotate.rs),
new files are created with mode `0600`; existing files are chmod'ed `0600` on
open. Laurel then applies an ACL containing owner `rw`, group `r`, other none,
plus one read ACL entry for every configured `read-users` name. Rotation
renames the basename to `.1`, `.2`, etc.; it does not recreate generations or
reapply ACLs during rename. Since each new basename is opened and ACL-applied
on the next write, configured named-user read access persists for new files and
rotated generations. The source does not document an inherited `default ACL`;
the ACL is explicitly applied to each active file. The parent directory is
chowned to the configured run-as user and chmod'ed `0755` in
[`src/bin/laurel/main.rs` at the same commit](https://raw.githubusercontent.com/threathunters-io/laurel/f552ee5c0bba949649355b566463fee8d60257bc/src/bin/laurel/main.rs).

`read-users` entries are resolved with `User::from_name`; a missing account
returns an error while logger construction is occurring, so the configured
`debian` user is not harmlessly ignored. A narrow collector ACL is therefore
possible without changing the upstream `read-users = ["debian"]`: configure
the collector account as an additional existing named `read-users` entry (and
ensure `debian` exists), or use a post-creation ACL mechanism only if native
testing proves rotation preservation. The cleanest v1 contract is to make the
collector identity an explicit existing account and set `read-users` to that
identity, rather than relying on a default ACL or broad directory access.

The same pinned `main.rs` shows that when Laurel starts as root and is
configured with a non-root user, its Linux `procfs` build retains effective
`CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` after UID/GID drop; it needs the
former for arbitrary file reads and the latter for process-environment
enrichment. It clears ambient capabilities afterward, but does **not** expose
an option in the inspected v0.6.3 config to disable those retained
capabilities. Running Laurel directly as a non-root service avoids the root
drop path (and logs “Not dropping privileges”), but may prevent audit-plugin
startup or enrichment as configured. Therefore explicit ACLs can address
Splunk readability, but must not be described as removing Laurel's capability
requirements; capability opt-out remains an unresolved packaging/service
design question requiring native testing and possibly a build/runtime change.

## UF ownership and generated-unit review follow-up

Splunk's [UF 10.4 least-privileged-user guide](https://help.splunk.com/en/splunk-cloud-platform/forward-and-process-data/universal-forwarder-manual/10.4/working-with-the-universal-forwarder/manage-a-linux-least-privileged-user)
explicitly instructs `chown -R splunkfwd:splunkfwd $SPLUNK_HOME`. Fresh recursive
ownership of the verified forwarder tree is therefore vendor-documented.
Its reference unit also includes an application-tree `ExecStartPre` chown and
CPU/memory cgroup `ExecStartPost` chowns, alongside the main launch command.
Rejecting every pre/post command would reject that documented unit shape.
The reference's main executable path differs from the package path selected
here; it must not be copied blindly. The page grants `CAP_DAC_READ_SEARCH` and
does not establish an opt-out flag. This role's empty-capability policy is a
local least-privilege choice, not a vendor compatibility claim. These 10.4
instructions are not evidence of the exact 10.6.1.1-generated unit or runtime.
