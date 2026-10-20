# ludus_splunk_collector

Install a standalone Splunk Universal Forwarder and configure it to send cooked
TCP data to an explicitly supplied Splunk receiver. This role does not install
or invoke `ludus_splunk_server`, change host firewall rules, configure TLS, or
create indexes.

> **Transport warning:** forwarding uses plaintext cooked TCP with no TLS.
> Keep the receiver and collector on an isolated, trusted lab network; do not
> expose this traffic to untrusted networks or treat it as production transport.

## Supported scope and evidence

Linux targets are Debian 13 (trixie), Ubuntu 24.04 (noble), and Ubuntu 26.04
(resolute), x86_64 with systemd. Windows targets are Windows 11 x64 and Windows
Server 2019/2022/2025 x64 with PowerShell 5.1. Both branches require ansible-core
>= 2.16; Windows uses `ansible.windows` 3.8.0 and `community.windows` 3.3.0.
Windows uses the separately pinned Universal Forwarder 10.6.1.1 x64 MSI and
SHA-512 checksum. The selected Windows OS/version compatibility, MSI service
identity, Event Log ACL behavior, seed authentication, and runtime convergence
remain **not verified** until separately authorized native tests.

Sources and evidence are summarized in
[`docs/research/ludus-splunk-collector-linux-logging.md`](../../../docs/research/ludus-splunk-collector-linux-logging.md).
No package installation or live target probe was performed while authoring this
role.

## Inputs

All inputs use the `ludus_splunk_collector_` prefix.

| Variable | Default | Purpose |
| --- | --- | --- |
| `package_url` | pinned Splunk 10.6.1.1 Debian artifact | HTTPS package source; URLs with embedded credentials are refused |
| `package_checksum` | publisher SHA-512 digest | Checksum required before installation |
| `version` | `10.6.1.1` | Exact Debian package version; a different installed version is refused, not silently upgraded |
| `accept_license` | `false` | Must be explicitly set to `true` |
| `admin_username` | `admin` | Used only for first-run initialization |
| `admin_password` | `SplunkLab-ChangeMe1!` | Disposable lab-only default; replace it for a lab, never use this literal in production |
| `receiver_host` | empty | Required DNS name or IPv4 host for the separate Splunk receiver |
| `receiver_port` | `9997` | Receiver TCP port, range 1–65535 |
| `monitors` | `/var/log/laurel/audit.log`, sourcetype `laurel:json`, index `main` | Explicit monitor entries; each has `path`, `sourcetype`, and `index` |

Windows additionally exposes four `ludus_splunk_collector_windows_*` artifact
inputs: `package_url`, `package_checksum`, `version`, and
`msi_product_version`. They default to the verified Splunk Universal Forwarder
10.6.1.1 Windows x64 MSI identity and checksum; changing them is not supported by
the fixed validation contract. Three role-prefixed Windows index defaults route
Security to `winlogs`, Sysmon to `sysmon`, and SilkService-Log to `etw`.
`accept_license` must still be explicitly true. Shared receiver and disposable
lab administrator inputs are used by both platforms.

The role validates monitor mappings, normalized literal absolute file paths,
unique paths, metadata names, receiver host/port, URL credentials, and license
acceptance before it changes the host. Monitor paths allow only ASCII letters,
digits, underscore, dot, slash, and hyphen; wildcard `*`, `...`, dot/dot-dot
components, duplicate/trailing separators, backslashes, brackets, and control
characters are rejected. Sourcetype, index, receiver host, and administrator
username are restricted to literal allowlisted character sets with true
end-of-string validation. A monitor path is allowed to be absent at installation time:
the configured Laurel file may be created later by its producer. There is no
recursive `/var/log` monitor and no default raw audit-log duplicate.

Example role variables:

```yaml
ludus_splunk_collector_accept_license: true
ludus_splunk_collector_receiver_host: "10.2.0.10" # replace with the server VM's explicit address
ludus_splunk_collector_receiver_port: 9997
ludus_splunk_collector_monitors:
  - path: /var/log/laurel/audit.log
    sourcetype: "laurel:json"
    index: main
```

Supply the receiver host through the range/blueprint topology rather than
depending on this role to infer a sibling VM or IP.

## Identity, inputs, and ordering

The role owns the fixed `splunkfwd` system account and group, home
`/opt/splunkforwarder`, and non-login shell `/usr/sbin/nologin`. It installs the
vendor-generated `SplunkForwarder.service` for that non-root identity and adds
an explicitly marked systemd drop-in that resets the capability bounding and
ambient sets and enables `NoNewPrivileges`. It inspects the effective service
identity, executable, drop-ins, and capabilities before starting the service.
An existing unrelated unit, identity, app, or pre-initialization seed is a
conflict and is not overwritten.

The unit guard validates exactly one main `ExecStart` for the selected
`/opt/splunkforwarder` home. For `ExecStartPre`/`ExecStartPost`, it accepts only
the vendor-documented recursive `splunkfwd:splunkfwd` chown of that application
tree or the CPU/memory system.slice cgroup path for `%n`/`SplunkForwarder.service`;
systemd's optional `-` ignore-failure prefix is allowed. The documented
`/bin/bash -c "chown -R splunkfwd:splunkfwd TARGET"` wrapper is accepted only
when its single inner command is an exact allowlisted chown; shell operators,
expansion, escapes, quotes, additional commands, and arbitrary targets are
refused. `+` and `!` privilege prefixes are refused. This allowlist is based on
the Splunk Universal Forwarder 10.4 least-privileged-user reference,
not the selected 10.6.1.1 build. The documented fresh-tree recursive ownership
is vendor-supported, but exact generated-unit and runtime compatibility remain
unverified for the selected package.

On Windows, the forwarder is installed at the fixed
`C:\Program Files\SplunkUniversalForwarder` home as service
`SplunkForwarder`, using the `NT SERVICE\SplunkForwarder` virtual account. The
role records phase, artifact/service identity, and managed configuration hashes
in an Administrators/SYSTEM-protected marker under
`C:\ProgramData\Ludus\SplunkCollector`, outside the service-writable home.
Unmanaged installations, unsafe reparse points, malformed ownership, and
conflicting inherited event/output stanzas fail closed. The role adds only
per-channel Event Log READ access for the local service SID; it does not use
LocalSystem or alter Security/Sysmon producer policy. Security is XML-rendered,
starts at `oldest`, uses `current_only=0`, and has no exclusions. Sysmon has no
collector-owned filters. Missing SilkService-Log is rendered disabled with a
warning and becomes enabled after the channel appears.

The forwarder app is isolated at
`/opt/splunkforwarder/etc/apps/ludus_collector/local/`. Its ownership marker
protects `inputs.conf` and `outputs.conf`; configuration edits notify a service
restart, while unchanged convergence does not restart an enabled service.
`outputs.conf` sends cooked TCP data to the configured receiver. The role does
not alter any host logging configuration, set ACLs, or assume default ACL
inheritance. If the monitored Laurel file is produced later, order the collector
before the logging producer and grant access explicitly. For example, run
`ludus_splunk_collector` and then `ludus_linux_logging` with
`ludus_linux_logging_read_users: [splunkfwd]`. This arranges the producer's
explicit named-user access; it does not make a nonexistent file a prerequisite
for collector installation.

The Enterprise receiver is a separate VM/role. Enable its receiving listener
with `ludus_splunk_server_receiver_enabled: true` for `ludus_splunk_server`, and express the server
VM as a `depends_on` prerequisite of the collector role in the range config,
using the installed role identity. Do not co-locate the two roles by assuming
this collector configures a receiver.

## Fresh authentication and limitations

The seed is created only when the forwarder's `etc/passwd` is absent. It is
mode `0600`, hidden from task logs and diffs, retained after any bootstrap or
authentication failure, and removed only after fresh authenticated readiness
and a nonempty initialized passwd database. On Linux, management API readiness
and fresh administrator authentication use Splunk's local
`/opt/splunkforwarder/var/run/splunk/cli.socket` Unix socket; readiness requires
an unauthenticated HTTP 401 response, rather than merely an open TCP port.
Existing initialized authentication is untouched; the role does not rotate
credentials. The lab password is a committed convenience default, not a
production credential management strategy.

No live verification of package compatibility, boot persistence, Laurel
rotation/readability, forwarder ingestion, or server interoperability has been
performed. Static checks cannot prove those behaviors. In particular, the
selected-version capability policy, seed syntax, and actual listener behavior
need authorized native tests; rotation and ingestion live verification remain
absent. The unauthenticated-to-authenticated bootstrap path, including Unix
socket readiness and authentication on the selected package, remains
unverified until authorized native testing.

Windows MSI reboot-required results stop the owned service, disable automatic
start, retain pending evidence, and fail without rebooting. Authentication
failures retain the protected seed and pending phase; cleanup occurs only after
authenticated loopback readiness and a nonempty `etc/passwd`. Ready convergence
checks actual service/product identity and managed configuration hashes. Only
changed managed input/output templates notify a guarded Windows restart.

For Windows lab use, deploy the receiver first and the Sysmon producer before
the collector; express role prerequisites using explicit `depends_on` VM and
installed role identities. The collector does not install Sysmon or SilkService.
