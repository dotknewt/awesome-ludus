# Design: Debian Linux logging and Splunk collection

**Date:** 2026-10-20  
**Status:** approved for implementation; no deployment, live test, or guest
probe is authorized by this document.

## Requirements and decisions

The following are **user requirements** unless marked **Assistant decision**.

- Add `ludus_splunk_collector` for Debian amd64 with the exact Universal
  Forwarder artifact requested:
  `https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb`.
- Use research SHA512
  `2172ed26173b4f29e3ffb051800dce3b21701f8fa202466063a5355dd9e7c2cac03714e5db026c4a5dd37249a23be017661a80b4969a339e1d653a16622180c31`.
- Add `ludus_linux_logging` by safely reworking the legacy
  `role_linux_logging`; leave both old roles unchanged.
- **Assistant decision:** both new roles support Debian 13 or Ubuntu 24.04 or
  Ubuntu 26.04, amd64, and systemd; the existing server role remains Debian 13
  only. Selected UF compatibility remains unverified until authorized native
  evidence.
- **Assistant decision:** pin Laurel v0.6.3; record tag commit `f552ee5c0bba949649355b566463fee8d60257bc`
  and observed SHA256 `ee7704e87c831bbfcac8cf8741e92eb56b49b3c6d64629d4730c98d97568ec53`
  as provenance, not publisher authenticity evidence.
- Replace the upstream unsafe remote script with idempotent Ansible.
- Preserve upstream audit policy/config defaults except safe narrow
  transformations and reader-interface changes; preserve attribution and
  applicable licenses. **User decision:** use checksum-pinned HTTPS
  downloads from the immutable research commits, not repository vendoring;
  do not claim publisher authentication beyond recorded provenance.
- Keep the optional server TCP/9997 receiver explicitly enabled by input.
- **Assistant decisions:** use `main` as the collector default index,
  plaintext TCP as lab-only v1 protocol, `splunkfwd` as default collector
  identity, and retain both legacy roles unchanged.

## Role boundaries and interfaces

Each role is standalone, namespaced, and owns only its component. No role
includes the other. A blueprint may order logging, collector, and server and
must document that order; topology and VM names remain in the blueprint.

| Producer/consumer | Contract | Default |
|---|---|---|
| logging → collector | Laurel directory/file and named-user ACL contract | `/var/log/laurel/audit.log`, standalone readers `[debian]`, paired readers `[splunkfwd]` |
| collector → server | required nonempty `host` plus explicit TCP `port` | no inferred host; `9997` |
| server receiver | dedicated managed Splunk config app | disabled |

The collector requires a nonempty `host` and defaults port to 9997 (no hidden
VM lookup), monitors `/var/log/laurel/audit.log` with sourcetype `laurel:json`,
and uses index `main` so it works with the bare server. Other paths are an
explicit list with explicit sourcetypes. `/var/log` recursion and raw auditd
double ingestion are never defaults. `/var/log/audit/audit.log` is opt-in and
conditional on auditd/file existence.

## `ludus_linux_logging`

The role validates Debian 13/amd64/systemd and all inputs before mutation.
It downloads `audit.rules` and `config.toml` from their immutable research
commits with pinned checksums, never vendors source files or follows a moving
branch. Laurel is the pinned v0.6.3 HTTPS archive with the observed transport
checksum and provenance above, not publisher-authenticated evidence. It owns a
separately named rules fragment under `/etc/audit/rules.d/`; it never deletes
`audit.rules` or unrelated fragments and `augenrules` merges them.

**Assistant decision:** transformations are narrow and explicit: remove global
deletion and immutable directives, parse exact path-watch syntax, omit watches
only when targets are absent, and document review of every other path rule.
The resulting diff and omitted paths are reviewable; no silently weakened
policy claim is made.

The role validates rules before loading, handles audit immutable state
explicitly, and refuses or reports a required operator transition rather than
silently forcing `-e 2` changes. Reload is handler-driven and only follows an
authorized change. Laurel retains upstream defaults including its log path,
`_laurel` identity, rotation values, enrichment/filter behavior, and
`read-users: [debian]` unless inputs override them. Config and log ownership
are restrictive and explicit.

The logging role's namespaced `read_users` defaults to `[debian]` standalone.
It verifies requested accounts exist before mutation and writes Laurel's
explicit `read-users`. The paired order uses `read_users: [splunkfwd]` after
the collector creates that account. Laurel resets read ACLs on each new file;
a default directory ACL is not treated as a solution. The collector may
monitor an absent Laurel file until the producer creates it, but never changes
producer config or hidden-includes the logging role. The forwarder gets no
`CAP_DAC_READ_SEARCH`; Laurel's upstream enrichment capabilities are a
separately documented behavior, not blanket-banned.

## `ludus_splunk_collector`

Inputs include pinned URL/checksum/version, explicit license acceptance,
service user/group, receiver endpoint, Laurel reader contract, and opt-in
monitor paths. Inputs are validated before mutation; URL credentials are
rejected and HTTPS certificate verification remains enabled. The role checks
Debian package name, amd64 architecture, and exact version, and refuses an
installed mismatch rather than upgrading or downgrading.

Use the package/vendor boot-start procedure, generating a distinct
`SplunkForwarder.service` and selecting non-root `splunkfwd` (or the actual
package-supported identity after discovery). Inspect the effective unit and
application ownership before starting. Do not assume the server's `splunk`
identity or incidental capabilities. Seed credentials follow the server
role's lifecycle: fresh-only, mode 0600, service-owned, removed only after an
authenticated initialization check; preserve initialized auth and refuse an
unmanaged seed. Do not rotate credentials or upgrade packages.

Own role-specific dedicated apps containing `inputs.conf` and `outputs.conf`
in the documented local configuration location; do not edit vendor defaults
or overwrite unmanaged apps. Restart the forwarder when managed configuration
changes, and make generated unit/application conflict checks fail closed. v1
is lab-only plain TCP: no TLS, firewall,
custom index creation, recursive logging, or unrelated app overwrite.

## Server receiver extension

Extend the existing server role only for this explicit optional interface:
default receiver disabled; when enabled, write a role-owned dedicated config
app containing `[splunktcp://9997] disabled = 0`, never overwrite unrelated
configuration, and restart the proper service after change. After
start/restart, tasks wait for and check the configured listener. Disabling
removes only the managed file/app and never an unmanaged receiver. Validate
endpoint and conflict state before mutation.

## Verification and evidence

Static verification will include role structure/meta identity, YAML/Jinja
syntax, input-contract tests, package/checksum literals, ownership/ACL
patterns, and official `validate.py`/repository Ansible checks. `ansible` is
currently unavailable on PATH; this is an evidence limitation, not proof of
runtime behavior. No mocks or simulations are evidence.

Separate, authorized live work (not performed here) must cover fresh install,
convergence, reboot persistence, Laurel rotation/readability, UF forwarding,
server receiver interoperability, immutable audit behavior, checksum/version
rejection, unmanaged conflicts, seed failure/recovery, and preservation of
unrelated files. The parent session owns contract review; a fresh design
reviewer owns independent review; fast-generic owns command-level validation
execution. Compatibility of UF 10.6.1.1 and the selected Laurel archive
remains open until native evidence. Builders may settle implementation details
only within these contracts.

## Deployment ordering and writer scopes

Examples place the server on a separate VM. The collector depends on that
server through Ludus `depends_on`; on the client VM, collector runs before
logging so `splunkfwd` exists when Laurel starts. Roles remain independently reusable.
The server writer owns only its receiver app, the collector writer only its
forwarder app/unit and explicit reader access, and the logging writer only its
audit fragment, Laurel downloads/config, and declared log paths. Each writer
validates conflicts and preserves unrelated files.

## Scope exclusions

No changes are permitted to `role_linux_logging`,
`role_splunk_collector_linuxv`, unrelated modified blueprints,
`threat-hunting/range-config.yml`, or other unrelated artifacts.
