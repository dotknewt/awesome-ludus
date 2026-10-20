# ludus_splunk_server

Install and bootstrap a minimal native Splunk Enterprise Debian package as a
non-root `splunk` systemd service. This role currently supports Debian 13
amd64 only. Ubuntu support is intentionally not enabled until tested.
Requires `ansible-core >= 2.16`.

## Inputs

Set these with the VM's Ludus `role_vars` or other normal Ansible variable
mechanism. Defaults pin the Splunk Enterprise 10.6.1.1 amd64 package URL,
publisher SHA-512 digest, and expected package version shown below. If selecting
a different artifact, change URL, checksum, and version together; the role
checks package metadata before installation.

| Variable | Default | Meaning |
|---|---|---|
| `ludus_splunk_server_package_url` | Splunk 10.6.1.1 `.deb` URL | HTTPS URL of the selected Splunk Enterprise amd64 package; URL credentials are rejected. |
| `ludus_splunk_server_package_checksum` | `sha512:f3f67f699fcd893ffd280b602a47215f5e7eb9b481cb242b08705a4db8ada489febb3fa49cb90f9bd1397603d9207ea5ac9bf59eec62f99d030c3f2ff738eb89` | Publisher checksum fetched from the artifact's `.sha512` sidecar. |
| `ludus_splunk_server_version` | `10.6.1.1` | Exact Debian package `Version` metadata expected; not yet inspected from a downloaded binary. |
| `ludus_splunk_server_accept_license` | `false` | Must be set to `true` only after the operator accepts applicable terms. |
| `ludus_splunk_server_admin_username` | `admin` | Initial Splunk application administrator username. |
| `ludus_splunk_server_admin_password` | `SplunkLab-ChangeMe1!` | Disposable lab credential; override it for each lab. |
| `ludus_splunk_server_receiver_enabled` | `false` | Explicitly opt in to a Splunk TCP (`splunktcp`) receiver. Disabled runs do not create or change receiver configuration. |
| `ludus_splunk_server_receiver_port` | `9997` | TCP listener port, integer 1–65535; ports 8000 (web) and 8089 (management) are rejected. |

Example (the artifact values are the defaults; terms acceptance remains an
explicit operator choice):

```yaml
role_vars:
  ludus_splunk_server_accept_license: true
  ludus_splunk_server_admin_username: admin
  ludus_splunk_server_admin_password: "<disposable-lab-password>"
```

The package URL was supplied by the user; its publisher checksum sidecar was
retrieved on 2026-10-19. See the
[source evidence](../../../docs/research/ludus-splunk-server-bootstrap.md). The published digest has not
been checked against a locally downloaded package, and the package's Debian
metadata has not been inspected. Do not put credentials in the download URL;
the URL must be reachable without an authentication flow. Do not use the
default admin password as a production credential. Setting
`ludus_splunk_server_accept_license: true` requires the operator to accept
applicable terms first.

## Optional TCP receiver

The receiver is disabled by default. The server role owns only its dedicated
`/opt/splunk/etc/apps/ludus_receiver/local/inputs.conf` and a marker in that
app. It refuses symlinks, an app without its exact ownership marker, and a
configured `splunktcp` port already present in another `inputs.conf`. When
enabled, it writes `[splunktcp://<port>]` with `disabled = 0`; changing the port
replaces this role-owned stanza. Disabling removes only the receiver's owned
inputs file and retains the ownership marker. Other app files and unrelated
Splunk configuration are preserved; retaining the marker supports later
disabled runs and re-enabling. Configuration changes restart Splunk once after
service identity checks. The role waits for the configured TCP port after
enabling it; this is listener readiness, not evidence of end-to-end ingestion.

The input is plaintext TCP (no TLS) and is for isolated labs only. It does not
configure HEC, indexes, or firewall rules. Permit the selected port through your
lab network separately if required.

## Separate server/client range example

Enable the receiver explicitly on the server VM:

```yaml
- vm_name: "splunk-server"
  roles:
    - ludus_splunk_server
  role_vars:
    ludus_splunk_server_accept_license: true
    ludus_splunk_server_receiver_enabled: true
    ludus_splunk_server_receiver_port: 9997
```

On a separate client VM, order the collector after the server with `depends_on`.
The logging role follows the collector so its forwarder service is available
when logging configuration is applied:

```yaml
- vm_name: "splunk-client"
  roles:
    - name: ludus_splunk_collector
      depends_on:
        - vm_name: "splunk-server"
          role: ludus_splunk_server
    - ludus_linux_logging
  role_vars:
    ludus_splunk_collector_receiver_host: "<splunk-server-address>"
    ludus_splunk_collector_receiver_port: 9997
    ludus_splunk_collector_accept_license: true
    ludus_linux_logging_read_users: [splunkfwd]
```

The client example uses the fully namespaced collector and logging role inputs
`ludus_splunk_collector_receiver_host`, `ludus_splunk_collector_receiver_port`,
`ludus_splunk_collector_accept_license`, and
`ludus_linux_logging_read_users`. Keep the server and
client as distinct VMs; the examples show role ordering and relevant inputs,
not complete range configurations. Role names are shown as source role
identities; resolve installed catalog identities for the target Ludus version.

The administrator password seeds only a fresh instance. Existing
`/opt/splunk/etc/passwd` is preserved and credentials are not rotated when
role variables change. An existing seed file with no initialized `passwd` is
treated as unmanaged and causes a refusal; with an existing `passwd`, any seed
is preserved untouched. A failed bootstrap retains a seed created by that
invocation. A later run will refuse that seed if `passwd` is still absent; an
operator must inspect the failed bootstrap and explicitly recover/remove only
the known role-created seed before retrying. The role never resets the
authentication database. The role does not change OS template login accounts.

If package installation fails after artifact verification, a subsequent run
accepts only the matching `splunk` group/account identity created by this role
(non-root UID, primary group `splunk`, home `/opt/splunk`, nologin shell) and
continues without a journal. Other conflicting identities still fail closed.

## Behavior and boundaries

The role validates package SHA-256/SHA-512 through Ansible `get_url`, checks
Debian package name, architecture, and exact version before installation, and
refuses a different installed version rather than upgrading or downgrading.
It asks Splunk to generate its own `Splunkd.service` before first start, then
checks the generated unit's non-root user/group. Splunk computes some generated
unit resource limits from host memory at generation time; review/re-generate
through Splunk's documented procedure if host sizing later changes.

Ansible task output and diffs are suppressed around secrets. The initial seed
is mode `0600`, is used only when `etc/passwd` is absent, and is removed only
after a successful fresh-instance authenticated readiness check and a
non-empty authentication database. Existing initialized instances receive
only a bounded web-listener wait, not an auth attempt with a potentially stale
role default. The fresh-instance management API check is loopback-only; TLS
certificate verification is disabled there only for Splunk's default
self-signed local certificate, and proxy use/redirects are disabled so the
basic-auth credentials are not sent elsewhere.

This is a bare server bootstrap, with the explicitly enabled receiver app as
the only optional input/app configuration. It does not configure HEC, indexes,
forwarding, telemetry, firewall/network rules, license-group changes, or
trial-to-Free transitions. Splunk's trial/Free licensing is an operator
lifecycle decision; Free mode has different authentication/user capabilities.
The role does not accept terms unless the operator explicitly enables that
input, and setting it is a representation of operator authorization, not
legal advice.

## Verification

Static checks inspect role YAML/Jinja contracts only (Python with PyYAML and
Jinja2 available):

```sh
python3 -m unittest discover -s ansible/roles/ludus_splunk_server/tests -v
```

Static checks do not prove Ansible runtime behavior, checksum rejection at
install time, compatibility of the selected Splunk build, or deployment
readiness. Live verification requires separate authorization and a disposable
native target: fresh installation and
authenticated readiness; rerun preserving credentials; reboot with service
enabled; package checksum/version rejection before installation; and relevant
failure paths preserving pre-existing state and retaining recovery evidence.
No target-side Ansible run or deployment is part of this role authoring.
