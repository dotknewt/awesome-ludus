# linux_splunk_server

Installs Splunk Enterprise on Linux for Ludus ranges and configures its
receiving port. The role keeps its existing role identity and installation
lifecycle.

## Shared inputs

Set values common to the server and forwarders once in range-level
`global_role_vars`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `splunk_version` | `10.6.1.1` | Splunk release |
| `splunk_build` | `b2ae2962645c` | Splunk release build |
| `splunk_accept_license` | `false` | Must be explicitly `true` before the role runs |
| `splunk_receiver_port` | `9997` | Receiver port configured for forwarders |

The false license default is intentional. The role asserts explicit acceptance
before any existing task, including installation or configuration.

## Server-only inputs

| Variable | Default | Purpose |
| --- | --- | --- |
| `splunk_server_download_token` | empty | Optional download token |
| `splunk_server_install_dir` | `/opt` | Installation parent directory |
| `splunk_server_home` | `/opt/splunk` | Existing installation/configuration home |
| `splunk_server_admin_user` | `admin` | Server administrator username |
| `splunk_server_admin_password` | `Changeme1!` | Server administrator password |
| `splunk_server_web_port` | `8000` | Web UI port |
| `splunk_server_mgmt_port` | `8089` | Management port |
| `splunk_server_license_file` | empty | Optional license file path |
| `splunk_server_enable_boot_start` | `true` | Enable systemd boot start |
| `splunk_server_disable_popups` | `true` | Disable first-login UI tours |

Example:

```yaml
# Illustrative fragment only; not a complete runnable range config.
# Hostname, template, network, and other VM fields are intentionally omitted.
global_role_vars:
  splunk_version: "10.6.1.1"
  splunk_build: "b2ae2962645c"
  splunk_accept_license: true
  splunk_receiver_port: 9997

ludus:
  - vm_name: "{{ range_id }}-splunk"
    # Replace this example role ID with the identity reported by the target server.
    roles:
      - dotknewt.ludus_splunk_server
    role_vars:
      splunk_server_admin_password: "ReplaceThisLabPassword!"
```

## Role identity and attribution

The source directory is `linux_splunk_server`; metadata declares the role name
`linux_splunk_enterprise`; active examples retain `dotknewt.ludus_splunk_server`
or `ludus_splunk`. The installed identity is **not verified**. Do not infer it
from the directory or metadata: use the identity reported by the target Ludus
server, and update both `roles` and any matching `depends_on.role` references
consistently. No role or example identity is renamed here.

This role was previously supplied through the stale
`curi0usJack/ludus_splunk` Git submodule mapping. The supplied local files declare
MIT (the README's license notice and role metadata); no separate `LICENSE` file
was supplied. The upstream source revision is not established here, and no
provenance audit is claimed. `galaxy_info.author: dotknewt` is maintainer
metadata, not a claim of sole authorship.

## Index configuration limitation

This role has no supported configurable index-list input; index-list
configuration is not supported. The existing tasks
create their hard-coded `wineventlog` and `sysmon` indexes; an old caller value
such as `ludus_splunk_server_indexes` was not consumed and has been removed from
examples. Do not assume a caller-provided index list changes server indexes or
that client index names are automatically aligned; that is separate work.

The role's existing template paths, seed path, and installation lifecycle are
unchanged. Runtime installation and selected-version compatibility are not
verified by static checks.
