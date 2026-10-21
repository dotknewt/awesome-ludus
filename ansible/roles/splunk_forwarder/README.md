# splunk_forwarder

Installs and configures Splunk Universal Forwarder on supported Linux and
Windows Ludus hosts. The role does not install a Splunk server, configure TLS,
or change firewall policy.

## Shared inputs

Values common to the forwarder and server belong in range-level
`global_role_vars`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `splunk_version` | `10.6.1.1` | Forwarder/server release |
| `splunk_build` | `b2ae2962645c` | Release build |
| `splunk_accept_license` | `false` | Must be explicitly `true` before either branch runs |
| `splunk_receiver_ip` | empty | Explicit receiver address for forwarders |
| `splunk_receiver_port` | `9997` | Receiver port; Linux accepts an integer or ASCII decimal string from `1` to `65535` |

## Forwarder-only inputs

All forwarder-specific inputs use `splunk_forwarder_*`. The administrator user
is shared between platform branches; Linux and Windows password defaults remain
platform-specific to preserve existing initialization behavior.

| Variable | Default | Purpose |
| --- | --- | --- |
| `splunk_forwarder_package_url` | version/build-derived Linux Debian URL | Linux package source |
| `splunk_forwarder_package_checksum` | pinned SHA-512 for the exact default package | Linux package integrity |
| `splunk_forwarder_admin_user` | `admin` | Forwarder administrator user |
| `splunk_forwarder_linux_admin_password` | `SplunkLab-ChangeMe1!` | Linux first-run password |
| `splunk_forwarder_windows_admin_password` | `Changeme1!` | Windows MSI password |
| `splunk_forwarder_monitors` | Laurel audit log mapping | Linux monitor list |
| `splunk_forwarder_download_token` | empty | Optional Windows download token |
| `splunk_forwarder_install_dir` | `C:\Program Files\SplunkUniversalForwarder` | Windows installation path |
| `splunk_forwarder_deployment_server` | empty | Optional Windows deployment server |
| `splunk_forwarder_inputs` | Security, System, Application | Windows input stanzas |
| `splunk_forwarder_start_service` | `true` | Windows service behavior |

The paired server role uses `splunk_server_*` for server-only settings, such as
`splunk_server_admin_user`, `splunk_server_admin_password`,
`splunk_server_home`, `splunk_server_web_port`, and
`splunk_server_enable_boot_start`. Shared release, acceptance, and receiver
settings remain the unprefixed shared inputs above.

The pinned Linux package is Universal Forwarder 10.6.1.1 build
`b2ae2962645c`, with SHA-512
`2172ed26173b4f29e3ffb051800dce3b21701f8fa202466063a535dd9e7c2cac03714e5db026c4a5dd37249a23be017661a80b4969a339e1d653a16622180c31`.
If version/build or the URL selects another artifact, the default checksum is
empty and validation fails until the caller supplies its matching explicit
checksum. No checksum discovery or package resolution is performed.

The Linux license/input validation runs before inspection or host mutation. The
Windows branch checks `splunk_accept_license` before service inspection,
download, installation, or configuration. Windows retains its input-driven
configuration and standalone install/service flow; it does not install Sysmon
or SILK and does not automatically subscribe to SILK.

Linux targets remain Debian 13, Ubuntu 24.04 and Ubuntu 26.04, x86_64 with
systemd. Forwarding uses cooked TCP without TLS; use only on a trusted lab
network. Existing Linux managed paths and ownership marker, Windows install
directory/config paths, and platform password defaults are preserved.

## Example

```yaml
global_role_vars:
  splunk_version: "10.6.1.1"
  splunk_build: "b2ae2962645c"
  splunk_accept_license: true
  splunk_receiver_ip: "10.2.0.10"
  splunk_receiver_port: 9997

ludus:
  - vm_name: "{{ range_id }}-splunk"
    hostname: "{{ range_id }}-splunk"
    template: REPLACE_WITH_DEBIAN_TEMPLATE
    linux: true
    roles:
      - dotknewt.ludus_splunk_server
    role_vars:
      splunk_server_admin_password: "ReplaceThisLabPassword!"
      splunk_server_enable_boot_start: true

  - vm_name: "{{ range_id }}-windows"
    hostname: "{{ range_id }}-windows"
    template: REPLACE_WITH_WINDOWS_TEMPLATE
    windows: {}
    roles:
      - dotknewt.splunk_forwarder
    role_vars:
      splunk_forwarder_inputs:
        - name: "WinEventLog://Security"
          index: winlogs
        - name: "WinEventLog://Microsoft-Windows-Sysmon/Operational"
          index: sysmon
          sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

Windows behavior retained from the standalone implementation includes
no-token downloads using `validate_certs: false` and hard-coded MSI
`AGREETOLICENSE=yes`; the shared acceptance assertion is still required before
the task flow starts. Static checks do not establish runtime installation,
convergence, event ingestion, selected-version compatibility, or installed
server-side role identity compatibility. Runtime behavior: not verified.

The Windows task flow is carried forward from
`curi0usJack/ludus_splunk_universalforwarder`. That role's metadata and README
declare MIT licensing; its source directory did not contain a separate LICENSE
file. The role author metadata identifies the repository maintainer and does not
claim sole authorship of the Windows work.
