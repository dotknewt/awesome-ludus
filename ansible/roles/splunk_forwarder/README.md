# splunk_forwarder

Installs and configures a Splunk Universal Forwarder on supported Linux and
Windows Ludus hosts. The role does not install a Splunk server, create indexes,
configure TLS, or change firewall policy.

## Linux inputs

Linux retains the existing `ludus_splunk_collector_*` API, defaults, filters,
ownership markers, task flow, and configuration behavior. The package is the
pinned Splunk 10.6.1.1 Debian artifact. The default license setting is false;
set it true explicitly and provide a receiver before installation.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ludus_splunk_collector_package_url` | pinned Debian artifact | Package source |
| `ludus_splunk_collector_package_checksum` | pinned SHA-512 | Package integrity |
| `ludus_splunk_collector_version` | `10.6.1.1` | Exact package version |
| `ludus_splunk_collector_accept_license` | `false` | Must be explicitly accepted |
| `ludus_splunk_collector_admin_username` | `admin` | First-run initialization |
| `ludus_splunk_collector_admin_password` | `SplunkLab-ChangeMe1!` | Disposable lab default |
| `ludus_splunk_collector_receiver_host` | empty | Explicit receiver host |
| `ludus_splunk_collector_receiver_port` | `9997` | Receiver port |
| `ludus_splunk_collector_monitors` | Laurel audit log mapping | Explicit file monitor list |

Linux targets are Debian 13, Ubuntu 24.04 and Ubuntu 26.04, x86_64 with
systemd. Forwarding uses cooked TCP without TLS; use only on a trusted lab
network. The role owns its `splunkfwd` account and managed application config.

## Windows inputs

Windows preserves the standalone role's `splunk_uf_*` defaults and behavior.
Its configuration is input-driven: supply the indexer and the `splunk_uf_inputs`
list for the channels to collect. The role does not install Sysmon or SILK and
does not automatically configure optional SILK collection. Existing callers
should specify their Security and Sysmon inputs explicitly when required.

| Variable | Default | Purpose |
| --- | --- | --- |
| `splunk_uf_version` | `9.3.2` | Forwarder version |
| `splunk_uf_build` | `d8bb32809498` | MSI build identifier |
| `splunk_uf_download_token` | empty | Optional download token |
| `splunk_uf_install_dir` | `C:\Program Files\SplunkUniversalForwarder` | Install path |
| `splunk_uf_deployment_server` | empty | Optional deployment server |
| `splunk_uf_indexer` | empty | Receiving host |
| `splunk_uf_indexer_port` | `9997` | Receiving port |
| `splunk_uf_admin_user` | `admin` | MSI admin user |
| `splunk_uf_admin_password` | `Changeme1!` | MSI admin password |
| `splunk_uf_accept_license` | `true` | License input retained from standalone role |
| `splunk_uf_inputs` | Security, System, Application | Input stanzas |
| `splunk_uf_start_service` | `true` | Start/configure service |

The standalone task flow retains its token/no-token download, cache and MSI
installation behavior, Event Log Readers membership, configuration rendering,
service ordering, and final service status reporting. Template names are
Windows-specific to avoid collisions with Linux templates.

Behavioral caveats retained from the standalone tasks: no-token downloads use
`validate_certs: false`; MSI arguments hardcode `AGREETOLICENSE=yes` and do not
enforce `splunk_uf_accept_license`, which remains a compatibility input.

## Example

```yaml
roles:
  - dotknewt.splunk_forwarder
role_vars:
  splunk_uf_indexer: "10.2.0.10"
  splunk_uf_accept_license: true
  splunk_uf_inputs:
    - name: "WinEventLog://Security"
      index: winlogs
    - name: "WinEventLog://Microsoft-Windows-Sysmon/Operational"
      index: sysmon
      sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

Role-directory/metadata naming is updated to `splunk_forwarder`; compatibility
with any installed server-side role identity has not been verified. Static
checks do not establish runtime installation, convergence, event ingestion, or
selected-version compatibility. Runtime behavior: not verified; live
verification remains unperformed.

The Windows task flow is carried forward from `curi0usJack/ludus_splunk_universalforwarder`.
That role's metadata and README declare MIT licensing; its source directory did
not contain a separate LICENSE file. This role's author metadata identifies the
repository maintainer and does not claim sole authorship of the Windows work.
