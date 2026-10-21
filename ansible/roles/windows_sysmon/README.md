# README
An Ansible Role that installs, upgrades, and configures Sysmon on Windows Server (2016, 2019, and 2022), Windows 10 and Windows 11.

## Defaults
```yml
---
sysmon_executable_path: 'C:\Windows\Sysmon64.exe'
sysmon_config_dest: 'C:\Windows\sysmonconfig.xml'
sysmon_drv_reg: '"C:\Windows\Sysmon64.exe" -i -accepteula'
sysmon_config_file: sysmonconfig.xml
sysmon_config_source: "{{ lookup('first_found', sysmon_config_file) }}"
sysmon_installer_url: https://download.sysinternals.com/files/Sysmon.zip
sysmon_download_latest: false
sysmon_installer_version: "15.22"
sysmon_archive_sha256sum: "00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54"
sysmon_eventlog_maxsize_gigabyte: 1
```

### Configuration selection

Set `sysmon_config_file` to the filename of a configuration in the role's `files/`
directory. It defaults to `sysmonconfig.xml`. For example, to use the bundled
`files/sysmonconfig_uc.xml`, set this in the VM's `role_vars`:

```yaml
role_vars:
  sysmon_config_file: sysmonconfig_uc.xml
```

The role copies the selected configuration to `sysmon_config_dest` and reloads
Sysmon when the configuration content changes. A missing configuration file causes
the lookup to fail. You can still override `sysmon_config_source` directly to
specify a source path.

### Archive selection

By default, the role copies `files/sysmon.zip` from the role to the Windows host.
Include that archive when distributing or installing the role. Keep
`sysmon_installer_version` and `sysmon_archive_sha256sum` aligned with the bundled
archive when replacing it. The role assumes the declared version is correct and
verifies the archive checksum before installing. If the installed version already
matches and its service exists, archive preparation is skipped.

Set this in the VM's `role_vars` in `range-config.yml` to fetch the latest release:

```yaml
role_vars:
  sysmon_download_latest: true
```

When enabled, the role downloads `sysmon_installer_url` on every run without archive
checksum verification. HTTPS certificate validation remains enabled. Set the switch
to `false` (or omit it) to use the bundled archive without contacting the download URL.

Downloaded mode reads `Sysmon64.exe`'s product version and ignores the bundled
version and checksum variables. Both modes prepare the archive before uninstalling
an existing installation. Sysmon is replaced when its installed version differs
from the target, or installed when its executable or service is absent.
Switching back to the bundled archive can therefore downgrade Sysmon. Temporary
staging files are removed even if preparation or installation fails.

### Hints

This converts the value of `sysmon_eventlog_maxsize_gigabyte` to bytes 
- `(sysmon_eventlog_maxsize_gigabyte | int * 1024 * 1024 * 1024)`

## Example Ludus Range Config

```yaml
ludus:
  - vm_name: "{{ range_id }}-ad-dc-win2022-server-x64-1"
    hostname: "{{ range_id }}-DC01-2022"
    template: win2022-server-x64-template
    vlan: 10
    ip_last_octet: 11
    ram_gb: 6
    cpus: 4
    windows:
      sysprep: true
    domain:
      fqdn: ludus.domain
      role: primary-dc
    roles:
      - {{ your github username }}.{{ this repo name }}
    role_vars:
      {{ example role var usage }}
```

## License

[//]: # "If you change the License type, be sure to change the actual LICENSE file as well"

GPLv3

## Author Information

This role was created by [{{Your Github Username}}](https://github.com/{{ your github username }}), for [Ludus](https://ludus.cloud/).
