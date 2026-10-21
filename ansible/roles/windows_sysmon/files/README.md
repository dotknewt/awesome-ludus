# Role files

- `sysmon.zip`: bundled Sysmon installer archive, used by default. It must contain
  `Sysmon64.exe` at the archive root. Include this file when packaging the role.
  Update `sysmon_installer_version` and `sysmon_archive_sha256sum` in defaults and
  argument specifications, and the README example, whenever replacing it.
- `sysmonconfig.xml`: default Sysmon configuration.

Set `sysmon_download_latest: true` in the VM's `role_vars` to download from
`sysmon_installer_url` instead of using the bundled archive, without archive
checksum verification.
