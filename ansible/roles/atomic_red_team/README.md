# atomic_red_team

An Ansible role that installs Invoke-AtomicRedTeam and its atomics for
cross-platform lab hosts. The role uses the upstream master installer and does
not pin a version.

## Supported platforms

The role dispatches on `ansible_os_family`:

- Windows Server and Windows client
- Debian, Ubuntu, and Kali Linux

macOS is not supported.

## Inputs

All inputs use the `atomic_red_team_` prefix.

| Variable | Default | Description |
| --- | --- | --- |
| `atomic_red_team_install_path_windows` | `C:\Tools` | Windows install path. |
| `atomic_red_team_install_path_linux` | `/opt/tools` | Linux install path. |
| `atomic_red_team_install_atomics` | `true` | Install the atomics folder. |
| `atomic_red_team_no_payloads` | `false` | Avoid downloading atomic payloads. |
| `atomic_red_team_defender_mode` | `disable` | Windows Defender mode: `disable`, `exclude`, or `none`. |
| `atomic_red_team_execution_policy` | `RemoteSigned` | PowerShell execution policy. |
| `atomic_red_team_installer_url` | `https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1` | Upstream installer URL. |
| `atomic_red_team_profile_marker` | `atomic_red_team` | Name used by the managed profile block markers. |

## Behavior

The role installs the module below the selected install path and, by default,
installs the atomics. It writes a marked import block to the AllUsersCurrentHost
PowerShell profile at `$PSHOME\Microsoft.PowerShell_profile.ps1`, so the module
loads for all users. The block also sets the default atomics folder without
replacing other PowerShell defaults.

On Windows, `disable` requests Defender real-time protection be disabled.
When protection remains on, the role falls back to an exclusion for the install
path. `exclude` adds only that exclusion, and `none` makes no Defender changes.

On Linux, an existing `pwsh` is used. If PowerShell is not already available,
Debian 12/13 and Ubuntu 22.04/24.04/26.04 use Microsoft's
`packages-microsoft-prod.deb` repository package, while Kali installs
`powershell` from its own repository. An unsupported Linux distribution or
version fails with an explicit message rather than attempting an unverified
package source.

On Windows, when the effective execution policy is `Restricted` or `AllSigned`,
the role sets the machine-wide policy to `atomic_red_team_execution_policy` if
neither `MachinePolicy` nor `UserPolicy` is enforcing the policy. If a
restrictive policy is enforced by Group Policy, the role fails instead of
claiming that the requested policy was applied.

Before pending Windows downloads, the role refuses to continue when Defender
real-time protection is active and the install path has no Defender exclusion.
This safety check runs after the requested Defender policy and fallback
exclusion handling.

## Example Ludus range config

```yaml
ludus:
  - vm_name: "{{ range_id }}-atomic-win2022"
    hostname: "{{ range_id }}-atomic-win2022"
    template: win2022-server-x64-template
    vlan: 10
    ip_last_octet: 50
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: true
    roles:
      - dotknewt.atomic_red_team
    role_vars:
      atomic_red_team_install_atomics: true
      atomic_red_team_no_payloads: false
```

## Verification note

This role has static validation only in this repository. Runtime installation,
PowerShell profile loading, Defender fallback behavior, and compatibility across
Windows, Debian, Ubuntu, and Kali remain unverified until an authorized live
deployment.

## Author

Created by [dotknewt](https://github.com/dotknewt) for Ludus.
