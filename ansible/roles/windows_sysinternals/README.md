# windows_sysinternals

Installs the full Sysinternals suite (Process Explorer, Process Monitor,
Autoruns, PsExec, and the rest) into `C:\Tools` for hands-on analysis, adds the
directory to the machine `PATH`, and pre-accepts the Sysinternals EULA so the
tools start without a license prompt.

Supported: Windows Server 2016, 2019, 2022, Windows 10, and Windows 11.

## Requirements

- The Windows VM needs internet access to
  `download.sysinternals.com` while the role runs. The role downloads the
  current suite on the guest; nothing is bundled in the role.
- Collections: `ansible.windows`, `community.windows`.

## Defaults

```yaml
sysinternals_install_dir: 'C:\Tools'
sysinternals_suite_url: https://download.sysinternals.com/files/SysinternalsSuite.zip
sysinternals_suite_sha256: ""      # empty = no checksum verification
sysinternals_update: false         # true = re-download and overwrite every run
sysinternals_add_to_path: true
sysinternals_accept_eula: true
```

## Usage

In `range-config.yml`:

```yaml
    roles:
      - dotknewt.windows_sysinternals
    role_vars:
      sysinternals_update: true
```

## Behavior

- **Install check.** After a successful extraction the role writes
  `.windows_sysinternals_installed` into `sysinternals_install_dir`. If that
  marker exists and `sysinternals_update` is false, the download is skipped;
  an interrupted extraction leaves no marker and is retried on the next run.
- **Download.** The zip is downloaded to a temporary directory and only
  extracted after the download (and the checksum, when
  `sysinternals_suite_sha256` is set) succeeds. The temporary directory is
  removed even on failure. Microsoft replaces the zip in place without
  versioning, so a pinned checksum breaks when a new suite is published.
- **Shared directory.** `C:\Tools` is also used by other roles such as
  `atomic_red_team`. This role only adds and overwrites files; it never removes
  anything from the install directory.
- **EULA.** The role sets the DWORD `HKCU\Software\Sysinternals\EulaAccepted=1`
  in the Default user profile (users created later) and in every existing user
  profile, loading unloaded profile hives temporarily. The global value is
  honored by current tools according to community sources
  ([The Lonely Administrator, 2022](https://jdhitsolutions.com/blog/powershell/9130/configure-sysinternals-eula-acceptance/));
  Microsoft does not document it. Command-line tools also accept
  `-accepteula`.
- **Sysmon.** The suite contains `Sysmon.exe`; this role copies it but does not
  install or configure Sysmon. Use `windows_sysmon` (`dotknewt.ludus_install_sysmon`)
  for that.
