# Ansible Role: Malcolm Install

Installs and operates [CISA Malcolm](https://github.com/cisagov/Malcolm) as a
pinned, native Ansible deployment on Debian 12 or Debian 13 amd64. The role
owns host prerequisites, immutable source acquisition, configuration,
authentication artifacts, TLS, image pulls, systemd lifecycle, and readiness.
It does not invoke the former remote Debian installer.

Live Debian 12/13 compatibility has not yet been proven. Complete
[`tests/VM_ACCEPTANCE.md`](tests/VM_ACCEPTANCE.md) on disposable VMs before
using the role outside a lab.

## Requirements

Controller:

- `ansible-core` (the reproducible suite pins 2.21.4)
- `ansible.posix >= 2.2.2`
- `community.crypto >= 3.4.0`

Target:

- Debian 12 or 13 on amd64
- The guest VM must already be powered on and reachable; Ludus owns VM lifecycle management.
- An existing role account, `debian` by default, with become access
- Internet access to Debian repositories, GitHub, PyPI, and Malcolm image registries during installation

The role depends on the existing `ludus_install_docker` role and passes its
selected account through the public `ludus_install_docker_user` input. That
dependency appends the account to the `docker` supplementary group; it does not
replace the account's primary group, UID, comment, or other memberships. Do not
run a second Docker installer for Malcolm.

The role installs its target packages, including `python3-cryptography`, and
creates a dedicated Python venv containing the exact direct runtime packages
required by the pinned release. See `tasks/packages.yml` and
`tasks/install.yml` for those target dependencies.

## Variables

Every public role variable and its default is listed below. The empty password
default deliberately makes preflight fail until the caller supplies a secret.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ludus_install_malcolm_user` | `debian` | Existing account that owns and runs Malcolm. |
| `ludus_install_malcolm_install_dir` | `/home/debian/Malcolm` | Source and persistent application directory. |
| `ludus_install_malcolm_version` | `v26.08.0` | Approved upstream release; other values are rejected. |
| `ludus_install_malcolm_commit` | `07bbccdfe2732fb5c5147070cdfca2857b85bacc` | Immutable approved source commit; other values are rejected. |
| `ludus_install_malcolm_venv_dir` | `{{ ludus_install_malcolm_install_dir }}/.venv` | Dedicated Malcolm Python environment. |
| `ludus_install_malcolm_admin_username` | `condef` | Basic-auth administrator name. |
| `ludus_install_malcolm_admin_password` | `""` | Required administrator password; store it in Ansible Vault or equivalent. |
| `ludus_install_malcolm_capture_enabled` | `false` | Enable live packet capture. |
| `ludus_install_malcolm_capture_interface` | `""` | Capture interface; empty selects the discovered default IPv4 interface. |
| `ludus_install_malcolm_capture_filter` | `""` | Optional BPF capture filter. |
| `ludus_install_malcolm_capture_rotation_megabytes` | `4096` | PCAP rotation size in MiB. |
| `ludus_install_malcolm_capture_rotation_minutes` | `10` | PCAP rotation interval in minutes. |
| `ludus_install_malcolm_image_pull_timeout_seconds` | `3600` | Bound for a required Compose image pull. |
| `ludus_install_malcolm_start_timeout_seconds` | `1800` | Bound for Malcolm startup. |
| `ludus_install_malcolm_stop_timeout_seconds` | `600` | Bound for Malcolm shutdown. |
| `ludus_install_malcolm_readiness_timeout_seconds` | `1800` | Shared bound for container and authenticated API readiness. |
| `ludus_install_malcolm_health_poll_interval_seconds` | `10` | Delay between aggregate container-health snapshots. |
| `ludus_install_malcolm_tls_dhparam_size` | `2048` | Web TLS Diffie-Hellman parameter size. |
| `ludus_install_malcolm_systemd_unit_path` | `/etc/systemd/system/malcolm.service` | Managed systemd unit location. |
| `ludus_install_malcolm_tcp_retries2` | `null` | Optional explicit `net.ipv4.tcp_retries2`; null preserves the host value. |

When capture is enabled, the resolved interface must exist. The role enables
netsniff-ng as the single live PCAP storage engine and keeps tcpdump disabled to
avoid duplicate packet storage.

## Example

Keep the password in encrypted inventory rather than plaintext role defaults:

```yaml
---
- name: Install Malcolm
  hosts: pcap
  become: true
  roles:
    - role: role_malcolm_install
  vars:
    ludus_install_malcolm_admin_username: condef
    ludus_install_malcolm_admin_password: "{{ vault_malcolm_admin_password }}"
    ludus_install_malcolm_capture_enabled: true
```

## Source And Migration Policy

The only accepted source is Git commit
`07bbccdfe2732fb5c5147070cdfca2857b85bacc`, corresponding to `v26.08.0`.
A fresh install clones to the sibling staging directory
`<install_dir>.ludus-partial`, verifies the exact commit, and renames it into
place. A narrowly identifiable interrupted no-checkout clone can resume only
when its origin, HEAD, commit object, and index state match the role's expected
state. No partial directory is recursively deleted.

An existing installation is adopted only when it is a clean Git checkout at
the exact commit. That established-source path does not require a particular
remote URL; origin enforcement applies to fresh and narrowly recoverable partial
clones. Tracked modifications, another commit, non-Git source, an ambiguous
partial tree, and arbitrary-version overrides fail before source mutation. Move
the old installation aside, preserve its data and configuration, and perform an
explicit operator-reviewed migration; the role does not upgrade, force-reset,
recursively replace, or recursively chown an existing tree.

## Reruns And Recovery

The role executes preflight, packages, system settings, installation,
configuration, authentication, and service convergence in that order. The
shared `ludus_install_docker` role runs at the start of the packages phase, only
after side-effect-free Malcolm input, account, capture, partial-tree, and source
checks pass. Missing release environment files are initialized from the pinned
examples; managed keys converge while unknown settings remain. Relevant changes
notify one `Restart Malcolm` handler. An unchanged run does not unconditionally
reload or restart systemd.

Backend credentials are recovered independently. Valid established values are
adopted and never rotated on an unchanged run. The role records durable
per-artifact initialization evidence outside each authoritative backend file and
the primary OpenSearch curlrc. A backend marker is committed only after the
final persisted value is read back and validated, so a failed final write leaves
no false evidence and can resume. Missing, empty, or known release placeholders
are generated only when that artifact has no initialization evidence and the
runtime is genuinely fresh. Evidence for one artifact does not block independent
interrupted fresh initialization of another.

Before environment examples or credentials are generated, the role classifies
an unmarked legacy installation as established when it has nonempty persistent
data, the managed systemd service unit, or a valid established administrator
crypt record. The pinned source placeholder `opensearch/.gitignore` is excluded
from persistent-data evidence; other entries, including hidden data, still count.
Missing backend files or the primary curlrc then fail closed even
without new markers. A malformed established secret, or complete loss of an
authoritative file from marked or legacy established state, fails before example
recreation or credential generation. Restore the missing authoritative artifact
from backup and rerun; removing its evidence or retained runtime signal to force
replacement is not a supported recovery path.

The clear administrator password is required on every run but is protected by
`no_log` and disabled diffs. Changing it rotates only the admin SHA-512 crypt
and bcrypt records. Changing the username removes only the prior managed admin
record. Other newline-delimited htpasswd principals are retained. Use encrypted
inventory and rotate the supplied vault value, then rerun the role; do not edit
generated hashes directly.

TLS uses self-signed web material and a separate retained forwarding CA. Valid
keys, certificates, trust copies, and the forwarding CA survive reruns. Missing
or expired derived leaf certificates are repaired while valid keys and the CA
remain. A leaf signed by the wrong CA is reissued under the retained CA when its
key is valid. Missing CA private keys, key/certificate mismatches, expired or
malformed established CAs, divergent trust copies, and complete loss of all
authoritative CA artifacts after initialization fail before CA rotation. Derived
CA requests and forwarding leaves also classify a legacy trust set as
established when durable evidence is not yet present. Restore the matching CA
key and certificate or trust copy from backup and rerun. The role never silently
replaces an unrecoverable established trust root, while missing derived leaves
remain independently repairable.

## Service And Readiness

The managed unit runs as the selected account with the dedicated venv,
`Type=oneshot`, `RemainAfterExit=yes`, explicit working directory and bounded
start/stop commands. Before startup the role validates the real Compose model
and exact `26.08.0` image tags, then pulls only when required images are absent.

Success requires all expected profile containers to be running and healthy (or
running without a healthcheck) within one shared timeout. It then performs a
bounded Basic-auth request to the self-signed localhost endpoint
`https://127.0.0.1/mapi/ready` and requires true `opensearch`, `pcap_monitor`,
`logstash_lumberjack`, and `logstash_pipelines` fields. TLS verification is
disabled only for that localhost readiness probe.

## Troubleshooting

Missing backend-file and primary OpenSearch credential guards report the missing
artifact and boolean initialization-marker/legacy-runtime evidence without
printing credential contents.

These commands report status without dumping environment files, hashes,
private keys, or clear credentials:

```bash
sudo systemctl status malcolm.service --no-pager
sudo journalctl -u malcolm.service --since today --no-pager
sudo -u debian docker compose --file /home/debian/Malcolm/docker-compose.yml --profile malcolm ps --all
curl --silent --show-error --insecure --user condef https://127.0.0.1/mapi/ready
```

The final `curl` command prompts for the password instead of placing it in shell
history. For nondefault account or install paths, substitute the configured
values. Source rejection diagnostics include detected provenance; do not work
around them with `git reset`, directory deletion, or manual secret regeneration.

## Validation

Reproducible local commands and prerequisites are in
[`tests/README.md`](tests/README.md). They execute production task includes only
against scratch paths and do not change Docker, systemd, sysctls, or packages on
the coding host. VM-only install, rerun, rotation, reboot, and ingestion checks
are intentionally separate in [`tests/VM_ACCEPTANCE.md`](tests/VM_ACCEPTANCE.md).

## License

GPLv3
