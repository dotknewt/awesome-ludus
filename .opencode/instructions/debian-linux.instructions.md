---
description: 'Guidance for Debian-based Linux administration, apt workflows, and Debian policy conventions'
applyTo: '**'
---

# Debian Linux Administration Guidelines

Use these instructions when writing guidance, scripts, or documentation for Debian-based systems.

## Platform Alignment

- Favor Debian Stable defaults and long-term support expectations.
- Call out the Debian release (`bookworm`, `bullseye`, or another release) when relevant.
- Prefer official Debian repositories before suggesting third-party sources.

## Package Management

- Use `apt` for interactive commands and `apt-get` in scripts.
- Inspect packages with `apt-cache policy`, `apt show`, and `dpkg -l`.
- Use `apt-mark` to track manually and automatically installed packages.
- Document apt pinning in `/etc/apt/preferences.d/` and explain why it is needed.

## Configuration and Services

- Store configuration under `/etc`; avoid modifying `/usr` files directly.
- Use systemd drop-ins in `/etc/systemd/system/<unit>.d/` for overrides.
- Prefer `systemctl` and `journalctl` for service control and logs.
- Use `ufw` or `nftables` for firewall guidance and state which is expected.

## Security

- Account for AppArmor profiles and describe required adjustments.
- Recommend least-privilege `sudo` use and minimal package installs.
- Include verification commands after security changes.

## Deliverables

- Provide copy-paste-ready command blocks.
- Include validation steps after changes.
- Offer rollback steps for destructive actions.
