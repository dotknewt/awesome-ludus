---
name: range-config
description: Create, edit, and validate Ludus range configuration YAML including VM definitions, domains, networking, router settings, testing behavior, and role configuration. Use when users need help authoring or reviewing `ludus` range config files.
---

# Ludus Range Configuration

Use this skill to build safe, valid Ludus YAML configurations and explain tradeoffs in topology, networking, and role design.

## Key Principles

1. **Always suggest the YAML schema validation header** at the top of configs:
   ```yaml
   # yaml-language-server: $schema=https://docs.ludus.cloud/schemas/range-config.json
   ```

2. **Range creation defaults (repository policy, not official Ludus defaults).** Unless explicitly told to change or exclude one or more of them, every range config created here must include all three of these settings in the range-level `defaults:` block:
   ```yaml
   defaults:
     snapshot_with_RAM: true
     stale_hours: 0
     timezone: Europe/Oslo
   ```
    The official schema default timezone is `America/New_York`; `Europe/Oslo` is this repository's mandated default. When a user explicitly asks to change or exclude a setting, apply the explicit instruction and note the deviation. If the whole `defaults:` block is unwanted, that too must be an explicit instruction — never drop these defaults silently.

   Also apply the router defaults required by the canonical [Ludus authoring policy](../../../docs/instructions/ludus-authoring.md#range-creation-defaults): `template: no-debian-13.5-x64-server-template`, `vm_name: "{{ range_id }}-router"`, and `hostname: "{{ range_id }}-router"`. Explicit user overrides or an explicit request for no router take precedence. These are repository defaults, not official Ludus defaults.

3. **Use `{{ range_id }}` template strings** in vm_name and hostname fields. This resolves to the user's range ID (e.g., "JS").

4. **Windows hostnames are limited to 15 characters** due to NETBIOS.

5. **VLANs must be 2-255** and become the third octet of the VM's IP (e.g., vlan 10 = 10.X.10.Y).

6. **ip_last_octet must be unique within a VLAN**.

7. **Set `linux: true`** for Linux VMs, **`windows:` key** for Windows VMs, **`macOS: true`** for macOS VMs.

8. **Domain roles** are: `primary-dc`, `alt-dc`, or `member`.

9. **role_vars must be a dictionary** - do not use hyphens to prefix variables.

10. **Roles must exist on the server** before deploy — verify installed roles and add any that are missing.

## Workflow

1. Clarify the target environment and intended use case.
2. Define required VMs and roles.
3. Apply the mandatory range creation defaults (Key Principle 2) to the `defaults:` block unless the user explicitly changed or excluded one or more of them.
4. Verify that required templates are available on the server.
5. Build or revise YAML in small, valid increments.
6. Propose network rules and testing behavior appropriate for the scenario.
7. Verify that required Ansible roles/collections are installed; recommend any that need to be added.
8. Validate structure and values against the schema reference.
9. When finishing role work, validate changed files only with file-scoped checks supported by available tools; do not expand completion checks to unchanged files or whole-role directories. If available tools cannot check the changed files without widening scope, report those checks as unavailable. Record unresolved paths or unsuitable harnesses as coverage gaps without validating unchanged targets. This role check is tied to finishing role work, not a prerequisite for live deployment or retries. Actual failures and coverage errors block claiming role work is complete; carry forward `PASS WITH WARNINGS — NOT VERIFIED` with every unavailable check and target. Static results do not establish runtime behavior or authorize deployment.

## References

- Use `references/schema.md` for full schema details, valid values, defaults, and complete examples.
- Use `https://docs.ludus.cloud/docs/configuration` for official configuration guidance.
- Use `https://docs.ludus.cloud/schemas/range-config.json` for schema-backed validation.
