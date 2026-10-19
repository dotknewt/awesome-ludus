---
name: ludus-troubleshoot
description: Use when diagnosing Ludus VM reachability or power-state issues, missing or misidentified source roles, or blueprint dependency installation failures requiring project-specific checks.
---

# Ludus Troubleshooting Extensions

**REQUIRED SUB-SKILL:** Load `troubleshooting` from [upstream Ludus skills](https://gitlab.com/badsectorlabs/ludus-skills) for the diagnostic workflow and common-error catalog. If unavailable, report the missing prerequisite and follow upstream installation instructions before proceeding. Apply the relevant local checks below alongside that workflow.

## VM reachability and power state

Verify each VM by its assigned numeric Proxmox VM ID (`proxmoxID`), not its name. Use `ludus-cli` and installed CLI help to confirm command syntax:

```bash
ludus range status --json | jq --argjson vmid "$VMID" '.VMs[] | select(.proxmoxID == $vmid)'
```

Inspect `poweredOn` in the matching result. No match is not proof the VM is powered off; confirm the range and assigned ID. A query failure does not establish power state. Do not automatically change power state.

## Source roles and blueprint dependencies

When a source role is missing, appears under an unexpected name, or dependency installation fails, read [source-role diagnostics](references/source-role-diagnostics.md) and apply its evidence checks before proposing changes.

Report the failing boundary, supporting evidence, and remaining uncertainty. Verify recovery after an approved correction; successful catalog discovery alone does not prove deployment succeeds.
