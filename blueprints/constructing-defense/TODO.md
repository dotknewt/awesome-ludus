# Roles

## First-deploy Docker access and range setup

- [ ] Review `ludus_install_docker`, `ludus_install_minikube`, `role_k8s_telemetry_collection`, `ludus_install_malcolm`, and this blueprint's `range-config.yml` for first-deploy ordering and Docker access fixes.
  - Observed 2026-10-16: Minikube startup on `linuxv` and Malcolm image pulls on `pcap` failed with Docker socket permission denied; rerunning `ludus deploy` resolved both. Root cause remains unconfirmed.
  - Check provisioning order, configured users, effective Ansible/become supplementary groups, connection resets, and Docker socket readiness; capture evidence during a fresh deployment before selecting a fix.
  - Review the Minikube command's folded YAML/backslashes and audit-policy home directory consistency.
  - Acceptance: both services deploy successfully on a fresh range without a second deployment, and a rerun remains convergent.

## role_gpo_deploy
ansible/roles/role_gpo_deploy/tasks/main.yml is a single big script; "convert" script to ansible using 

## role_malcolm_install

- [x] Replace the remote installer with native, pinned, convergent Ansible tasks.
- [x] Retain `ludus_install_docker` as the Docker dependency.
- [ ] Run and record the VM acceptance checklist on Debian 12 and Debian 13.
- [ ] Confirm real Docker Compose pull/start/health/readiness behavior, default DH generation, rerun convergence, reboot recovery, and PCAP ingestion on both releases.

The local behavioral suite passes independently of a Ludus deployment, but live
Debian 12/13 compatibility is not proven until every item in the role's
`tests/VM_ACCEPTANCE.md` has been executed successfully.

## make ansible from scripts
1. `create-shares.ps1` — creates AD users `OlaBruker` / `OlaAdmin`, 15 folders under
   `C:\Shares\Share1..15`, and SMB shares `Logs1..15`.
2. `kerberoast-telemetry.ps1` — creates `OU=Kerberoast` and users with SPNs so Kerberoasting
   generates telemetry.
