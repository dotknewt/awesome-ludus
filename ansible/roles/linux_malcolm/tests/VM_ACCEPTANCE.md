# VM Acceptance Checklist

These checks have not yet been run. They are deliberately VM-only because the
role changes apt packages, Docker access, sysctls, limits, TLS files, and
systemd. Never target the coding host. Record command output separately for
Debian 12 and Debian 13; success on one release does not prove the other.

## Preparation

- [ ] Provision clean amd64 Debian 12 and Debian 13 VMs with the selected role account and become access.
- [ ] Verify required roles, `ansible.posix >= 2.2.2`, and `community.crypto >= 3.4.0` are installed on the controller.
- [ ] Place the administrator password in Ansible Vault or another no-log variable source, not CLI extra vars or shell history.
- [ ] Put each VM in a dedicated `malcolm_acceptance` inventory group and set `malcolm_acceptance_authorized: true` only for that group.
- [ ] Take a VM snapshot before destructive fault-injection checks.
- [ ] For Ludus, run the server-side range-config validation before deployment; do not treat local YAML parsing as a live compatibility result.

Invoke `vm-acceptance.yml` with encrypted inventory values. Leave
`malcolm_acceptance_capture_interface` empty to test default-interface
discovery, then repeat with the actual capture NIC explicitly selected.

```bash
ansible-playbook --inventory acceptance.ini ansible/roles/role_malcolm_install/tests/vm-acceptance.yml --ask-vault-pass
```

## Each Debian Release

- [ ] **Fresh install:** On a clean Debian 12 VM, run the acceptance playbook and retain the recap, Malcolm source HEAD, Compose validation, image-pull timing, systemd status, container-health result, and authenticated readiness result.
- [ ] **Fresh install:** Repeat the independent clean-VM procedure on Debian 13.
- [ ] **Pinned source:** For each role-created fresh checkout, confirm `git -C /home/debian/Malcolm rev-parse HEAD` is `07bbccdfe2732fb5c5147070cdfca2857b85bacc` and the origin is the CISA Malcolm repository. Record separately that adoption of an existing clean checkout enforces the commit and tracked status but not its remote URL.
- [ ] **Target compatibility:** Confirm apt package availability, owner Docker access, target Python cryptography modules, real `docker compose config`, all 23 pinned image references, image pulls, and default 2048-bit DH generation.
- [ ] **Readiness:** Confirm every expected Compose service is running and healthy or has no healthcheck, then confirm authenticated `/mapi/ready` reports true for `opensearch`, `pcap_monitor`, `logstash_lumberjack`, and `logstash_pipelines`.
- [ ] **second-run convergence:** Immediately rerun the same acceptance command. Require `changed=0`, no systemd daemon reload/restart, and identical backend secret and forwarding-CA fingerprints.
- [ ] **secret fingerprints:** Save only the SHA-256 values emitted by the playbook. Never archive environment files, htpasswd contents, private keys, clear passwords, or Ansible `-vvv` secret output.
- [ ] **secondary principal:** Add a disposable non-admin bcrypt principal with the target venv's Passlib, rotate the vaulted admin password, and rerun with `malcolm_acceptance_expected_secondary_username` set. Confirm the secondary record remains and only the admin-related fingerprint changes.
- [ ] **Admin rename:** Change the managed admin username and rerun. Confirm the old managed admin record is removed, the new record authenticates, and the secondary principal remains.
- [ ] **interrupted recovery:** From a disposable snapshot, stop Malcolm, remove only a recoverable derived web leaf certificate while retaining its valid key, and rerun. Confirm the leaf is repaired, backend secret and forwarding-CA fingerprints remain unchanged, readiness returns, and the following run converges.
- [ ] **Unrecoverable-state guard:** From a disposable snapshot, remove the forwarding CA private key while retaining its certificate/trust copy. Confirm the role fails before mutation, reports recovery guidance, and does not rotate the CA or alter backend secret fingerprints. Restore the snapshot afterward.
- [ ] **complete backend-file loss:** After a successful initialized run, stop Malcolm and remove `config/postgres.env` while retaining `.ludus-initialization/config__postgres.env`. Rerun and confirm the role fails in the configure phase before recreating the example, the missing file remains absent, and no other credential fingerprint changes. Restore the snapshot afterward.
- [ ] **complete primary-credential loss:** After a successful initialized run, stop Malcolm and remove `.opensearch.primary.curlrc` while retaining `.ludus-initialization/opensearch-primary-curlrc`. Rerun and confirm the role fails before password generation, the curlrc remains absent, and backend data and credential fingerprints remain unchanged. Restore the snapshot afterward.
- [ ] **complete forwarding CA-set loss:** After a successful initialized run, stop Malcolm and remove `logstash/certs/ca.key`, `logstash/certs/ca.crt`, and `filebeat/certs/ca.crt` while retaining `.ludus-initialization/forwarding-ca`. Rerun and confirm the role fails before CA generation, all three artifacts remain absent, derived leaf fingerprints remain unchanged, and recovery guidance requires restoring the authoritative CA. Restore the snapshot afterward.
- [ ] **legacy complete backend-file loss:** From an initialized disposable snapshot, remove `config/postgres.env` and its `.ludus-initialization/config__postgres.env` marker while retaining nonempty `postgres` data. Rerun and confirm legacy classification fails in the configure phase before example recreation or any credential mutation. Restore the snapshot afterward.
- [ ] **legacy primary-credential loss:** From an initialized disposable snapshot, remove `.opensearch.primary.curlrc` and its `.ludus-initialization/opensearch-primary-curlrc` marker while retaining nonempty `opensearch` data. Rerun and confirm the role fails before backend mutation or primary password generation. Restore the snapshot afterward.
- [ ] **reboot:** Reboot the VM, wait for SSH and network readiness, and confirm `malcolm.service`, containers, and authenticated readiness recover. Rerun the role and require convergence.
- [ ] **PCAP ingestion:** Generate or replay a small non-sensitive PCAP on the configured capture path/interface. Confirm one capture storage engine, packet visibility in Malcolm, processing-ready fields remain true, and rotation settings match the role inputs.
- [ ] **Capture disabled:** On a snapshot or separate VM, set capture false and verify both live capture engines are disabled without affecting imported PCAP workflows.
- [ ] **Failure diagnostics:** Exercise one bounded readiness failure and confirm the final aggregate Compose snapshot identifies starting, exited, and missing services without exposing secrets.

## Evidence To Record

Record OS version and architecture, controller Ansible/collection versions,
role commit/diff identifier, all play recaps, elapsed pull/start/readiness times,
non-secret artifact and initialization-evidence fingerprints, reboot outcome,
and PCAP observation. Preserve initialization evidence with the corresponding
authoritative backup. Mark a check `NOT RUN` rather than inferring success.
Until both release records contain all applicable evidence, Debian 12/13 live
compatibility remains not yet proven.
