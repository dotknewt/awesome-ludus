# TODO

## Docs
- [ ] Create project setup instructions that can be fed to an agent to configure and install MCPs and skills
    - https://gitlab.com/badsectorlabs/ludus-mcp; replace `<YOUR_API_KEY>` with `{file:~/<PATH_TO_A_FILE>}`;gitignored if inside repo
    - https://gitlab.com/badsectorlabs/ludus-skills;install to project if not already present

## Roles
- [ ] **DOCKER-001 — in-progress:** Fix first-run Docker socket access without requiring redeployment.
    - Evidence: the 2026-10-19 `thrunt-malcolm` deployment changed Docker group membership and ran `reset_connection`, but the later Malcolm image pull failed with socket permission denied. Guest diagnostics show Docker was ready before the failure; a later login has the Docker group and the socket is `660 root:docker`.
    - Leading cause remains a hypothesis: stale Ansible session groups due to untemplated connection options during `reset_connection` ([upstream fix](https://github.com/ansible/ansible/pull/84240)). Before the hotfix, controller Ansible-core 2.16.14 passed raw variables to reset, while Ludus `c6528ccc` templates `ansible_user`; this may select a different SSH control socket. The failing process's groups were not captured, so the original incident's causal trace is unconfirmed.
    - The [controller backport and safeguards](troubleshooting/docker-socket-reset/README.md) were applied with explicit user authorization on 2026-10-20. The operator log records successful pre/post service runtime, version, config/module path, import, syntax, and file-hash checks; the retained backup is `/var/backups/ludus-ansible-reset-rrf8afhd`. Parent-session read-only SSH independently confirmed installed hashes match all three expected patched hashes. No service restart, deployment, guest probe, or role entrypoint execution occurred. Ansible-core 2.16.14/Python 3.13.5 remains an unsupported baseline.
    - Acceptance remains pending: separately authorized fresh deployment succeeds without a second run and rerun remains convergent. No full Ansible play or fresh-role behavior has been verified; static and import checks alone do not establish this.

### New
- [ ] **SPLUNK-001 — proposed:** Evaluate optional Windows Security event exclusions after collecting a baseline.
    - Decide separately whether the 4662, 566, and 5145 C$ exclusions are warranted by event volume, noise, and detection value; document the rationale for each decision.
    - Before applying filters, verify XML field/regex behavior with separately authorized native keep/drop control events and confirm distinct blacklist keys do not override one another.
    - Depends on a deployed Windows logging pipeline and representative unfiltered logs. Keep every exclusion disabled until explicitly approved; this item does not authorize live evaluation or enabling filters.
    - See [Windows Splunk design](superpowers/specs/2026-10-20-ludus-windows-splunk-logging-design.md).
- [ ] **SPLUNK-002 — proposed:** Defer optional HEC for a reusable server role. Desired outcome: optionally configure secure HEC on `8088` with a securely managed token while preserving existing Kubernetes/application consumers and native UF delivery on `9997` unchanged. Dependencies: future default-index, TLS, and token-handling decisions plus official documentation verification. Later work requires static tests and separately authorized live delivery tests; this is explicitly deferred and does not authorize execution. See [Splunk HEC setup](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/set-up-and-use-http-event-collector-in-splunk-web) and the legacy role reference; do not copy its secret-output script behavior.
- [ ] Create a kubernetes installer role
- [ ] Create gitlab builder/runner/worker roles (targeting docker/kubernetes as well as "native")
- [ ] Create ludus role for https://github.com/S3N4T0R-0X0/BEAR-C2
