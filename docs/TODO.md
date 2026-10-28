# TODO

## Docs
- [ ] Create project setup instructions that can be fed to an agent to configure and install MCPs and skills
    - https://gitlab.com/badsectorlabs/ludus-mcp; replace `<YOUR_API_KEY>` with `{file:~/<PATH_TO_A_FILE>}`;gitignored if inside repo
    - https://gitlab.com/badsectorlabs/ludus-skills;install to project if not already present

## Roles
- [ ] **ROLES-001 — ready:** Standardize Linux role identities and metadata on the preferred names.
    - Canonical names (replace the corresponding legacy identity):
        - `linux_splunk_server` over `linux_splunk_enterprise`.
        - `linux_gitlab_ce` over `ludus_gitlab_ce`.
        - `linux_logging` over `ludus_linux_logging`.
        - `linux_gitlab_runner` over `ludus_gitlab_runner`.
        - `linux_k3s_bootstrap` over `ludus_k3s_bootstrap`.
        - `linux_install_docker` over `ludus_install_docker`.
    - Scope: reconcile role directory names and `galaxy_info.role_name`, source/blueprint dependencies, range role assignments and `depends_on` references, internal role calls, and current documentation/static checks. Preserve author attribution and existing variable APIs; variable-prefix renames are not part of this task.
    - Acceptance: the six canonical identities are consistent across active repository references; relevant static checks pass; any retained legacy references are explicitly documented as historical or migration guidance. Verify installed identities against the target Ludus version/catalog before claiming server compatibility.
    - Dependency/open question: determine how existing installed legacy roles will be migrated or retired without breaking deployed ranges. Server installation/removal and live deployment require separate authorization.
    - Backlog only: ready does not authorize implementation.
- [x] **DOCKER-001 — done:** Fix first-run Docker socket access without requiring redeployment.
    - Evidence: the 2026-10-19 `thrunt-malcolm` deployment changed Docker group membership and ran `reset_connection`, but the later Malcolm image pull failed with socket permission denied. Guest diagnostics show Docker was ready before the failure; a later login has the Docker group and the socket is `660 root:docker`.
    - Leading cause remains a hypothesis: stale Ansible session groups due to untemplated connection options during `reset_connection` ([upstream fix](https://github.com/ansible/ansible/pull/84240)). Before the hotfix, controller Ansible-core 2.16.14 passed raw variables to reset, while Ludus `c6528ccc` templates `ansible_user`; this may select a different SSH control socket. The failing process's groups were not captured, so the original incident's causal trace is unconfirmed.
    - The [controller backport and safeguards](../ansible/roles/linux_docker/docker-socket-reset/README.md) were applied with explicit user authorization on 2026-10-20. The operator log records successful pre/post service runtime, version, config/module path, import, syntax, and file-hash checks; the retained backup is `/var/backups/ludus-ansible-reset-rrf8afhd`. Parent-session read-only SSH independently confirmed installed hashes match all three expected patched hashes. No service restart, deployment, guest probe, or role entrypoint execution occurred. Ansible-core 2.16.14/Python 3.13.5 remains an unsupported baseline.
    - Acceptance: the user confirmed the 2026-10-20 `dev-malcolm` deployment succeeded on the first try, providing live first-run verification after the backport. A separate convergence rerun was not performed; the original 2026-10-19 `thrunt-malcolm` failure's causal trace also remains unconfirmed.
- [ ] Add opt-out installation of the PSTree splunk app (https://github.com/murchisd/splunk_pstree_app) when installing ludus_splunk_server
- [ ] **SPLUNK-001 — proposed:** Evaluate optional Windows Security event exclusions after collecting a baseline.
    - Decide separately whether the 4662, 566, and 5145 C$ exclusions are warranted by event volume, noise, and detection value; document the rationale for each decision.
    - Before applying filters, verify XML field/regex behavior with separately authorized native keep/drop control events and confirm distinct blacklist keys do not override one another.
    - Depends on a deployed Windows logging pipeline and representative unfiltered logs. Keep every exclusion disabled until explicitly approved; this item does not authorize live evaluation or enabling filters.
    - See [Windows Splunk design](superpowers/specs/2026-10-20-ludus-windows-splunk-logging-design.md).

## Range configs
- [ ] **RANGE-001 — blocked:** Re-review and fix `blueprints/detect-evil/range-config.yml` after ROLES-001.
    - Dependency: ROLES-001 must be completed before this follow-up begins; reassess the then-current config rather than blindly applying earlier review snippets.
    - Scope: review role inputs and ordering against the finalized role contracts and current official Ludus schema; apply confirmed range-config fixes. Recheck exact `depends_on` matches, the new Linux VM's forwarder-before-logging order and explicit `splunkfwd` Laurel reader, global Windows/Linux inputs, and GPO link structures.
    - Open question: confirm whether GitLab Docker-job logs must be collected in addition to K3s pod logs; do not silently expand telemetry scope or change executor architecture.
    - Preserve the prior review exclusions: no separate role-inventory/migration work beyond ROLES-001, Malcolm capture-topology work, fleet-wide Linux telemetry expansion, Defender overlap cleanup, blueprint metadata cleanup, or schema-header-only cleanup.
    - Acceptance: confirmed in-scope issues are fixed, dependency references match assigned roles, scoped static/schema checks are recorded, and remaining telemetry decisions and runtime verification gaps are explicit. Live deployment and guest probes require separate authorization.
    - Backlog only: this entry does not authorize implementation or automatic execution when ROLES-001 completes.

## Splunk
- [ ] **SPLUNK-001 — proposed:** Evaluate optional Windows Security event exclusions after collecting a baseline.
    - Decide separately whether the 4662, 566, and 5145 C$ exclusions are warranted by event volume, noise, and detection value; document the rationale for each decision.
    - Before applying filters, verify XML field/regex behavior with separately authorized native keep/drop control events and confirm distinct blacklist keys do not override one another.
    - Depends on a deployed Windows logging pipeline and representative unfiltered logs. Keep every exclusion disabled until explicitly approved; this item does not authorize live evaluation or enabling filters.
    - See [Windows Splunk design](superpowers/specs/2026-10-20-ludus-windows-splunk-logging-design.md).
- [ ] **SPLUNK-002 — proposed:** Defer optional HEC for a reusable server role. Desired outcome: optionally configure secure HEC on `8088` with a securely managed token while preserving existing Kubernetes/application consumers and native UF delivery on `9997` unchanged. Dependencies: future default-index, TLS, and token-handling decisions plus official documentation verification. Later work requires static tests and separately authorized live delivery tests; this is explicitly deferred and does not authorize execution. See [Splunk HEC setup](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/set-up-and-use-http-event-collector-in-splunk-web) and the legacy role reference; do not copy its secret-output script behavior.
- [ ] **SPLUNK-003 — blocked:** Evaluate optional SILK channel autoconfiguration for the consolidated Windows forwarder. Scope: only consider adding opt-in input-driven SILK channel configuration after the merged Windows forwarder has passed separately authorized basic live installation and convergence verification; no implementation or automatic subscription is authorized by this item. Acceptance: document the supported opt-in contract and producer/channel assumptions; add focused static coverage; after separate authorization, verify native channel-present and channel-absent behavior and resulting event routing without changing the default Security/Sysmon inputs. Dependency: basic merged Windows forwarder functionality must first be live-verified on an authorized target and the user must approve the feature contract. Until then, omit SILK from examples and keep this item blocked.
- [ ] Configure an appropriate default date-time format so search results display like `2026-10-21T15:30:54.825+02:00`, not `10/21/26 3:30:54.825 PM`

### New
- [ ] Create or reuse existing kubernetes installer role (https://github.com/NetPenguins/ludus_k3s)
- [ ] Create gitlab builder/runner/worker roles (targeting docker/kubernetes as well as "native")
- [ ] Create ludus role for https://github.com/S3N4T0R-0X0/BEAR-C2
- [ ] Improve existing flarevm role using official documentation: https://github.com/mandiant/flare-vm
- [ ] Improve existing commandovm role using official documentation: https://github.com/mandiant/commando-vm
