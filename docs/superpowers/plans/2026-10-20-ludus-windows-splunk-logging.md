# Windows Splunk logging extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `ludus_splunk_collector` to collect Windows Security, Sysmon, and SilkService-Log data while preserving Linux behavior and safely managing only owned configuration.

**Architecture:** Add a guarded Windows branch to the existing collector task graph; keep Linux task files and defaults behaviorally unchanged. Run `ludus_install_sysmon` explicitly before the collector in Windows examples, with no hidden sibling execution. Extend `ludus_splunk_server` independently with append-only index management.

**Tech Stack:** Ansible roles/YAML/Jinja, Windows Ansible collections, PowerShell/Windows services, Splunk Universal Forwarder MSI, Python `unittest` static contracts, repository `ansible-validation` script.

**Spec:** `docs/superpowers/specs/2026-10-20-ludus-windows-splunk-logging-design.md`; research: `docs/research/ludus-splunk-collector-windows.md`.

## Global Constraints

- Target only Windows 11 x64 and Server 2019/2022/2025 x64; older platforms remain deferred.
- Preserve Debian/Linux collector behavior; all Linux mutations remain platform-guarded.
- Verified Windows pin: `ludus_splunk_collector_windows_version: 10.6.1.1` (vendor release), `ludus_splunk_collector_windows_msi_product_version: 10.6.1.1`, URL `https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi`, checksum `sha512:980658ef29a964e430ee7b601b170324185a2d93fcee83f55d992a522d20355dc784f2947839690b12265ba775f861810d610244c7cc978c65e20f588147f693`.
- If Task 0 cannot verify those inputs, stop the Windows work; do not invent flags, product codes, hashes, or use a fallback LocalSystem path.
- Prefix every collector variable with `ludus_splunk_collector_`; Windows package inputs must be explicit and must not change Debian defaults.
- Security is an unfiltered XML baseline: `oldest`, `current_only=0`, index `winlogs`, with no inherited TA exclusions.
- Optional exclusion candidates remain commented docs-only: `blacklist1` 4662, `blacklist2` 566, `blacklist3` 5145 C$; SPLUNK-001 is not authorization.
- Sysmon event filtering remains producer-owned; the collector owns the channel input indexed as `sysmon` and does not change `ludus_install_sysmon` filters.
- SilkService-Log is collection-only: `disabled=0`, `index=etw`, `sourcetype=json`; never install, start, configure, or alter its producer/audit policy.
- Server consumes only `ludus_splunk_server_indexes`; receiver host/port remain external topology inputs to the collector. Indexes match `^[a-z][a-z0-9_]{0,79}$`, reject reserved/internal/default names, and use `[winlogs, sysmon, etw]` only in the integration example.
- No firewall changes, TLS work, full TA installation, legacy role/blueprint migration, automatic reboot/upgrade, password rotation, or command-line credentials.
- Reject unmanaged competing installations/configuration, reparse points/symlinks, unsafe injection, and same-version blind adoption.
- Fresh installation must use an ownership marker and crash-safe install transition; credential seed cleanup follows fresh authenticated readiness only.
- Missing SilkService channel is a producer prerequisite: use documented nonblocking config plus warning if supported; otherwise stop for research without silently creating the channel or blocking Security.
- Verification is static only in this plan; no deployment, guest probe, package install, simulated runtime, or live evaluation is authorized.
- HEC is deferred and out of scope: preserve native TCP `9997`; do not implement port `8088`, token handling, TLS, or legacy secret-output behavior. Track future work as `SPLUNK-002` only.

## Review Focus

- **Artifact identity:** URL/checksum/version/ProductVersion/vendor-version distinctions and target support — Task 0.
- **Service security:** verified virtual account, bootstrap/start control, and Security/Sysmon/Silk Event Log access without credential fallback — Task 0/2.
- **Platform isolation:** Windows branch cannot alter Linux defaults or run Linux modules; Linux regression assertions — Task 3.
- **Ownership and recovery:** unmanaged state fails before mutation; partial install recovery and marker transitions are explicit — Task 2/3.
- **Input semantics:** zero Security exclusions, exact three-source routing, and no XML flags on SilkService — Task 3.

---

## File map and shared interfaces

**Modify:** `ansible/roles/ludus_splunk_collector/defaults/main.yml`, `tasks/main.yml` (entrypoint guard/import seams only), `tasks/windows/main.yml`, `tasks/windows/validate.yml`, `tasks/windows/inspect.yml`, `tasks/windows/install.yml`, `tasks/windows/configure.yml`, `templates/windows-inputs.conf.j2`, `templates/windows-outputs.conf.j2`, `templates/windows-user-seed.conf.j2`, `handlers/main.yml`, `meta/main.yml`, `README.md`, `tests/test_windows_static.py`, and `tests/syntax-windows.yml`. Existing Linux task files remain unchanged except the entrypoint guard; update existing Linux-only metadata assertions precisely where the platform matrix changes.

**Modify:** `ansible/roles/ludus_splunk_server/defaults/main.yml`, `tasks/main.yml`, `tasks/indexes_preflight.yml`, `tasks/indexes_configure.yml`, `templates/indexes.conf.j2`, `README.md`, and `tests/test_indexes_static.py`; use a separately owned app at `/opt/splunk/etc/apps/ludus_indexes/local/indexes.conf` and an ownership marker. Do not edit `receiver_preflight.yml` or `receiver_configure.yml` absent a concrete need.

**Do not modify:** `ansible/roles/ludus_install_sysmon/**`, legacy `role_splunk_collector_win11v`, existing legacy blueprint, or unrelated blueprints/TODO entries.

**Shared collector inputs:**

```yaml
ludus_splunk_collector_receiver_host: external-receiver-host
ludus_splunk_collector_receiver_port: 9997
ludus_splunk_collector_accept_license: true
ludus_splunk_collector_windows_package_url: "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi"
ludus_splunk_collector_windows_package_checksum: "sha512:980658ef29a964e430ee7b601b170324185a2d93fcee83f55d992a522d20355dc784f2947839690b12265ba775f861810d610244c7cc978c65e20f588147f693"
ludus_splunk_collector_windows_version: "10.6.1.1" # vendor release string
ludus_splunk_collector_windows_msi_product_version: "10.6.1.1"
ludus_splunk_collector_windows_security_index: winlogs
ludus_splunk_collector_windows_sysmon_index: sysmon
ludus_splunk_collector_windows_silkservice_index: etw
```

These package inputs are now a verified pin; ProductCode `{B253F87A-EEBB-46C4-AA25-D9FDB2542B63}` is evidence, not a default input because `win_package` derives identity from the local MSI. The server receives `ludus_splunk_server_indexes: []` by default or `[winlogs, sysmon, etw]` in the explicit integration example. Fixed Windows home is `C:\Program Files\SplunkUniversalForwarder`; service is `SplunkForwarder`; neither is configurable.

**Role ordering interface:** examples must invoke the installed Sysmon role explicitly before `ludus_splunk_collector` on Windows and use verified installed role identities only. Do not infer an installed identity from a source directory; unresolved identity evidence remains a documented gap.

## Task 0: Research stop gate

**Files:**
- Read: `docs/research/ludus-splunk-collector-windows.md`, official primary sources, selected role metadata and requirements.
- Update only if evidence is found: `docs/research/ludus-splunk-collector-windows.md`.

**Interfaces:** Produces a recorded artifact URL, checksum, version mapping, supported target matrix, installer/bootstrap behavior, virtual service account, start/reboot behavior, Security/Sysmon/Silk Event Log permissions, Windows collection pins, and verified role identities for later tasks.

- [x] Record publisher-verified Windows artifact URL/checksum, exact MSI ProductVersion, vendor release string, and architecture; Task 0 artifact identity is partially closed.
- [ ] Confirm installer properties/bootstrap and service start control from primary sources; record no invented product codes or flags.
- [ ] Confirm the documented virtual service account and required Security, Sysmon, and SilkService Event Log access; reject LocalSystem fallback.
- [ ] Confirm supported `ansible.windows`/PowerShell pins and collection behavior for the selected artifact.
- [ ] Use verified Splunk page evidence for `LAUNCHSPLUNK`, `SERVICESTARTTYPE`, and the no-user seed route; separately verify exact seed syntax, permissions including DC-safe EventLogReaders access, collection documentation/pins, and selected-version compatibility. Do not claim Task 0 fully closed until parent advisory review.
- [x] Documentary Task 0 prerequisites are recorded; native ACL, seed authentication, channel presence, source-version compatibility, and runtime validation remain separate gates and must not be claimed as verified.

## Task 1: Lock collector inputs and platform dispatch

**Files:**
- Modify: `ansible/roles/ludus_splunk_collector/defaults/main.yml`, `tasks/main.yml`, `meta/main.yml`.
- Create: `ansible/roles/ludus_splunk_collector/tests/test_windows_static.py`, `tests/syntax-windows.yml`.

**Interfaces:** Consumes Task 0 evidence. Produces validated `ludus_splunk_collector_windows_*` inputs and mutually exclusive Linux/Windows task branches. This is shared skeleton work, not independently deployable; Tasks 1–3 form one atomic collector deliverable owned by one writer.

**Required behavior (implemented only after red tests):**

- Four package inputs are explicit: URL, checksum, vendor version, and MSI ProductVersion; the three fixed index inputs are `winlogs`, `sysmon`, and `etw`. Home and service identity remain fixed, not configurable.
- Main imports the Windows seam before any mutation and before service start/restart; Linux task files remain unchanged except the entrypoint guard.

- Preserve Debian defaults; expose only the four package inputs and three index inputs defined above.
- Require pre-mutation assertions for supported OS/version/architecture, HTTPS URL, checksum format, ProductVersion mapping, receiver, license, bounded paths/indexes, and no command-line credentials.
- Confine Linux tasks and `become` to the Linux branch; guard Windows tasks with the selected Windows matrix.
- [ ] First write static assertions in `tests/test_windows_static.py` using `ROLE = Path(__file__).resolve().parents[1]`, `_load_yaml`, and `_task_sequence`: `test_windows_defaults_are_verified_and_named` includes `defaults=yaml.safe_load((ROLE/'defaults/main.yml').read_text()); self.assertEqual(defaults['ludus_splunk_collector_windows_security_index'],'winlogs'); self.assertEqual(defaults['ludus_splunk_collector_windows_package_url'],'https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi'); self.assertEqual(defaults['ludus_splunk_collector_windows_msi_product_version'],'10.6.1.1')`; also assert exact checksum/pin and validation-before-mutation; `test_linux_defaults_and_tasks_remain_immutable` asserts existing Debian package/checksum/monitor values.
- [ ] Ask fast-generic to run red: `python3 -m unittest discover -s ansible/roles/ludus_splunk_collector/tests -p 'test_windows_static.py' -v`; expected FAIL because the new contract is absent.
- [ ] Add the defaults, guarded imports, and metadata; name `tasks/windows/main.yml` imports in order `validate.yml`, `inspect.yml`, `install.yml`, `configure.yml`, before service start/restart.
- [ ] Ask fast-generic to rerun the same command and require PASS. Do not checkpoint yet: Tasks 1–3 share the collector writer and must finish as one atomic deliverable, followed by all collector tests, Windows syntax, and regression checks.

## Task 2: Implement owned Windows installation and safe lifecycle

**Files:**
- Create/modify: `ansible/roles/ludus_splunk_collector/tasks/windows/validate.yml`, `inspect.yml`, `install.yml`, `configure.yml`, `tasks/windows/main.yml`, `templates/windows-user-seed.conf.j2`, `handlers/main.yml`, and role README.
- Test: `ansible/roles/ludus_splunk_collector/tests/test_windows_static.py`.

**Interfaces:** Consumes Task 1 inputs and Task 0 installer/account evidence. Produces an owned installation with verified service path, identity, ProductVersion, marker, ACLs, and configuration transition state.

**Required behavior (implemented only after red tests):**

- Preflight is before all mutation; fixed home is `C:\Program Files\SplunkUniversalForwarder` and service is `SplunkForwarder`.

- Preflight existing service/path/marker/config state; fail before mutation on unmanaged or conflicting installation, unsafe reparse/symlink state, wrong identity/version, or incompatible ACL.
- Download MSI with verified checksum and install only using documented properties; distinguish MSI ProductVersion from release string in assertions.
- Use the verified virtual service account and documented Event Log permissions; never expose credentials or use LocalSystem fallback.
- Make ownership marker creation and install transition crash-safe; partial installation must be recoverable or fail with explicit remediation, never blind-adopt same-version state.
- Configure service start without an automatic reboot; report required reboot if the documented installer requires one, and do not continue as if started.
- Preserve unrelated files/resources and clean fresh-only credential seed only after authenticated readiness; protect failure paths and retain no command-line secret.
- [ ] First add `test_windows_install_preflight_precedes_mutation`, `test_unmanaged_same_version_is_rejected`, `test_partial_installation_is_not_adopted`, and `test_seed_cleanup_follows_authenticated_readiness`; assert task order using `_task_sequence()`, module names, fixed home/service, marker, no LocalSystem, seed retention on credential failure, and cleanup after authenticated readiness.
- [ ] Ask fast-generic to run the collector test command above; expected FAIL.
- [ ] Implement preflight, verified MSI install, marker transition, virtual account, protected seed, and documented `AGREETOLICENSE=Yes LAUNCHSPLUNK=0 GENRANDOMPASSWORD=0` route; do not invent seed syntax until Task 0 confirms it.
- [ ] Ask fast-generic to rerun the same command and require PASS; no checkpoint until Task 3 and combined collector checks pass.

## Task 3: Render three owned inputs and convergence behavior

**Files:**
- Create/modify: `ansible/roles/ludus_splunk_collector/tasks/windows/configure.yml`, `templates/windows-inputs.conf.j2`, `templates/windows-outputs.conf.j2`, `tests/test_windows_static.py`, and README.

**Interfaces:** Consumes the owned service from Task 2. Produces one managed inputs configuration with Security `winlogs`, Sysmon `sysmon`, and SilkService-Log `etw`.

**Required behavior (implemented only after red tests):**

- Render the actual Jinja template with `jinja2.Environment`/`StrictUndefined` and the three index variables; assert parsed stanzas and blacklist absence, not literal hard-coded indexes in template source.

- Render Security with XML, `start_from=oldest`, `current_only=0`, `index=winlogs`, and no blacklist keys or inherited TA exclusions.
- Keep the three candidate blacklist lines commented in documentation only; do not render them. Preserve exact candidate strings in the design, not executable defaults.
- Render exact Sysmon source/channel routing to `sysmon` without changing producer-owned filters or invoking `ludus_install_sysmon`.
- Render `[WinEventLog://SilkService-Log]`, `disabled=0`, `index=etw`, `sourcetype=json`, with no XML-specific Security flags.
- Implement documented nonblocking missing-channel warning if supported; otherwise record the research stop condition without creating the producer/channel or blocking Security.
- Restart only when managed rendered configuration changes; unchanged convergence must not restart. Mark reboot-needed separately from restart-needed.
- [ ] First write `test_windows_inputs_are_unfiltered_and_routed` rendering `templates/windows-inputs.conf.j2` with `jinja2.Environment`/`StrictUndefined`, then asserting exact parsed Security `start_from=oldest`, `current_only=0`, `index=winlogs`, no blacklist keys; exact Sysmon source/index; and exact Silk stanza with `disabled=0`, `index=etw`, `sourcetype=json` and no XML flags. Add `test_config_change_notifies_only_on_template_change` asserting notify guards, not runtime restart behavior.
- [ ] Ask fast-generic to run the collector test command; expected FAIL.
- [ ] Implement the two templates and configure task; keep candidate exclusions docs-only and use nonblocking missing-channel warning only if documented.
- [ ] Ask fast-generic to rerun the same command and require PASS; then run `python3 -m unittest discover -s ansible/roles/ludus_splunk_collector/tests -v`, the Windows syntax target, and Linux/server regression static checks plus `git diff --check -- ansible/roles/ludus_splunk_collector`; checkpoint one combined collector commit only after all integrated checks pass.

## Task 4: Extend append-only server indexes independently

**Files:**
- Modify: `ansible/roles/ludus_splunk_server/defaults/main.yml`, `tasks/main.yml`.
- Create: `ansible/roles/ludus_splunk_server/tasks/indexes_preflight.yml`, `tasks/indexes_configure.yml`, `templates/indexes.conf.j2`, `tests/test_indexes_static.py`.

**Interfaces:** Consumes only `ludus_splunk_server_indexes`; produces a separately owned index app. No dependency on collector receiver inputs or Windows installation tasks.

**Required behavior (implemented only after red tests):**

- Use marker `/opt/splunk/etc/apps/ludus_indexes/.ludus-managed.json` with `{schema_version:1,indexes:[...]}` and config `/opt/splunk/etc/apps/ludus_indexes/local/indexes.conf`.
- Parent ruling: use fixed data paths `/opt/splunk/var/lib/splunk/<name>/{db,colddb,thaweddb}` (custom roots are unsupported), so preflight and rendering inspect the same locations. Mutable index options are out of scope. Preflight precedes every mutation and imports precede service start/restart.

- Keep default `ludus_splunk_server_indexes: []` a true no-op when never managed.
- [ ] First write `test_server_indexes_are_append_only` with `ROLE=Path(__file__).resolve().parents[1]`, `defaults=yaml.safe_load((ROLE/'defaults/main.yml').read_text()); self.assertEqual(defaults['ludus_splunk_server_indexes'],[])`; inspect source tree with `_task_sequence()` and assert marker/config/data paths, duplicate-free `fullmatch` validation (no `$` newline weakness), reserved `main/history/summary` plus default/internal rejection, and `old-requested` removal failure including formerly-managed `[]`.
- [ ] Ask fast-generic to run `python3 -m unittest discover -s ansible/roles/ludus_splunk_server/tests -p 'test_indexes_static.py' -v`; expected FAIL.
- [ ] Implement independent index preflight/configure imports and append-only set comparison; never edit receiver task files, delete data, alter retention, or consume receiver host/port.
- [ ] Ask fast-generic to rerun that command and all server tests with `python3 -m unittest discover -s ansible/roles/ludus_splunk_server/tests -v`; require PASS, then `git diff --check -- ansible/roles/ludus_splunk_server`; checkpoint server files only. This work is independently executable after execution approval even if Windows Task 0 remains blocked.

## Task 5: Standalone examples, requirements, and static evidence

**Files:**
- Create: `docs/examples/windows-splunk/range-config.yml`, `docs/examples/windows-splunk/requirements.yml`, `docs/examples/windows-splunk/README.md`; modify only scoped role README/syntax fixtures.

**Interfaces:** Documents explicit server/client ordering and dependencies without changing the legacy blueprint; inventory includes only selected roles/dependencies.

**Required behavior (implemented only after red tests):**
- Example: Debian receiver port `9997`, server indexes `[winlogs, sysmon, etw]`, Sysmon before collector, illustrative role identities marked unverified. Task 5 depends on both collector and server tasks, not target-server access.
- Declare Windows collection prerequisites and supported pins; no full Splunk TA or optional CIM assets.
- Static checks cover no hidden sibling calls, legacy blueprint migration, firewall/TLS changes, or Sysmon filter edits.
- Do not query a target server or invent installed IDs; document explicit role ordering and server-owned indexes.
- [ ] First add syntax/static assertions for example ordering and no hidden role calls; ask fast-generic to run collector/server test suites and expected-red syntax checks.
- [ ] Implement the three docs only; rerun the same tests and `git diff --check -- docs/examples/windows-splunk ansible/roles/ludus_splunk_collector/tests ansible/roles/ludus_splunk_server/tests`; checkpoint docs/example files only.
- [ ] Fast-generic must inspect `.opencode/skills/ansible-validation/SKILL.md` and run actual syntax/inventory scope: `python3 .opencode/skills/ansible-validation/scripts/validate.py --role ansible/roles/ludus_splunk_collector --role ansible/roles/ludus_splunk_server --role ansible/roles/ludus_install_sysmon --playbook ansible/roles/ludus_splunk_collector/tests/syntax-windows.yml --data docs/examples/windows-splunk/range-config.yml --data docs/examples/windows-splunk/requirements.yml`; add `--coverage-gap <exact-gap>` for each exact gap. Missing tools warn only when coverage is complete and all available checks pass; any missing role/module/collection dependency or coverage gap is FAIL. Existing role `tests/syntax.yml` is included by `--role`.

## Task 6: Evidence report and authorization handoff

**Files:**
- Modify only scoped test/report documentation if needed; do not modify unrelated docs/TODO/blueprints.

- [ ] Record one evidence owner per claim: Task 0 primary-source compatibility, static tests for contracts, fast-generic for command output, parent for diff/review.
- [ ] Report static task tests, selected-role/dependency inventory, repository `ansible-validation`, both Linux and Windows syntax targets, and existing Linux/server regression static tests separately.
- [ ] Keep native work unexecuted and separately listed: fresh install, convergence without restart, config restart, reboot handling, unsafe-state pre-mutation failure, partial recovery, protected credential failure/cleanup, unrelated-resource preservation, and actual logs in all three indexes.
- [ ] State explicitly that Security 4662/566/5145 events are expected to remain in the default baseline and SPLUNK-001 is a later separately authorized evaluation.
- [ ] Ensure static tests reject regex/control/newline injection, detect unmanaged inherited TA blacklist collisions, reject owned-index removal including `[]`, and assert credential-failure seed retention; these are static contracts only and do not establish lifecycle behavior.
- [ ] Parent self-reviews this plan and the final implementation diff; this plan does not substitute for parent review or authorize execution.

## Syntax harness and self-review checklist

- [ ] `tests/syntax-windows.yml` must enter the real collector role through `tasks/main.yml`, use an unconditional `ansible.builtin.fail` in `pre_tasks` so the play cannot execute locally, and provide dummy variables only for parsing. `--syntax-check` parses static `import_tasks` seams without running the fail task; the harness must never conditionally escape it. It is a static syntax target, not a runtime simulation.
- [x] Parent checks Skill requirement coverage: file map names every created/modified path; every task has interfaces; every implementation task writes assertions, runs expected-red, edits, reruns green, and records `git diff --check`; exact values and commands are present; review-focus risks map to tests.
- [x] Parent confirms dependency graph: Task 0 blocks Windows Tasks 1–3; Task 4 server indexes is independent after execution approval; Task 5 integration docs depend on both local collector/server tasks but not target-server access; no shared writer file is assigned to both.
- [x] Parent confirms no command in this plan authorizes installation, fetch, deployment, guest probes, or live evaluation; fast-generic owns command execution and parent owns final review.

## Commit scopes (execution only, not performed here)

- `feat(collector): add Windows forwarder and event log collection` — one atomic collector role/tests/docs commit after Tasks 1–3 and integrated checks.
- `feat(server): add append-only configured indexes` — server role files/tests/docs only.
- `docs: add standalone Windows Splunk integration example` — standalone scoped example/requirements only.

Plan approval/execution handoff is required before implementation; all live actions remain separately unauthorized. Documentation-only checks are permitted.
