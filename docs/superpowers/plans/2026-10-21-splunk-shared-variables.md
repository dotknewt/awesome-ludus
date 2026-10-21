# Shared Splunk Variables Implementation Plan

> **For agentic workers:** Use subagent-driven-development for this coherent migration.

**Goal:** Configure server and forwarders once through a shared public API.
**Architecture:** Shared `splunk_*` inputs, with role-specific `splunk_server_*` and `splunk_forwarder_*` inputs. Preserve persisted state and existing installation lifecycle.
**Tech Stack:** Ansible, Jinja2, Ludus YAML, Python static tests.

> **Spec:** user-approved chat scope. This is a clean variable rename with no legacy aliases: shared `splunk_version`, `splunk_build`, `splunk_accept_license`, `splunk_receiver_ip`, and `splunk_receiver_port`; server-only `splunk_server_*`; forwarder-only `splunk_forwarder_*` on Linux and Windows. Do not rename role identities.

## Review gate

- [ ] Parent reviews this plan before implementation.
- [ ] Fixer performs one coherent migration; fast-generic owns the later commands and reports static evidence separately from unverified runtime behavior.

## Implementation task — tests first

1. **Add/adjust static contracts before source edits.** In `ansible/roles/splunk_forwarder/tests/test_static.py`, `test_windows_static.py`, and `test_consolidation_static.py`, assert the clean namespace (no legacy aliases), shared version/build/license/receiver inputs, forwarder-only inputs on both platforms, unified `splunk_forwarder_admin_user`, default `splunk_accept_license: false`, and validation before any mutation. Assert Linux and Windows preserve their existing on-disk ownership markers and installation/configuration paths so existing installations remain recognizable. Extend the server role's focused static coverage alongside `ansible/roles/linux_splunk_server/tests/` if that harness exists; do not use mocks or stateful fakes.
2. **Standardize forwarder defaults and tasks.** Update `ansible/roles/splunk_forwarder/defaults/main.yml`, `tasks/main.yml`, `tasks/validate.yml`, `tasks/install.yml`, `tasks/inspect.yml`, `tasks/configure.yml`, `tasks/windows/main.yml`, handlers, templates, and README as needed. Use shared `splunk_version: "10.6.1.1"`, `splunk_build: "b2ae2962645c"`, `splunk_accept_license: false`, `splunk_receiver_ip`, and `splunk_receiver_port`; use `splunk_forwarder_*` for forwarder-specific settings, including `splunk_forwarder_admin_user`. Preserve existing platform password defaults where needed to avoid password behavior drift. Put an explicit license acceptance assertion/gate in both Linux and Windows validation before inspection, download, install, service, or configuration mutation.
3. **Standardize the server role without inventing interfaces.** Update `ansible/roles/linux_splunk_server/defaults/main.yml`, `tasks/main.yml`, README, and its focused tests so its version/build/license use the shared names, server-specific settings use `splunk_server_*`, and its receiver port is the shared `splunk_receiver_port` where applicable. Do not add or refactor an indices variable: current server callers' legacy/unsupported index settings must not be fabricated into a new supported interface. Preserve server ownership markers and paths.
4. **Preserve package integrity and installation state.** Keep the confirmed Linux UF URL and checksum in the forwarder defaults for the exact 10.6.1.1/build package: `https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb` with SHA-512 `2172ed26173b4f29e3ffb051800dce3b21701f8fa202466063a535dd9e7c2cac03714e5db026c4a5dd37249a23be017661a80b4969a339e1d653a16622180c31`. Derive URLs from version/build where the existing implementation does so, but require a matching explicit checksum for any alternate package; never silently apply the pinned checksum to an override.
5. **Migrate active callers and shared placement.** Use documented top-level `global_role_vars` (confirmed by the official schema) for values genuinely shared across roles, with no YAML-anchor workaround. Update active blueprints/examples and tests, including `blueprints/threat-hunting/range-config.yml`, `docs/examples/splunk-dev1/range-config.yml`, `docs/examples/windows-splunk/range-config.yml`, and role syntax fixtures. Set callers' license acceptance explicitly to `true`; translate receiver/indexer settings to shared names and forwarder-only names. Preserve topology and existing input lists. Leave historical plans/specs/research unchanged, except a superseded notice only if required.
6. **Document the resulting contract.** Update active role READMEs and caller guidance with the shared/global variables, server-only and forwarder-only namespaces, default-false license gate, credential behavior, checksum rule, and no supported index-variable claim. Do not add upgrading logic, SILK, TLS, index refactoring, or unrelated server fixes.

## Static validation (fast-generic)

- [ ] Add server static coverage at `ansible/roles/linux_splunk_server/tests/test_shared_variables_static.py`; run the new contracts and capture expected failures before implementation.
- [ ] Add the server acceptance assertion before all existing tasks; update server handlers and both templates as well as defaults/tasks. Test missing/false acceptance structurally for each entrypoint.
- [ ] Derive the Linux UF default package URL from shared version/build too. Preserve the known digest for the pinned artifact; alternate artifacts require an explicit checksum, without adding an automatic download/discovery mechanism.
- [ ] Remove unsupported server-only caller settings rather than invent support; document existing server index provisioning and leave client input lists unchanged. Index-alignment changes remain separate.
- [ ] Do not use whole-role validation (`--role`). Enumerate explicit changed files and record syntax role-resolution setup.

- [ ] Run the existing focused static suites with `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ansible/roles/splunk_forwarder/tests -p 'test_*.py'` and the corresponding file-scoped server tests.
- [ ] Run narrow Ansible/YAML syntax and lint validation explicitly against changed role files and `ansible/roles/splunk_forwarder/tests/{syntax.yml,syntax-windows.yml}`; use the repository validation script with only the changed role/data/playbook paths.
- [ ] Assert by static inspection that license gates precede mutation on both platforms, persisted marker/path strings are unchanged, no legacy variable aliases remain, global variables are top-level, callers set license true, and no unsupported indices interface was introduced.
- [ ] Actual installation, convergence, and selected-version compatibility are not verified; no live operations are authorized by this plan.

## Source evidence

- Official range schema: <https://docs.ludus.cloud/schemas/range-config.json> — confirms documented top-level `global_role_vars`.
- Official product/download pages: <https://www.splunk.com/en_us/download/splunk-enterprise.html> and <https://www.splunk.com/en_us/download/universal-forwarder.html> — evidence for the selected 10.6.1.1/build pin.
- Pinned Linux UF package: `https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb`; confirmed SHA-512 is recorded above.
- Repository source map: `ansible/roles/splunk_forwarder/{defaults/main.yml,tasks/{main,validate,install,inspect,configure}.yml,tasks/windows/main.yml,templates,handlers/main.yml,tests}` and `ansible/roles/linux_splunk_server/{defaults/main.yml,tasks/main.yml,README.md}`.

## Review risks

- A clean rename can break unlisted callers; the active-reference scan must find every old variable without adding compatibility aliases.
- Moving values into `global_role_vars` can unintentionally pass server/forwarder-only settings to the wrong role; static contracts must enforce ownership.
- Changing license defaults to false may expose callers that do not explicitly opt in; every active caller must set true before mutation.
- Renaming admin users while preserving platform passwords can alter seed/config templates; verify rendered variable references and persisted paths statically.
- URL derivation plus checksum overrides can weaken integrity if alternate URLs inherit the pinned digest; require explicit matching checksums.
