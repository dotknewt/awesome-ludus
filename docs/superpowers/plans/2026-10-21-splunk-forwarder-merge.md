# Plan: consolidate Splunk forwarder roles

> **Spec:** the chat-approved scope is the specification: one `splunk_forwarder` role; preserve Linux behavior and the `ludus_splunk_collector_*` API/defaults/filter names/ownership markers; replace all unfinished Windows elements with the user-reported verified standalone implementation; preserve the `splunk_uf_*` API/defaults; no new features or hardening.

## Planning gate

- [ ] Oracle reviews this plan before implementation.
- [ ] A parallel explorer scans active callers, dependencies, fixtures, and role paths; historical plans/specs/research remain unchanged.

## Implementation phase — fixer owns the complete change

- [x] Move the whole Linux role tree to `ansible/roles/splunk_forwarder/`, preserving Linux file/template paths and behavior. Update metadata, README, tests, and role identity to `splunk_forwarder` with the real project author.
- [x] Retain Linux defaults, `tasks/{validate,inspect,install,configure}.yml`, templates, `filter_plugins/collector_unit.py`, handlers, collector-prefixed registers, filter names, and ownership markers with only required identity changes.
- [x] Replace the moved role's unfinished Windows branch wholesale with the standalone implementation. Preserve `splunk_uf_*` names/defaults, token/no-token download/cache/install behavior, Event Log Readers membership, configuration, service ordering, and final status. Use explicit Windows template paths. Do not add role-local MSI resolution.
- [x] Preserve standalone handlers and registers; remove unfinished Windows tasks, templates, defaults, and alternate execution paths.
- [x] Retire both old role directories; only `ansible/roles/splunk_forwarder/` remains.

### Active callers and harnesses

- [x] Update the two Linux callers in `blueprints/threat-hunting/range-config.yml` to `dotknewt.splunk_forwarder`, preserving topology and collector license/receiver values.
- [x] Update its Windows caller to `dotknewt.splunk_forwarder`; preserve Sysmon/topology and translate to `splunk_uf_accept_license`, `splunk_uf_indexer`, and explicit `splunk_uf_inputs` for Security/Sysmon logging.
- [x] Update `docs/examples/windows-splunk/range-config.yml` to the consolidated role and explicit `splunk_uf_*` inputs, preserving dependencies/topology and Security/Sysmon indexes. Do not invent package URL/checksum overrides. **User approved SILK omission**; the standalone role is input-driven and SILK autoconfiguration remains blocked in `SPLUNK-003` pending basic merged functionality verification.
- [x] Update `docs/examples/splunk-dev1/range-config.yml` from `ludus_splunk_universalforwarder` to the consolidated role while preserving its `splunk_uf_*` values, inputs, dependency, and topology.
- [x] Move/update the role syntax harnesses and static tests: Linux fixtures retain collector inputs; Windows fixtures use only `splunk_uf_*`; assertions cover identity, Linux preservation, explicit Windows templates, service/Event Log Readers flow, and absence of unfinished symbols.
- [x] Update active role documentation only for the two APIs, Windows input-driven behavior, and the approved SILK choice. Historical docs/plans/specs/research are unchanged.

## Implementation validation

- [ ] Command-validation owner runs changed static test files explicitly, and uses the ansible-validation skill to select supported changed-file YAML (`--data`) and syntax (`--playbook`) checks. Do not use whole-role `--role` validation. Verify role resolution for syntax fixtures; the wrapper removes `ANSIBLE_ROLES_PATH` without `--role`. Record unavailable coverage without widening scope.
- [ ] Preserve static dispatch assertions: unsupported platforms fail, Windows runs only standalone Windows tasks, and Linux alone uses `become`.
- [ ] Run focused YAML/Ansible syntax and lint checks on changed files only; statically compare pre-move Linux files/templates with the consolidated copies and assert no old role directories, unfinished branch, or collector-only Windows API remains.
- [ ] Report static results separately from runtime evidence. No simulations, stateful fakes, or mocked runtime evidence; live fresh-install/convergence requires separate authorization and remains unverified.

## Post-validation oracle gate

- [ ] After implementation validation, oracle reviews the diff and evidence.
- [ ] In parallel, explorer rescans active references for `ludus_splunk_collector`, `ludus_splunk_universalforwarder`, `splunk_uf_`, `linux_splunk_forwarder`, and `splunk_forwarder`; confirm topology, no old directories/alternate Windows path, and untouched historical documentation.

## Real blockers

- SILK conditional subscription has no standalone equivalent: omission from the migrated example is approved; optional autoconfiguration is deferred and blocked in `docs/TODO.md` pending basic merged functionality live verification.
- Live fresh-install/convergence verification is separately unauthorized and remains unverified.
