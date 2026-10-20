# Windows Splunk example: pre-live closeout

**Prior static closeout: recorded — 2026-10-20.** The evidence below was
collected with `ansible.windows` 3.8.0 and `community.windows` 3.3.0. The
example now pins the currently Ludus-installed baseline (`ansible.windows`
2.7.0, `community.windows` 2.3.0); validation against those versions is pending
the validation owner. No older-version compatibility is claimed. Target
preparation and separately authorized native verification also remain
outstanding. This is not a deployment-readiness claim and authorizes no
installation, deployment, guest probes, API calls, or live evaluation.

## Static evidence

- Collector tests: fresh run, 28 passed:
  `python3 -m unittest discover -s ansible/roles/ludus_splunk_collector/tests -p 'test_*.py'`
- Reused unchanged static results: Splunk server 28 passed and Linux logging 21
  passed; total evidence is 77 tests. Commands were
  `env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ansible/roles/ludus_splunk_server/tests -p test_*.py`
  and `env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ansible/roles/ludus_linux_logging/tests -p test_*.py`.
  Provenance: `/tmp/opencode/splunk-prelive-validation.txt`; these roles/tests
  were unchanged in the closeout validation.
- Final validator command:
  `python3 .opencode/skills/ansible-validation/scripts/validate.py --data docs/examples/windows-splunk/range-config.yml --data docs/examples/windows-splunk/requirements.yml --role ansible/roles/ludus_splunk_collector --role ansible/roles/ludus_splunk_server --role ansible/roles/ludus_linux_logging --role ansible/roles/ludus_install_sysmon --playbook ansible/roles/ludus_splunk_collector/tests/syntax-windows.yml`
  **PASS:** 4 roles, 5 syntax targets, 5 lint targets, 42 yamllint targets,
  zero coverage errors. `ansible-playbook`, `ansible-lint`, and `yamllint` all
  passed; overall status PASS. Output provenance:
  `/tmp/opencode/splunk-prelive-closeout-validation.txt`.
  This run and the 77-test total below predate the requirements pin change and
  therefore are evidence for the newer collection versions only.
- Warnings, not failures: syntax checks used implicit localhost; lint directory
  expansion encountered 72 files; the repository yamllint configuration is
  incompatible with ansible-lint's required settings, disabling fix mode. The
  standalone Sysmon syntax target does not recursively parse dynamic
  `include_tasks` bodies.
- Official range-config schema: unmodified schema selected
  `Draft201909Validator`; `check_schema` PASS; zero instance errors. Provenance:
  Python 3.14 `jsonschema` `validator_for` + `check_schema` + instance validation;
  `/tmp/opencode/splunk-prelive-validation.txt`. Schema:
  <https://docs.ludus.cloud/schemas/range-config.json>.
- Dependency documentation checked against the current official configuration
  docs and published schema. The example's string/object `roles` entries,
  `depends_on` `{vm_name, role}` shape, same-VM order, and cross-VM dependency
  semantics are documented. This does not confirm installed role availability
  or service readiness. Sources: <https://docs.ludus.cloud/docs/configuration/>
  and <https://docs.ludus.cloud/schemas/range-config.json>. Comparison notes:
  `/tmp/opencode/splunk-prelive-dependency-docs.md`.
- Final scoped ACL review: Oracle **ACCEPT**. Service-account filesystem
  masks include .NET's `Synchronize` bit; inspection calls execute directly
  under the Ansible `when` gate. ACL management remains bounded and fail-closed:
  unfamiliar policy is refused rather than reconciled. It may refuse the actual
  MSI-created ACL until separately reviewed. This review and all checks are
  static only.
- `git diff --check`: PASS. Validator cleanup restored tracked bytecode and
  removed generated untracked bytecode; see the closeout validation record.

## Remaining target and live gates

- Target Ludus version, installed role IDs, template catalog names, and a
  receiver address resolvable from Windows remain placeholders/unverified.
- UF 10.6.1.1 OS support, actual MSI-created ACL compatibility, effective
  service-account Event Log/file access, seed authentication, and runtime
  lifecycle behavior remain unverified. A fail-closed ACL refusal may require
  a separately reviewed change after authorized target evidence.
- Fresh install, convergence/restart, reboot and recovery paths, credential
  failure/cleanup, and actual three-index ingestion were not exercised; each
  requires separate authorization.
- Security 4662/566/5145 remain in the default baseline. SPLUNK-001 exclusion
  evaluation is separate and unauthorized here.
- No TODO items were implemented. External TODO and policy edits were preserved
  and excluded from this closeout.
