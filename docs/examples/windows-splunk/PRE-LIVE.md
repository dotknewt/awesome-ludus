# Windows Splunk example: pre-live closeout

> **Historical / superseded:** This closeout predates the forwarder-role
> consolidation. Its recorded commands and results below refer to retired paths
> and are preserved as historical evidence, not current validation. See the
> merged [`splunk_forwarder` role](../../../ansible/roles/splunk_forwarder/README.md)
> and [current consolidation plan](../../superpowers/plans/2026-10-21-splunk-forwarder-merge.md)
> for the current static scope; this notice does not imply runtime readiness.

**Supersession update: 2026-10-20.** The filesystem ACL review and ACL-hardening
claims recorded in this historical static closeout are superseded: user
direction confirmed no stricter Windows filesystem ACL requirement. The role now
retains normal installer/inherited filesystem permissions and does not require
or claim ACL-backed marker ownership. The separate Event Log channel READ ACE
behavior remains. The test and validator results below predate this update and
are not validation evidence for the resulting tree.

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
  These paths are recorded as run before the 2026-10-28 role identity rename;
  see [`docs/role-identity-migration.md`](../../role-identity-migration.md).
  Provenance: `/tmp/opencode/splunk-prelive-validation.txt`; these roles/tests
  were unchanged in the closeout validation.
- Final validator command (same pre-rename paths noted above):
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
- Historical ACL review: Oracle **ACCEPT** was recorded for the now-superseded
  custom filesystem ACL policy. That policy was agent-invented and has been
  removed at the user's direction; this review is not a current requirement or
  validation result. The current role does not inspect or modify Windows
  filesystem ACLs. Event Log READ ACE management remains separate.
- `git diff --check`: PASS. Validator cleanup restored tracked bytecode and
  removed generated untracked bytecode; see the closeout validation record.

## Remaining target and live gates

- Target Ludus version, installed role IDs, template catalog names, and a
  receiver address resolvable from Windows remain placeholders/unverified.
- UF 10.6.1.1 OS support, effective service-account Event Log/file access, seed
  authentication, and runtime lifecycle behavior remain unverified. Windows
  filesystem permissions are retained from the installer/inherited environment;
  the role does not certify effective file access or impose a filesystem ACL
  policy.
- Fresh install, convergence/restart, reboot and recovery paths, credential
  failure/cleanup, and actual three-index ingestion were not exercised; each
  requires separate authorization.
- Security 4662/566/5145 remain in the default baseline. SPLUNK-001 exclusion
  evaluation is separate and unauthorized here.
- No TODO items were implemented. External TODO and policy edits were preserved
  and excluded from this closeout.
