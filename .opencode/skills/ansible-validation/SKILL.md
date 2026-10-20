---
name: ansible-validation
description: Use when statically validating Ansible roles, playbooks, Ludus range configs, blueprints, or sources before requesting live verification or deployment authorization.
---

# Ansible Validation

Build a complete, scope-specific inventory, then pass explicit local paths to the bundled validator. This is repository workflow: Ludus documents how artifacts reference roles and dependencies, but it does not define this validation gate.

## Inventory the requested scope

Work from locally inspectable files. Report the inventory before running the command; for every role record its name, reference location, source-local or external provenance, resolved local path, and `tests/syntax.yml` harness.

| Scope | Required inventory |
| --- | --- |
| Role | The role directory, dependencies declared by its metadata, and any actual entrypoint playbooks |
| Range | The range YAML as data; every role under VM or router `roles`, including each `depends_on[].role`; each resolved role and its declared dependencies |
| Blueprint | `blueprint.yml`, `range-config.yml`, and `requirements.yml` as data; all range references; all declared roles, collections that supply referenced roles, and subscription roles; source-local copies and already available external role paths |
| Source | `source.yml` and blueprint artifact YAML as data; every source-local role; every role referenced or declared by included blueprints; relevant collection YAML and roles; all declared dependencies |

Resolve names only to source-local directories or external directories already available for inspection. A server inventory may establish availability, but it does not provide local bytes for these checks. Do not fetch or install roles, collections, or tools. Exclude repository roles unrelated to the selected artifact.

Follow dependency declarations only far enough to inventory the selected artifact: inspect `requirements.yml` and each resolved role's metadata, add resolved local dependencies, and preserve every unresolved role, collection-provided role, subscription role, path, or dependency as a coverage gap. This is not a general dependency resolver.

Use an existing `tests/syntax.yml` only when it truthfully exercises that role's required variables, hosts, and entrypoint. Supply additional real playbooks separately. Never generate a generic harness. Missing or unsuitable harnesses are coverage gaps.

## Invoke the validator

Classify artifact manifests and range/source/blueprint YAML as data, not playbooks. Build one command from the reported inventory:

```bash
python3 .opencode/skills/ansible-validation/scripts/validate.py \
  --data path/to/range-config.yml \
  --role path/to/resolved-role \
  --playbook path/to/actual-playbook.yml \
  --coverage-gap 'external role example.role has no locally inspectable path'
```

Repeat each option as needed. Quote every gap so the report identifies the role or path and where it was referenced. The script validates role YAML and the role's existing `tests/syntax.yml`; `--playbook` targets all three checks; `--data` targets only `yamllint`. Use `--all` alone only for intentional repository-wide validation:

```bash
python3 .opencode/skills/ansible-validation/scripts/validate.py --all
```

## Interpret and hand off

- `PASS`: all tools were available, all checks passed, and target coverage was complete.
- `PASS WITH WARNINGS — NOT VERIFIED`: coverage was complete and available checks passed, but one or more tools were `NOT AVAILABLE`. Prominently carry forward every unavailable check and its unverified targets when requesting live authorization.
- `FAIL`: fix every blocking check failure and coverage error before requesting live authorization. Apply the [repository Galaxy metadata policy](../../../docs/instructions/ludus-authoring.md#reusable-role-design): missing optional Galaxy fields are advisory; missing or empty `galaxy_info.role_name` or `galaxy_info.author` remains blocking. An available tool's missing role, collection, module, or other dependency is a failure, not tool unavailability.

Preserve the validator's raw output, exit status, and overall status. If a raw `FAIL` is caused solely by missing optional Galaxy metadata, report `Workflow gate: NON-BLOCKING — optional Galaxy metadata only`, list those findings as advisory, and continue the authorization-request workflow without requiring metadata padding. Do not report the raw tool result as `PASS`. If blocking findings or coverage errors also exist, report `Workflow gate: BLOCKED` and name those blockers separately from the metadata advisories. Missing optional metadata alone is neither a coverage gap nor a reason to mark runtime behavior unverified; runtime verification remains separate regardless.

Neither `PASS` nor warning-only output proves runtime readiness or authorizes deployment. Report static output separately from `Live verification: NOT RUN — requires separate authorization`; installation, registration, deployment, and guest probes require their own authorization.

## Official Ludus references

- [Sources and source-local assets](https://docs.ludus.cloud/docs/using-ludus/sources/)
- [Blueprint directory and requirements](https://docs.ludus.cloud/docs/using-ludus/blueprints/#directory-structure)
- [Range role references](https://docs.ludus.cloud/docs/configuration/)
- [Roles](https://docs.ludus.cloud/docs/using-ludus/roles/) and [role development](https://docs.ludus.cloud/docs/developers/ansible-roles/)
