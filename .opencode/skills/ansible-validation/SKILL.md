---
name: ansible-validation
description: Use when statically validating changed Ansible role work or selected Ludus artifacts.
---

# Ansible Validation

Build a scope-specific inventory, then pass explicit local paths to supported checks. For role completion, validate changed files only. Use file-scoped checks supported by the available tools; do not use `--role` to expand completion validation to an entire role directory. If the available tools cannot check the changed files without widening scope, report those checks as unavailable rather than validating unchanged files. This is required when finishing role work, not a prerequisite for live deployment or retries. This is repository workflow: Ludus documents how artifacts reference roles and dependencies, but it does not define this validation gate.

## Inventory the requested scope

Work from locally inspectable files. Report the inventory before running the command; for every role record its name, reference location, source-local or external provenance, resolved local path, and `tests/syntax.yml` harness.

| Scope | Required inventory |
| --- | --- |
| Changed role work completion | Changed files only; use file-scoped checks supported by available tools. Record dependency or harness context needed to explain coverage, but do not validate unchanged files or roles |
| Explicit role review | The selected role directory, dependencies declared by its metadata, and any actual entrypoint playbooks |
| Range | The range YAML as data; every role under VM or router `roles`, including each `depends_on[].role`; each resolved role and its declared dependencies |
| Blueprint | `blueprint.yml`, `range-config.yml`, and `requirements.yml` as data; all range references; all declared roles, collections that supply referenced roles, and subscription roles; source-local copies and already available external role paths |
| Source | `source.yml` and blueprint artifact YAML as data; every source-local role; every role referenced or declared by included blueprints; relevant collection YAML and roles; all declared dependencies |

Use the changed-role-work row for completion checks. The other rows describe explicit selected-artifact review modes; use them only when that broader artifact scope is requested, not automatically when finishing changed role work. Resolve names only to source-local directories or external directories already available for inspection. A server inventory may establish availability, but it does not provide local bytes for these checks. Do not fetch or install roles, collections, or tools. Exclude repository roles unrelated to the selected artifact.

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

Repeat each option as needed. Quote every gap so the report identifies the role or path and where it was referenced. The generic `--role` example is for an explicitly requested whole-role review: it validates role YAML and the role's existing `tests/syntax.yml`; `--playbook` targets all three checks; `--data` targets only `yamllint`. Do not use `--role` for changed-role completion when that would include unchanged files. Use `--all` alone only for intentional repository-wide validation:

```bash
python3 .opencode/skills/ansible-validation/scripts/validate.py --all
```

## Interpret and hand off

- `PASS`: all tools were available, all checks passed, and target coverage was complete.
- `PASS WITH WARNINGS — NOT VERIFIED`: coverage was complete and available checks passed, but one or more tools were `NOT AVAILABLE`. Prominently carry forward every unavailable check and its unverified targets when reporting role-work completion.
- `FAIL`: fix every blocking check failure and coverage error before claiming role work is complete. Apply the [repository Galaxy metadata policy](../../../docs/instructions/ludus-authoring.md#reusable-role-design): missing optional Galaxy fields are advisory; missing or empty `galaxy_info.role_name` or `galaxy_info.author` remains blocking. An available tool's missing role, collection, module, or other dependency is a failure, not tool unavailability.

Preserve the validator's raw output, exit status, and overall status. If a raw `FAIL` is caused solely by missing optional Galaxy metadata, report `Workflow gate: NON-BLOCKING — optional Galaxy metadata only`, list those findings as advisory, and continue the scoped validation report without requiring metadata padding. Do not report the raw tool result as `PASS`. If blocking findings or coverage errors also exist, report `Workflow gate: BLOCKED` and name those blockers separately from the metadata advisories. Missing optional metadata alone is neither a coverage gap nor a reason to mark runtime behavior unverified; runtime verification remains separate regardless.

Neither `PASS` nor warning-only output proves runtime behavior or authorizes deployment. Report static output separately from live evidence. Installation, registration, deployment, and guest probes remain subject to the applicable live-request scope and repository authorization boundaries.

## Official Ludus references

- [Sources and source-local assets](https://docs.ludus.cloud/docs/using-ludus/sources/)
- [Blueprint directory and requirements](https://docs.ludus.cloud/docs/using-ludus/blueprints/#directory-structure)
- [Range role references](https://docs.ludus.cloud/docs/configuration/)
- [Roles](https://docs.ludus.cloud/docs/using-ludus/roles/) and [role development](https://docs.ludus.cloud/docs/developers/ansible-roles/)
