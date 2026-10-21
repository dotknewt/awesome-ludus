---
name: ludus-blueprint
description: Use when creating reusable Ludus blueprint packages from lab ideas or existing range configurations, or preparing blueprints for distribution in a Ludus source repository.
---

# Ludus Blueprint

Own the **package**, composing the upstream [Ludus skills](https://gitlab.com/badsectorlabs/ludus-skills). Range behavior belongs to `range-config`.

## Required handoffs

| Work | Required skill |
|---|---|
| Author, edit, inspect, or validate range YAML | `range-config` |
| Commands, read-only server inventory, requested deployment | `ludus-cli` |
| Choose an existing pre-built lab | `environment-guide` |
| Finish changed role work with scoped static validation | `ansible-validation` |

Load the named skill when its branch applies. For `range-config`, `ludus-cli`, or `environment-guide`, report an unavailable skill and use upstream's installation instructions before resuming that branch. `ansible-validation` is bundled with this repository; if it is missing, report a repository defect and an unverified validation gap, then restore the bundled skill before resuming. Reference upstream skills directly rather than copying their schema rules, command catalogs, or environment lists.

## Workflow

1. **Inspect.** Read repository instructions, source metadata, existing blueprints, and supplied configuration. Consult current [blueprint formats](https://docs.ludus.cloud/docs/using-ludus/blueprints#directory-structure) and [source packaging](https://docs.ludus.cloud/docs/using-ludus/sources#authoring-a-source). Resolve version differences through official docs and installed CLI help.
2. **Agree.** Ask only about missing requirements: lab purpose, topology, provisioning, success criteria, identity/version, and distribution target. Use `range-config` for topology decisions. Obtain approval of the package design before writing. Conversion preserves existing behavior; present necessary changes for approval. Identify missing roles/templates as blockers for future component-authoring skills.
3. **Package.** Create the blueprint directory below. Preserve existing source metadata; add `source.yml` for a new source with user-supplied attribution/license. Write dependency declarations using verified versions or immutable refs; report unresolved pins rather than inventing them.
4. **Account for dependencies.** For every role/collection identified through `range-config`, record its declaration or source-root vendored path. Collections are identified by `galaxy.yml`, not directory name. An undeclared, unbundled role/collection blocks package completion; a README prerequisite alone does not satisfy coverage. Record templates separately as bundled build definitions or external prerequisites. Server-installed assets alone do not make a portable package. Subscription roles carry names only. Defer missing component creation.
5. **Validate.** Run the package checker below and upstream range validation. For changed role work, use `ansible-validation` only when finishing that work, scoped to changed role files and changed declared dependencies; do not make it a pre-deploy gate. When connected, use `ludus-cli` for read-only role/template inventory. Registration, installation, apply, build, and deployment are outside package validation and follow the user's explicit request and the live workflow's scope boundaries.
6. **Deliver.** Report files, package-check results, range-validation results, any role-work static results, dependency coverage, server checks, and unresolved prerequisites separately. Preserve `PASS WITH WARNINGS — NOT VERIFIED` and its unavailable checks/targets. Include reproducible deployment instructions through `ludus-cli`; static results do not establish runtime behavior. Report live evidence from the requested or otherwise authorized cycle separately.

## Package example

```text
source.yml
ansible/roles/shared_role/       # existing vendored role
templates/custom-os/            # existing build definition, when needed
blueprints/workshop/
  blueprint.yml
  range-config.yml
  requirements.yml              # external dependencies, when needed
  README.md
```

README covers purpose/topology, prerequisites and pins, resource needs, lab credentials/setup, deployment, manual steps, success checks, and known limitations.

## Local check

Requires Python 3.9+ and PyYAML. From this skill directory:

```bash
python3 scripts/validate_package.py /path/to/source workshop
```

The checker enforces this skill's authoring profile, not an official manifest schema. It checks metadata, packaged paths, README presence, and dependency declaration shape. Semantic dependency coverage and range validation remain separate required steps.

## Common mistakes

- Put vendored roles/collections and templates at the **source root**, not inside a blueprint.
- Distribute custom assets through a source: single-blueprint exports omit local roles and templates.
- Treat parsing/package-check success as package evidence, not deployability.
