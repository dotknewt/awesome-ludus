# Ansible Validation Skill Design

## Intent

Add a small repository skill that inventories the Ansible/YAML targets relevant to the user's requested scope and runs three real static checks when their executables are already available:

- `ansible-playbook --syntax-check`
- `ansible-lint`
- `yamllint`

The validator never installs tools or roles. Missing validation tools are warnings, not failures, but the report must say that the corresponding checks were **NOT VERIFIED**, name the missing packages, and give a safe isolated install suggestion plus the exact rerun command.

Static validation remains separate from live verification. The command never installs/registers anything on Ludus, deploys, probes guests, or grants deployment authorization.

## Scope and coverage

The skill owns scope selection and target inventory; the bundled script only validates explicit paths supplied by the skill. For a range, source, or blueprint evaluated for deployment readiness, the skill must identify every included/referenced role and declared role dependency. Unrelated repository roles do not participate.

The inventory records:

- scope and artifact data files;
- each role name, where it was referenced, whether it is source-local or externally supplied, and its resolved local path;
- each role's truthful syntax harness;
- additional playbooks; and
- unresolved roles, dependencies, paths, or harnesses.

Artifact YAML is supplied as data for `yamllint`, not as an Ansible playbook. Source-local roles and locally available external roles are supplied as role paths. An unresolved or unavailable external role is shown as an unresolved coverage gap; the skill must not silently validate only the local subset and call the entire artifact clean. Before writing Ludus-specific target-resolution guidance, the implementer follows `docs/instructions/ludus-skill-documentation.md` and verifies current official source, blueprint, range, requirements, and role documentation rather than inventing schema semantics.

A missing target or syntax harness is distinct from a missing executable:

- missing `ansible-playbook` means a known syntax target was not checked and may yield `PASS WITH WARNINGS`;
- a role that should be in scope but cannot be resolved, or has no truthful syntax harness, is a coverage error and makes the invocation fail;
- the script never generates a generic harness because that could misrepresent the role's required variables, hosts, or entrypoint.

Whole-repository validation remains available through `--all` (or an equally simple final interface). It inventories all repository roles and relevant YAML/playbooks. Missing harnesses block that whole-repository run only; they do not block a different artifact scope that excludes those roles.

## Proposed interface

Exact flags and paths are implementation choices, not user-approved syntax. The proposed script location and interface are:

```text
python3 .opencode/skills/ansible-validation/scripts/validate.py \
  --role PATH [--role PATH ...] \
  --playbook PATH [--playbook PATH ...] \
  --data PATH [--data PATH ...] \
  [--coverage-gap TEXT ...]

python3 .opencode/skills/ansible-validation/scripts/validate.py --all
```

`--role` contributes the role directory to `ansible-lint`, all role YAML to `yamllint`, and its existing `tests/syntax.yml` to syntax checking. `--playbook` contributes to all three tools. `--data` contributes only to `yamllint`. `--coverage-gap` lets the skill make unresolved inventory items explicit and failing without pretending they were tool findings. `--all` performs the same simple repository-specific expansion.

Malformed arguments, nonexistent explicit paths, a missing harness for an in-scope role, subprocess launch/runtime errors, and coverage gaps are script errors and return nonzero. They are not converted into missing-tool warnings.

## Tool discovery and execution

The script discovers each executable independently with `PATH` lookup and runs every available tool even when another is missing:

| Executable | Check | Suggested package when missing |
| --- | --- | --- |
| `ansible-playbook` | `--syntax-check` for each syntax target | `ansible-core` |
| `ansible-lint` | lint explicit role/playbook targets using shared config | `ansible-lint` |
| `yamllint` | lint explicit role/playbook/data YAML using shared config | `yamllint` |

The script never invokes `pip`, creates a virtual environment, installs collections/roles, or mutates remote systems. A safe suggestion may use an isolated environment, for example:

```bash
python3 -m venv .venv/ansible-validation
.venv/ansible-validation/bin/python -m pip install ansible-core ansible-lint yamllint
PATH="$PWD/.venv/ansible-validation/bin:$PATH" python3 .opencode/skills/ansible-validation/scripts/validate.py <same arguments>
```

The suggestion includes only packages corresponding to missing binaries. Its shell-quoted exact rerun command activates the new environment or prefixes `PATH` as above so the installed executables are discoverable.

`ansible-lint` must run in its officially supported offline/no-dependency-install mode. The implementer verifies the current option against official documentation and installed `--help` before finalizing the command; the script must not permit `ansible-lint` or another child process to install roles or collections. If an executable exists but reports missing roles, collections, Python modules, or other dependencies, that is a real tool `FAIL`, not `NOT AVAILABLE`.

Shared `.ansible-lint` and `.yamllint.yml` files remain lightweight. Exceptions use tool-native, path-local syntax and include an adjacent human-readable reason visible in the reviewed source/configuration. There is no custom exception scanner, registry, fingerprint matcher, or grandfathered legacy baseline.

## Status and exit semantics

Each tool reports its resolved executable (when present), command/check count, and one status:

- `PASS` — the available tool ran all of its targets successfully;
- `FAIL` — the available tool reported a check failure or could not complete; or
- `NOT AVAILABLE` — the executable was absent, so those targets were not verified.

Overall status:

- `PASS`: all three tools were available, all checks passed, and coverage was complete;
- `PASS WITH WARNINGS — NOT VERIFIED`: one, two, or all three tools were unavailable, every available tool passed, and coverage was complete; exit zero is allowed;
- `FAIL`: any available tool failed, coverage was incomplete, invocation was malformed, or the script had a runtime error; exit nonzero.

An available tool failure always wins over missing-tool warnings. For example, failing `ansible-lint` plus unavailable `yamllint` is `FAIL`, not warning-only. A run with no tools may exit zero, but it must unmistakably say that syntax, Ansible lint, and YAML lint were not verified; it must never print unqualified `PASS` or “clean.”

The authorization gate becomes: **no actual check failures and no target-coverage errors**. Missing-tool warnings may proceed to a request for live deployment authorization only when the unverified checks and affected targets are explicitly carried forward. This does not prove runtime readiness or grant authorization.

Every report has separate sections:

- **Static validation:** inventory, per-tool status, failures, warnings, missing packages, and rerun command.
- **Live verification:** `NOT RUN — requires separate authorization`.

## Skill and documentation handoffs

Create a thin `.opencode/skills/ansible-validation/SKILL.md` that explains how to build the complete target inventory, invoke the bundled script, interpret warning-only results, and preserve unresolved coverage. Add only minimal references from:

- `.opencode/instructions/ansible.instructions.md`;
- `docs/instructions/ludus-authoring.md`;
- `.opencode/skills/ludus-blueprint/SKILL.md`;
- `.opencode/skills/range-config/SKILL.md`; and
- `.opencode/skills/ludus-cli/SKILL.md`.

The handoffs use the same rule: actual static failures or coverage errors block an authorization request; unavailable-tool warnings may proceed only with prominent unverified coverage. Static and live evidence remain separate.

## Non-goals

- Dependency locks, managed environments, automatic installation, registry/cache infrastructure, or a Ludus dependency resolver in the script.
- CI, pre-commit hooks, or mandatory linting for unrelated work.
- Auto-generated syntax harnesses, simulations, check mode, Molecule, mocked/stateful Ludus runtime evidence, or role cleanup.
- Remote role installation/registration, deployment, guest probes, or any live mutation.
- Treating static checks—or warning-only missing checks—as runtime readiness.

## Acceptance criteria

- The skill supplies complete explicit targets for role/range/source/blueprint work; unrelated roles are excluded and unresolved targets are prominent coverage errors.
- `--all` or its simple equivalent covers all repository roles and relevant YAML without changing artifact-scope behavior.
- All available tools run independently; missing tools produce `NOT AVAILABLE`, package/install guidance, affected unverified targets, and the exact rerun command without auto-installing.
- `ansible-lint` runs with its verified offline/no-install option; missing dependencies reported by any available tool are failures, not unavailable-tool warnings.
- All/partial/no-tool success states follow the status table; an available-tool failure plus another missing tool is nonzero `FAIL`.
- Missing paths/harnesses, malformed invocation, coverage gaps, and script runtime errors are nonzero and are not mislabeled as tool unavailability.
- Tool-native exceptions are reasoned and visible without a custom audit engine.
- Reports separate static results from live-not-run status and never turn a warning-only static result into deployment permission.
