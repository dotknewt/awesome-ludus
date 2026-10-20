# Authoring Ludus sources, blueprints, ranges, and roles

Use this policy when creating or reviewing Ludus source content, blueprints, range configurations, or Ansible roles in this repository. Check for existing components and reuse them before adding or duplicating one. Follow official Ludus documentation and the [range-config schema](https://docs.ludus.cloud/schemas/range-config.json) for actual Ludus behavior; this document's reuse and role-design rules are repository policy, not claims about what Ludus enforces.

## Keep artifacts in their lane

- A source is a versioned bundle of blueprints, Packer templates, and Ansible roles/collections. Keep reusable implementation there; a source may also contain no blueprints when it only distributes roles or templates.
- A blueprint bundles a range config with dependency information. A range config describes the lab topology and the roles, templates, and inputs used by its VMs. Keep lab-specific topology, VM names, and values in the blueprint/range configuration—not hidden inside generally reusable roles.
- Use the documented files: source metadata in root `source.yml`; each source blueprint has `blueprint.yml` metadata and `range-config.yml` topology, with `requirements.yml` for Galaxy roles, collections, or subscription roles. Declare dependencies there with appropriate version pins, or provide source-local roles under `ansible/roles/` and collections under `ansible/collections/`. Do not copy large schemas into examples; link to the official schema and check it for valid fields and types.
- Treat source content as executable code on the Ludus host; review it before installation and prefer an immutable source ref when appropriate.

## Reusable role design

- Make each role independently reusable, namespaced, and usable without a particular blueprint. Own the installation and configuration of the component the role represents.
- Do not rely on hidden sibling-role execution or hardcode lab-specific VM names, addresses, or topology. Express configurable values through role inputs and documented Ludus-provided variables; keep topology-dependent values in the range config.
- Use role-specific prefixes for role variables to reduce collisions. Document supported operating systems/platforms, configurable inputs and their defaults, and how to use the role. Follow the standard Ansible role structure; Ludus's role-development documentation requires `meta/main.yml`.
- Require nonempty `galaxy_info.role_name` and `galaxy_info.author` in each role's `meta/main.yml`. For project-authored roles, use the author's GitHub username as `author`; preserve upstream attribution for vendored roles.
- These are the only Galaxy metadata fields whose absence blocks this repository's validation workflow. Missing other Galaxy metadata (for example, `description`, `license`, `min_ansible_version`, `platforms`, or `galaxy_tags`) is advisory, not a blocker or coverage gap. Preserve raw validator output and exit status, but distinguish optional-metadata-only findings from blocking failures in the workflow verdict. This exception covers missing fields only; malformed YAML, invalid supplied values, dependency errors, and unrelated check failures remain blocking. This is repository policy, not a claim about Galaxy publication requirements.
- Keep blueprint role assignments, `depends_on` role references, internal `include_role`/`import_role` calls, and metadata dependencies consistent with installed role identities. Compare metadata with the target server's reported identity rather than inferring the installed name from the source directory alone.
- Resolve documentation/server naming discrepancies against the target Ludus version: record that version and compare version-matched official documentation or source with read-only server catalog and installed-role evidence. Report unresolved discrepancies and missing evidence explicitly before claiming identity compatibility.
- Declare normal platform prerequisites and required Ansible collections as dependencies where appropriate. They are not hidden sibling-role coupling.
- When pinning dependency versions, use the currently installed version as the minimum by default; raise that minimum only when concrete evidence supports it, such as a documented version requirement from `ansible.windows` or `community.windows`.
- A server/client pair may be an exception when the integration has a documented interface and the range config explicitly orders the server before the client. The documented `roles` entry supports `depends_on` entries containing the prerequisite `vm_name` and `role`; verify both the interface and ordering rather than assuming deployment order.

## Credentials and inputs

- Never change template default credentials. For simple application username/password defaults used by a role in a disposable lab, define defaults under `<role>/defaults/main.yml`; allow optional per-VM overrides in the range config's `role_vars` (which Ludus passes to user-defined roles).
- Do not require Ansible Vault or add password generation/rotation machinery solely for disposable in-lab application credentials. These are lab inputs, not production secret-management policy.
- Real external tokens and credentials for infrastructure or paid services are not disposable lab defaults: do not commit them or expose them as role defaults. Keep them outside committed artifacts and use the appropriate external secret mechanism.

## Verification and evidence

- Verification is static and live only; do not add or rely on simulations, stateful fakes, or mocked behavior as verification evidence. Static checks may validate structure, syntax, manifests, schema conformance, and code patterns, but do not prove runtime behavior. Follow [AGENTS.md's behavioral verification requirements](../../AGENTS.md#behavioral-verification) for actual-entrypoint evidence, lifecycle and sanitization checks, evidence reporting/reuse, and authorization.
- For Ansible/YAML checks, use the repository's `ansible-validation` skill and `.opencode/skills/ansible-validation/scripts/validate.py`. Inventory every role and declared dependency in the selected artifact while excluding unrelated roles. Actual check failures and coverage errors block a live-authorization request, except for the missing optional Galaxy metadata defined above; `PASS WITH WARNINGS — NOT VERIFIED` may proceed only when every unavailable check and unverified target remains prominent. Static output never proves runtime readiness or grants deployment authorization.

## Official references

- [Ludus documentation](https://docs.ludus.cloud/)
- [Sources](https://docs.ludus.cloud/docs/using-ludus/sources)
- [Blueprints](https://docs.ludus.cloud/docs/using-ludus/blueprints)
- [Range configuration](https://docs.ludus.cloud/docs/configuration) and [range-config schema](https://docs.ludus.cloud/schemas/range-config.json)
- [Roles](https://docs.ludus.cloud/docs/using-ludus/roles) and [role development](https://docs.ludus.cloud/docs/developers/ansible-roles)
- [Default passwords](https://docs.ludus.cloud/docs/using-ludus/passwords)
