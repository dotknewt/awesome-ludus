---
description: 'Ansible conventions and best practices'
applyTo: '**/*.yaml, **/*.yml'
---

# Ansible Conventions and Best Practices

## General Instructions

- Use Ansible to configure and manage infrastructure.
- Use version control for your Ansible configurations.
- Keep things simple; use advanced features only when necessary.
- Give every play, block, and task a concise, descriptive `name`.
  - Start names with an action verb such as "Install," "Configure," or "Copy".
  - Capitalize the first letter of the task name.
  - Omit periods from the end of task names.
  - Omit the role name from role tasks; Ansible displays it automatically.
  - When including tasks from a separate file, you may prefix names with the filename (for example, `<TASK_FILENAME> : <TASK_NAME>`).
- Use comments to explain what, how, or why something is being done; omit redundant comments.
- Use dynamic inventory for cloud resources and tags to create groups by environment, function, location, or similar attributes.
- Use idempotent Ansible modules whenever possible. Avoid `shell`, `command`, and `raw` because they can break idempotency.
  - If `shell` or `command` is necessary, use `creates:` or `removes:` where feasible.
- Use fully qualified collection names (FQCN) and prefer the `ansible.builtin` collection for built-in modules and plugins.
- Group related tasks to improve readability and modularity.
- Set `state: present` or `state: absent` explicitly when a module's `state` is optional.
- Use the lowest privileges necessary.
  - Set `become: true` at play or include level only when all included tasks require elevated privileges.
  - Otherwise set `become: true` only on the tasks that require it.

## Secret Management

- For disposable Ludus lab credentials, follow the mandatory [Ludus authoring policy](../../docs/instructions/ludus-authoring.md).
- For real external secrets (not disposable Ludus lab defaults), when using Ansible alone, store secrets with Ansible Vault:
  1. Create a `group_vars/` subdirectory named after the group.
  2. Create `vars` and `vault` files inside it.
  3. Define required variables, including sensitive ones, in `vars`.
  4. Copy sensitive variables into `vault` with a `vault_` prefix.
  5. Reference matching vaulted variables from `vars`, for example `db_password: "{{ vault_db_password }}"`.
  6. Encrypt the `vault` file.
  7. Use the variable from `vars` in playbooks.
- For real external secrets used with other tools, store them in an appropriate external secrets manager, such as HashiCorp Vault or AWS Secrets Manager.

## Style

- Use 2-space indentation and always indent lists.
- Separate adjacent host blocks, task blocks, and host/include blocks with one blank line.
- Use `snake_case` for variable names.
- Sort variables alphabetically in `vars:` maps and variable files.
- Use multi-line map syntax, even for one key/value pair.
- Prefer single quotes. Use double quotes only for nested single-quoted strings or strings requiring escapes.
- Use folded (`>`) or literal (`|`) block scalars for long strings.
- Order a play as `hosts`, alphabetized host options, `pre_tasks`, `roles`, and `tasks`.
- Order a task as `name`, task declaration, multi-line parameters, loops, alphabetized options, and `tags`.
- Quote filenames in `include` statements. Add blank lines between includes only when the includes are multi-line.

## Linting

- Use the `ansible-validation` skill and bundled validator for scoped `ansible-playbook --syntax-check`, `ansible-lint`, and `yamllint` checks. Its inventory must cover every in-scope target and represent unresolved paths or harnesses as coverage errors; missing executables remain prominent unverified warnings.
- For Ludus artifacts, follow the [static-and-live verification policy](../../docs/instructions/ludus-authoring.md#verification-and-evidence); use separately authorized live runs rather than check-mode simulations to verify runtime behavior.

## Sources

- [Ansible Documentation - Tips and Tricks](https://docs.ansible.com/ansible/latest/tips_tricks/index.html)
- [Whitecloud Ansible Styleguide](https://github.com/whitecloud/ansible-styleguide)
