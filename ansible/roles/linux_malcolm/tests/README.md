# Local Validation

The behavioral suite runs production task includes against pytest temporary
directories. It does not install packages, modify sysctls, control systemd, or
use the host Docker daemon. Service tests provide PATH-scoped fake executables.
The guest VM must already be powered on and reachable before the role runs; VM
lifecycle management belongs to Ludus, not this guest-level role.

## Prerequisites

- Python capable of creating a venv (validated with Python 3.14.7)
- Git
- A real `cisagov/Malcolm` checkout whose `HEAD` is the pinned
  `07bbccdfe2732fb5c5147070cdfca2857b85bacc` commit (`v26.08.0`)
- Network access while creating the tools environment and while the source
  installation test builds its scratch Malcolm venv

The upstream checkout is a test fixture and provenance source, not a deployment
source. Tests reject a checkout at another commit. Paths are caller-selected;
the suite contains no fixed scratch-tool or upstream-source location.

## Setup

Run from the repository root. Set `MALCOLM_UPSTREAM_SOURCE` to the real pinned
checkout before invoking pytest.

```bash
export MALCOLM_TEST_ROOT="${MALCOLM_TEST_ROOT:-$(mktemp -d)}"
python3 -m venv "$MALCOLM_TEST_ROOT/venv"
"$MALCOLM_TEST_ROOT/venv/bin/pip" install --requirement ansible/roles/role_malcolm_install/tests/requirements.txt
"$MALCOLM_TEST_ROOT/venv/bin/ansible-galaxy" collection install --requirements-file ansible/roles/role_malcolm_install/tests/requirements.yml --collections-path "$MALCOLM_TEST_ROOT/collections"
export MALCOLM_TEST_VENV="$MALCOLM_TEST_ROOT/venv"
export ANSIBLE_PLAYBOOK="$MALCOLM_TEST_VENV/bin/ansible-playbook"
export ANSIBLE_COLLECTIONS_PATH="$MALCOLM_TEST_ROOT/collections"
export ANSIBLE_ROLES_PATH="$PWD/ansible/roles"
export MALCOLM_UPSTREAM_SOURCE="/path/to/pinned/Malcolm"
git -C "$MALCOLM_UPSTREAM_SOURCE" rev-parse HEAD
git -C "$MALCOLM_UPSTREAM_SOURCE" describe --tags --exact-match HEAD
```

The two Git commands must print the approved commit and `v26.08.0`.

## Commands

Run the full behavioral suite once on the integrated state:

```bash
PYTHONDONTWRITEBYTECODE=1 "$MALCOLM_TEST_VENV/bin/pytest" -q ansible/roles/role_malcolm_install/tests
```

Syntax-check the complete role, including its Docker dependency:

```bash
"$ANSIBLE_PLAYBOOK" --syntax-check --inventory localhost, ansible/roles/role_malcolm_install/tests/syntax.yml
```

Lint the complete production role and changed Docker dependency interface:

```bash
"$MALCOLM_TEST_VENV/bin/ansible-lint" -x 'var-naming,yaml[line-length]' ansible/roles/role_malcolm_install ansible/roles/ludus_install_docker/defaults/main.yml ansible/roles/ludus_install_docker/tasks/main.yml
```

`var-naming` is excluded because the approved public and internal prefix is
`ludus_install_malcolm_*` / `_ludus_install_malcolm_*`, while ansible-lint
derives `role_malcolm_install_*` from the retained role directory name.
`yaml[line-length]` is excluded only in ansible-lint because exact commits,
schemas, argv, and validation expressions are clearer intact. Standalone
yamllint applies the repository's explicit policy, which disables only line
length:

```bash
"$MALCOLM_TEST_VENV/bin/yamllint" -d '{extends: default, rules: {line-length: disable}}' ansible/roles/role_malcolm_install blueprints/constructing-defense/requirements.yml blueprints/constructing-defense/range-config.yml
```

`test_documentation.py` parses and validates the blueprint's Malcolm contract,
collection declarations, exact public variable coverage, and VM acceptance
inventory. Validate the blueprint against the official schema without setting
or deploying a range:

```bash
"$MALCOLM_TEST_VENV/bin/python" -c "import json, urllib.request, yaml; from jsonschema.validators import validator_for; data=yaml.safe_load(open('blueprints/constructing-defense/range-config.yml', encoding='utf-8')); schema=json.load(urllib.request.urlopen('https://docs.ludus.cloud/schemas/range-config.json', timeout=30)); validator_for(schema)(schema).validate(data); print('blueprint schema validation passed')"
```

This requires network access to retrieve the schema. Schema-aware editors use
the same URL from `range-config.yml`; the authoritative server-side check
remains the Ludus range-config validation during VM acceptance, not on the
coding host.
