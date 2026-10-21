# Local tests

The pytest suite invokes the production role from a fake guest inventory. The
production tasks delegate to localhost with privilege escalation, but tests use
an isolated become wrapper, fake `ip`/`ifquery` executables, fake ifupdown2
configuration, and a temporary hook directory. It never writes to `/etc` or
changes real networking.

Both the guest and localhost inventory entries name a deliberately nonexistent
Python interpreter. The guest therefore cannot execute modules accidentally;
the role must delegate to localhost and replace the inventory interpreter with
`ansible_playbook_python`. The fake become executable records every invocation,
allowing the suite to require root escalation without granting real privilege.

From the repository root:

```bash
python3 -m venv /tmp/ludus-configure-bridge-venv
/tmp/ludus-configure-bridge-venv/bin/pip install \
  --requirement ansible/roles/ludus_configure_bridge/tests/requirements.txt
export ANSIBLE_PLAYBOOK=/tmp/ludus-configure-bridge-venv/bin/ansible-playbook
export ANSIBLE_ROLES_PATH="$PWD/ansible/roles"
PYTHONDONTWRITEBYTECODE=1 \
  /tmp/ludus-configure-bridge-venv/bin/pytest -q \
  ansible/roles/ludus_configure_bridge/tests
/tmp/ludus-configure-bridge-venv/bin/ansible-playbook \
  --syntax-check --inventory guest, \
  ansible/roles/ludus_configure_bridge/tests/syntax.yml
/tmp/ludus-configure-bridge-venv/bin/yamllint \
  ansible/roles/ludus_configure_bridge
/tmp/ludus-configure-bridge-venv/bin/ansible-lint \
  ansible/roles/ludus_configure_bridge
```

The suite covers two allocations, invalid/missing metadata, cluster rejection,
Linux-bridge validation, matching, missing, and nonmatching `IFACE` hook
invocations, propagated hook errors, immediate drift correction, nondefault
settings, and second-run idempotence. It parses the documented Ludus assignment
example and exercises the documented retirement snippet against isolated hook
fixtures, including allocation validation and preservation of unrelated hooks.
It also checks the Constructing Defense blueprint role order, manual fallback
commands, persistence documentation, and retirement guidance.

It does not perform a live deployment, reboot, ifreload, traffic-acceptance
test, or packet capture. Those remain explicit host acceptance steps.
