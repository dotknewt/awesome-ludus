# Awesome Ludus Source
Add: `ludus source add https://github.com/dotknewt/awesome-ludus-sauce.git --id awesome-ludus-sauce --force` 
Apply a blueprint: `ludus blueprint apply awesome-ludus-sauce/constructing-defense --target-range condef`

## Deploy local role changes

Use the [reusable deployment utility](docs/using-ludus-deployment.md) for changed
configured-role uploads, one launch, and explicit history observation:

```sh
python scripts/ludus_deploy.py deploy --range RANGE
```

Follow the guide's dependency and secure environment setup first. Default scope
is the range's user-defined roles; acceptance is not completion. Agents must
reuse this utility and follow the [one-cycle live policy](docs/instructions/live-debugging.md).
Live compatibility remains **PASS WITH WARNINGS — NOT VERIFIED**.

## Submodule checklist

When adding an upstream Ansible role:

- [ ] Inspect the destination for existing files. If it is an empty directory,
  remove it with `rmdir` before adding the submodule.
- [ ] Register the submodule:
  `git submodule add <repository-url> ansible/roles/<role-name>`.
  Editing `.gitmodules` alone does not register a submodule.
- [ ] Run `git ls-files --stage ansible/roles/<role-name>` and confirm the entry
  has mode `160000`. Its commit must match
  `git -C ansible/roles/<role-name> rev-parse HEAD`.
- [ ] Run `git submodule update --init --recursive`, then
  `git submodule status --recursive`. Confirm there are no `-` (uninitialized),
  `+` (commit mismatch), or `U` (conflict) prefixes.
- [ ] Include both `.gitmodules` and the pinned submodule entry in the parent
  repository commit. Ensure the pinned commit is available from the upstream
  repository so other clones can initialize it.

## Configure the host packet capture bridge

Once the range bridge exists, use the [bridge role guide](ansible/roles/ludus_bridge_promisq/README.md)
to run its wrapper **on the single-node Ludus/Proxmox host**, with Ansible installed:

```sh
cd /path/to/awesome-ludus/ansible/roles/ludus_bridge_promisq
BRIDGE_NUM=3 ./configure-bridge.sh
```

Replace `3` with your range's numeric `range_second_octet` allocation (1–254),
not its textual range ID. This example selects `vmbr1003` (`1000 + 3`).
The playbook runs locally on the host, enables promiscuous mode, sets bridge
ageing time to `0`, and installs a persistent interface-up hook to reapply those
settings. The bridge must already exist.

See the [bridge role documentation](ansible/roles/ludus_bridge_promisq/README.md)
for host prerequisites and the hook retirement procedure.
