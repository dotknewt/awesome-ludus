# `ludus_bridge_promisq` role directory

Configures packet-observation behavior on the existing private Linux bridge for
one Ludus 2.x range. The source directory is `ansible/roles/ludus_bridge_promisq`;
its `meta/main.yml` declares the role identity `ludus_bridge_promisq`. Do not
infer compatibility with a role name installed on a Ludus server from either
name alone; this guide invokes the repository role by its path.

Every task runs once on `localhost` (the Ludus/Proxmox host), uses the
playbook's local Python interpreter, and escalates to root. The repository-root
playbook `ludus-configure-bridge.yaml` is explicitly a local play. Run it on
the Ludus server itself, with this repository present there. An operator
working remotely must SSH into the server and run the command there.

## Run from the Ludus server

1. Ensure this repository is available on the Ludus server and change to its
   root directory (the directory containing `ludus-configure-bridge.yaml`).
   Ansible 2.15 or newer must be available there, as declared by the role
   metadata; this guide does not install it.
2. Obtain the range's numeric `range_second_octet` allocation from Ludus. Supply
   it as a JSON integer from 1 through 254; do not use textual `range_id`.
3. Run the root playbook. For allocation `2`, with an account that can use sudo:

   ```bash
   ansible-playbook -K -e '{"range_second_octet": 2}' ludus-configure-bridge.yaml
   ```

   `-K` prompts for the become/sudo password. If already running as root, omit
   `-K`. The playbook and role still require root privileges for their host
   operations.

The playbook targets `localhost` and has `connection: local`. In addition, the
role tasks set `delegate_to: localhost`, `run_once: true`, and `become: true`.
Consequently, changing an inventory or targeting a remote host does not retarget
these tasks: running an inventory-based playbook from an operator workstation
is **not supported by this unchanged role**. Keep execution local to the Ludus
server; do not try to redirect the role by overriding inventory hosts.

For example, from the operator workstation, replace the placeholder with the
server's SSH destination:

```bash
ssh user@ludus-server
# Run these commands in the server's SSH shell:
cd /path/to/awesome-ludus
ansible-playbook -K -e '{"range_second_octet": 2}' ludus-configure-bridge.yaml
```

This runs the playbook in an interactive shell on the server; it does not make the
workstation an Ansible control host for this role. Adjust the repository path
and allocation as needed.

This role supports **single-node Ludus only**. It rejects cluster mode because
clusters use Proxmox SDN VNets rather than the local Linux bridges managed here.
It does not create bridges, edit Ludus-managed interface stanzas, or restart
networking.

## Bridge selection

Ludus supplies the numeric `range_second_octet`. After validating it as a
decimal allocation from 1 through 254, the role derives:

```text
vmbr{{ 1000 + range_second_octet }}
```

For example, allocations 2 and 254 select `vmbr1002` and `vmbr1254`.
`range_id` is textual metadata and is not a bridge suffix. A bridge cannot be
provided manually.

The selected bridge carries the whole range `/16`; VLANs within that bridge are
not independently configurable by this role. Applying promiscuous mode or an
ageing time therefore affects the range bridge, not one range VLAN.

## Variables

| Variable | Default | Contract |
| --- | --- | --- |
| `ludus_configure_bridge_promiscuous` | `true` | Boolean; controls the bridge `PROMISC` flag. |
| `ludus_configure_bridge_ageing_time` | `0` | Integer centiseconds, 0-4294967295; controls learned-FDB ageing. |

The role requires Ludus-provided `range_second_octet`. It accepts
`ludus_cluster_mode` when supplied and requires it to be boolean and false.

## Behavior and prerequisites

Before changing anything, the role verifies on the host that:

- `ip` and ifupdown2's `ifquery` are executable;
- ifupdown2 reports its version and has `addon_scripts_support=1`;
- `/etc/network/if-up.d` exists; and
- the derived interface exists and reports `info_kind: bridge` through
  `ip -d -j link show`.

Linux exposes bridge timers to iproute2 in `USER_HZ` units (centiseconds on the
supported host), and iproute2 passes and prints the `ageing_time` integer
without converting it to seconds. The role therefore defines the public value,
the command argument, and the observed JSON value in centiseconds. For example,
`3000` means 30 seconds. It changes each setting only when it drifts, then reads
the bridge again and verifies both settings.

Persistence is an executable run-parts-compatible file named
`/etc/network/if-up.d/ludus-configure-bridge-BRIDGE` (deliberately no `.sh`
extension). ifupdown2 invokes it in the post-up lifecycle. The hook exits for
all other `IFACE` values, reapplies both values for the matching bridge, and
uses `set -eu` so command errors fail the hook.

## Example range role assignment

```yaml
roles:
  - ludus_bridge_promisq
role_vars:
  ludus_configure_bridge_promiscuous: false
  ludus_configure_bridge_ageing_time: 3000
```

`roles` and `role_vars` are sibling VM properties in a Ludus range
configuration. This nondefault example disables promiscuous mode and uses a
30-second ageing time. The example uses the role identity declared in this
repository's metadata; before using it in a range, verify the installed role
identity in the target server's Ludus role catalog. Do not infer compatibility
from the source directory or metadata alone. Do not pass a bridge name.

The playbook invocation above uses the role defaults: promiscuous mode enabled
and ageing time `0`. To override either setting for this manual playbook run,
pass its role variable in the same `-e` JSON object, keeping
`range_second_octet` an integer. For example:

```bash
ansible-playbook -K \
  -e '{"range_second_octet": 2, "ludus_configure_bridge_promiscuous": false, "ludus_configure_bridge_ageing_time": 3000}' \
  ludus-configure-bridge.yaml
```

This selects `vmbr1002`, disables promiscuous mode, and sets ageing time to 30
seconds. No bridge-name override is supported: the role derives the bridge from
the allocation and requires that bridge to exist already. It rejects Ludus
cluster mode.

## Read-only checks and operational cautions

Before running, an administrator can inspect the derived bridge without making
changes. For allocation `2`:

```bash
sudo ip -d -j link show dev vmbr1002
sudo ifquery --version
sudo grep -nE '^[[:space:]]*addon_scripts_support[[:space:]]*=[[:space:]]*1[[:space:]]*(#.*)?$' /etc/network/ifupdown2/ifupdown2.conf
sudo test -d /etc/network/if-up.d && printf '%s\n' 'if-up hook directory exists'
```

The role requires executable `ip` and ifupdown2 `ifquery`, ifupdown2 with
`addon_scripts_support=1`, the `/etc/network/if-up.d` directory, and an existing
derived Linux bridge. The configuration-file path checked by the role is
`/etc/network/ifupdown2/ifupdown2.conf`. These checks are read-only; they do not
establish that the role has been run or that its desired settings are active.

After a successful run, inspect the live bridge and exact hook read-only (again
using allocation `2`):

```bash
sudo ip -d -j link show dev vmbr1002
sudo ls -l /etc/network/if-up.d/ludus-configure-bridge-vmbr1002
```

In the JSON, check that `flags` contains `PROMISC` with the defaults (or omits
it when promiscuous mode was overridden to `false`), and that
`linkinfo.info_data.ageing_time` is `0` by default or the requested centisecond
value (for example, `3000` for the override above). The hook inspection should
show that exact file exists and is executable. These are read-only observations,
not proof of persistence through a later interface-up or reboot.

Do not use Ansible `--check` as a reliable preview for this role: it relies on
command tasks whose registered output feeds later validation and state checks,
and check mode may skip those commands. An Ansible syntax check only checks
playbook syntax; it does not execute the role or validate the host bridge.

The role changes the live bridge and installs a persistent executable
`/etc/network/if-up.d/ludus-configure-bridge-BRIDGE` hook. Review the selected
range and intended network effect before running: this is privileged host
network configuration. The hook reapplies settings during interface-up events.
There is no automatic rollback, and removing the role or deleting a range does
not remove the hook or restore prior bridge settings. Follow the retirement
instructions below before reusing a range allocation.

## Retiring a range or this role

The host hook is persistent host state. It does **not** disappear automatically
when this role is removed from a VM or when a range is deleted. Because its name
is derived from the numeric allocation, a stale hook can configure a later
range that reuses the same `range_second_octet`.

Before deleting the range or allowing its allocation to be reused:

1. Stop deployment/testing activity for that range. Remove every
   assignment of this role (using the actual role identity configured for that
   range) from the VM `roles` lists so a later role run cannot recreate the hook.
2. While the range still exists, obtain its current numeric
   `range_second_octet` from Ludus. Do not derive it from textual `range_id`.
3. On the Ludus host, save the following snippet and run it with that numeric
   allocation as its only argument (for example, `sh remove-bridge-hook.sh 2`).
   It validates the allocation before deriving and removing one exact hook.

<!-- bridge-retirement-snippet-start -->
```sh
#!/bin/sh
set -eu

range_second_octet="${1:?usage: remove-bridge-hook.sh CURRENT_RANGE_SECOND_OCTET}"
case "$range_second_octet" in
    [1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4]) ;;
    *)
        printf '%s\n' 'range_second_octet must be a decimal integer from 1 through 254' >&2
        exit 2
        ;;
esac

bridge="vmbr$((1000 + range_second_octet))"
hook_dir="${LUDUS_CONFIGURE_BRIDGE_HOOK_DIR:-/etc/network/if-up.d}"
hook="${hook_dir}/ludus-configure-bridge-${bridge}"
if [ ! -f "$hook" ]; then
    printf 'expected range hook does not exist: %s\n' "$hook" >&2
    exit 3
fi
printf 'removing range hook: %s\n' "$hook"
sudo rm -- "$hook"
```
<!-- bridge-retirement-snippet-end -->

Never use a wildcard to remove hooks: hooks for other active ranges may be in
the same directory. Deleting this hook prevents future interface-up events from
reapplying the role's values; it does not restore the bridge's current live
settings. If the bridge will remain, explicitly apply your own known desired
baseline after hook removal. There is no assumed host baseline and no automatic
rollback. Confirm the exact hook is absent before deleting the range or reusing
its allocation.

## Validation scope

See [`tests/README.md`](tests/README.md) for local test details. Those tests use
fake host commands and temporary hook directories; in accordance with the
repository's static-and-live-only verification policy, they are not runtime
verification evidence and do **not** establish behavior on a real host. They
do not alter `/etc`, host networking, or a real bridge.

No live Ludus deployment, host reboot, ifreload, traffic acceptance, or packet
capture is established by the local tests or claimed here. Before production
use, an administrator must perform an authorized scoped deployment and
separately verify persistence after a planned reboot/ifreload and verify that
the intended traffic reaches the consumer.

## References

- [Ansible delegation and local actions](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_delegation.html)
- [Ludus roles](https://docs.ludus.cloud/docs/using-ludus/roles)
- [Ludus configuration](https://docs.ludus.cloud/docs/configuration)
