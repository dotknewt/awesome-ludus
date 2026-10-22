# `ludus_bridge_promisq` role directory

Configures packet-observation behavior on the existing private Linux bridge for
one Ludus 2.x range. The source directory is `ansible/roles/ludus_bridge_promisq`;
its `meta/main.yml` declares the role identity `ludus_bridge_promisq`. Do not
infer compatibility with a role name installed on a Ludus server from either
name alone; this guide invokes the repository role by its path.

The `configure-bridge.sh` wrapper and `ludus-configure-bridge.yaml` playbook
are colocated with this role. The wrapper resolves the playbook relative to its
own location; run it on the Ludus server itself, with the repository present
there. Every role task runs once on `localhost` (the Ludus/Proxmox host), uses
the playbook's local Python interpreter, and escalates to root.

## Run from the Ludus server
1. Ensure this repository is available on the Ludus server. Ansible 2.15 or
   newer must be available there, as declared by the role metadata; this guide
   does not install it. The wrapper also requires `ip` and `jq` on the server.
   `ansible-playbook` is required only when the live bridge does not match the
   requested state.
2. Change to the role directory and provide the bridge selection. `BRIDGE_NUM`
   accepts an allocation from `1` through `254`, a full bridge number from
   `1001` through `1254`, or a name from `vmbr1001` through `vmbr1254`.

   ```bash
   cd /path/to/awesome-ludus/ansible/roles/ludus_bridge_promisq
   ./configure-bridge.sh
   BRIDGE_NUM=2 ./configure-bridge.sh
   BRIDGE_NUM=1002 ./configure-bridge.sh
   BRIDGE_NUM=vmbr1002 ./configure-bridge.sh
   BRIDGE_NUM=vmbr1002 PROMISCUOUS=false ./configure-bridge.sh
   ```

   `PROMISCUOUS` accepts exactly `true` or `false`, defaults to `true`, and
   controls the bridge `PROMISC` flag. Ageing time is always `0` centiseconds.
   If `BRIDGE_NUM` is unset, the wrapper prompts only in an interactive shell;
   an unset value in noninteractive use fails. An explicitly empty value also
   fails rather than prompting.

For example, from an operator workstation, SSH to the Ludus server first, then
run the wrapper in that server shell:

```text
ssh user@ludus-server
cd /path/to/awesome-ludus/ansible/roles/ludus_bridge_promisq
BRIDGE_NUM=2 ./configure-bridge.sh
```

The wrapper intentionally runs on the Ludus server. The playbook targets
`localhost`, and role tasks use `delegate_to: localhost`, `run_once: true`, and
`become: true`; an operator workstation inventory cannot retarget them.
`ansible-playbook -K` is used automatically when the wrapper is not run as
root; root execution omits `-K`.

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

The wrapper's default is promiscuous mode enabled and ageing time `0`. Use
`PROMISCUOUS=false` to disable promiscuous mode; ageing time is intentionally
fixed at `0` by this wrapper. The playbook remains available for direct
administrative use from this directory, but the wrapper is the documented
workflow.

No bridge-name override is passed to Ansible: the wrapper normalizes the
selection to the range allocation and the role derives the bridge name. The
role requires the selected bridge to exist and rejects Ludus cluster mode.

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

In the JSON, check that `flags` contains `PROMISC` with the default (or omits
it when `PROMISCUOUS=false` was used), and that
`linkinfo.info_data.ageing_time` is `0`; the wrapper always requests that value.
The hook inspection should show that exact file exists and is executable.
These are read-only observations, not proof of persistence through a later
interface-up or reboot.

The wrapper's early-exit decision checks the same live-state properties. For
example, this read-only predicate checks the default state for `vmbr1002`:

```bash
ip -d -j link show dev vmbr1002 |
  jq -e '.[0].linkinfo.info_data.ageing_time == 0 and
    (.[0].flags | contains(["PROMISC"]))' >/dev/null
```

The wrapper additionally validates the command result, record shape, bridge
kind, and expected promiscuous setting before it can skip Ansible. The early
exit deliberately checks **live bridge state only**: it does not inspect,
verify, install, or repair the persistent if-up hook. If live settings match
but the hook is missing or stale, the wrapper still exits without invoking
Ansible; inspect the hook separately as shown above.

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
