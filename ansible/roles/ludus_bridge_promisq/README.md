# ludus_configure_bridge

Configures packet-observation behavior on the existing private Linux bridge for
one Ludus 2.x range. The role is assigned to a guest in a range configuration,
but every task runs once on `localhost` (the Ludus/Proxmox host), uses the
playbook's local Python interpreter, and escalates to root.

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
  - ludus_configure_bridge
role_vars:
  ludus_configure_bridge_promiscuous: false
  ludus_configure_bridge_ageing_time: 3000
```

`roles` and `role_vars` are sibling VM properties in a Ludus range
configuration. This nondefault example disables promiscuous mode and uses a
30-second ageing time. Do not pass a bridge name.

## Retiring a range or this role

The host hook is persistent host state. It does **not** disappear automatically
when this role is removed from a VM or when a range is deleted. Because its name
is derived from the numeric allocation, a stale hook can configure a later
range that reuses the same `range_second_octet`.

Before deleting the range or allowing its allocation to be reused:

1. Stop deployment/testing activity for that range. Remove every
   `ludus_configure_bridge` assignment from the range's VM `roles` lists so a
   later role run cannot recreate the hook.
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

See [`tests/README.md`](tests/README.md) for reproducible local commands. Those
tests execute the production tasks against isolated fake host commands and
temporary hook directories. They do **not** alter `/etc`, host networking, or a
real bridge.

No live Ludus deployment, host reboot, ifreload, traffic acceptance, or packet
capture is claimed by the local suite. Before production use, an administrator
must perform a scoped deployment and separately verify persistence after a
planned reboot/ifreload and verify that the intended traffic reaches the
consumer.
