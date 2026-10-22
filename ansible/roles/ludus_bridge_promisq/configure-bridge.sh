#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: configure-bridge.sh

Configure the Ludus range bridge on this server. Set BRIDGE_NUM to an
allocation (1-254), full bridge number (1001-1254), or bridge name
(vmbr1001-vmbr1254). If BRIDGE_NUM is unset, you will be prompted.

PROMISCUOUS accepts true or false and defaults to true. Bridge ageing time
is always set to 0 centiseconds.

Examples:
  BRIDGE_NUM=2 ./configure-bridge.sh
  BRIDGE_NUM=1002 ./configure-bridge.sh
  BRIDGE_NUM=vmbr1002 PROMISCUOUS=false ./configure-bridge.sh
EOF
}

fail() {
    printf 'configure-bridge: %s\n' "$*" >&2
    exit 1
}

if (($#)); then
    if (($# == 1)) && [[ $1 == --help || $1 == -h ]]; then
        usage
        exit 0
    fi
    usage >&2
    exit 2
fi

if [[ ${BRIDGE_NUM+x} ]]; then
    input=$BRIDGE_NUM
    [[ -n $input ]] || fail 'BRIDGE_NUM is set but empty; provide a bridge allocation, number, or name.'
else
    [[ -t 0 ]] || fail 'BRIDGE_NUM is unset and stdin is noninteractive; set BRIDGE_NUM.'
    read -r -p 'Bridge allocation (1-254), bridge number (1001-1254), or name (vmbr1001-vmbr1254): ' input ||
        fail 'could not read bridge selection.'
fi

# Match complete decimal forms before using arithmetic, excluding leading zeros
# and out-of-range values. Full bridge forms normalize by subtracting 1000.
allocation_re='^([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$'
bridge_re='^(10(0[1-9]|[1-9][0-9])|11[0-9]{2}|12([0-4][0-9]|5[0-4]))$'
if [[ $input =~ $allocation_re ]]; then
    allocation=$input
elif [[ $input =~ ^vmbr(.*)$ ]]; then
    bridge_number=${BASH_REMATCH[1]}
    [[ $bridge_number =~ $bridge_re ]] ||
        fail 'invalid bridge name; expected vmbr1001 through vmbr1254.'
    allocation=$((10#$bridge_number - 1000))
elif [[ $input =~ $bridge_re ]]; then
    allocation=$((10#$input - 1000))
else
    fail 'invalid bridge selection; use allocation 1-254, bridge number 1001-1254, or vmbr1001-vmbr1254.'
fi

bridge_number=$((1000 + allocation))
bridge_name="vmbr${bridge_number}"

if [[ ${PROMISCUOUS+x} ]]; then
    promiscuous=$PROMISCUOUS
else
    promiscuous=true
fi
case $promiscuous in
    true|false) ;;
    *) fail 'PROMISCUOUS must be exactly true or false.' ;;
esac

command -v ip >/dev/null 2>&1 || fail 'required command not found: ip.'
command -v jq >/dev/null 2>&1 || fail 'required command not found: jq.'

if ! link_json=$(ip -d -j link show dev "$bridge_name"); then
    fail "could not read bridge state for ${bridge_name}; no changes were made."
fi

# Refuse to proceed unless ip returned exactly one well-formed Linux bridge.
if ! jq -e --arg name "$bridge_name" '
    type == "array" and length == 1 and
    (.[0] | type == "object" and
      .ifname == $name and
      .linkinfo.info_kind == "bridge" and
      (.linkinfo.info_data.ageing_time | type == "number" and floor == .) and
      (.flags | type == "array" and all(.[]; type == "string")))
' <<<"$link_json" >/dev/null; then
    fail "could not validate JSON bridge state for ${bridge_name}; no changes were made."
fi

if jq -e --argjson desired_promiscuous "$promiscuous" '
    .[0].linkinfo.info_data.ageing_time == 0 and
    ((.[0].flags | contains(["PROMISC"])) == $desired_promiscuous)
' <<<"$link_json" >/dev/null; then
    printf '%s already has ageing_time=0 and promiscuous=%s; no changes needed.\n' \
        "$bridge_name" "$promiscuous"
    exit 0
fi

command -v ansible-playbook >/dev/null 2>&1 ||
    fail 'required command not found: ansible-playbook (bridge differs from the requested state).'

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
playbook="${script_dir}/ludus-configure-bridge.yaml"
[[ -f $playbook ]] || fail "playbook not found: ${playbook}"

become_args=()
if ((EUID != 0)); then
    become_args=(-K)
fi
extra_vars=$(printf '{"range_second_octet": %d, "ludus_configure_bridge_promiscuous": %s, "ludus_configure_bridge_ageing_time": 0}' \
    "$allocation" "$promiscuous")

exec "$(command -v ansible-playbook)" "${become_args[@]}" \
    -e "$extra_vars" "$playbook"
