from pathlib import Path
import subprocess

import pytest

from support import run_production_include


ROLE = Path(__file__).resolve().parents[1]


def _fake_nft(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir(parents=True)
    nft = fake / "nft"
    nft.write_text(f"#!/bin/sh\necho invoked >> {tmp_path / 'nft-calls'}\nexit 0\n")
    nft.chmod(0o755)
    return fake


def _policy_vars(profile, rules, service_ports):
    return {
        "detection_firewall_profile": profile,
        "detection_firewall_allowed_tcp": rules,
        "detection_firewall_expected_tcp": rules,
        "detection_firewall_verified_service_ports": service_ports,
    }


def test_role_replaces_only_its_named_table(tmp_path):
    destination = tmp_path / "rules.nft"
    result = run_production_include(
        "ludus_detection_guest_firewall", "configure",
        {
            **_policy_vars("workload", [{"sources": ["10.0.0.0/24"], "ports": [22]}], [22]),
            "detection_firewall_lab_ip": "10.10.10.15",
            "detection_firewall_management_cidrs": ["10.0.0.0/24"],
            "detection_firewall_vpn_cidrs": ["10.1.0.0/24"],
            "detection_firewall_docker_bridges": ["docker0"],
            "detection_firewall_rules_path": str(destination),
            "detection_firewall_apply": False,
        }, _fake_nft(tmp_path),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    rules = destination.read_text()
    assert "table inet ludus_detection" in rules
    assert "flush ruleset" not in rules
    assert "table ip nat" not in rules
    assert not (tmp_path / "nft-calls").exists()
    assert (ROLE / "templates/ludus-detection-firewall.service.j2").is_file()


def test_malcolm_profile_allows_only_management_vpn_and_verified_ui_ports(tmp_path):
    destination = tmp_path / "rules.nft"
    result = run_production_include(
        "ludus_detection_guest_firewall", "configure",
        {
            **_policy_vars("malcolm", [
                {"sources": ["192.0.2.0/24"], "ports": [22]},
                {"sources": ["198.51.100.0/24"], "ports": [443, 8443]},
            ], [22, 443, 8443]),
            "detection_firewall_lab_ip": "10.10.10.13",
            "detection_firewall_management_cidrs": ["192.0.2.0/24"],
            "detection_firewall_vpn_cidrs": ["198.51.100.0/24"],
            "detection_firewall_docker_bridges": ["docker0"],
            "detection_firewall_rules_path": str(destination),
            "detection_firewall_apply": False,
        }, _fake_nft(tmp_path),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    rules = destination.read_text()
    assert "192.0.2.0/24" in rules and "198.51.100.0/24" in rules
    assert "22" in rules and "443" in rules and "8443" in rules
    assert "0.0.0.0/0" not in rules


def test_firewall_rejects_untyped_or_unverified_policy_before_mutation(tmp_path):
    cases = [
        [{"sources": ["999.1.1.1/33"], "ports": [22]}],
        [{"sources": ["10.0.0.0/24"], "ports": [0]}],
        [{"sources": "10.0.0.0/24", "ports": [22]}],
        [{"sources": ["10.0.0.0/24"], "ports": [23]}],
    ]
    for index, rules in enumerate(cases):
        destination = tmp_path / f"bad-{index}.nft"
        result = run_production_include(
            "ludus_detection_guest_firewall", "configure",
            {
                **_policy_vars("workload", rules, [22]),
                "detection_firewall_lab_ip": "10.10.10.15",
                "detection_firewall_management_cidrs": ["10.0.0.0/24"],
                "detection_firewall_vpn_cidrs": ["10.1.0.0/24"],
                "detection_firewall_docker_bridges": ["docker0"],
                "detection_firewall_rules_path": str(destination),
                "detection_firewall_apply": False,
            }, _fake_nft(tmp_path / str(index)),
        )
        assert result.returncode != 0
        assert not destination.exists()

    unauthorized = [{"sources": ["203.0.113.0/24"], "ports": [443]}]
    result = run_production_include(
        "ludus_detection_guest_firewall", "configure",
        {
            **_policy_vars("malcolm", unauthorized, [22, 443]),
            "detection_firewall_lab_ip": "10.10.10.13",
            "detection_firewall_management_cidrs": ["192.0.2.0/24"],
            "detection_firewall_vpn_cidrs": ["198.51.100.0/24"],
            "detection_firewall_docker_bridges": ["docker0"],
            "detection_firewall_rules_path": str(tmp_path / "malcolm-bad.nft"),
            "detection_firewall_apply": False,
        }, _fake_nft(tmp_path / "malcolm"),
    )
    assert result.returncode != 0


def _run_user_network_namespace(script, *arguments):
    return subprocess.run(
        ["unshare", "-Urn", "sh", "-s", "--", *map(str, arguments)],
        input=script,
        text=True,
        capture_output=True,
    )


def test_docker_dnat_bypass_is_dropped(tmp_path):
    rules_path = tmp_path / "rules.nft"
    render = run_production_include(
        "ludus_detection_guest_firewall", "configure",
        {
            **_policy_vars("gitlab", [
                {"sources": ["10.30.1.0/24"], "ports": [22]},
                {"sources": ["10.30.1.2/32"], "ports": [80]},
            ], [22, 80]),
            "detection_firewall_lab_ip": "192.0.2.10",
            "detection_firewall_management_cidrs": ["10.30.1.0/24"],
            "detection_firewall_vpn_cidrs": ["10.30.1.2/32"],
            "detection_firewall_docker_bridges": ["docker0"],
            "detection_firewall_rules_path": str(rules_path),
            "detection_firewall_apply": False,
        }, _fake_nft(tmp_path),
    )
    assert render.returncode == 0, render.stdout + render.stderr

    probe = _run_user_network_namespace("""
set -eu
command -v nft >/dev/null
command -v ip >/dev/null
command -v nsenter >/dev/null
command -v socat >/dev/null
nft add table inet capability_probe
ip link add name probe0 type veth peer name probe1
ip link delete probe0
""")
    if probe.returncode:
        pytest.fail(
            "BLOCKED: disposable user/network namespace capability probe failed\n"
            f"stdout:\n{probe.stdout}\nstderr:\n{probe.stderr}"
        )

    invalid_path = tmp_path / "invalid.nft"
    invalid_path.write_text("this is not nft syntax\n")
    helper = ROLE / "files/apply-owned-table.sh"
    exercise = _run_user_network_namespace("""
set -eu
rules=$1
helper=$2
invalid=$3
work=$4
keepers=""
workers=""
cleanup() {
  [ -z "$workers" ] || kill $workers 2>/dev/null || true
  [ -z "$keepers" ] || kill $keepers 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

unshare -n sleep 60 & allowed=$!; keepers="$keepers $allowed"
unshare -n sleep 60 & public=$!; keepers="$keepers $public"
unshare -n sleep 60 & container=$!; keepers="$keepers $container"

ip link add name allow_r type veth peer name allow_c
ip link add name public_r type veth peer name public_c
ip link add name docker0 type veth peer name docker_c
ip link set allow_c netns "$allowed"
ip link set public_c netns "$public"
ip link set docker_c netns "$container"

ip addr add 10.30.1.1/24 dev allow_r
ip addr add 10.30.2.1/24 dev public_r
ip addr add 10.30.3.1/24 dev docker0
ip addr add 192.0.2.10/32 dev lo
ip addr add 192.0.2.11/32 dev lo
ip link set lo up
ip link set allow_r up
ip link set public_r up
ip link set docker0 up

nsenter -t "$allowed" -n ip link set lo up
nsenter -t "$allowed" -n ip addr add 10.30.1.2/24 dev allow_c
nsenter -t "$allowed" -n ip link set allow_c up
nsenter -t "$allowed" -n ip route add default via 10.30.1.1
nsenter -t "$public" -n ip link set lo up
nsenter -t "$public" -n ip addr add 10.30.2.2/24 dev public_c
nsenter -t "$public" -n ip link set public_c up
nsenter -t "$public" -n ip route add default via 10.30.2.1
nsenter -t "$container" -n ip link set lo up
nsenter -t "$container" -n ip addr add 10.30.3.2/24 dev docker_c
nsenter -t "$container" -n ip link set docker_c up
nsenter -t "$container" -n ip route add default via 10.30.3.1
sysctl -q -w net.ipv4.ip_forward=1

nft -f - <<'EOF'
table inet non_owned_sentinel {
  chain marker {
  }
}
table ip docker {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    ip daddr { 192.0.2.10, 192.0.2.11 } tcp dport 80 dnat to 10.30.3.2:8080
    ip daddr 192.0.2.10 tcp dport 82 dnat to 10.30.3.2:8080
  }
}
EOF
nft list table inet non_owned_sentinel > "$work/sentinel.before"
nft list table ip docker > "$work/docker.before"

sh "$helper" "$rules"
nft list table inet ludus_detection > "$work/owned.before"
if sh "$helper" "$invalid" >/dev/null 2>&1; then
  echo "invalid owned-table candidate unexpectedly succeeded" >&2
  exit 31
fi
nft list table inet ludus_detection > "$work/owned.after-invalid"
cmp "$work/owned.before" "$work/owned.after-invalid"
sh "$helper" "$rules"
nft list table inet non_owned_sentinel > "$work/sentinel.after-reapply"
nft list table ip docker > "$work/docker.after-reapply"
cmp "$work/sentinel.before" "$work/sentinel.after-reapply"
cmp "$work/docker.before" "$work/docker.after-reapply"

nsenter -t "$container" -n socat TCP-LISTEN:8080,reuseaddr,fork EXEC:/bin/cat &
workers="$workers $!"
socat TCP-LISTEN:22,bind=192.0.2.10,reuseaddr,fork EXEC:/bin/cat &
workers="$workers $!"
sleep 0.2
allowed_reply=$(printf allowed | timeout 5 nsenter -t "$allowed" -n socat -T 2 - TCP:192.0.2.10:80)
[ "$allowed_reply" = allowed ]
input_reply=$(printf input | timeout 5 nsenter -t "$allowed" -n socat -T 2 - TCP:192.0.2.10:22)
[ "$input_reply" = input ]
if printf public | timeout 5 nsenter -t "$public" -n socat -T 1 - TCP:192.0.2.10:80 >/dev/null 2>&1; then
  echo "unlisted source reached DNAT service" >&2
  exit 32
fi
if printf wrong-port | timeout 5 nsenter -t "$allowed" -n socat -T 1 - TCP:192.0.2.10:82 >/dev/null 2>&1; then
  echo "unverified original destination port reached DNAT service" >&2
  exit 33
fi
if printf wrong-address | timeout 5 nsenter -t "$allowed" -n socat -T 1 - TCP:192.0.2.11:80 >/dev/null 2>&1; then
  echo "unverified original destination address reached DNAT service" >&2
  exit 35
fi
if printf public-input | timeout 5 nsenter -t "$public" -n socat -T 1 - TCP:192.0.2.10:22 >/dev/null 2>&1; then
  echo "unlisted source reached host input service" >&2
  exit 34
fi

nsenter -t "$allowed" -n socat TCP-LISTEN:19090,reuseaddr,fork EXEC:/bin/cat &
workers="$workers $!"
sleep 0.2
outbound_reply=$(printf outbound | timeout 5 nsenter -t "$container" -n socat -T 2 - TCP:10.30.1.2:19090)
[ "$outbound_reply" = outbound ]

nft list table inet non_owned_sentinel > "$work/sentinel.after-traffic"
nft list table ip docker > "$work/docker.after-traffic"
cmp "$work/sentinel.before" "$work/sentinel.after-traffic"
cmp "$work/docker.before" "$work/docker.after-traffic"
""", rules_path, helper, invalid_path, tmp_path)
    assert exercise.returncode == 0, exercise.stdout + exercise.stderr


def test_production_apply_include_invokes_configured_helper(tmp_path):
    calls = tmp_path / "calls"
    helper = tmp_path / "apply"
    helper.write_text(f'#!/bin/sh\n[ -f "$1" ] || exit 8\necho "$1" >> {calls}\n')
    helper.chmod(0o755)
    rules = tmp_path / "rules.nft"
    rules.write_text("synthetic fixture")
    result = run_production_include(
        "ludus_detection_guest_firewall", "apply",
        {
            "detection_firewall_apply": True,
            "detection_firewall_apply_helper_path": str(helper),
            "detection_firewall_rules_path": str(rules),
        }, tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text().splitlines() == [str(rules)]
    unit = (ROLE / "templates/ludus-detection-firewall.service.j2").read_text()
    assert "detection_firewall_apply_helper_path" in unit
