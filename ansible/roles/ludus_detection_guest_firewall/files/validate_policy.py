#!/usr/bin/env python3
"""Validate the complete firewall contract before any durable mutation."""
import ipaddress
import json
import re
import sys


def fail(message):
    raise ValueError(message)


def cidrs(values, name):
    if not isinstance(values, list) or not values:
        fail(f"{name} must be a nonempty list")
    for value in values:
        if not isinstance(value, str):
            fail(f"{name} elements must be strings")
        if ipaddress.ip_network(value, strict=False).version != 4:
            fail(f"{name} supports IPv4 CIDRs only")


def rules(value, name):
    if not isinstance(value, list) or not value:
        fail(f"{name} must be a nonempty list")
    for rule in value:
        if not isinstance(rule, dict) or set(rule) != {"sources", "ports"}:
            fail(f"{name} rules require only sources and ports")
        cidrs(rule["sources"], f"{name}.sources")
        if not isinstance(rule["ports"], list) or not rule["ports"]:
            fail(f"{name}.ports must be a nonempty list")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in rule["ports"]):
            fail(f"{name}.ports must be integers in 1..65535")
        if len(rule["ports"]) != len(set(rule["ports"])):
            fail(f"{name}.ports must not contain duplicates")


def main():
    data = json.loads(sys.argv[1])
    if data["profile"] not in {"gitlab", "runner", "malcolm", "splunk", "workload"}:
        fail("unknown profile")
    if ipaddress.ip_address(data["lab_ip"]).version != 4:
        fail("lab_ip must be IPv4")
    cidrs(data["management_cidrs"], "management_cidrs")
    cidrs(data["vpn_cidrs"], "vpn_cidrs")
    if not isinstance(data["docker_bridges"], list) or not data["docker_bridges"]:
        fail("docker_bridges must be a nonempty list")
    if any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", item)
           for item in data["docker_bridges"]):
        fail("docker bridge names must be valid interface names")
    rules(data["allowed"], "allowed")
    rules(data["expected"], "expected")
    if data["allowed"] != data["expected"]:
        fail("allowed rules must exactly equal independently assembled expected policy")
    service_ports = data["service_ports"]
    if (not isinstance(service_ports, list) or not service_ports or
            any(type(port) is not int or not 1 <= port <= 65535 for port in service_ports)):
        fail("verified service ports must be integers in 1..65535")
    if len(service_ports) != len(set(service_ports)):
        fail("verified service ports must not contain duplicates")
    if any(port not in service_ports for rule in data["allowed"] for port in rule["ports"]):
        fail("allowed port is not a verified service port")
    management = data["management_cidrs"]
    vpn = data["vpn_cidrs"]
    for rule in data["allowed"]:
        if rule["sources"] == management and rule["ports"] != [22]:
            fail("management sources may authorize only SSH")
    vpn_ports = {"gitlab": [80], "runner": [], "splunk": [8000, 8089], "workload": []}
    if data["profile"] == "malcolm":
        vpn_ports["malcolm"] = [port for port in service_ports if port != 22]
        expected_sources = {tuple(management), tuple(vpn)}
        if any(tuple(rule["sources"]) not in expected_sources for rule in data["allowed"]):
            fail("Malcolm accepts only management and VPN sources")
    for rule in data["allowed"]:
        if rule["sources"] == vpn and rule["ports"] != vpn_ports[data["profile"]]:
            fail("VPN ports do not match the profile policy")
    matching_management = [rule for rule in data["allowed"] if rule["sources"] == management]
    if matching_management != [{"sources": management, "ports": [22]}]:
        fail("profile policy requires exactly one management SSH rule")
    matching_vpn = [rule for rule in data["allowed"] if rule["sources"] == vpn]
    expected_vpn = ([{"sources": vpn, "ports": vpn_ports[data["profile"]]}]
                    if vpn_ports[data["profile"]] else [])
    if matching_vpn != expected_vpn:
        fail("profile policy VPN rule does not match expected ports")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"invalid firewall policy: {error}", file=sys.stderr)
        raise SystemExit(2)
