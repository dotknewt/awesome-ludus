#!/usr/bin/env python3
"""Render a save-ready range file or refuse an ineligible deployment payload."""

from __future__ import annotations

import argparse
import copy
import ipaddress
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent
PROFILES = ("gitlab", "runner", "malcolm", "splunk", "workload")
COMMON_PACKAGES = [
    "acl", "auditd", "ca-certificates", "curl", "gnupg", "logrotate",
    "python3", "rsyslog",
]
EXPECTED_RESOURCES = {
    "gitlab": (8, 4, 10, 11),
    "runner": (8, 4, 10, 12),
    "malcolm": (64, 8, 10, 13),
    "splunk": (12, 4, 10, 14),
    "workload": (16, 6, 10, 15),
}
EXPECTED_ROLES = {
    "gitlab": [
        "ludus_detection_gitlab",
        {"name": "ludus_detection_forwarder_pipeline", "depends_on": [
            {"vm_name": "{{ range_id }}-splunk", "role": "ludus_detection_splunk"}
        ]},
    ],
    "runner": [
        {"name": "ludus_detection_runner", "depends_on": [
            {"vm_name": "{{ range_id }}-gitlab", "role": "ludus_detection_gitlab"}
        ]},
        {"name": "ludus_detection_forwarder_pipeline", "depends_on": [
            {"vm_name": "{{ range_id }}-splunk", "role": "ludus_detection_splunk"}
        ]},
    ],
    "malcolm": ["ludus_install_malcolm"],
    "splunk": ["ludus_detection_splunk"],
    "workload": [
        {"name": "ludus_detection_workload", "depends_on": [
            {"vm_name": "{{ range_id }}-splunk", "role": "ludus_detection_splunk"}
        ]},
        {"name": "ludus_detection_forwarder_pipeline", "depends_on": [
            {"vm_name": "{{ range_id }}-splunk", "role": "ludus_detection_splunk"}
        ]},
    ],
}
REQUIRED_PRODUCT_SECTIONS = {
    "apt": {"gitlab", "runner", "docker", "containerd", "docker_plugins"},
    "downloads": {"splunk", "forwarder", "laurel", "minikube", "kubectl", "helm", "otel_host"},
    "artifact_layouts": {"minikube", "kubectl", "helm", "otel_host"},
    "git": {"malcolm"},
    "charts": {"otel"},
    "capabilities": {
        "splunk", "runner_api", "gitlab_readiness_contract", "runner_jobs_contract",
        "forwarder_bootstrap_contract", "otel",
    },
}
REQUIRED_COLLECTIONS = [
    {"name": "ansible.posix", "version": "2.2.2"},
    {"name": "community.crypto", "version": "3.5.0"},
]
REQUIRED_TARGET_ROLES = {
    "ludus_detection_forwarder", "ludus_detection_forwarder_pipeline",
    "ludus_detection_gitlab",
    "ludus_detection_linux_logging", "ludus_detection_runner",
    "ludus_detection_splunk", "ludus_detection_workload",
    "ludus_install_malcolm", "ludus_install_docker", "ludus_install_minikube",
}
MANDATORY_STATIC_PRODUCT_GATES = {
    "apt.gitlab", "apt.runner", "apt.docker", "apt.containerd", "apt.docker_plugins",
    "downloads.splunk", "downloads.forwarder", "downloads.laurel", "downloads.minikube",
    "downloads.kubectl", "downloads.helm", "downloads.otel_host",
    "artifact_layouts.minikube", "artifact_layouts.kubectl", "artifact_layouts.helm", "artifact_layouts.otel_host",
    "git.malcolm", "charts.otel", "capabilities.splunk", "capabilities.runner_api",
    "capabilities.gitlab_readiness_contract", "capabilities.runner_jobs_contract",
    "capabilities.forwarder_bootstrap_contract", "capabilities.otel",
}
PROVISIONING_TIME_CHECKS = [
    "existing_debian_account_and_home",
    "guest_capture_interface_discovery_and_validation",
    "selected_product_installation_and_bootstrap",
    "native_producer_and_service_readiness",
]
POST_PROVISIONING_ACCEPTANCE_CHECKS = [
    "gitlab_external_readiness",
    "runner_registered_paused_and_zero_jobs",
    "splunk_hec_search_and_authentication",
    "telemetry_delivery_and_packet_visibility",
    "credential_cleanup_and_final_service_state",
]


class Refusal(ValueError):
    """An incomplete or unsafe materialization request."""


class PublicationUncertain(OSError):
    """The output was linked, but its directory entry may not be durable."""


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Refusal(f"{path} must be a mapping")
    return value


def _string(value: Any, path: str, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise Refusal(f"{path} must be a nonempty string")
    return value


def _static_gate(gate: Any, path: str) -> tuple[Any, dict[str, Any]]:
    item = _mapping(gate, path)
    if set(item) != {"status", "source", "observed", "limitation", "stops"}:
        raise Refusal(f"{path} must be an exact static gate")
    if item["status"] != "VERIFIED" or item["observed"] is None:
        raise Refusal(f"{path} must contain statically VERIFIED facts")
    source = _mapping(item["source"], f"{path}.source")
    if set(source) != {"url", "observed_at"} or not str(source["url"]).startswith("https://"):
        raise Refusal(f"{path}.source must contain HTTPS provenance")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(source["observed_at"])):
        raise Refusal(f"{path}.source.observed_at must be RFC3339 UTC")
    _string(item["limitation"], f"{path}.limitation")
    return item["observed"], item


def _exact_package_version(value: Any, path: str) -> str:
    version = _string(value, path)
    if any(token in version for token in ("*", ">", "<", "^", "~=")):
        raise Refusal(f"{path} must be an exact package pin")
    return version


def _exact_keys(value: Any, keys: set[str], path: str) -> dict[str, Any]:
    item = _mapping(value, path)
    if set(item) != keys:
        raise Refusal(f"{path} has an invalid shape")
    return item


def _https(value: Any, path: str) -> str:
    text = _string(value, path)
    if not re.fullmatch(r"https://[^\s]+", text):
        raise Refusal(f"{path} must be HTTPS")
    return text


def _nonnegative_int(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise Refusal(f"{path} must be a nonnegative integer")
    return value


def _strings(value: Any, path: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise Refusal(f"{path} must be {'a nonempty ' if nonempty else 'a '}list of strings")
    for index, item in enumerate(value):
        _string(item, f"{path}[{index}]")
    return value


def _artifact(observed: Any, path: str, allow_build: bool = True) -> dict[str, Any]:
    item = _mapping(observed, path)
    expected = {"version", "build", "url", "sha256", "download_auth_required"}
    if set(item) != expected:
        raise Refusal(f"{path} has an invalid artifact shape")
    _string(item["version"], f"{path}.version")
    if not allow_build and item["build"] is not None:
        raise Refusal(f"{path}.build must be null")
    if item["build"] is not None:
        _string(item["build"], f"{path}.build")
    if not re.fullmatch(r"https://[^\s]+", str(item["url"])):
        raise Refusal(f"{path}.url must be HTTPS")
    if not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
        raise Refusal(f"{path}.sha256 must be SHA-256")
    if item["download_auth_required"] is not False:
        raise Refusal(f"{path}.download_auth_required must be false")
    return copy.deepcopy(item)


def _product_projection(products: Any, requirements: Any) -> dict[str, dict[str, Any]]:
    root = _mapping(products, "product-pins")
    if set(root) != {"schema_version", "observed_at", "status", *REQUIRED_PRODUCT_SECTIONS, "collections"}:
        raise Refusal("product-pins has missing or unexpected top-level sections")
    if root["schema_version"] != 1 or root["status"] != "STATIC_FACTS_RESOLVED_RUNTIME_AND_TARGET_GATES_BLOCKED":
        raise Refusal("product-pins must preserve its static/runtime boundary")
    for section, expected_names in REQUIRED_PRODUCT_SECTIONS.items():
        actual = _mapping(root[section], f"product-pins.{section}")
        if set(actual) != expected_names:
            raise Refusal(f"product-pins.{section} must contain exactly {sorted(expected_names)}")

    apt: dict[str, Any] = {}
    expected_packages = {
        "gitlab": {"gitlab-ce"},
        "runner": {"gitlab-runner"},
        "docker": {"docker-ce", "docker-ce-cli"},
        "containerd": {"containerd.io"},
        "docker_plugins": {"docker-buildx-plugin", "docker-compose-plugin"},
    }
    for name in sorted(REQUIRED_PRODUCT_SECTIONS["apt"]):
        observed, _ = _static_gate(root["apt"][name], f"product-pins.apt.{name}")
        item = _mapping(observed, f"product-pins.apt.{name}.observed")
        if set(item) != {"repository_url", "signing_key_url", "signing_key_fingerprint", "packages"}:
            raise Refusal(f"product-pins.apt.{name}.observed has an invalid shape")
        if not item["packages"]:
            raise Refusal(f"product-pins.apt.{name}.packages must not be empty")
        _https(item["repository_url"], f"product-pins.apt.{name}.repository_url")
        _https(item["signing_key_url"], f"product-pins.apt.{name}.signing_key_url")
        if not re.fullmatch(r"[0-9A-F]{40}", str(item["signing_key_fingerprint"])):
            raise Refusal(f"product-pins.apt.{name}.signing_key_fingerprint must be a full fingerprint")
        for package in item["packages"]:
            pin = _mapping(package, f"product-pins.apt.{name}.package")
            if set(pin) != {"name", "version"}:
                raise Refusal(f"product-pins.apt.{name} package pin has an invalid shape")
            _string(pin["name"], f"product-pins.apt.{name}.package.name")
            _exact_package_version(pin["version"], f"product-pins.apt.{name}.{pin['name']}.version")
        if {pin["name"] for pin in item["packages"]} != expected_packages[name]:
            raise Refusal(f"product-pins.apt.{name}.packages is incomplete or unexpected")
        apt[name] = copy.deepcopy(item)
    docker_repository = apt["docker"]["repository_url"]
    docker_key = (apt["docker"]["signing_key_url"], apt["docker"]["signing_key_fingerprint"])
    for name in ("containerd", "docker_plugins"):
        if apt[name]["repository_url"] != docker_repository or (
            apt[name]["signing_key_url"], apt[name]["signing_key_fingerprint"]
        ) != docker_key:
            raise Refusal(f"product-pins.apt.{name} must use the Docker repository and signing key")

    downloads: dict[str, Any] = {}
    for name in sorted(REQUIRED_PRODUCT_SECTIONS["downloads"]):
        observed, _ = _static_gate(root["downloads"][name], f"product-pins.downloads.{name}")
        downloads[name] = _artifact(observed, f"product-pins.downloads.{name}.observed")
        if (name in {"splunk", "forwarder"}) != (downloads[name]["build"] is not None):
            raise Refusal(f"product-pins.downloads.{name}.build has the wrong selected-artifact shape")

    layouts: dict[str, Any] = {}
    for name in sorted(REQUIRED_PRODUCT_SECTIONS["artifact_layouts"]):
        observed, gate = _static_gate(root["artifact_layouts"][name], f"product-pins.artifact_layouts.{name}")
        layout = _mapping(observed, f"product-pins.artifact_layouts.{name}.observed")
        if set(layout) != {"artifact_sha256", "format", "member"} or layout["artifact_sha256"] != downloads[name]["sha256"]:
            raise Refusal(f"product-pins.artifact_layouts.{name} is not digest-bound to its artifact")
        expected_layout = {
            "minikube": ("raw", None),
            "kubectl": ("raw", None),
            "helm": ("tar.gz", "linux-amd64/helm"),
            "otel_host": ("tar.gz", "otelcol-contrib"),
        }[name]
        if (layout["format"], layout["member"]) != expected_layout:
            raise Refusal(f"product-pins.artifact_layouts.{name} has an unsupported archive layout")
        layouts[name] = copy.deepcopy(gate)

    capabilities: dict[str, Any] = {}
    capability_gates: dict[str, Any] = {}
    for name in sorted(REQUIRED_PRODUCT_SECTIONS["capabilities"]):
        observed, gate = _static_gate(root["capabilities"][name], f"product-pins.capabilities.{name}")
        capabilities[name] = copy.deepcopy(observed)
        capability_gates[name] = copy.deepcopy(gate)
    runner = _mapping(capabilities["runner_api"], "runner_api")
    _exact_keys(runner, {"bootstrap_auth", "manager"}, "runner_api")
    bootstrap = _exact_keys(
        runner["bootstrap_auth"],
        {"credential_type", "scopes", "expiration_days", "creation_argv", "protected_path", "mode", "revoke_endpoint", "revoke_method"},
        "runner_api.bootstrap_auth",
    )
    if runner["bootstrap_auth"]["scopes"] != ["create_runner", "manage_runner", "read_api"]:
        raise Refusal("runner PAT scopes must be create_runner, manage_runner, read_api")
    if bootstrap["credential_type"] != "personal_access_token" or bootstrap["expiration_days"] != 1 or bootstrap["mode"] != "0600":
        raise Refusal("runner bootstrap credential contract is invalid")
    _strings(bootstrap["creation_argv"], "runner_api.bootstrap_auth.creation_argv", nonempty=True)
    for field in ("credential_type", "protected_path", "mode", "revoke_endpoint", "revoke_method"):
        _string(bootstrap[field], f"runner_api.bootstrap_auth.{field}")
    manager = _exact_keys(
        runner["manager"],
        {"runner_type", "create_scope", "manage_scope", "read_scope", "create_endpoint", "create_method", "lookup_endpoint", "lookup_method", "detail_endpoint", "detail_method", "update_endpoint", "update_method", "request_fields", "response_token_field", "local_verify_command", "pause_at_create"},
        "runner_api.manager",
    )
    if [manager["create_scope"], manager["manage_scope"], manager["read_scope"]] != bootstrap["scopes"] or manager["pause_at_create"] is not True:
        raise Refusal("runner manager contract is not bound to its bootstrap scopes and paused state")
    for field in (
        "runner_type", "create_scope", "manage_scope", "read_scope",
        "create_endpoint", "create_method", "lookup_endpoint", "lookup_method",
        "detail_endpoint", "detail_method", "update_endpoint", "update_method",
        "response_token_field",
    ):
        _string(manager[field], f"runner_api.manager.{field}")
    _strings(manager["request_fields"], "runner_api.manager.request_fields", nonempty=True)
    _strings(manager["local_verify_command"], "runner_api.manager.local_verify_command", nonempty=True)
    readiness = _mapping(capabilities["gitlab_readiness_contract"], "gitlab_readiness_contract")
    if readiness != {
        "transport_base_url": "http://localhost", "endpoint": "/-/readiness", "method": "GET",
        "success_statuses": [200], "attempts": 60, "delay_seconds": 5,
    }:
        raise Refusal("GitLab readiness must use the selected-version loopback contract")
    splunk = _exact_keys(
        capabilities["splunk"],
        {"initial_mode", "trial_days_user_confirmed", "terms_confirmation", "expiry_behavior", "hec", "search_api", "auth_behavior"},
        "splunk",
    )
    if splunk["initial_mode"] != "ENTERPRISE_60_DAY_TRIAL" or splunk["trial_days_user_confirmed"] != 60:
        raise Refusal("Splunk selected license contract is invalid")
    if splunk["hec"] is not True or splunk["search_api"] is not True:
        raise Refusal("Splunk required HEC and search capabilities must be supported")
    for field in ("terms_confirmation", "expiry_behavior", "auth_behavior"):
        _string(splunk[field], f"splunk.{field}")
    forwarder = _mapping(capabilities["forwarder_bootstrap_contract"], "forwarder_bootstrap_contract")
    _exact_keys(forwarder, {"version", "build", "seed", "first_start", "boot_start", "unit"}, "forwarder_bootstrap")
    if (forwarder.get("version"), forwarder.get("build")) != (
        downloads["forwarder"]["version"], downloads["forwarder"]["build"]
    ):
        raise Refusal("forwarder bootstrap facts are not version/build-bound")
    seed = _exact_keys(
        forwarder["seed"],
        {"path", "section", "username_key", "username", "password_key", "mode", "owner", "group"},
        "forwarder_bootstrap.seed",
    )
    if seed["mode"] != "0600" or seed["owner"] != "splunkfwd" or seed["group"] != "splunkfwd":
        raise Refusal("forwarder seed ownership/mode contract is invalid")
    for field, value in seed.items():
        _string(value, f"forwarder_bootstrap.seed.{field}")
    for field, expected_identity in (("first_start", "splunkfwd"), ("boot_start", "root")):
        action = _exact_keys(forwarder[field], {"identity", "argv"}, f"forwarder_bootstrap.{field}")
        if action["identity"] != expected_identity:
            raise Refusal(f"forwarder_bootstrap.{field}.identity is invalid")
        _strings(action["argv"], f"forwarder_bootstrap.{field}.argv", nonempty=True)
    unit = _exact_keys(forwarder["unit"], {"path", "service_name", "effective_user"}, "forwarder_bootstrap.unit")
    if unit["service_name"] != "SplunkForwarder.service" or unit["effective_user"] != "splunkfwd":
        raise Refusal("forwarder systemd unit contract is invalid")
    for field, value in unit.items():
        _string(value, f"forwarder_bootstrap.unit.{field}")

    malcolm, _ = _static_gate(root["git"]["malcolm"], "product-pins.git.malcolm")
    chart, _ = _static_gate(root["charts"]["otel"], "product-pins.charts.otel")
    malcolm = _exact_keys(malcolm, {"repository", "tag", "commit"}, "product-pins.git.malcolm.observed")
    _https(malcolm["repository"], "product-pins.git.malcolm.repository")
    _string(malcolm["tag"], "product-pins.git.malcolm.tag")
    if not re.fullmatch(r"[0-9a-f]{40}", str(malcolm["commit"])):
        raise Refusal("product-pins.git.malcolm.commit must be a full commit hash")
    chart = _exact_keys(chart, {"repository", "chart", "version", "digest"}, "product-pins.charts.otel.observed")
    _https(chart["repository"], "product-pins.charts.otel.repository")
    _string(chart["chart"], "product-pins.charts.otel.chart")
    _exact_package_version(chart["version"], "product-pins.charts.otel.version")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(chart["digest"])):
        raise Refusal("product-pins.charts.otel.digest must be SHA-256")
    runner_jobs = _exact_keys(capabilities["runner_jobs_contract"], {"endpoint", "method"}, "runner_jobs_contract")
    if runner_jobs != {"endpoint": "/api/v4/runners/:id/jobs", "method": "GET"}:
        raise Refusal("runner jobs contract is invalid")
    otel = _exact_keys(
        capabilities["otel"],
        {"secret_file_provider", "audit_path", "node_log_inputs", "required_rbac"},
        "otel",
    )
    if otel["secret_file_provider"] is not True:
        raise Refusal("OTEL secret file provider must be supported")
    _string(otel["audit_path"], "otel.audit_path")
    _strings(otel["node_log_inputs"], "otel.node_log_inputs", nonempty=True)
    if otel["required_rbac"] != {
        "nodes": ["get", "list", "watch"], "pods": ["get", "list", "watch"]
    }:
        raise Refusal("OTEL required RBAC contract is incomplete")
    if root["collections"] != REQUIRED_COLLECTIONS:
        raise Refusal("product collection pins are incomplete or not exact")
    requirement_root = _mapping(requirements, "requirements")
    if set(requirement_root) != {"collections"} or requirement_root["collections"] != root["collections"]:
        raise Refusal("requirements.yml must equal the product collection projection")

    laurel = {key: value for key, value in downloads["laurel"].items() if key != "build"}
    runtime_artifacts = {
        key: {field: value for field, value in downloads[key].items() if field != "build"}
        for key in ("minikube", "kubectl", "helm")
    }
    projection = {profile: {"detection_laurel_artifact": copy.deepcopy(laurel)} for profile in ("gitlab", "runner", "splunk", "workload")}
    for profile in ("gitlab", "runner", "workload"):
        projection[profile].update({
            "detection_forwarder_artifact": copy.deepcopy(downloads["forwarder"]),
            "detection_forwarder_bootstrap_contract": copy.deepcopy(capability_gates["forwarder_bootstrap_contract"]),
        })
    projection["gitlab"].update({
        "detection_gitlab_packages": apt["gitlab"]["packages"],
        "detection_gitlab_repository_url": apt["gitlab"]["repository_url"],
        "detection_gitlab_signing_key_url": apt["gitlab"]["signing_key_url"],
        "detection_gitlab_signing_key_fingerprint": apt["gitlab"]["signing_key_fingerprint"],
        "detection_runner_api_contract": capabilities["runner_api"],
        "detection_gitlab_readiness_contract": readiness,
    })
    projection["runner"].update({
        "detection_runner_packages": apt["runner"]["packages"],
        "detection_runner_repository_url": apt["runner"]["repository_url"],
        "detection_runner_signing_key_url": apt["runner"]["signing_key_url"],
        "detection_runner_signing_key_fingerprint": apt["runner"]["signing_key_fingerprint"],
        "detection_runner_api_contract": capabilities["runner_api"],
        "detection_gitlab_readiness_contract": readiness,
        "detection_runner_jobs_contract": capabilities["runner_jobs_contract"],
    })
    projection["malcolm"] = {
        "ludus_install_malcolm_version": malcolm["tag"],
        "ludus_install_malcolm_commit": malcolm["commit"],
    }
    projection["splunk"].update({
        "detection_splunk_artifact": downloads["splunk"],
        "detection_splunk_license": capabilities["splunk"],
        "detection_splunk_hec_supported": capabilities["splunk"]["hec"],
        "detection_splunk_search_api_supported": capabilities["splunk"]["search_api"],
    })
    docker_packages = [
        *apt["docker"]["packages"], *apt["containerd"]["packages"], *apt["docker_plugins"]["packages"]
    ]
    if len({pin["name"] for pin in docker_packages}) != len(docker_packages):
        raise Refusal("Docker package projection contains duplicate names")
    projection["workload"].update({
        "detection_docker_packages": docker_packages,
        "detection_docker_repository_url": apt["docker"]["repository_url"],
        "detection_docker_signing_key_url": apt["docker"]["signing_key_url"],
        "detection_docker_signing_key_fingerprint": apt["docker"]["signing_key_fingerprint"],
        **{f"detection_{name}_artifact": runtime_artifacts[name] for name in runtime_artifacts},
        "detection_otel_host_artifact": downloads["otel_host"],
        "detection_runtime_artifact_layouts": layouts,
        "detection_otel_chart": chart,
        "detection_otel_contract": capabilities["otel"],
    })
    return projection


def _validate_graph(draft: Any, projection: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    config = _mapping(draft, "range configuration")
    vms = config.get("ludus")
    if not isinstance(vms, list) or len(vms) != len(PROFILES):
        raise Refusal("draft must contain exactly five VMs")
    found: dict[str, dict[str, Any]] = {}
    for vm in vms:
        hostname = _string(_mapping(vm, "draft VM").get("hostname"), "draft VM hostname")
        profile = hostname.removeprefix("{{ range_id }}-")
        if profile not in PROFILES or profile in found or vm.get("vm_name") != hostname:
            raise Refusal("draft VM identities must be the exact unique five-profile graph")
        found[profile] = vm
    if tuple(found) != PROFILES:
        raise Refusal("draft VM order must be gitlab, runner, malcolm, splunk, workload")
    for profile, vm in found.items():
        ram, cpus, vlan, octet = EXPECTED_RESOURCES[profile]
        if (vm.get("ram_gb"), vm.get("cpus"), vm.get("vlan"), vm.get("ip_last_octet")) != (ram, cpus, vlan, octet):
            raise Refusal(f"draft {profile} resources differ from the approved graph")
        if vm.get("roles") != EXPECTED_ROLES[profile]:
            raise Refusal(f"draft {profile} role/dependency graph differs from the approved graph")
        if profile == "malcolm":
            if vm.get("linux") is not True:
                raise Refusal("draft malcolm linux contract must remain true")
        elif vm.get("linux") != {"packages": COMMON_PACKAGES}:
            raise Refusal(f"draft {profile} must include exact native logging prerequisites")
        role_vars = _mapping(vm.get("role_vars"), f"draft {profile}.role_vars")
        for key, expected in projection[profile].items():
            if role_vars.get(key) != expected:
                raise Refusal(f"draft {profile}.{key} diverges from product-pins projection")
    return copy.deepcopy(vms)


def _operator_gate(value: Any, path: str, mode: str) -> tuple[str, Any, list[str], bool]:
    gate = _mapping(value, path)
    expected = {"status", "source", "observed", "limitation", "required_for_deployment", "unresolved"}
    if set(gate) != expected or gate["status"] not in {"VERIFIED", "BLOCKED"}:
        raise Refusal(f"{path} must be an exact VERIFIED/BLOCKED target gate")
    source = _mapping(gate["source"], f"{path}.source")
    if set(source) != {"kind", "reference", "observed_at"} or source["kind"] not in {"USER_PROVIDED", "LUDUS_API_READ", "COMPOSITE"}:
        raise Refusal(f"{path}.source has an invalid provenance shape")
    _string(source["reference"], f"{path}.source.reference")
    if source["observed_at"] is not None and not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(source["observed_at"])
    ):
        raise Refusal(f"{path}.source.observed_at must be RFC3339 UTC or null")
    if not isinstance(gate["required_for_deployment"], bool) or not isinstance(gate["unresolved"], list):
        raise Refusal(f"{path} has invalid gate metadata")
    if gate["required_for_deployment"] is not True:
        raise Refusal(f"{path} must be required for deployment")
    _strings(gate["unresolved"], f"{path}.unresolved")
    if gate["status"] == "VERIFIED" and (gate["observed"] is None or gate["unresolved"]):
        raise Refusal(f"{path} cannot be VERIFIED with missing observations")
    timestamp_missing = gate["status"] == "VERIFIED" and source["observed_at"] is None
    if mode == "deployment" and timestamp_missing:
        raise Refusal(f"{path}.source.observed_at is required for deployment evidence")
    return gate["status"], gate["observed"], gate["unresolved"], timestamp_missing


def _validate_target(inputs: Any, mode: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], list[str]]:
    root = _mapping(inputs, "target-inputs")
    if set(root) != {"schema_version", "target_range", "templates", "capacity", "network", "provisioning_identity", "role_inventory"} or root["schema_version"] != 4:
        raise Refusal("target-inputs must match schema_version 4 exactly")
    outstanding: list[str] = []
    status, target_value, unresolved, timestamp_missing = _operator_gate(root["target_range"], "target_range", mode)
    target = _mapping(target_value, "target_range.observed")
    if target != {"name": "thrunt", "range_number": 3, "range_cidr": "10.3.0.0/16", "state": "NEVER_DEPLOYED", "vm_count": 0, "testing": False}:
        raise Refusal("target_range does not match the authorized thrunt range facts")
    if status != "VERIFIED":
        outstanding.append("target_range")
    if timestamp_missing:
        outstanding.append("target_range.source.observed_at")

    templates = _mapping(root["templates"], "templates")
    if set(templates) != set(PROFILES):
        raise Refusal("templates must contain exactly the five VM profiles")
    selected: dict[str, Any] = {}
    for profile in PROFILES:
        gate_status, value, missing, timestamp_missing = _operator_gate(templates[profile], f"templates.{profile}", mode)
        item = _mapping(value, f"templates.{profile}.observed")
        if set(item) != {"name", "os_type", "distribution", "major_version", "architecture", "built", "inherited_disk_gb"}:
            raise Refusal(f"templates.{profile}.observed has an invalid shape")
        if item["name"] != "debian-12-x64-server-template" or item["os_type"] != "linux" or item["distribution"] != "Debian" or item["major_version"] != 12 or item["built"] is not True:
            raise Refusal(f"templates.{profile} does not match the observed built Debian 12 Linux template")
        if item["architecture"] is not None and item["architecture"] not in {"x86_64", "amd64"}:
            raise Refusal(f"templates.{profile}.architecture is unsupported")
        if gate_status == "VERIFIED" and item["architecture"] not in {"x86_64", "amd64"}:
            raise Refusal(f"templates.{profile}.architecture is required for deployment")
        if item["inherited_disk_gb"] is not None:
            _nonnegative_int(item["inherited_disk_gb"], f"templates.{profile}.inherited_disk_gb")
        if gate_status == "VERIFIED" and not item["inherited_disk_gb"]:
            raise Refusal(f"templates.{profile}.inherited_disk_gb is required for initial provisioning")
        if gate_status != "VERIFIED":
            outstanding.append(f"templates.{profile}")
        if timestamp_missing:
            outstanding.append(f"templates.{profile}.source.observed_at")
        selected[profile] = item

    capacity_status, capacity_value, _, capacity_timestamp_missing = _operator_gate(root["capacity"], "capacity", mode)
    capacity = {} if capacity_value is None else _mapping(capacity_value, "capacity.observed")
    if capacity_value is not None:
        expected = {"total_ram_gb", "free_ram_gb", "reported_cpu_cores", "current_allocations", "storage_pools", "deployment_sufficient", "decision_basis"}
        if set(capacity) != expected:
            raise Refusal("capacity must record the exact host facts and reviewed sufficiency schema")
        if capacity["total_ram_gb"] != 128:
            raise Refusal("capacity.total_ram_gb must preserve the user-supplied 128 GB host total")
        if capacity["reported_cpu_cores"] != 16:
            raise Refusal("capacity.reported_cpu_cores must preserve the API-reported 16 cores")
        if capacity["free_ram_gb"] is not None:
            _nonnegative_int(capacity["free_ram_gb"], "capacity.free_ram_gb")
        if capacity["current_allocations"] is not None:
            allocations = _exact_keys(
                capacity["current_allocations"], {"ram_gb", "cpus", "storage_gb"},
                "capacity.current_allocations",
            )
            for field, value in allocations.items():
                _nonnegative_int(value, f"capacity.current_allocations.{field}")
        pools = capacity["storage_pools"]
        if not isinstance(pools, list) or not pools:
            raise Refusal("capacity.storage_pools must contain the observed storage pools")
        for index, pool_value in enumerate(pools):
            pool = _exact_keys(pool_value, {"name", "type", "size_gb", "used_gb", "free_gb"}, f"capacity.storage_pools[{index}]")
            _string(pool["name"], f"capacity.storage_pools[{index}].name")
            _string(pool["type"], f"capacity.storage_pools[{index}].type")
            for field in ("size_gb", "used_gb", "free_gb"):
                if isinstance(pool[field], bool) or not isinstance(pool[field], (int, float)) or pool[field] < 0:
                    raise Refusal(f"capacity.storage_pools[{index}].{field} must be nonnegative numeric data")
        _string(capacity["decision_basis"], "capacity.decision_basis")
        if capacity_status == "VERIFIED":
            if capacity["free_ram_gb"] is None or capacity["current_allocations"] is None:
                raise Refusal("capacity verified evidence requires free RAM and current allocations")
            if capacity["deployment_sufficient"] is not True:
                raise Refusal("capacity requires an explicit reviewed deployment-sufficient decision")
    if capacity_status != "VERIFIED" or not capacity.get("deployment_sufficient", False):
        outstanding.append("capacity")
    if capacity_timestamp_missing:
        outstanding.append("capacity.source.observed_at")

    network_status, network_value, _, network_timestamp_missing = _operator_gate(root["network"], "network", mode)
    network = {} if network_value is None else _mapping(network_value, "network.observed")
    if network_value is not None:
        expected = {"range_cidr", "lab_cidr", "host_bridge", "host_bridge_promiscuous_mode"}
        if set(network) != expected:
            raise Refusal("network.observed has an invalid shape")
        if network["range_cidr"] != target["range_cidr"]:
            raise Refusal("network range_cidr is not bound to target_range")
        if network["lab_cidr"] is not None:
            lab = ipaddress.ip_network(network["lab_cidr"], strict=True)
            if lab.version != 4 or not lab.subnet_of(ipaddress.ip_network(target["range_cidr"])):
                raise Refusal("network.lab_cidr must be an observed subnet of the target range")
            if lab != ipaddress.ip_network("10.3.10.0/24"):
                raise Refusal("network.lab_cidr must be the approved VLAN 10 subnet 10.3.10.0/24")
        if network["host_bridge"] != "vmbr3":
            raise Refusal("network.host_bridge must be vmbr3 for numeric range ID 3")
        if network["host_bridge_promiscuous_mode"] != "USER_MANAGED_NOT_A_PROVISIONING_GATE":
            raise Refusal("network host bridge promiscuous mode must remain an explicit user-managed non-blocker")
        if network_status == "VERIFIED":
            if network["lab_cidr"] is None:
                raise Refusal("network.lab_cidr is required in verified deployment evidence")
    if network_status != "VERIFIED":
        outstanding.append("network")
    if network_timestamp_missing:
        outstanding.append("network.source.observed_at")

    identity_status, identity_value, _, identity_timestamp_missing = _operator_gate(root["provisioning_identity"], "provisioning_identity", mode)
    identity = {} if identity_value is None else _mapping(identity_value, "provisioning_identity.observed")
    if identity_value is not None:
        if set(identity) != {"user", "home", "account_kind", "documented_default_login", "password_action", "create_user"} or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", str(identity["user"])):
            raise Refusal("provisioning_identity has an invalid user")
        home = str(identity["home"])
        path = PurePosixPath(home)
        if ".." in path.parts:
            raise Refusal("provisioning_identity.home must not contain parent traversal")
        if not path.is_absolute() or home != str(path) or home == "/":
            raise Refusal("provisioning_identity.home must be an observed normalized absolute path")
        if identity != {
            "user": "debian", "home": "/home/debian",
            "account_kind": "existing_template_login",
            "documented_default_login": "debian:debian",
            "password_action": "preserve_existing", "create_user": False,
        }:
            raise Refusal("provisioning_identity must preserve the documented existing debian login without password or user mutation")
    if identity_status != "VERIFIED":
        outstanding.append("provisioning_identity")
    if identity_timestamp_missing:
        outstanding.append("provisioning_identity.source.observed_at")

    role_policy = _exact_keys(
        root["role_inventory"],
        {"status", "source", "observed", "waiver", "limitation", "required_for_deployment", "unresolved"},
        "role_inventory",
    )
    if role_policy["status"] != "PRESENCE_OBSERVED_CONTENT_VERIFICATION_WAIVED":
        raise Refusal("role_inventory must record the explicit user content-verification waiver")
    source = _exact_keys(role_policy["source"], {"kind", "reference", "observed_at"}, "role_inventory.source")
    if source["kind"] != "COMPOSITE" or source["observed_at"] is not None:
        raise Refusal("role_inventory source must preserve untimestamped observed presence plus user waiver")
    _string(source["reference"], "role_inventory.source.reference")
    roles = _exact_keys(
        role_policy["observed"], {"present_roles", "collections", "content_verification"},
        "role_inventory.observed",
    )
    if not isinstance(roles["present_roles"], list) or len(roles["present_roles"]) != len(set(roles["present_roles"])) or not REQUIRED_TARGET_ROLES.issubset(set(roles["present_roles"])):
        raise Refusal("role_inventory.present_roles must contain the observed required role names")
    if not isinstance(roles["collections"], list) or not all(pin in roles["collections"] for pin in REQUIRED_COLLECTIONS):
        raise Refusal("role_inventory.collections is missing a required exact collection")
    if roles["content_verification"] != "USER_WAIVED_NOT_VERIFIED":
        raise Refusal("role_inventory must not claim verified role versions or contents")
    waiver = _exact_keys(role_policy["waiver"], {"decision", "recorded_on"}, "role_inventory.waiver")
    if waiver != {"decision": "USER_WAIVED_ROLE_VERSION_AND_CONTENT_COMPARISON", "recorded_on": "2026-10-19"}:
        raise Refusal("role_inventory waiver does not match the recorded user decision")
    _string(role_policy["limitation"], "role_inventory.limitation")
    if role_policy["required_for_deployment"] is not False or role_policy["unresolved"] != []:
        raise Refusal("role_inventory content verification waiver must be non-blocking")
    if mode == "deployment" and outstanding:
        raise Refusal(f"deployment target gates remain blocked: {sorted(set(outstanding))}")
    return target, selected, network, identity, sorted(set(outstanding))


def _lifecycle_blockers(verified_inputs: Any) -> list[str]:
    root = _mapping(verified_inputs, "verified-inputs")
    expected_root = {
        "schema_version", "verified_at", "user_supplied_candidates", "templates",
        "capacity", "network", "apt", "downloads", "artifact_layouts", "git",
        "charts", "capabilities", "test_tools", "lifecycle",
    }
    if set(root) != expected_root or root["schema_version"] != 2:
        raise Refusal("verified-inputs must match lifecycle schema_version 2 exactly")
    lifecycle = _exact_keys(
        root["lifecycle"],
        {"selected_product_contract", "provisioning_time", "post_provisioning"},
        "verified-inputs.lifecycle",
    )
    selected = _exact_keys(
        lifecycle["selected_product_contract"],
        {"status", "source", "gate_paths", "limitation", "required_for_initial_provisioning"},
        "verified-inputs.lifecycle.selected_product_contract",
    )
    if selected["status"] not in {"STATIC_APPROVED", "BLOCKED"}:
        raise Refusal("selected product contract status must be STATIC_APPROVED or BLOCKED")
    if selected["required_for_initial_provisioning"] is not True:
        raise Refusal("selected product contract must be required for initial provisioning")
    source = _exact_keys(
        selected["source"], {"kind", "reference", "observed_at"},
        "verified-inputs.lifecycle.selected_product_contract.source",
    )
    if source["kind"] != "LOCAL_REVIEWED_STATIC_EVIDENCE" or source["reference"] != "product-pin-provenance.md":
        raise Refusal("selected product contract must cite the reviewed static product evidence")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(source["observed_at"])):
        raise Refusal("selected product contract observed_at must be RFC3339 UTC")
    if selected["gate_paths"] != sorted(MANDATORY_STATIC_PRODUCT_GATES):
        raise Refusal("selected product contract gate_paths must exactly name the mandatory static product facts")
    _string(selected["limitation"], "verified-inputs.lifecycle.selected_product_contract.limitation")

    for phase, expected_checks in (
        ("provisioning_time", PROVISIONING_TIME_CHECKS),
        ("post_provisioning", POST_PROVISIONING_ACCEPTANCE_CHECKS),
    ):
        record = _exact_keys(
            lifecycle[phase],
            {"status", "required_for_initial_provisioning", "checks", "evidence", "limitation"},
            f"verified-inputs.lifecycle.{phase}",
        )
        if record["status"] != "PENDING" or record["evidence"] is not None:
            raise Refusal(f"verified-inputs.lifecycle.{phase} must remain PENDING without runtime evidence")
        if record["required_for_initial_provisioning"] is not False:
            raise Refusal(f"verified-inputs.lifecycle.{phase} must not block initial provisioning")
        if record["checks"] != expected_checks:
            raise Refusal(f"verified-inputs.lifecycle.{phase}.checks differs from the approved lifecycle")
        _string(record["limitation"], f"verified-inputs.lifecycle.{phase}.limitation")
    return [] if selected["status"] == "STATIC_APPROVED" else ["selected_product_contract"]


def _static_product_blockers(
    verified_inputs: Any,
    products: Any,
) -> list[str]:
    root = _mapping(verified_inputs, "verified-inputs")
    product_root = _mapping(products, "product-pins")
    blockers = _lifecycle_blockers(verified_inputs)
    for path in sorted(MANDATORY_STATIC_PRODUCT_GATES):
        value: Any = root
        for segment in path.split("."):
            value = _mapping(value, f"verified-inputs.{path}").get(segment)
        gate = _mapping(value, f"verified-inputs.{path}")
        if gate.get("status") != "VERIFIED" or gate.get("observed") is None:
            blockers.append(f"static_product.{path}")
            continue
        observed, _ = _static_gate(gate, f"verified-inputs.{path}")
        section, name = (path.split(".") + [None])[:2]
        selected = _mapping(product_root[section], f"product-pins.{section}")[name]["observed"]
        if observed != selected:
            raise Refusal(f"verified-inputs.{path}.observed does not equal product-pins selected evidence")
    return blockers


def _read_protected(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
            raise Refusal("protected inputs must be a caller-owned regular file with mode 0600")
        with os.fdopen(fd, encoding="utf-8") as stream:
            fd = -1
            data = yaml.safe_load(stream)
    finally:
        if fd >= 0:
            os.close(fd)
    root = _mapping(data, "protected-inputs")
    expected = {"schema_version", "splunk_admin_password", "malcolm_admin_username", "malcolm_admin_password", "hec_workload_state"}
    if set(root) != expected or root["schema_version"] != 2:
        raise Refusal("protected-inputs has an invalid shape")
    for key in ("splunk_admin_password", "malcolm_admin_password"):
        _string(root[key], f"protected-inputs.{key}")
    _string(root["malcolm_admin_username"], "protected-inputs.malcolm_admin_username")
    if root["hec_workload_state"] != "present":
        raise Refusal("protected-inputs.hec_workload_state must be present")
    return root


def _ip(network: dict[str, Any], octet: int) -> str | None:
    if not network.get("lab_cidr"):
        return None
    return str(ipaddress.ip_network(network["lab_cidr"]).network_address + octet)


def materialize(target_inputs: Any, products: Any, verified_inputs: Any, requirements: Any, draft: Any, mode: str, protected: dict[str, Any] | None = None) -> dict[str, Any]:
    if mode not in {"public-save", "private-save", "deployment"}:
        raise Refusal(f"unsupported materialization mode: {mode}")
    projection = _product_projection(products, requirements)
    vms = _validate_graph(draft, projection)
    target, templates, network, identity, target_blockers = _validate_target(target_inputs, mode)
    authoritative_blockers = _static_product_blockers(verified_inputs, products)
    if mode == "deployment" and authoritative_blockers:
        raise Refusal(f"authoritative deployment gates remain blocked: {authoritative_blockers}")
    if mode in {"private-save", "deployment"} and protected is None:
        raise Refusal(f"{mode} mode requires protected inputs")
    if mode == "public-save" and protected is not None:
        raise Refusal("public-save mode must retain application password placeholders")

    for vm in vms:
        profile = vm["hostname"].removeprefix("{{ range_id }}-")
        role_vars = vm["role_vars"]
        role_vars.update(copy.deepcopy(projection[profile]))
        vm["template"] = templates[profile]["name"]
        if profile == "malcolm":
            user = identity.get("user")
            home = identity.get("home")
            role_vars["ludus_install_malcolm_user"] = user
            role_vars["ludus_install_malcolm_install_dir"] = None if home is None else f"{home}/Malcolm"
            role_vars["ludus_install_malcolm_venv_dir"] = None if home is None else f"{home}/Malcolm/.venv"
            role_vars["ludus_install_malcolm_admin_username"] = "debian" if protected is None else protected["malcolm_admin_username"]
            role_vars["ludus_install_malcolm_admin_password"] = None if protected is None else protected["malcolm_admin_password"]
            role_vars["ludus_install_malcolm_capture_interface"] = ""
        elif profile == "splunk":
            role_vars["detection_splunk_bind_ip"] = _ip(network, vm["ip_last_octet"])
            role_vars["detection_splunk_admin_username"] = "debian"
            role_vars["detection_splunk_admin_password"] = None if protected is None else protected["splunk_admin_password"]
        elif profile == "workload":
            role_vars["detection_workload_user"] = identity.get("user")
            role_vars["detection_workload_home"] = identity.get("home")
            role_vars["detection_kubeconfig_path"] = None if not identity.get("home") else f"{identity['home']}/.kube/config"
            role_vars["detection_minikube_home"] = None if not identity.get("home") else f"{identity['home']}/.minikube"
            role_vars["detection_audit_policy_stage_path"] = None if not identity.get("home") else f"{identity['home']}/.minikube/files/etc/kubernetes/audit-policy.yaml"
            role_vars["detection_runtime_token_state"] = "present" if protected is None else protected["hec_workload_state"]
    execution_facts = sorted(set(target_blockers + authoritative_blockers))
    publication: dict[str, Any] = {
        "mode": mode,
        "save_ready": True,
        "contains_protected_credentials": protected is not None,
        "deployment_authorized": False,
        "runtime_acceptance": "PENDING_POST_PROVISIONING",
        "provisioning_time_checks": copy.deepcopy(PROVISIONING_TIME_CHECKS),
        "post_provisioning_acceptance_checks": copy.deepcopy(POST_PROVISIONING_ACCEPTANCE_CHECKS),
        "post_provisioning_acceptance_required": True,
        "target_range": target,
        "target_network": network,
        "unresolved_execution_facts": execution_facts,
        "warning": "Saving this configuration does not authorize apply or deployment.",
    }
    if mode == "public-save":
        publication["application_password_placeholders"] = [
            "ludus_install_malcolm_admin_password",
            "detection_splunk_admin_password",
        ]
    if mode == "deployment":
        publication.update({
            "eligibility_phase": "INITIAL_PROVISIONING",
            "initial_provisioning_eligible": not execution_facts,
            "deployment_eligible": not execution_facts,
            "deployment_blocked": bool(execution_facts),
            "outstanding_gates": execution_facts,
        })
    source_extensions = _mapping(_mapping(draft, "range configuration").get("ludus_extensions", {}), "range configuration.ludus_extensions")
    extensions: dict[str, Any] = {}
    if "detection_engineering_contract" in source_extensions:
        extensions["detection_engineering_contract"] = copy.deepcopy(
            _mapping(source_extensions["detection_engineering_contract"], "detection_engineering_contract")
        )
    extensions["detection_engineering_publication"] = publication
    return {
        "ludus": vms,
        "ludus_extensions": extensions,
    }


def _publish_no_clobber(output: Path, payload: Any) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    published = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            yaml.safe_dump(payload, stream, sort_keys=False, width=1000)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output)
        published = True
        directory_fd = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as error:
        raise Refusal(f"output already exists: {output}") from error
    except OSError as error:
        if published:
            raise PublicationUncertain(
                f"output was linked but directory durability is uncertain; inspect output path before retrying: {output}"
            ) from error
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("public-save", "private-save", "deployment"))
    parser.add_argument("--target-inputs", required=True, type=Path)
    parser.add_argument("--protected-inputs", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.mode in {"private-save", "deployment"} and args.protected_inputs is None:
            raise Refusal(f"{args.mode} mode requires --protected-inputs")
        if args.mode == "public-save" and args.protected_inputs is not None:
            raise Refusal("public-save mode does not accept protected inputs")
        protected = None if args.protected_inputs is None else _read_protected(args.protected_inputs)
        result = materialize(
            yaml.safe_load(args.target_inputs.read_text(encoding="utf-8")),
            yaml.safe_load((ROOT / "product-pins.yml").read_text(encoding="utf-8")),
            yaml.safe_load((ROOT / "verified-inputs.yml").read_text(encoding="utf-8")),
            yaml.safe_load((ROOT / "requirements.yml").read_text(encoding="utf-8")),
            yaml.safe_load((ROOT / "range-config.yml").read_text(encoding="utf-8")),
            args.mode,
            protected,
        )
        _publish_no_clobber(args.output, result)
    except PublicationUncertain as error:
        print(f"PUBLICATION UNCERTAIN: {error}", file=sys.stderr)
        return 3
    except (OSError, Refusal, yaml.YAMLError, ValueError) as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
