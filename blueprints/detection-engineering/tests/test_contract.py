"""Offline factual-gate and blueprint contract checks."""

from __future__ import annotations

import copy
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import pytest
from jinja2 import StrictUndefined, Template

import support
from support import run_production_include


CANDIDATE = {
    "provenance": "USER_SUPPLIED_UNVERIFIED",
    "version": "10.6.1.1",
    "build": "b2ae2962645c",
    "enterprise_deb_url": "https://download.splunk.com/products/splunk/releases/10.6.1.1/linux/splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb",
    "forwarder_deb_url": "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb",
    "forwarder_tgz_reference_url": "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.tgz",
    "windows_msi_reference_url": "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi",
}

EXPECTED_ROLE_VARIABLES = {
    "guest_firewall": {
        "detection_firewall_profile",
        "detection_firewall_lab_ip",
        "detection_firewall_management_cidrs",
        "detection_firewall_vpn_cidrs",
        "detection_firewall_docker_bridges",
        "detection_firewall_allowed_tcp",
    },
    "linux_logging": {"detection_linux_host_id", "detection_audit_dispatch"},
    "splunk": {
        "detection_splunk_artifact",
        "detection_splunk_download_auth_path",
        "detection_splunk_license",
        "detection_splunk_hec_supported",
        "detection_splunk_search_api_supported",
        "detection_splunk_bind_ip",
        "detection_splunk_admin_password",
        "detection_splunk_restore_authorized",
        "detection_splunk_maintenance_state_path",
    },
    "forwarder": {
        "detection_forwarder_artifact",
        "detection_forwarder_download_auth_path",
        "detection_forwarder_profile",
        "detection_forwarder_inputs",
        "detection_splunk_receiver_host",
        "detection_splunk_receiver_port",
    },
    "gitlab": {
        "detection_gitlab_packages",
        "detection_gitlab_repository_url",
        "detection_gitlab_signing_key_url",
        "detection_gitlab_signing_key_fingerprint",
        "detection_gitlab_log_contract",
        "detection_runner_api_contract",
        "detection_gitlab_root_password",
    },
    "runner": {
        "detection_runner_packages",
        "detection_runner_repository_url",
        "detection_runner_signing_key_url",
        "detection_runner_signing_key_fingerprint",
        "detection_runner_description",
        "detection_gitlab_host",
        "detection_runner_api_contract",
    },
    "workload": {
        "detection_docker_packages",
        "detection_docker_repository_url",
        "detection_docker_signing_key_url",
        "detection_docker_signing_key_fingerprint",
        "detection_minikube_artifact",
        "detection_kubectl_artifact",
        "detection_helm_artifact",
        "detection_otel_chart",
        "detection_otel_contract",
        "detection_workload_user",
        "detection_cluster_name",
        "detection_splunk_hec_url",
        "detection_runtime_token_state",
    },
    "malcolm": {
        "ludus_install_malcolm_user",
        "ludus_install_malcolm_install_dir",
        "ludus_install_malcolm_venv_dir",
        "ludus_install_malcolm_admin_username",
        "ludus_install_malcolm_admin_password",
        "ludus_install_malcolm_capture_enabled",
        "ludus_install_malcolm_capture_interface",
        "ludus_install_malcolm_capture_filter",
        "ludus_install_malcolm_capture_rotation_megabytes",
        "ludus_install_malcolm_capture_rotation_minutes",
        "ludus_install_malcolm_image_pull_timeout_seconds",
        "ludus_install_malcolm_start_timeout_seconds",
        "ludus_install_malcolm_stop_timeout_seconds",
        "ludus_install_malcolm_readiness_timeout_seconds",
        "ludus_install_malcolm_health_poll_interval_seconds",
        "ludus_install_malcolm_tls_dhparam_size",
        "ludus_install_malcolm_systemd_unit_path",
        "ludus_install_malcolm_tcp_retries2",
        "ludus_install_malcolm_version",
        "ludus_install_malcolm_commit",
    },
}


def _load(blueprint_root: Path, read_yaml, filename: str):
    return read_yaml(blueprint_root / filename)


def _gate_records(inputs: dict):
    for name, record in inputs["templates"].items():
        yield f"templates.{name}", record
    yield "capacity", inputs["capacity"]
    yield "network", inputs["network"]
    for section in ("apt", "downloads", "git", "charts"):
        for name, record in inputs[section].items():
            yield f"{section}.{name}", record
    for name, record in inputs["capabilities"].items():
        if name != "splunk_free":
            yield f"capabilities.{name}", record
    yield "test_tools", inputs["test_tools"]


def _assert_gate(name: str, gate: dict):
    assert set(gate) == {"status", "source", "observed", "limitation", "stops"}, name
    assert gate["status"] in {"VERIFIED", "BLOCKED"}, name
    assert set(gate["source"]) == {"url", "observed_at"}, name
    parsed = urlparse(gate["source"]["url"])
    assert parsed.scheme == "https" and parsed.netloc, name
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", gate["source"]["observed_at"]), name
    assert isinstance(gate["limitation"], str) and gate["limitation"].strip(), name
    assert isinstance(gate["stops"], list) and all(isinstance(task, int) for task in gate["stops"]), name
    if gate["status"] == "BLOCKED":
        assert gate["observed"] is None, name
    else:
        assert gate["observed"] is not None, name


def _assert_verified_package_pins(inputs: dict):
    for section in ("apt",):
        for name, gate in inputs[section].items():
            if gate["status"] != "VERIFIED":
                continue
            for package in gate["observed"]["packages"]:
                assert package["name"].strip(), f"{section}.{name} package name"
                version = package["version"]
                assert isinstance(version, str) and version.strip(), f"{section}.{name} package version"
                assert not any(token in version for token in ("*", ">", "<", "~=")), f"{section}.{name} must be exactly pinned"


def test_two_range_ids_render_disjoint_identities(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    contract = config["ludus_extensions"]["detection_engineering_contract"]
    templates = [vm["vm_name_template"] for vm in contract["planned_vms"]]
    templates += [vm["host_id_template"] for vm in contract["planned_vms"]]
    templates.append(contract["cluster_name_template"])

    def render(range_id):
        return {
            Template(value, undefined=StrictUndefined).render(range_id=range_id)
            for value in templates
        }

    assert [vm["identity_suffix"] for vm in contract["planned_vms"]] == [
        "gitlab", "runner", "malcolm", "splunk", "workload"
    ]
    assert set(templates) == {
        "{{ range_id }}-gitlab",
        "{{ range_id }}-runner",
        "{{ range_id }}-malcolm",
        "{{ range_id }}-splunk",
        "{{ range_id }}-workload",
        "{{ range_id }}-minikube",
    }
    alpha = render("alpha")
    bravo = render("bravo")
    assert alpha.isdisjoint(bravo)
    assert alpha == {
        "alpha-gitlab", "alpha-runner", "alpha-malcolm", "alpha-splunk",
        "alpha-workload", "alpha-minikube",
    }


def test_exact_resource_totals(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    vms = config["ludus_extensions"]["detection_engineering_contract"]["planned_vms"]
    assert [(vm["identity_suffix"], vm["ram_gb"], vm["cpus"]) for vm in vms] == [
        ("gitlab", 8, 4),
        ("runner", 8, 4),
        ("malcolm", 64, 8),
        ("splunk", 12, 4),
        ("workload", 16, 6),
    ]
    assert sum(vm["ram_gb"] for vm in vms) == 108
    assert sum(vm["cpus"] for vm in vms) == 26
    assert config["ludus"] == []
    assert config["ludus_extensions"]["detection_engineering_contract"]["deployment_blocked"] is True


def test_gate_records_have_source_status_limitation_and_stops(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    for name, gate in _gate_records(inputs):
        _assert_gate(name, gate)

    malformed = copy.deepcopy(inputs)
    malformed["downloads"]["splunk"] = {
        **malformed["downloads"]["splunk"],
        "status": "VERIFIED",
        "observed": None,
    }
    with pytest.raises(AssertionError):
        _assert_gate("downloads.splunk", malformed["downloads"]["splunk"])

    unpinned = copy.deepcopy(inputs)
    unpinned["apt"]["gitlab"] = {
        **unpinned["apt"]["gitlab"],
        "status": "VERIFIED",
        "observed": {
            "repository_url": "https://packages.gitlab.com/runner/gitlab-runner",
            "signing_key_url": "https://packages.gitlab.com/gpg.key",
            "signing_key_fingerprint": "not-a-real-verified-fingerprint",
            "packages": [{"name": "gitlab-ce", "version": ">=18"}],
        },
    }
    with pytest.raises(AssertionError):
        _assert_verified_package_pins(unpinned)


def test_every_manifest_value_maps_to_exact_role_var(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    actual = config["ludus_extensions"]["detection_engineering_contract"]["role_variable_contracts"]
    assert set(actual) == set(EXPECTED_ROLE_VARIABLES)
    for consumer, expected in EXPECTED_ROLE_VARIABLES.items():
        assert set(actual[consumer]) == expected
        for variable, mapping in actual[consumer].items():
            assert set(mapping) in (
                {"source", "type"},
                {"value", "type"},
                {"operation", "inputs", "type"},
            ), variable
            assert isinstance(mapping["type"], str) and mapping["type"]
            if "source" in mapping:
                assert mapping["source"].startswith(
                    ("verified_inputs.", "planned_vm.", "contract.", "runtime_secret.", "role_defaults.")
                ), variable
    assert actual["splunk"]["detection_splunk_restore_authorized"] == {"value": False, "type": "bool"}
    assert actual["forwarder"]["detection_splunk_receiver_port"] == {"value": 9997, "type": "int"}
    assert actual["workload"]["detection_cluster_name"] == {
        "source": "contract.cluster_name_template",
        "type": "range_template[str]",
    }
    assert actual["guest_firewall"]["detection_firewall_lab_ip"]["operation"] == "derive_lab_ip"
    assert actual["guest_firewall"]["detection_firewall_allowed_tcp"]["operation"] == "assemble_firewall_rules"
    assert actual["forwarder"]["detection_forwarder_inputs"]["operation"] == "project_forwarder_inputs"
    for name in ("detection_minikube_artifact", "detection_kubectl_artifact", "detection_helm_artifact"):
        assert actual["workload"][name]["operation"] == "project_runtime_artifact"


def test_every_matrix_input_has_one_reader(blueprint_root, read_yaml):
    matrix = _load(blueprint_root, read_yaml, "telemetry-matrix.yml")
    assert set(matrix) == {"schema_version", "sources"}
    assert matrix["schema_version"] == 1
    expected_keys = {
        "id", "boundary", "vm_role", "class", "path_or_input", "reader", "index",
        "sourcetype", "safe_fields", "negative_fields", "required", "capability_gate",
    }
    ids = []
    inputs = []
    for source in matrix["sources"]:
        assert set(source) == expected_keys
        assert source["reader"] in {"forwarder", "splunk_local", "otel_host", "otel_cluster"}
        assert source["required"] is True
        assert source["safe_fields"]
        assert source["negative_fields"]
        ids.append(source["id"])
        inputs.append((source["boundary"], source["vm_role"], source["path_or_input"]))
    assert len(ids) == len(set(ids))
    assert len(inputs) == len(set(inputs))
    assert len(ids) == 23

    expected = {
        source_id: values
        for source_id, values in [
            ("gitlab-auth", ("host", "gitlab", "/var/log/auth.log", "forwarder", "de_linux", "linux:auth", None)),
            ("gitlab-system", ("host", "gitlab", "/var/log/syslog", "forwarder", "de_linux", "linux:system", None)),
            ("gitlab-audit-safe", ("host", "gitlab", "/var/log/detection-engineering/audit-safe.jsonl", "forwarder", "de_linux", "linux:audit:safe", "capabilities.audit_dispatch")),
            ("runner-auth", ("host", "runner", "/var/log/auth.log", "forwarder", "de_linux", "linux:auth", None)),
            ("runner-system", ("host", "runner", "/var/log/syslog", "forwarder", "de_linux", "linux:system", None)),
            ("runner-audit-safe", ("host", "runner", "/var/log/detection-engineering/audit-safe.jsonl", "forwarder", "de_linux", "linux:audit:safe", "capabilities.audit_dispatch")),
            ("workload-auth", ("host", "workload", "/var/log/auth.log", "forwarder", "de_linux", "linux:auth", None)),
            ("workload-system", ("host", "workload", "/var/log/syslog", "forwarder", "de_linux", "linux:system", None)),
            ("workload-audit-safe", ("host", "workload", "/var/log/detection-engineering/audit-safe.jsonl", "forwarder", "de_linux", "linux:audit:safe", "capabilities.audit_dispatch")),
            ("splunk-auth", ("host", "splunk", "/var/log/auth.log", "splunk_local", "de_linux", "linux:auth", None)),
            ("splunk-system", ("host", "splunk", "/var/log/syslog", "splunk_local", "de_linux", "linux:system", None)),
            ("splunk-audit-safe", ("host", "splunk", "/var/log/detection-engineering/audit-safe.jsonl", "splunk_local", "de_linux", "linux:audit:safe", "capabilities.audit_dispatch")),
            ("gitlab-access", ("host", "gitlab", "/var/log/gitlab/nginx/gitlab_access.log", "forwarder", "de_gitlab", "gitlab:access", "capabilities.gitlab_ce_logs")),
            ("gitlab-application", ("host", "gitlab", "capabilities.gitlab_ce_logs.observed.paths.application", "forwarder", "de_gitlab", "gitlab:application", "capabilities.gitlab_ce_logs")),
            ("gitlab-audit", ("host", "gitlab", "capabilities.gitlab_ce_logs.observed.paths.audit", "forwarder", "de_gitlab", "gitlab:audit", "capabilities.gitlab_ce_logs")),
            ("runner-service", ("host", "runner", "systemd:gitlab-runner", "forwarder", "de_runner", "gitlab:runner", None)),
            ("runner-registration", ("host", "runner", "/var/log/detection-engineering/runner-registration.jsonl", "forwarder", "de_runner", "gitlab:runner:registration", "capabilities.runner_api")),
            ("splunk-internal", ("host", "splunk", "$SPLUNK_HOME/var/log/splunk/*.log", "splunk_local", "_internal", "splunk:native", "capabilities.splunk")),
            ("workload-docker-daemon", ("host", "workload", "systemd:dockerd", "forwarder", "de_runtime", "docker:daemon", None)),
            ("workload-docker-container", ("host", "workload", "/var/lib/docker/containers/*/*-json.log", "otel_host", "de_runtime", "docker:container", "capabilities.otel")),
            ("minikube-api-audit", ("node", "workload", "capabilities.otel.observed.audit_path", "otel_cluster", "de_runtime", "kube:audit", "capabilities.otel")),
            ("minikube-node-service", ("node", "workload", "systemd:kubelet", "otel_cluster", "de_runtime", "kube:node", "capabilities.otel")),
            ("minikube-container", ("node", "workload", "/var/log/containers/*.log", "otel_cluster", "de_runtime", "kube:container", "capabilities.otel")),
        ]
    }
    actual = {
        source["id"]: tuple(source[key] for key in (
            "boundary", "vm_role", "path_or_input", "reader", "index",
            "sourcetype", "capability_gate",
        ))
        for source in matrix["sources"]
    }
    def assert_canonical(value):
        assert value == expected

    assert_canonical(actual)
    bad = copy.deepcopy(actual)
    bad["workload-docker-container"] = (*bad["workload-docker-container"][:3], "otel_cluster", *bad["workload-docker-container"][4:])
    with pytest.raises(AssertionError):
        assert_canonical(bad)


def test_splunk_candidate_record_matches_spec_urls_verbatim(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    record = inputs["user_supplied_candidates"]["splunk_10_6_1_1"]
    _assert_gate("user_supplied_candidates.splunk_10_6_1_1", record)
    assert record["observed"] == CANDIDATE
    assert record["stops"] == []
    assert record["observed"]["enterprise_deb_url"].endswith(".deb")
    assert record["observed"]["forwarder_deb_url"].endswith(".deb")
    assert "sha256" not in record["observed"]
    assert record["observed"]["forwarder_tgz_reference_url"].endswith(".tgz")
    assert record["observed"]["windows_msi_reference_url"].endswith(".msi")
    assert set(inputs["downloads"]) == {"splunk", "forwarder", "minikube", "kubectl", "helm"}


def test_initial_trial_does_not_require_verified_free_gate(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    trial = inputs["capabilities"]["splunk"]
    free = inputs["capabilities"]["splunk_free"]
    assert trial["status"] == "BLOCKED"
    assert trial["observed"] is None
    confirmation = inputs["user_supplied_candidates"]["splunk_initial_trial"]
    assert confirmation == {
        "record_type": "USER_CONFIRMATION",
        "status": "CONFIRMED",
        "source": {
            "kind": "USER_CONFIRMATION",
            "recorded_at": confirmation["source"]["recorded_at"],
        },
        "observed": {
            "initial_mode": "ENTERPRISE_60_DAY_TRIAL",
            "trial_days_user_confirmed": 60,
            "terms_confirmation": "USER_CONFIRMED_NOT_INDEPENDENTLY_VERIFIED",
        },
        "limitation": "User intent only; this is not independent package, license, expiry, HEC, search, or authentication evidence.",
        "stops": [],
    }
    assert free["status"] == "UNVERIFIED"
    assert free["observed"] is None
    assert set(free) == {"status", "source", "observed", "limitation"}
    assert "initial trial" in free["limitation"]


def test_uninstall_gate_stops_only_task_11(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    uninstall = inputs["capabilities"]["splunk_uninstall"]
    assert uninstall["status"] == "BLOCKED"
    assert uninstall["observed"] is None
    assert uninstall["stops"] == [11]


def test_production_include_harness_invokes_real_role_task(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    getent = fake_bin / "getent"
    getent.write_text("#!/bin/sh\nprintf 'deuser:x:1000:1000::/home/deuser:/bin/bash\\n'\n", encoding="utf-8")
    getent.chmod(0o755)

    result = run_production_include(
        "ludus_install_malcolm",
        "preflight",
        {
            "ansible_distribution": "Debian",
            "ansible_distribution_major_version": "13",
            "ansible_architecture": "x86_64",
            "ansible_interfaces": ["eth0"],
            "ansible_default_ipv4": {"interface": "eth0"},
            "ludus_install_malcolm_user": "deuser",
            "ludus_install_malcolm_install_dir": str(tmp_path / "Malcolm"),
            "ludus_install_malcolm_capture_enabled": False,
        },
        fake_bin,
    )

    assert isinstance(result, subprocess.CompletedProcess)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Validate supported Malcolm deployment inputs" in result.stdout


def test_target_inventory_is_deployment_only(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    contract = config["ludus_extensions"]["detection_engineering_contract"]
    policy = contract["target_inventory_policy"]
    assert contract["stage"] == "TASK_1_OFFLINE_CONTRACT"
    assert contract["offline_contract_status"] == "READY_FOR_ROLE_DEVELOPMENT"
    assert contract["deployment_readiness"] == "BLOCKED"
    assert policy == {
        "collection_method": "MCP",
        "collection_stage": "PREDEPLOYMENT",
        "required_for": ["DEPLOYMENT"],
        "not_required_for": ["OFFLINE_CONTRACT_VALIDATION", "ROLE_DEVELOPMENT"],
        "automatic_action": False,
    }

    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    target_gates = [*inputs["templates"].values(), inputs["capacity"], inputs["network"]]
    for gate in target_gates:
        assert gate["status"] == "BLOCKED"
        assert gate["observed"] is None
        assert gate["stops"] == [10]


def test_new_range_predeployment_requirement_is_explicit(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    requirement = config["ludus_extensions"]["detection_engineering_contract"]["new_range_requirement"]
    assert requirement == {
        "required": True,
        "stage": "PREDEPLOYMENT",
        "existing_range_reuse": "FORBIDDEN",
        "creation_authorized": False,
        "automatic_action": False,
    }


def test_mapping_contract_resolves_explicit_synthetic_sources(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    contract = config["ludus_extensions"]["detection_engineering_contract"]
    schema = contract["mapping_source_schema"]
    assert schema["planned_vm"]["provisioning_user"] == {
        "type": "linux_user",
        "required_at": "TASK_8_MATERIALIZATION",
        "source": "MCP_TEMPLATE_DISCOVERY",
    }
    assert schema["planned_vm"]["lab_ip"]["derive"] == {
        "operation": "derive_lab_ip",
        "inputs": ["verified_inputs.network.observed.lab_cidr", "planned_vm.ip_last_octet"],
    }
    assert set(schema["planned_vm"]["dependencies"]) == {"gitlab", "splunk"}

    artifact = {
        "version": "1.2.3",
        "build": "build7",
        "url": "https://example.invalid/tool",
        "sha256": "a" * 64,
        "download_auth_required": False,
    }
    package_pin = [{"name": "synthetic-package", "version": "1.2.3-1"}]
    trial = {
        "initial_mode": "ENTERPRISE_60_DAY_TRIAL",
        "trial_days_user_confirmed": 60,
        "terms_confirmation": "USER_CONFIRMED_NOT_INDEPENDENTLY_VERIFIED",
        "expiry_behavior": "synthetic-expiry",
        "hec": True,
        "search_api": True,
        "auth_behavior": "synthetic-auth",
    }
    audit_dispatch = {
        "package_version": "1.2.3-1",
        "plugin_protocol": "builtin_af_unix",
        "write_logs_false": True,
        "fail_closed": True,
    }
    gitlab_logs = {
        "paths": {
            "application": "/synthetic/gitlab/application.log",
            "audit": "/synthetic/gitlab/audit.log",
        },
        "producer_safe_fields": {
            "application": ["method", "status"],
            "audit": ["author_id", "entity_type"],
        },
        "query_and_auth_excluded": True,
        "unavailable_classes": [],
    }
    runner_api = {
        "bootstrap_auth": {
            "credential_type": "synthetic-access-token",
            "minimum_scope": "create_runner",
            "creation_argv": ["synthetic-client"],
            "stdin_operation": "token-via-stdin",
            "protected_path": "/etc/detection-engineering/secrets/runner-api-bootstrap.token",
            "mode": "0600",
            "revoke_endpoint": "/synthetic/revoke",
            "revoke_method": "DELETE",
        },
        "manager": {
            "runner_type": "project_type",
            "create_endpoint": "/synthetic/runners",
            "create_method": "POST",
            "lookup_endpoint": "/synthetic/runners/:id",
            "lookup_method": "GET",
            "update_endpoint": "/synthetic/runners/:id",
            "update_method": "PUT",
            "request_fields": ["description", "paused"],
            "response_token_field": "token",
            "local_verify_command": ["gitlab-runner", "verify"],
            "pause_at_create": True,
        },
    }
    otel = {
        "secret_file_provider": True,
        "audit_path": "/synthetic/kubernetes/audit.log",
        "node_log_inputs": ["/synthetic/node.log"],
        "required_rbac": {"pods": ["get", "list", "watch"]},
    }
    chart = {
        "repository": "https://example.invalid/charts",
        "chart": "synthetic-otel",
        "version": "1.2.3",
        "digest": "sha256:" + "c" * 64,
    }
    planned_vms = [
        {
            **vm,
            "provisioning_user": "debian",
        }
        for vm in contract["planned_vms"]
    ]
    sources = {
        "planned_vm.identity_suffix": "workload",
        "planned_vm.host_id_template": "{{ range_id }}-workload",
        "planned_vm.ip_last_octet": 15,
        "planned_vm.provisioning_user": "debian",
        "contract.planned_vms": planned_vms,
        "contract.cluster_name_template": contract["cluster_name_template"],
        "contract.firewall_policy": contract["firewall_policy"],
        "contract.telemetry_matrix.sources": _load(blueprint_root, read_yaml, "telemetry-matrix.yml")["sources"],
        "verified_inputs.network.observed.lab_cidr": "10.77.10.0/24",
        "verified_inputs.network.observed.management_cidrs": ["10.77.0.0/24"],
        "verified_inputs.network.observed.vpn_cidrs": ["10.78.0.0/24"],
        "verified_inputs.network.observed.docker_bridge_interfaces": ["docker0"],
        "verified_inputs.network.observed.service_ports": {
            "gitlab": [22, 80],
            "runner": [22],
            "malcolm": [22, 443, 5601],
            "splunk": [22, 8000, 8089, 9997, 8088],
            "workload": [22],
        },
        "verified_inputs.network.observed.guest_interface": "eth0",
        "verified_inputs.capabilities.audit_dispatch.observed": audit_dispatch,
        "verified_inputs.downloads.splunk.observed": artifact,
        "verified_inputs.downloads.forwarder.observed": artifact,
        "verified_inputs.downloads.minikube.observed": artifact,
        "verified_inputs.downloads.kubectl.observed": artifact,
        "verified_inputs.downloads.helm.observed": artifact,
        "verified_inputs.capabilities.splunk.observed": trial,
        "verified_inputs.capabilities.splunk.observed.hec": True,
        "verified_inputs.capabilities.splunk.observed.search_api": True,
        "verified_inputs.apt.gitlab.observed.packages": package_pin,
        "verified_inputs.apt.gitlab.observed.repository_url": "https://example.invalid/gitlab",
        "verified_inputs.apt.gitlab.observed.signing_key_url": "https://example.invalid/gitlab-key",
        "verified_inputs.apt.gitlab.observed.signing_key_fingerprint": "SYNTHETIC-GITLAB",
        "verified_inputs.apt.runner.observed.packages": package_pin,
        "verified_inputs.apt.runner.observed.repository_url": "https://example.invalid/runner",
        "verified_inputs.apt.runner.observed.signing_key_url": "https://example.invalid/runner-key",
        "verified_inputs.apt.runner.observed.signing_key_fingerprint": "SYNTHETIC-RUNNER",
        "verified_inputs.apt.docker.observed.packages": package_pin,
        "verified_inputs.apt.docker.observed.repository_url": "https://example.invalid/docker",
        "verified_inputs.apt.docker.observed.signing_key_url": "https://example.invalid/docker-key",
        "verified_inputs.apt.docker.observed.signing_key_fingerprint": "SYNTHETIC-DOCKER",
        "verified_inputs.capabilities.gitlab_ce_logs.observed": gitlab_logs,
        "verified_inputs.capabilities.runner_api.observed": runner_api,
        "verified_inputs.charts.otel.observed": chart,
        "verified_inputs.capabilities.otel.observed": otel,
        "verified_inputs.git.malcolm.observed.tag": "v1.2.3",
        "verified_inputs.git.malcolm.observed.commit": "b" * 40,
        "runtime_secret.splunk_download_auth_path": None,
        "runtime_secret.splunk_admin_password": "Synthetic123!",
        "runtime_secret.forwarder_download_auth_path": None,
        "runtime_secret.gitlab_root_password": "Synthetic123!",
        "runtime_secret.hec_workload.state": "present",
        "runtime_secret.malcolm_admin_username": "synthetic-admin",
        "runtime_secret.malcolm_admin_password": "Synthetic123!",
        "role_defaults.ludus_install_malcolm.install_dir": "/opt/malcolm",
        "role_defaults.ludus_install_malcolm.venv_dir": "/opt/malcolm/.venv",
        "role_defaults.ludus_install_malcolm.capture_filter": "",
        "role_defaults.ludus_install_malcolm.capture_rotation_megabytes": 4096,
        "role_defaults.ludus_install_malcolm.capture_rotation_minutes": 10,
        "role_defaults.ludus_install_malcolm.image_pull_timeout_seconds": 3600,
        "role_defaults.ludus_install_malcolm.start_timeout_seconds": 1800,
        "role_defaults.ludus_install_malcolm.stop_timeout_seconds": 600,
        "role_defaults.ludus_install_malcolm.readiness_timeout_seconds": 1800,
        "role_defaults.ludus_install_malcolm.health_poll_interval_seconds": 10,
        "role_defaults.ludus_install_malcolm.tls_dhparam_size": 2048,
        "role_defaults.ludus_install_malcolm.systemd_unit_path": "/etc/systemd/system/malcolm.service",
        "role_defaults.ludus_install_malcolm.tcp_retries2": None,
    }

    resolved = support.resolve_role_variable_contracts(contract, sources)
    assert resolved["guest_firewall"]["detection_firewall_lab_ip"] == "10.77.10.15"
    assert resolved["guest_firewall"]["detection_firewall_allowed_tcp"] == [{
        "sources": ["10.77.0.0/24"],
        "ports": [22],
    }]
    assert resolved["forwarder"]["detection_splunk_receiver_host"] == "{{ range_id }}-splunk"
    assert resolved["forwarder"]["detection_forwarder_inputs"][0].keys() == {"path", "index", "sourcetype", "safe_fields"}
    assert resolved["workload"]["detection_minikube_artifact"] == {
        "version": "1.2.3",
        "url": "https://example.invalid/tool",
        "sha256": "a" * 64,
        "download_auth_required": False,
    }
    assert "build" not in resolved["workload"]["detection_minikube_artifact"]
    assert resolved["runner"]["detection_gitlab_host"] == "{{ range_id }}-gitlab"
    assert resolved["workload"]["detection_splunk_hec_url"] == "http://{{ range_id }}-splunk:8088/services/collector"
    assert resolved["malcolm"]["ludus_install_malcolm_user"] == "debian"

    expected_pairs = {
        "gitlab": {
            ("10.77.0.0/24", 22),
            ("10.78.0.0/24", 80),
            ("10.77.10.12", 80),
        },
        "runner": {("10.77.0.0/24", 22)},
        "malcolm": {
            ("10.77.0.0/24", 22),
            ("10.78.0.0/24", 443),
            ("10.78.0.0/24", 5601),
        },
        "splunk": {
            ("10.77.0.0/24", 22),
            ("10.78.0.0/24", 8000),
            ("10.78.0.0/24", 8089),
            ("10.77.10.11", 9997),
            ("10.77.10.12", 9997),
            ("10.77.10.15", 9997),
            ("10.77.10.15", 8088),
        },
        "workload": {("10.77.0.0/24", 22)},
    }
    for profile, expected in expected_pairs.items():
        rules = support.assemble_firewall_rules(contract["firewall_policy"], sources, profile)
        actual_pairs = {
            (source, port)
            for rule in rules
            for source in rule["sources"]
            for port in rule["ports"]
        }
        assert actual_pairs == expected

    splunk_pairs = expected_pairs["splunk"]
    assert ("10.78.0.0/24", 9997) not in splunk_pairs
    assert ("10.78.0.0/24", 8088) not in splunk_pairs
    assert ("10.77.10.11", 8088) not in splunk_pairs
    assert ("10.77.10.12", 8088) not in splunk_pairs
    assert ("10.77.10.13", 9997) not in splunk_pairs
    assert ("10.77.10.14", 9997) not in splunk_pairs
    assert ("10.77.10.12", 22) not in expected_pairs["gitlab"]

    required_service_ports = {
        "gitlab": {22, 80},
        "runner": {22},
        "splunk": {22, 8000, 8089, 9997, 8088},
        "workload": {22},
    }
    for profile, required_ports in required_service_ports.items():
        for missing_port in required_ports:
            missing_allowance = copy.deepcopy(sources)
            missing_allowance["verified_inputs.network.observed.service_ports"][profile] = sorted(
                required_ports - {missing_port}
            )
            with pytest.raises(ValueError, match=rf"service_ports\.{profile}"):
                support.assemble_firewall_rules(
                    contract["firewall_policy"], missing_allowance, profile
                )

        contrary_allowance = copy.deepcopy(sources)
        contrary_allowance["verified_inputs.network.observed.service_ports"][profile].append(65535)
        with pytest.raises(ValueError, match=rf"service_ports\.{profile}"):
            support.assemble_firewall_rules(
                contract["firewall_policy"], contrary_allowance, profile
            )

    malcolm_rules = support.assemble_firewall_rules(
        contract["firewall_policy"], sources, "malcolm"
    )
    malcolm_vpn_rule = next(
        rule for rule in malcolm_rules if rule["sources"] == ["10.78.0.0/24"]
    )
    assert malcolm_vpn_rule["ports"] == [443, 5601]
    assert 22 not in malcolm_vpn_rule["ports"]

    invalid_runner_api = copy.deepcopy(runner_api)
    invalid_runner_api["manager"]["pause_at_create"] = False
    invalid_complex_sources = [
        (
            "verified_inputs.capabilities.audit_dispatch.observed",
            {**audit_dispatch, "fail_closed": False},
            "AuditDispatch",
        ),
        (
            "verified_inputs.capabilities.splunk.observed",
            {**trial, "initial_mode": "SYNTHETIC_WRONG_MODE"},
            "SplunkTrialCapability",
        ),
        (
            "verified_inputs.capabilities.gitlab_ce_logs.observed",
            {**gitlab_logs, "query_and_auth_excluded": "not-a-bool"},
            "GitLabLogContract",
        ),
        (
            "verified_inputs.capabilities.runner_api.observed",
            invalid_runner_api,
            "RunnerApiContract",
        ),
        (
            "verified_inputs.charts.otel.observed",
            {**chart, "digest": ""},
            "HelmChartPin",
        ),
        (
            "verified_inputs.capabilities.otel.observed",
            {**otel, "secret_file_provider": "not-a-bool"},
            "OtelContract",
        ),
    ]
    for source_path, invalid_value, type_name in invalid_complex_sources:
        invalid = copy.deepcopy(sources)
        invalid[source_path] = invalid_value
        with pytest.raises(ValueError, match=type_name):
            support.resolve_role_variable_contracts(contract, invalid)

    missing = copy.deepcopy(sources)
    del missing["verified_inputs.network.observed.lab_cidr"]
    with pytest.raises(ValueError, match="missing source"):
        support.resolve_role_variable_contracts(contract, missing)

    wrong_type = copy.deepcopy(sources)
    wrong_type["verified_inputs.network.observed.service_ports"]["malcolm"] = "443"
    with pytest.raises(ValueError, match="service_ports.*list"):
        support.assemble_firewall_rules(contract["firewall_policy"], wrong_type, "malcolm")


def test_verified_inputs_strict_schema_rejects_malformed_verified_records(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    support.validate_verified_inputs(inputs)

    mutations = [
        ("templates", "gitlab"),
        ("capacity", None),
        ("network", None),
        ("apt", "gitlab"),
        ("downloads", "splunk"),
        ("git", "malcolm"),
        ("charts", "otel"),
        ("capabilities", "splunk"),
        ("capabilities", "splunk_uninstall"),
        ("capabilities", "gitlab_ce_logs"),
        ("capabilities", "runner_api"),
        ("capabilities", "audit_dispatch"),
        ("capabilities", "otel"),
        ("test_tools", None),
    ]
    for section, name in mutations:
        malformed = copy.deepcopy(inputs)
        record = malformed[section] if name is None else malformed[section][name]
        record["status"] = "VERIFIED"
        record["observed"] = {}
        with pytest.raises(ValueError, match="observed"):
            support.validate_verified_inputs(malformed)

    malformed_future = copy.deepcopy(inputs)
    malformed_future["capabilities"]["splunk_free"]["status"] = "VERIFIED"
    malformed_future["capabilities"]["splunk_free"]["observed"] = {}
    with pytest.raises(ValueError, match="observed"):
        support.validate_verified_inputs(malformed_future)

    malformed_root = copy.deepcopy(inputs)
    del malformed_root["schema_version"]
    with pytest.raises(ValueError, match="verified_inputs"):
        support.validate_verified_inputs(malformed_root)

    malformed_time = copy.deepcopy(inputs)
    malformed_time["verified_at"] = "not-a-timestamp"
    with pytest.raises(ValueError, match="verified_at"):
        support.validate_verified_inputs(malformed_time)

    malformed_future_source = copy.deepcopy(inputs)
    del malformed_future_source["capabilities"]["splunk_free"]["source"]["url"]
    with pytest.raises(ValueError, match="splunk_free.source"):
        support.validate_verified_inputs(malformed_future_source)


def test_tool_pins_equal_requirements_and_reference_formats_stay_non_v1(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    requirements = {}
    for line in (blueprint_root / "tests" / "requirements.txt").read_text(encoding="utf-8").splitlines():
        name, version = line.split("==", 1)
        requirements[name] = version
    assert requirements == inputs["test_tools"]["observed"]

    malformed = copy.deepcopy(inputs)
    malformed["downloads"]["forwarder_tgz"] = copy.deepcopy(malformed["downloads"]["forwarder"])
    with pytest.raises(ValueError, match="verified_inputs.downloads"):
        support.validate_verified_inputs(malformed)

    wrong_deb = copy.deepcopy(inputs)
    wrong_deb["downloads"]["forwarder"]["status"] = "VERIFIED"
    wrong_deb["downloads"]["forwarder"]["observed"] = {
        "version": "10.6.1.1",
        "build": "b2ae2962645c",
        "url": "https://example.invalid/not-the-candidate.deb",
        "sha256": "0" * 64,
        "download_auth_required": False,
    }
    with pytest.raises(ValueError, match="candidate URL"):
        support.validate_verified_inputs(wrong_deb)
