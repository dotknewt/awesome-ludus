"""Offline factual-gate and blueprint contract checks."""

from __future__ import annotations

import ast
import copy
import hashlib
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
    "linux_logging": {
        "detection_linux_host_id",
        "detection_laurel_artifact",
        "detection_laurel_read_user",
        "detection_laurel_rotate_size",
        "detection_laurel_rotate_generations",
    },
    "splunk": {
        "detection_splunk_artifact",
        "detection_splunk_download_auth_path",
        "detection_splunk_license",
        "detection_splunk_hec_supported",
        "detection_splunk_search_api_supported",
        "detection_splunk_bind_ip",
        "detection_splunk_admin_username",
        "detection_splunk_admin_password",
        "detection_splunk_restore_authorized",
        "detection_splunk_maintenance_state_path",
    },
    "forwarder": {
        "detection_forwarder_artifact",
        "detection_forwarder_download_auth_path",
        "detection_forwarder_bootstrap_contract",
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
        "detection_gitlab_external_url",
        "detection_gitlab_readiness_contract",
        "detection_runner_api_contract",
    },
    "runner": {
        "detection_runner_packages",
        "detection_runner_repository_url",
        "detection_runner_signing_key_url",
        "detection_runner_signing_key_fingerprint",
        "detection_runner_description",
        "detection_gitlab_host",
        "detection_runner_api_contract",
        "detection_gitlab_readiness_contract",
        "detection_runner_jobs_contract",
    },
    "workload": {
        "detection_docker_packages",
        "detection_docker_repository_url",
        "detection_docker_signing_key_url",
        "detection_docker_signing_key_fingerprint",
        "detection_minikube_artifact",
        "detection_kubectl_artifact",
        "detection_helm_artifact",
        "detection_otel_host_artifact",
        "detection_runtime_artifact_layouts",
        "detection_otel_chart",
        "detection_otel_contract",
        "detection_workload_user",
        "detection_cluster_name",
        "detection_splunk_hec_url",
        "detection_splunk_hec_handoff",
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
    for section in ("apt", "downloads", "artifact_layouts", "git", "charts"):
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


def _synthetic_gate(observed, stops):
    return {
        "status": "VERIFIED",
        "source": {
            "url": "https://example.invalid/explicitly-synthetic",
            "observed_at": "2026-10-17T00:00:00Z",
        },
        "observed": observed,
        "limitation": "Explicitly synthetic contract fixture; not factual evidence.",
        "stops": stops,
    }


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
    assert len(config["ludus"]) == 5
    render = config["ludus_extensions"]["detection_engineering_publication"]
    assert render["save_ready"] is True
    assert render["deployment_authorized"] is False


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
                    ("product_pins.", "target_inputs.", "planned_vm.", "contract.", "runtime_secret.", "role_defaults.", "provisioning_time.")
                ), variable
    assert actual["splunk"]["detection_splunk_restore_authorized"] == {"value": False, "type": "bool"}
    assert actual["forwarder"]["detection_splunk_receiver_port"] == {"value": 9997, "type": "int"}
    assert actual["workload"]["detection_cluster_name"] == {
        "source": "contract.cluster_name_template",
        "type": "range_template[str]",
    }
    assert actual["forwarder"]["detection_forwarder_inputs"]["operation"] == "project_forwarder_inputs"
    for name in ("detection_minikube_artifact", "detection_kubectl_artifact", "detection_helm_artifact"):
        assert actual["workload"][name]["operation"] == "project_runtime_artifact"


def test_native_laurel_contract_is_bounded_by_host_role(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    mappings = config["ludus_extensions"]["detection_engineering_contract"][
        "role_variable_contracts"
    ]
    linux = mappings["linux_logging"]
    assert linux["detection_laurel_read_user"] == {
        "operation": "map_laurel_read_user",
        "inputs": {"profile": {"source": "planned_vm.identity_suffix"}},
        "type": "enum[splunkfwd,splunk]",
    }
    assert linux["detection_laurel_artifact"]["operation"] == "project_runtime_artifact"
    assert linux["detection_laurel_rotate_size"] == {"value": 5000000, "type": "int"}
    assert linux["detection_laurel_rotate_generations"] == {"value": 10, "type": "int"}
    for role in mappings.values():
        assert "detection_linux_forwarder_access" not in role
        assert "detection_log_reader_group" not in role
        assert "detection_forwarder_producer_contract" not in role

    for profile in ("gitlab", "runner", "workload"):
        assert support.map_laurel_read_user(profile) == "splunkfwd"
    assert support.map_laurel_read_user("splunk") == "splunk"
    for unsupported in ("malcolm", "unknown", ""):
        with pytest.raises(ValueError, match="Laurel host profile"):
            support.map_laurel_read_user(unsupported)


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
        ids.append(source["id"])
        inputs.append((source["boundary"], source["vm_role"], source["path_or_input"]))
    assert len(ids) == len(set(ids))
    assert len(inputs) == len(set(inputs))
    assert len(ids) == 18

    expected_negative_fields = {source_id: [] for source_id in ids}
    expected_negative_fields["minikube-api-audit"] = ["request_body", "response_body"]
    assert {
        source["id"]: source["negative_fields"] for source in matrix["sources"]
    } == expected_negative_fields
    support.validate_telemetry_negative_fields(matrix["sources"])

    blanket_redaction = copy.deepcopy(matrix["sources"])
    next(row for row in blanket_redaction if row["id"] == "gitlab-auth")[
        "negative_fields"
    ] = ["password", "token", "authorization"]
    with pytest.raises(ValueError, match="blanket telemetry redaction"):
        support.validate_telemetry_negative_fields(blanket_redaction)

    expected = {
        source_id: values
        for source_id, values in [
            ("gitlab-auth", ("host", "gitlab", "/var/log/auth.log", "forwarder", "de_linux", "linux:auth", None)),
            ("gitlab-system", ("host", "gitlab", "/var/log/syslog", "forwarder", "de_linux", "linux:system", None)),
            ("gitlab-audit-laurel", ("host", "gitlab", "/var/log/laurel/audit.log", "forwarder", "de_linux", "linux:audit:laurel", None)),
            ("runner-auth", ("host", "runner", "/var/log/auth.log", "forwarder", "de_linux", "linux:auth", None)),
            ("runner-system", ("host", "runner", "/var/log/syslog", "forwarder", "de_linux", "linux:system", None)),
            ("runner-audit-laurel", ("host", "runner", "/var/log/laurel/audit.log", "forwarder", "de_linux", "linux:audit:laurel", None)),
            ("workload-auth", ("host", "workload", "/var/log/auth.log", "forwarder", "de_linux", "linux:auth", None)),
            ("workload-system", ("host", "workload", "/var/log/syslog", "forwarder", "de_linux", "linux:system", None)),
            ("workload-audit-laurel", ("host", "workload", "/var/log/laurel/audit.log", "forwarder", "de_linux", "linux:audit:laurel", None)),
            ("splunk-auth", ("host", "splunk", "/var/log/auth.log", "splunk_local", "de_linux", "linux:auth", None)),
            ("splunk-system", ("host", "splunk", "/var/log/syslog", "splunk_local", "de_linux", "linux:system", None)),
            ("splunk-audit-laurel", ("host", "splunk", "/var/log/laurel/audit.log", "splunk_local", "de_linux", "linux:audit:laurel", None)),
            ("runner-registration", ("host", "runner", "/var/log/detection-engineering/runner-registration.jsonl", "forwarder", "de_runner", "gitlab:runner:registration", "capabilities.runner_api")),
            ("splunk-internal", ("host", "splunk", "$SPLUNK_HOME/var/log/splunk/*.log", "splunk_local", "_internal", "splunk:native", "capabilities.splunk")),
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
    assert set(inputs["downloads"]) == {
        "splunk", "forwarder", "laurel", "minikube", "kubectl", "helm", "otel_host"
    }


def test_static_initial_trial_contract_does_not_promote_future_free_runtime(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    trial = inputs["capabilities"]["splunk"]
    free = inputs["capabilities"]["splunk_free"]
    assert trial["status"] == "VERIFIED"
    assert trial["observed"]["initial_mode"] == "ENTERPRISE_60_DAY_TRIAL"
    assert "live service acceptance" in trial["limitation"]
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


def test_production_include_harness_ast_is_unchanged():
    tree = ast.parse(Path(support.__file__).read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_production_include"
    )
    digest = hashlib.sha256(
        ast.dump(function, include_attributes=False).encode()
    ).hexdigest()
    assert digest == "2b49069c34d83f3c58b3c5ef9df092afcd2f215ff0a6098fe78c4f6e9ffe793b"


def test_save_ready_range_keeps_target_inventory_as_deployment_only_evidence(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    contract = config["ludus_extensions"]["detection_engineering_contract"]
    policy = contract["target_inventory_policy"]
    assert contract["stage"] == "SAVE_READY_RANGE_CONFIGURATION"
    assert contract["offline_contract_status"] == "IMPLEMENTED"
    assert contract["save_readiness"] == "READY"
    assert contract["deployment_authorization"] == "NOT_GRANTED"
    assert "deployment_readiness" not in contract
    assert "deployment_blocked" not in contract
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


def test_existing_empty_thrunt_range_is_the_only_authorized_save_target(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    requirement = config["ludus_extensions"]["detection_engineering_contract"]["new_range_requirement"]
    assert requirement == {
        "required": False,
        "stage": "NOT_APPLICABLE_EXISTING_EMPTY_RANGE",
        "existing_range_reuse": "AUTHORIZED_THRUNT_ONLY",
        "creation_authorized": False,
        "automatic_action": False,
    }


def test_mapping_contract_resolves_explicit_synthetic_sources(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    contract = config["ludus_extensions"]["detection_engineering_contract"]
    schema = contract["mapping_source_schema"]
    assert schema["planned_vm"]["provisioning_user"] == {
        "type": "linux_user",
        "required_at": "RANGE_FILE_MATERIALIZATION",
        "value": "debian",
    }
    assert schema["planned_vm"]["lab_ip"]["derive"] == {
        "operation": "derive_lab_ip",
        "inputs": ["target_inputs.network.observed.lab_cidr", "planned_vm.ip_last_octet"],
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
    runner_api = {
        "bootstrap_auth": {
            "credential_type": "personal_access_token",
            "scopes": ["create_runner", "manage_runner", "read_api"],
            "expiration_days": 1,
            "creation_argv": ["gitlab-rails", "runner", "-"],
            "protected_path": "/etc/detection-engineering/secrets/runner-api-bootstrap.token",
            "mode": "0600",
            "revoke_endpoint": "/api/v4/personal_access_tokens/self",
            "revoke_method": "DELETE",
        },
        "manager": {
            "runner_type": "instance_type",
            "create_scope": "create_runner",
            "manage_scope": "manage_runner",
            "read_scope": "read_api",
            "create_endpoint": "/api/v4/user/runners",
            "create_method": "POST",
            "lookup_endpoint": "/api/v4/runners/all",
            "lookup_method": "GET",
            "detail_endpoint": "/api/v4/runners/:id",
            "detail_method": "GET",
            "update_endpoint": "/api/v4/runners/:id",
            "update_method": "PUT",
            "request_fields": ["runner_type", "description", "paused"],
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
    package_observed = {
        "repository_url": "https://example.invalid/docker",
        "signing_key_url": "https://example.invalid/docker-key",
        "signing_key_fingerprint": "SYNTHETIC-DOCKER",
        "packages": package_pin,
    }
    package_gates = {
        name: _synthetic_gate(package_observed, [7, 8, 9, 10])
        for name in ("docker", "containerd", "docker_plugins")
    }
    artifact_gates = {
        name: _synthetic_gate(artifact, [7, 8, 9, 10])
        for name in ("minikube", "kubectl", "helm", "otel_host")
    }
    layout_gates = {
        name: _synthetic_gate(
            {"artifact_sha256": "a" * 64, "format": "raw", "member": None},
            [7, 8, 9, 10],
        )
        for name in ("minikube", "kubectl", "helm", "otel_host")
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
        "contract.forwarder_source_policy": contract["forwarder_source_policy"],
        "contract.telemetry_matrix.sources": _load(blueprint_root, read_yaml, "telemetry-matrix.yml")["sources"],
        "target_inputs.network.observed.lab_cidr": "10.77.10.0/24",
        "provisioning_time.guest_capture_interface_discovery": "eth0",
        "product_pins.downloads.splunk.observed": artifact,
        "product_pins.downloads.forwarder.observed": artifact,
        "product_pins.downloads.laurel.observed": artifact,
        "product_pins.downloads.minikube.observed": artifact,
        "product_pins.downloads.kubectl.observed": artifact,
        "product_pins.downloads.helm.observed": artifact,
        "product_pins.downloads.otel_host.observed": artifact,
        "product_pins.downloads.minikube": artifact_gates["minikube"],
        "product_pins.downloads.kubectl": artifact_gates["kubectl"],
        "product_pins.downloads.helm": artifact_gates["helm"],
        "product_pins.downloads.otel_host": artifact_gates["otel_host"],
        "product_pins.artifact_layouts.minikube": layout_gates["minikube"],
        "product_pins.artifact_layouts.kubectl": layout_gates["kubectl"],
        "product_pins.artifact_layouts.helm": layout_gates["helm"],
        "product_pins.artifact_layouts.otel_host": layout_gates["otel_host"],
        "product_pins.capabilities.splunk.observed": trial,
        "product_pins.capabilities.splunk.observed.hec": True,
        "product_pins.capabilities.splunk.observed.search_api": True,
        "product_pins.apt.gitlab.observed.packages": package_pin,
        "product_pins.apt.gitlab.observed.repository_url": "https://example.invalid/gitlab",
        "product_pins.apt.gitlab.observed.signing_key_url": "https://example.invalid/gitlab-key",
        "product_pins.apt.gitlab.observed.signing_key_fingerprint": "SYNTHETIC-GITLAB",
        "product_pins.apt.runner.observed.packages": package_pin,
        "product_pins.apt.runner.observed.repository_url": "https://example.invalid/runner",
        "product_pins.apt.runner.observed.signing_key_url": "https://example.invalid/runner-key",
        "product_pins.apt.runner.observed.signing_key_fingerprint": "SYNTHETIC-RUNNER",
        "product_pins.apt.docker.observed.packages": package_pin,
        "product_pins.apt.docker.observed.repository_url": "https://example.invalid/docker",
        "product_pins.apt.docker.observed.signing_key_url": "https://example.invalid/docker-key",
        "product_pins.apt.docker.observed.signing_key_fingerprint": "SYNTHETIC-DOCKER",
        "product_pins.apt.docker": package_gates["docker"],
        "product_pins.apt.containerd": package_gates["containerd"],
        "product_pins.apt.docker_plugins": package_gates["docker_plugins"],
        "product_pins.capabilities.runner_api.observed": runner_api,
        "product_pins.capabilities.gitlab_readiness_contract.observed": {
            "transport_base_url": "http://localhost",
            "endpoint": "/-/readiness", "method": "GET", "success_statuses": [200],
            "attempts": 60, "delay_seconds": 5,
        },
        "product_pins.capabilities.runner_jobs_contract.observed": {
            "endpoint": "/api/v4/runners/:id/jobs", "method": "GET",
        },
        "product_pins.capabilities.forwarder_bootstrap_contract": _synthetic_gate({
            "version": "10.6.1.1", "build": "b2ae2962645c",
            "seed": {"path": "/opt/splunkforwarder/etc/system/local/user-seed.conf", "section": "user_info", "username_key": "USERNAME", "username": "admin", "password_key": "PASSWORD", "mode": "0600", "owner": "splunkfwd", "group": "splunkfwd"},
            "first_start": {"identity": "splunkfwd", "argv": ["start", "--accept-license", "--answer-yes", "--no-prompt"]},
            "boot_start": {"identity": "root", "argv": ["enable", "boot-start", "-user", "splunkfwd", "--accept-license", "--answer-yes", "--no-prompt"]},
            "unit": {"path": "/etc/systemd/system/SplunkForwarder.service", "service_name": "SplunkForwarder.service", "effective_user": "splunkfwd"},
        }, [4, 8, 9, 10]),
        "product_pins.charts.otel.observed": chart,
        "product_pins.capabilities.otel.observed": otel,
        "product_pins.git.malcolm.observed.tag": "v1.2.3",
        "product_pins.git.malcolm.observed.commit": "b" * 40,
        "runtime_secret.splunk_download_auth_path": None,
        "runtime_secret.splunk_admin_password": "Synthetic123!",
        "runtime_secret.forwarder_download_auth_path": None,
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
    assert resolved["forwarder"]["detection_splunk_receiver_host"] == "{{ range_id }}-splunk"
    assert resolved["linux_logging"]["detection_laurel_artifact"] == {
        "version": "1.2.3",
        "url": "https://example.invalid/tool",
        "sha256": "a" * 64,
        "download_auth_required": False,
    }
    assert resolved["linux_logging"]["detection_laurel_read_user"] == "splunkfwd"
    assert resolved["forwarder"]["detection_forwarder_inputs"][0].keys() == {"path", "index", "sourcetype", "safe_fields"}
    assert len(resolved["forwarder"]["detection_forwarder_inputs"]) == 3
    assert resolved["workload"]["detection_minikube_artifact"] == {
        "version": "1.2.3",
        "url": "https://example.invalid/tool",
        "sha256": "a" * 64,
        "download_auth_required": False,
    }
    assert "build" not in resolved["workload"]["detection_minikube_artifact"]
    assert resolved["runner"]["detection_gitlab_host"] == "{{ range_id }}-gitlab"
    assert resolved["workload"]["detection_splunk_hec_url"] == "http://{{ range_id }}-splunk:8088/services/collector/event"
    assert resolved["malcolm"]["ludus_install_malcolm_user"] == "debian"

    invalid_runner_api = copy.deepcopy(runner_api)
    invalid_runner_api["manager"]["pause_at_create"] = False
    invalid_complex_sources = [
        (
            "product_pins.capabilities.splunk.observed",
            {**trial, "initial_mode": "SYNTHETIC_WRONG_MODE"},
            "SplunkTrialCapability",
        ),
        (
            "product_pins.capabilities.runner_api.observed",
            invalid_runner_api,
            "RunnerApiContract",
        ),
        (
            "product_pins.charts.otel.observed",
            {**chart, "digest": ""},
            "HelmChartPin",
        ),
        (
            "product_pins.capabilities.otel.observed",
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
    del missing["target_inputs.network.observed.lab_cidr"]
    with pytest.raises(ValueError, match="missing source"):
        support.resolve_role_variable_contracts(contract, missing)

    unknown_reader_contract = copy.deepcopy(contract)
    unknown_reader_contract["role_variable_contracts"]["linux_logging"][
        "detection_laurel_read_user"
    ] = {"value": "root", "type": "enum[splunkfwd,splunk]"}
    with pytest.raises(ValueError, match="must be one of"):
        support.resolve_role_variable_contracts(unknown_reader_contract, sources)


def test_firewall_scope_is_absent_from_active_contract(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    contract = config["ludus_extensions"]["detection_engineering_contract"]
    assert "firewall_policy" not in contract
    assert "guest_firewall" not in contract["role_variable_contracts"]
    text = (blueprint_root / "range-config.yml").read_text()
    for forbidden in ("ludus_detection_guest_firewall", "detection_firewall_", "guest_docker_bridge"):
        assert forbidden not in text


def test_forwarder_projects_native_laurel_profiles_without_producer_proof(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    contract = config["ludus_extensions"]["detection_engineering_contract"]
    policy = contract["forwarder_source_policy"]
    matrix = _load(blueprint_root, read_yaml, "telemetry-matrix.yml")["sources"]
    expected_paths = {
        "gitlab": {
            "/var/log/auth.log", "/var/log/syslog",
            "/var/log/laurel/audit.log",
        },
        "runner": {
            "/var/log/auth.log", "/var/log/syslog",
            "/var/log/laurel/audit.log",
            "/var/log/detection-engineering/runner-registration.jsonl",
        },
        "workload": {
            "/var/log/auth.log", "/var/log/syslog",
            "/var/log/laurel/audit.log",
        },
    }
    for profile in ("gitlab", "runner", "workload"):
        projected = support.project_forwarder_profile(profile, matrix, policy)
        assert {item["path"] for item in projected} == expected_paths[profile]
        assert len(projected) == {"gitlab": 3, "runner": 4, "workload": 3}[profile]
        assert all(set(item) == {"path", "index", "sourcetype", "safe_fields"} for item in projected)

    wrong_path = copy.deepcopy(matrix)
    next(row for row in wrong_path if row["id"] == "runner-registration")["path_or_input"] = "/tmp/arbitrary.log"
    with pytest.raises(ValueError, match="canonical.*runner-registration"):
        support.project_forwarder_profile("runner", wrong_path, policy)

    missing_common = [row for row in matrix if row["id"] != "workload-auth"]
    with pytest.raises(ValueError, match="common.*coverage"):
        support.project_forwarder_profile("workload", missing_common, policy)


def test_removed_service_contracts_cannot_be_reintroduced(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    contract = config["ludus_extensions"]["detection_engineering_contract"]
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    matrix = _load(blueprint_root, read_yaml, "telemetry-matrix.yml")["sources"]
    removed_ids = {
        "gitlab-access", "gitlab-application", "gitlab-audit",
        "runner-service", "workload-docker-daemon",
    }
    removed_capabilities = {
        "gitlab_ce_logs", "runner_service_log", "docker_daemon_log",
        "audit_dispatch",
    }
    assert removed_ids.isdisjoint({row["id"] for row in matrix})
    assert removed_capabilities.isdisjoint(inputs["capabilities"])
    assert "detection_gitlab_log_contract" not in contract["role_variable_contracts"]["gitlab"]
    serialized = "\n".join(
        (blueprint_root / name).read_text(encoding="utf-8")
        for name in ("range-config.yml", "verified-inputs.yml", "telemetry-matrix.yml")
    )
    for removed in (
        "audit-safe.jsonl", "linux:audit:safe", "audit_dispatch",
        "managed_root_v1", "detection-forwarder-readers",
        "detection_forwarder_producer_contract",
    ):
        assert removed not in serialized

    legal_gate = _synthetic_gate(
        {
            "input": "systemd:gitlab-runner",
            "output_path": "/var/log/detection-engineering/runner-service.jsonl",
            "native_fields": ["__REALTIME_TIMESTAMP", "MESSAGE"],
            "excluded_fields": ["CMDLINE"],
        },
        [4, 8, 9, 10],
    )
    reintroduced_inputs = copy.deepcopy(inputs)
    reintroduced_inputs["capabilities"]["runner_service_log"] = legal_gate
    with pytest.raises(ValueError, match="verified_inputs.capabilities"):
        support.validate_verified_inputs(reintroduced_inputs)

    reintroduced_rows = copy.deepcopy(matrix)
    reintroduced_rows.append({
        "id": "runner-service",
        "boundary": "host",
        "vm_role": "runner",
        "class": "runner_service",
        "path_or_input": "/var/log/detection-engineering/runner-service.jsonl",
        "reader": "forwarder",
        "index": "de_runner",
        "sourcetype": "gitlab:runner",
        "safe_fields": ["_time", "host", "source", "sourcetype", "message"],
        "negative_fields": [],
        "required": True,
        "capability_gate": None,
    })
    with pytest.raises(ValueError, match="profile coverage"):
        support.project_forwarder_profile(
            "runner", reintroduced_rows, contract["forwarder_source_policy"]
        )


def test_laurel_artifact_and_native_privacy_contract(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    laurel = inputs["downloads"]["laurel"]
    assert laurel["status"] == "VERIFIED"
    assert laurel["observed"]["sha256"] == "110fd0436cb492fafab2ee68fcae681e611488baf376657ff9eab875608ceb6c"
    assert laurel["stops"] == [8, 9, 10]
    assert laurel["source"]["url"].endswith("/laurel-v0.6.3-x86_64-glibc.tar.gz")
    assert "statically inspected" in laurel["limitation"]
    assert "runtime gates" in laurel["limitation"]

    rows = _load(blueprint_root, read_yaml, "telemetry-matrix.yml")["sources"]
    audit_rows = [row for row in rows if row["class"] == "audit_process"]
    assert len(audit_rows) == 4
    for row in audit_rows:
        assert row["path_or_input"] == "/var/log/laurel/audit.log"
        assert row["sourcetype"] == "linux:audit:laurel"
        assert row["capability_gate"] is None
        assert row["negative_fields"] == []
        assert "argv" not in row["safe_fields"]
        assert "environment" not in row["safe_fields"]


def test_laurel_scope_docs_preserve_native_content_and_original_roles(repository_root):
    spec = (repository_root / "docs/superpowers/specs/2026-10-16-detection-engineering-design.md").read_text(encoding="utf-8")
    plan = (repository_root / "docs/superpowers/plans/2026-10-16-detection-engineering.md").read_text(encoding="utf-8")
    combined = spec + plan
    assert "Native command arguments/environment are not redaction failures" in spec
    assert "Telemetry redaction is not a V1 goal" in plan
    assert "Metadata-only Kubernetes audit remains a collection-scope choice" in plan
    assert "Canary zero-results" not in plan
    assert "absent from telemetry/evidence" not in plan
    assert "credential operation and evidence hygiene" in plan
    for role in (
        "role_linux_logging", "role_splunk_collector_linuxv",
        "role_k8s_telemetry_collection",
    ):
        assert role in combined
    assert "read-only" in combined
    assert "floating TLS-verification-disabled" in combined


def test_runtime_layouts_and_combined_packages_are_strictly_bound(blueprint_root, read_yaml):
    config = _load(blueprint_root, read_yaml, "range-config.yml")
    contract = config["ludus_extensions"]["detection_engineering_contract"]
    mappings = contract["role_variable_contracts"]["workload"]
    assert mappings["detection_docker_packages"]["operation"] == "combine_apt_package_gates"
    assert mappings["detection_otel_host_artifact"] == {
        "source": "product_pins.downloads.otel_host.observed",
        "type": "Artifact",
    }
    assert mappings["detection_runtime_artifact_layouts"]["operation"] == "bind_artifact_layouts"

    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    assert set(inputs["artifact_layouts"]) == {"minikube", "kubectl", "helm", "otel_host"}
    assert inputs["downloads"]["otel_host"]["status"] == "VERIFIED"
    assert inputs["downloads"]["otel_host"]["observed"] == _load(
        blueprint_root, read_yaml, "product-pins.yml"
    )["downloads"]["otel_host"]["observed"]

    def artifact(name, digest):
        return _synthetic_gate(
            {
                "version": "1.2.3",
                "build": None,
                "url": f"https://example.invalid/{name}",
                "sha256": digest,
                "download_auth_required": False,
            },
            [7, 8, 9, 10],
        )

    digests = {name: str(index) * 64 for index, name in enumerate(("minikube", "kubectl", "helm", "otel_host"), 1)}
    artifacts = {name: artifact(name, digest) for name, digest in digests.items()}
    layouts = {
        "minikube": _synthetic_gate(
            {"artifact_sha256": digests["minikube"], "format": "raw", "member": None},
            [7, 8, 9, 10],
        ),
        "kubectl": _synthetic_gate(
            {"artifact_sha256": digests["kubectl"], "format": "raw", "member": None},
            [7, 8, 9, 10],
        ),
        "helm": _synthetic_gate(
            {"artifact_sha256": digests["helm"], "format": "tar.gz", "member": "linux-amd64/helm"},
            [7, 8, 9, 10],
        ),
        "otel_host": _synthetic_gate(
            {"artifact_sha256": digests["otel_host"], "format": "tar.gz", "member": "otelcol-contrib"},
            [7, 8, 9, 10],
        ),
    }
    bound = support.bind_artifact_layouts(artifacts, layouts)
    assert bound == layouts
    assert set(bound["helm"]) == {"status", "source", "observed", "limitation", "stops"}

    mismatch = copy.deepcopy(layouts)
    mismatch["helm"]["observed"]["artifact_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="SHA"):
        support.bind_artifact_layouts(artifacts, mismatch)

    traversal = copy.deepcopy(layouts)
    traversal["helm"]["observed"]["member"] = "../helm"
    with pytest.raises(ValueError, match="safe relative"):
        support.bind_artifact_layouts(artifacts, traversal)

    raw_member = copy.deepcopy(layouts)
    raw_member["minikube"]["observed"]["member"] = "minikube"
    with pytest.raises(ValueError, match="null for raw"):
        support.bind_artifact_layouts(artifacts, raw_member)

    support.validate_archive_members(
        layouts["helm"]["observed"],
        [
            {"path": "linux-amd64", "type": "directory"},
            {"path": "linux-amd64/README", "type": "regular"},
            {"path": "linux-amd64/helm", "type": "regular"},
        ],
    )
    for bad_members in (
        [
            {"path": "linux-amd64/helm", "type": "regular"},
            {"path": "linux-amd64/helm", "type": "regular"},
        ],
        [{"path": "linux-amd64/helm", "type": "symlink"}],
        [{"path": "/linux-amd64/helm", "type": "regular"}],
        [{"path": "../helm", "type": "regular"}],
        [{"path": "linux-amd64/other", "type": "regular"}],
    ):
        with pytest.raises(ValueError):
            support.validate_archive_members(layouts["helm"]["observed"], bad_members)

    def package_gate(name, packages, repository="https://example.invalid/docker", key_url="https://example.invalid/key", fingerprint="SYNTHETIC-FINGERPRINT"):
        return _synthetic_gate(
            {
                "repository_url": repository,
                "signing_key_url": key_url,
                "signing_key_fingerprint": fingerprint,
                "packages": [{"name": package, "version": version} for package, version in packages],
            },
            [7, 8, 9, 10],
        )

    package_gates = {
        "docker": package_gate("docker", [("docker-ce", "1.2.3-1")]),
        "containerd": package_gate("containerd", [("containerd.io", "1.2.3-1")]),
        "docker_plugins": package_gate("docker_plugins", [("docker-buildx-plugin", "1.2.3-1"), ("docker-ce", "1.2.3-1")]),
    }
    combined = support.combine_apt_package_gates(package_gates)
    assert combined["packages"] == [
        {"name": "docker-ce", "version": "1.2.3-1"},
        {"name": "containerd.io", "version": "1.2.3-1"},
        {"name": "docker-buildx-plugin", "version": "1.2.3-1"},
    ]
    assert combined["repository_url"] == "https://example.invalid/docker"

    conflict = copy.deepcopy(package_gates)
    conflict["docker_plugins"]["observed"]["packages"][1]["version"] = "9.9.9-1"
    with pytest.raises(ValueError, match="conflicting.*docker-ce"):
        support.combine_apt_package_gates(conflict)

    mismatch_repo = copy.deepcopy(package_gates)
    mismatch_repo["containerd"]["observed"]["repository_url"] = "https://example.invalid/other"
    with pytest.raises(ValueError, match="repository/key"):
        support.combine_apt_package_gates(mismatch_repo)


def test_verified_inputs_strict_schema_rejects_malformed_verified_records(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    support.validate_verified_inputs(inputs)

    mutations = [
        ("templates", "gitlab"),
        ("capacity", None),
        ("network", None),
        ("apt", "gitlab"),
        ("downloads", "splunk"),
        ("downloads", "laurel"),
        ("artifact_layouts", "helm"),
        ("git", "malcolm"),
        ("charts", "otel"),
        ("capabilities", "splunk"),
        ("capabilities", "splunk_uninstall"),
        ("capabilities", "runner_api"),
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


def test_verified_inputs_separate_static_selection_from_runtime_acceptance(blueprint_root, read_yaml):
    inputs = _load(blueprint_root, read_yaml, "verified-inputs.yml")
    support.validate_verified_inputs(inputs)
    lifecycle = inputs["lifecycle"]
    assert lifecycle["selected_product_contract"]["status"] == "STATIC_APPROVED"
    assert lifecycle["selected_product_contract"]["required_for_initial_provisioning"] is True
    for phase in ("provisioning_time", "post_provisioning"):
        assert lifecycle[phase]["status"] == "PENDING"
        assert lifecycle[phase]["required_for_initial_provisioning"] is False
        assert lifecycle[phase]["evidence"] is None


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
