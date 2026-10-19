"""Shared test support for the detection-engineering blueprint."""

from __future__ import annotations

import os
import ipaddress
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BLUEPRINT_ROOT = REPOSITORY_ROOT / "blueprints" / "detection-engineering"


def load_yaml(path: Path) -> Any:
    """Load one YAML document from *path*."""

    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def _fail(path: str, message: str) -> None:
    raise ValueError(f"{path}: {message}")


def _keys(value: Any, expected: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    if set(value) != expected:
        _fail(path, f"keys must be {sorted(expected)}")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(path, "must be a nonempty string")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(path, f"must be an integer >= {minimum}")
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        _fail(path, "must be a boolean")
    return value


def _strings(value: Any, path: str) -> list[str]:
    if not isinstance(value, list):
        _fail(path, "must be a list")
    for index, item in enumerate(value):
        _string(item, f"{path}[{index}]")
    return value


def _https(value: Any, path: str) -> str:
    text = _string(value, path)
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.netloc:
        _fail(path, "must be an https URL")
    return text


def _source(value: Any, path: str) -> None:
    source = _keys(value, {"url", "observed_at"}, path)
    _https(source["url"], f"{path}.url")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(source["observed_at"])):
        _fail(f"{path}.observed_at", "must be RFC3339 UTC")


def _object_of_string_lists(value: Any, path: str) -> None:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    for key, items in value.items():
        _string(key, f"{path} key")
        _strings(items, f"{path}.{key}")


def _gate(value: Any, path: str, stops: list[int], observed_validator) -> None:
    gate = _keys(value, {"status", "source", "observed", "limitation", "stops"}, path)
    if gate["status"] not in {"VERIFIED", "BLOCKED"}:
        _fail(f"{path}.status", "must be VERIFIED or BLOCKED")
    _source(gate["source"], f"{path}.source")
    _string(gate["limitation"], f"{path}.limitation")
    if gate["stops"] != stops:
        _fail(f"{path}.stops", f"must equal {stops}")
    if gate["status"] == "BLOCKED":
        if gate["observed"] is not None:
            _fail(f"{path}.observed", "must be null while BLOCKED")
    else:
        if gate["observed"] is None:
            _fail(f"{path}.observed", "must not be null while VERIFIED")
        observed_validator(gate["observed"], f"{path}.observed")


def _template(value: Any, path: str) -> None:
    item = _keys(value, {"name", "os_type", "distribution", "major_version", "architecture", "built", "inherited_disk_gb"}, path)
    _string(item["name"], f"{path}.name")
    if item["os_type"] != "linux" or item["distribution"] != "Debian":
        _fail(path, "must be the selected Linux Debian template schema")
    _integer(item["major_version"], f"{path}.major_version", minimum=1)
    _string(item["architecture"], f"{path}.architecture")
    _boolean(item["built"], f"{path}.built")
    _integer(item["inherited_disk_gb"], f"{path}.inherited_disk_gb", minimum=1)


def _capacity(value: Any, path: str) -> None:
    item = _keys(
        value,
        {"total_ram_gb", "free_ram_gb", "reported_cpu_cores", "current_allocations", "storage_pools", "deployment_sufficient", "decision_basis"},
        path,
    )
    for key in ("total_ram_gb", "free_ram_gb", "reported_cpu_cores"):
        _integer(item[key], f"{path}.{key}", minimum=1)
    allocations = _keys(item["current_allocations"], {"ram_gb", "cpus", "storage_gb"}, f"{path}.current_allocations")
    for key, allocation in allocations.items():
        _integer(allocation, f"{path}.current_allocations.{key}", minimum=0)
    if not isinstance(item["storage_pools"], list) or not item["storage_pools"]:
        _fail(f"{path}.storage_pools", "must be a nonempty list")
    for index, pool_value in enumerate(item["storage_pools"]):
        pool = _keys(pool_value, {"name", "type", "size_gb", "used_gb", "free_gb"}, f"{path}.storage_pools[{index}]")
        _string(pool["name"], f"{path}.storage_pools[{index}].name")
        _string(pool["type"], f"{path}.storage_pools[{index}].type")
        for key in ("size_gb", "used_gb", "free_gb"):
            if isinstance(pool[key], bool) or not isinstance(pool[key], (int, float)) or pool[key] < 0:
                _fail(f"{path}.storage_pools[{index}].{key}", "must be nonnegative numeric data")
    if item["deployment_sufficient"] is not True:
        _fail(f"{path}.deployment_sufficient", "must be an explicit true decision")
    _string(item["decision_basis"], f"{path}.decision_basis")


def _network(value: Any, path: str) -> None:
    item = _keys(
        value,
        {
            "lab_cidr", "host_bridge", "host_bridge_promiscuous_mode", "range_cidr",
        },
        path,
    )
    for key in ("range_cidr", "lab_cidr", "host_bridge", "host_bridge_promiscuous_mode"):
        _string(item[key], f"{path}.{key}")


def _packages(value: Any, path: str) -> None:
    item = _keys(value, {"repository_url", "signing_key_url", "signing_key_fingerprint", "packages"}, path)
    _https(item["repository_url"], f"{path}.repository_url")
    _https(item["signing_key_url"], f"{path}.signing_key_url")
    _string(item["signing_key_fingerprint"], f"{path}.signing_key_fingerprint")
    if not isinstance(item["packages"], list) or not item["packages"]:
        _fail(f"{path}.packages", "must be a nonempty list")
    for index, package in enumerate(item["packages"]):
        pin = _keys(package, {"name", "version"}, f"{path}.packages[{index}]")
        _string(pin["name"], f"{path}.packages[{index}].name")
        version = _string(pin["version"], f"{path}.packages[{index}].version")
        if any(token in version for token in ("*", ">", "<", "~=", "^")):
            _fail(f"{path}.packages[{index}].version", "must be exactly pinned")


def _artifact(value: Any, path: str) -> None:
    item = _keys(value, {"version", "build", "url", "sha256", "download_auth_required"}, path)
    _string(item["version"], f"{path}.version")
    if item["build"] is not None:
        _string(item["build"], f"{path}.build")
    _https(item["url"], f"{path}.url")
    if not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
        _fail(f"{path}.sha256", "must be 64 lowercase hexadecimal characters")
    _boolean(item["download_auth_required"], f"{path}.download_auth_required")
    if path.endswith(("downloads.splunk.observed", "downloads.forwarder.observed")) and not item["url"].endswith(".deb"):
        _fail(f"{path}.url", "V1 Splunk artifacts must be Debian packages")


def _artifact_layout(value: Any, path: str) -> None:
    item = _keys(value, {"artifact_sha256", "format", "member"}, path)
    if not re.fullmatch(r"[0-9a-f]{64}", str(item["artifact_sha256"])):
        _fail(f"{path}.artifact_sha256", "must be 64 lowercase hexadecimal characters")
    if item["format"] not in {"raw", "tar.gz"}:
        _fail(f"{path}.format", "must be raw or tar.gz")
    if item["format"] == "raw":
        if item["member"] is not None:
            _fail(f"{path}.member", "must be null for raw artifacts")
        return
    member = _string(item["member"], f"{path}.member")
    member_path = Path(member)
    if member_path.is_absolute() or ".." in member_path.parts or member in {".", ""}:
        _fail(f"{path}.member", "must be a safe relative path")


def _git_pin(value: Any, path: str) -> None:
    item = _keys(value, {"repository", "tag", "commit"}, path)
    _https(item["repository"], f"{path}.repository")
    _string(item["tag"], f"{path}.tag")
    if not re.fullmatch(r"[0-9a-f]{40}", str(item["commit"])):
        _fail(f"{path}.commit", "must be 40 lowercase hexadecimal characters")


def _chart(value: Any, path: str) -> None:
    item = _keys(value, {"repository", "chart", "version", "digest"}, path)
    _https(item["repository"], f"{path}.repository")
    for key in ("chart", "version", "digest"):
        _string(item[key], f"{path}.{key}")


def _splunk_capability(value: Any, path: str) -> None:
    item = _keys(
        value,
        {
            "initial_mode", "trial_days_user_confirmed", "terms_confirmation",
            "expiry_behavior", "hec", "search_api", "auth_behavior",
        },
        path,
    )
    if item["initial_mode"] != "ENTERPRISE_60_DAY_TRIAL":
        _fail(f"{path}.initial_mode", "must be ENTERPRISE_60_DAY_TRIAL")
    if item["trial_days_user_confirmed"] != 60:
        _fail(f"{path}.trial_days_user_confirmed", "must equal 60")
    if item["terms_confirmation"] != "USER_CONFIRMED_NOT_INDEPENDENTLY_VERIFIED":
        _fail(f"{path}.terms_confirmation", "has the wrong confirmation type")
    _string(item["expiry_behavior"], f"{path}.expiry_behavior")
    _boolean(item["hec"], f"{path}.hec")
    _boolean(item["search_api"], f"{path}.search_api")
    _string(item["auth_behavior"], f"{path}.auth_behavior")


def _splunk_free(value: Any, path: str) -> None:
    item = _keys(value, {"version", "perpetual_free", "hec", "search_api", "auth_behavior"}, path)
    _string(item["version"], f"{path}.version")
    for key in ("perpetual_free", "hec", "search_api"):
        _boolean(item[key], f"{path}.{key}")
    _string(item["auth_behavior"], f"{path}.auth_behavior")


def _uninstall(value: Any, path: str) -> None:
    item = _keys(
        value,
        {
            "package_name", "version", "build", "architecture", "package_sha256",
            "metadata_reviewed", "maintainer_script_sha256s", "remove_argv",
            "required_preserve_paths", "disposable_preservation_test",
        },
        path,
    )
    if item["package_name"] != "splunk" or item["architecture"] != "amd64":
        _fail(path, "must describe the splunk amd64 package")
    _string(item["version"], f"{path}.version")
    _string(item["build"], f"{path}.build")
    if not re.fullmatch(r"[0-9a-f]{64}", str(item["package_sha256"])):
        _fail(f"{path}.package_sha256", "must be sha256")
    if item["metadata_reviewed"] is not True:
        _fail(f"{path}.metadata_reviewed", "must be true")
    if not isinstance(item["maintainer_script_sha256s"], dict):
        _fail(f"{path}.maintainer_script_sha256s", "must be an object")
    for name, digest in item["maintainer_script_sha256s"].items():
        _string(name, f"{path}.maintainer_script_sha256s key")
        if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            _fail(f"{path}.maintainer_script_sha256s.{name}", "must be sha256")
    if item["remove_argv"] != ["dpkg", "-r", "splunk"]:
        _fail(f"{path}.remove_argv", "must be the reviewed non-purge argv")
    _strings(item["required_preserve_paths"], f"{path}.required_preserve_paths")
    preservation = _keys(item["disposable_preservation_test"], {"passed", "fixture_manifest_sha256"}, f"{path}.disposable_preservation_test")
    if preservation["passed"] is not True:
        _fail(f"{path}.disposable_preservation_test.passed", "must be true")
    if not re.fullmatch(r"[0-9a-f]{64}", str(preservation["fixture_manifest_sha256"])):
        _fail(f"{path}.disposable_preservation_test.fixture_manifest_sha256", "must be sha256")


def _runner_api(value: Any, path: str) -> None:
    item = _keys(value, {"bootstrap_auth", "manager"}, path)
    bootstrap = _keys(
        item["bootstrap_auth"],
        {"credential_type", "scopes", "expiration_days", "creation_argv", "protected_path", "mode", "revoke_endpoint", "revoke_method"},
        f"{path}.bootstrap_auth",
    )
    for key in ("credential_type", "revoke_endpoint", "revoke_method"):
        _string(bootstrap[key], f"{path}.bootstrap_auth.{key}")
    if bootstrap["credential_type"] != "personal_access_token":
        _fail(f"{path}.bootstrap_auth.credential_type", "must be personal_access_token")
    if bootstrap["scopes"] != ["create_runner", "manage_runner", "read_api"]:
        _fail(f"{path}.bootstrap_auth.scopes", "must use the selected-version conventional PAT scopes")
    if bootstrap["expiration_days"] != 1:
        _fail(f"{path}.bootstrap_auth.expiration_days", "must equal one")
    _strings(bootstrap["creation_argv"], f"{path}.bootstrap_auth.creation_argv")
    if bootstrap["protected_path"] != "/etc/detection-engineering/secrets/runner-api-bootstrap.token" or bootstrap["mode"] != "0600":
        _fail(f"{path}.bootstrap_auth", "has the wrong protected path or mode")
    manager = _keys(
        item["manager"],
        {
            "runner_type", "create_scope", "manage_scope", "read_scope",
            "create_endpoint", "create_method", "lookup_endpoint", "lookup_method",
            "detail_endpoint", "detail_method", "update_endpoint", "update_method",
            "request_fields", "response_token_field", "local_verify_command", "pause_at_create",
        },
        f"{path}.manager",
    )
    for key in ("runner_type", "create_scope", "manage_scope", "read_scope", "create_endpoint", "create_method", "lookup_endpoint", "lookup_method", "detail_endpoint", "detail_method", "update_endpoint", "update_method", "response_token_field"):
        _string(manager[key], f"{path}.manager.{key}")
    if [manager["create_scope"], manager["manage_scope"], manager["read_scope"]] != bootstrap["scopes"]:
        _fail(f"{path}.manager", "scope fields must match the conventional PAT scopes")
    _strings(manager["request_fields"], f"{path}.manager.request_fields")
    _strings(manager["local_verify_command"], f"{path}.manager.local_verify_command")
    if manager["pause_at_create"] is not True:
        _fail(f"{path}.manager.pause_at_create", "must be true")


def _readiness(value: Any, path: str) -> None:
    item = _keys(value, {"transport_base_url", "endpoint", "method", "success_statuses", "attempts", "delay_seconds"}, path)
    if item["transport_base_url"] != "http://localhost" or item["endpoint"] != "/-/readiness" or item["method"] != "GET" or item["success_statuses"] != [200]:
        _fail(path, "must use the selected-version loopback readiness route")
    _integer(item["attempts"], f"{path}.attempts", minimum=1)
    _integer(item["delay_seconds"], f"{path}.delay_seconds")


def _runner_jobs(value: Any, path: str) -> None:
    item = _keys(value, {"endpoint", "method"}, path)
    if item != {"endpoint": "/api/v4/runners/:id/jobs", "method": "GET"}:
        _fail(path, "must use the selected-version runner jobs route")


def _forwarder_bootstrap(value: Any, path: str) -> None:
    item = _keys(value, {"version", "build", "seed", "first_start", "boot_start", "unit"}, path)
    if item["version"] != "10.6.1.1" or item["build"] != "b2ae2962645c":
        _fail(path, "must match the selected forwarder package")
    _keys(item["seed"], {"path", "section", "username_key", "username", "password_key", "mode", "owner", "group"}, f"{path}.seed")
    _keys(item["first_start"], {"identity", "argv"}, f"{path}.first_start")
    _keys(item["boot_start"], {"identity", "argv"}, f"{path}.boot_start")
    _keys(item["unit"], {"path", "service_name", "effective_user"}, f"{path}.unit")


def _otel(value: Any, path: str) -> None:
    item = _keys(value, {"secret_file_provider", "audit_path", "node_log_inputs", "required_rbac"}, path)
    _boolean(item["secret_file_provider"], f"{path}.secret_file_provider")
    _string(item["audit_path"], f"{path}.audit_path")
    _strings(item["node_log_inputs"], f"{path}.node_log_inputs")
    _object_of_string_lists(item["required_rbac"], f"{path}.required_rbac")


def _test_tools(value: Any, path: str) -> None:
    item = _keys(value, {"pytest", "PyYAML", "jsonschema", "ansible-core", "ansible-lint", "yamllint"}, path)
    for name, version in item.items():
        if not re.fullmatch(r"\d+(?:\.\d+)+", str(version)):
            _fail(f"{path}.{name}", "must be an exact numeric version")


def validate_verified_inputs(inputs: Any) -> None:
    """Validate the complete Task 1 Gate/FutureGate contract."""

    root = _keys(
        inputs,
        {
            "schema_version", "verified_at", "user_supplied_candidates", "templates",
            "capacity", "network", "apt", "downloads", "artifact_layouts", "git", "charts",
            "capabilities", "test_tools", "lifecycle",
        },
        "verified_inputs",
    )
    if root["schema_version"] != 2:
        _fail("verified_inputs.schema_version", "must equal 2")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(root["verified_at"])):
        _fail("verified_inputs.verified_at", "must be RFC3339 UTC")

    candidates = _keys(
        root["user_supplied_candidates"],
        {"splunk_10_6_1_1", "splunk_initial_trial"},
        "verified_inputs.user_supplied_candidates",
    )

    def candidate_observed(value: Any, path: str) -> None:
        item = _keys(
            value,
            {
                "provenance", "version", "build", "enterprise_deb_url",
                "forwarder_deb_url", "forwarder_tgz_reference_url",
                "windows_msi_reference_url",
            },
            path,
        )
        if item["provenance"] != "USER_SUPPLIED_UNVERIFIED" or item["version"] != "10.6.1.1" or item["build"] != "b2ae2962645c":
            _fail(path, "has incorrect provenance, version, or build")
        for key in ("enterprise_deb_url", "forwarder_deb_url", "forwarder_tgz_reference_url", "windows_msi_reference_url"):
            _https(item[key], f"{path}.{key}")
        if not item["enterprise_deb_url"].endswith(".deb") or not item["forwarder_deb_url"].endswith(".deb"):
            _fail(path, "V1 candidates must be Debian packages")
        if not item["forwarder_tgz_reference_url"].endswith(".tgz") or not item["windows_msi_reference_url"].endswith(".msi"):
            _fail(path, "reference formats are incorrect")

    _gate(candidates["splunk_10_6_1_1"], "verified_inputs.user_supplied_candidates.splunk_10_6_1_1", [], candidate_observed)
    confirmation = _keys(
        candidates["splunk_initial_trial"],
        {"record_type", "status", "source", "observed", "limitation", "stops"},
        "verified_inputs.user_supplied_candidates.splunk_initial_trial",
    )
    if confirmation["record_type"] != "USER_CONFIRMATION" or confirmation["status"] != "CONFIRMED":
        _fail("verified_inputs.user_supplied_candidates.splunk_initial_trial", "must be a confirmed user confirmation")
    confirmation_source = _keys(
        confirmation["source"],
        {"kind", "recorded_at"},
        "verified_inputs.user_supplied_candidates.splunk_initial_trial.source",
    )
    if confirmation_source["kind"] != "USER_CONFIRMATION":
        _fail("verified_inputs.user_supplied_candidates.splunk_initial_trial.source.kind", "must be USER_CONFIRMATION")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(confirmation_source["recorded_at"])):
        _fail("verified_inputs.user_supplied_candidates.splunk_initial_trial.source.recorded_at", "must be RFC3339 UTC")
    _string(confirmation["limitation"], "verified_inputs.user_supplied_candidates.splunk_initial_trial.limitation")
    if confirmation["stops"] != []:
        _fail("verified_inputs.user_supplied_candidates.splunk_initial_trial.stops", "must be empty")
    confirmed = _keys(
        confirmation["observed"],
        {"initial_mode", "trial_days_user_confirmed", "terms_confirmation"},
        "verified_inputs.user_supplied_candidates.splunk_initial_trial.observed",
    )
    if confirmed != {
        "initial_mode": "ENTERPRISE_60_DAY_TRIAL",
        "trial_days_user_confirmed": 60,
        "terms_confirmation": "USER_CONFIRMED_NOT_INDEPENDENTLY_VERIFIED",
    }:
        _fail("verified_inputs.user_supplied_candidates.splunk_initial_trial.observed", "has incorrect confirmation fields")

    templates = _keys(root["templates"], {"gitlab", "runner", "malcolm", "splunk", "workload"}, "verified_inputs.templates")
    for name, value in templates.items():
        _gate(value, f"verified_inputs.templates.{name}", [10], _template)
    _gate(root["capacity"], "verified_inputs.capacity", [10], _capacity)
    _gate(root["network"], "verified_inputs.network", [10], _network)

    apt = _keys(root["apt"], {"gitlab", "runner", "docker", "containerd", "docker_plugins"}, "verified_inputs.apt")
    apt_stops = {"gitlab": [5, 8, 9, 10], "runner": [6, 8, 9, 10], "docker": [7, 8, 9, 10], "containerd": [7, 8, 9, 10], "docker_plugins": [7, 8, 9, 10]}
    for name, value in apt.items():
        _gate(value, f"verified_inputs.apt.{name}", apt_stops[name], _packages)

    downloads = _keys(root["downloads"], {"splunk", "forwarder", "laurel", "minikube", "kubectl", "helm", "otel_host"}, "verified_inputs.downloads")
    download_stops = {"splunk": [3, 4, 7, 8, 9, 10], "forwarder": [4, 8, 9, 10], "laurel": [8, 9, 10], "minikube": [7, 8, 9, 10], "kubectl": [7, 8, 9, 10], "helm": [7, 8, 9, 10], "otel_host": [7, 8, 9, 10]}
    for name, value in downloads.items():
        _gate(value, f"verified_inputs.downloads.{name}", download_stops[name], _artifact)
    candidate_urls = candidates["splunk_10_6_1_1"]["observed"]
    required_v1_urls = {
        "splunk": candidate_urls["enterprise_deb_url"],
        "forwarder": candidate_urls["forwarder_deb_url"],
    }
    for name, required_url in required_v1_urls.items():
        if downloads[name]["status"] == "VERIFIED" and downloads[name]["observed"]["url"] != required_url:
            _fail(f"verified_inputs.downloads.{name}.observed.url", "must equal the canonical V1 candidate URL")

    artifact_layouts = _keys(
        root["artifact_layouts"],
        {"minikube", "kubectl", "helm", "otel_host"},
        "verified_inputs.artifact_layouts",
    )
    for name, value in artifact_layouts.items():
        _gate(
            value,
            f"verified_inputs.artifact_layouts.{name}",
            [7, 8, 9, 10],
            _artifact_layout,
        )

    git = _keys(root["git"], {"malcolm"}, "verified_inputs.git")
    _gate(git["malcolm"], "verified_inputs.git.malcolm", [7, 8, 9, 10], _git_pin)
    charts = _keys(root["charts"], {"otel"}, "verified_inputs.charts")
    _gate(charts["otel"], "verified_inputs.charts.otel", [7, 8, 9, 10], _chart)

    capabilities = _keys(root["capabilities"], {"splunk", "splunk_free", "splunk_uninstall", "runner_api", "gitlab_readiness_contract", "runner_jobs_contract", "forwarder_bootstrap_contract", "otel"}, "verified_inputs.capabilities")
    _gate(capabilities["splunk"], "verified_inputs.capabilities.splunk", [3, 4, 7, 8, 9, 10], _splunk_capability)
    future = _keys(capabilities["splunk_free"], {"status", "source", "observed", "limitation"}, "verified_inputs.capabilities.splunk_free")
    if future["status"] not in {"UNVERIFIED", "VERIFIED", "INCOMPATIBLE"}:
        _fail("verified_inputs.capabilities.splunk_free.status", "has an invalid FutureGate status")
    _source(future["source"], "verified_inputs.capabilities.splunk_free.source")
    _string(future["limitation"], "verified_inputs.capabilities.splunk_free.limitation")
    if future["status"] == "UNVERIFIED" and future["observed"] is not None:
        _fail("verified_inputs.capabilities.splunk_free.observed", "must be null while UNVERIFIED")
    if future["status"] == "VERIFIED":
        if future["observed"] is None:
            _fail("verified_inputs.capabilities.splunk_free.observed", "must not be null while VERIFIED")
        _splunk_free(future["observed"], "verified_inputs.capabilities.splunk_free.observed")
    if future["status"] == "INCOMPATIBLE" and future["observed"] is not None:
        _splunk_free(future["observed"], "verified_inputs.capabilities.splunk_free.observed")
    _gate(capabilities["splunk_uninstall"], "verified_inputs.capabilities.splunk_uninstall", [11], _uninstall)
    _gate(capabilities["runner_api"], "verified_inputs.capabilities.runner_api", [5, 6, 8, 9, 10], _runner_api)
    _gate(capabilities["gitlab_readiness_contract"], "verified_inputs.capabilities.gitlab_readiness_contract", [5, 6, 8, 9, 10], _readiness)
    _gate(capabilities["runner_jobs_contract"], "verified_inputs.capabilities.runner_jobs_contract", [6, 8, 9, 10], _runner_jobs)
    _gate(capabilities["forwarder_bootstrap_contract"], "verified_inputs.capabilities.forwarder_bootstrap_contract", [4, 8, 9, 10], _forwarder_bootstrap)
    _gate(capabilities["otel"], "verified_inputs.capabilities.otel", [7, 8, 9, 10], _otel)
    _gate(root["test_tools"], "verified_inputs.test_tools", [1, 2, 3, 4, 5, 6, 7, 8, 9], _test_tools)

    lifecycle = _keys(
        root["lifecycle"],
        {"selected_product_contract", "provisioning_time", "post_provisioning"},
        "verified_inputs.lifecycle",
    )
    selected = _keys(
        lifecycle["selected_product_contract"],
        {"status", "source", "gate_paths", "limitation", "required_for_initial_provisioning"},
        "verified_inputs.lifecycle.selected_product_contract",
    )
    if selected["status"] not in {"STATIC_APPROVED", "BLOCKED"}:
        _fail("verified_inputs.lifecycle.selected_product_contract.status", "must be STATIC_APPROVED or BLOCKED")
    source = _keys(
        selected["source"], {"kind", "reference", "observed_at"},
        "verified_inputs.lifecycle.selected_product_contract.source",
    )
    if source != {
        "kind": "LOCAL_REVIEWED_STATIC_EVIDENCE",
        "reference": "product-pin-provenance.md",
        "observed_at": "2026-10-18T18:30:00Z",
    }:
        _fail("verified_inputs.lifecycle.selected_product_contract.source", "must cite the frozen reviewed static evidence")
    expected_static_paths = sorted(
        f"{section}.{name}"
        for section, names in {
            "apt": {"gitlab", "runner", "docker", "containerd", "docker_plugins"},
            "downloads": {"splunk", "forwarder", "laurel", "minikube", "kubectl", "helm", "otel_host"},
            "artifact_layouts": {"minikube", "kubectl", "helm", "otel_host"},
            "git": {"malcolm"},
            "charts": {"otel"},
            "capabilities": {"splunk", "runner_api", "gitlab_readiness_contract", "runner_jobs_contract", "forwarder_bootstrap_contract", "otel"},
        }.items()
        for name in names
    )
    if selected["gate_paths"] != expected_static_paths:
        _fail("verified_inputs.lifecycle.selected_product_contract.gate_paths", "must exactly name the selected static product facts")
    if selected["required_for_initial_provisioning"] is not True:
        _fail("verified_inputs.lifecycle.selected_product_contract.required_for_initial_provisioning", "must be true")
    _string(selected["limitation"], "verified_inputs.lifecycle.selected_product_contract.limitation")
    expected_phase_checks = {
        "provisioning_time": [
            "existing_debian_account_and_home",
            "guest_capture_interface_discovery_and_validation",
            "selected_product_installation_and_bootstrap",
            "native_producer_and_service_readiness",
        ],
        "post_provisioning": [
            "gitlab_external_readiness",
            "runner_registered_paused_and_zero_jobs",
            "splunk_hec_search_and_authentication",
            "telemetry_delivery_and_packet_visibility",
            "credential_cleanup_and_final_service_state",
        ],
    }
    for phase, expected_checks in expected_phase_checks.items():
        record = _keys(
            lifecycle[phase],
            {"status", "required_for_initial_provisioning", "checks", "evidence", "limitation"},
            f"verified_inputs.lifecycle.{phase}",
        )
        if record["status"] != "PENDING" or record["evidence"] is not None:
            _fail(f"verified_inputs.lifecycle.{phase}", "must remain PENDING without runtime evidence")
        if record["required_for_initial_provisioning"] is not False:
            _fail(f"verified_inputs.lifecycle.{phase}.required_for_initial_provisioning", "must be false")
        if record["checks"] != expected_checks:
            _fail(f"verified_inputs.lifecycle.{phase}.checks", "does not match the lifecycle contract")
        _string(record["limitation"], f"verified_inputs.lifecycle.{phase}.limitation")


def _synthetic_source(sources: Mapping[str, Any], name: str) -> Any:
    if name not in sources:
        _fail(name, "missing source")
    return sources[name]


def _mapping_input(specification: Any, sources: Mapping[str, Any], path: str) -> Any:
    item = _keys(specification, {"source"} if isinstance(specification, dict) and "source" in specification else {"value"}, path)
    if "source" in item:
        return _synthetic_source(sources, item["source"])
    return item["value"]


def _lab_ip(cidr: Any, last_octet: Any, path: str) -> str:
    cidr_text = _string(cidr, f"{path}.lab_cidr")
    octet = _integer(last_octet, f"{path}.ip_last_octet", minimum=1)
    try:
        network = ipaddress.ip_network(cidr_text, strict=False)
    except ValueError as error:
        _fail(f"{path}.lab_cidr", f"must be a valid network: {error}")
    if network.version != 4 or network.prefixlen != 24 or octet > 253:
        _fail(path, "derive_lab_ip requires an IPv4 /24 and last octet 1..253")
    return str(network.network_address + octet)


def _planned_vm(planned_vms: Any, role: Any, path: str) -> dict[str, Any]:
    if not isinstance(planned_vms, list):
        _fail(f"{path}.planned_vms", "must be a list")
    role_name = _string(role, f"{path}.role")
    matches = [vm for vm in planned_vms if isinstance(vm, dict) and vm.get("identity_suffix") == role_name]
    if len(matches) != 1:
        _fail(path, f"dependency role {role_name!r} must match exactly one planned VM")
    return matches[0]


def _verified_gate_observed(
    gate: Any,
    path: str,
    stops: list[int],
    validator,
) -> Any:
    _gate(gate, path, stops, validator)
    if gate["status"] != "VERIFIED":
        _fail(path, "must be VERIFIED before contract materialization")
    return gate["observed"]


def validate_telemetry_negative_fields(rows: Any) -> None:
    """Allow only the explicit Kubernetes audit collection-scope exclusions."""

    if not isinstance(rows, list):
        _fail("telemetry.sources", "must be a list")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            _fail(f"telemetry.sources[{index}]", "must be an object")
        source_id = _string(row.get("id"), f"telemetry.sources[{index}].id")
        actual = _strings(
            row.get("negative_fields"),
            f"telemetry.sources[{index}].negative_fields",
        )
        expected = (
            ["request_body", "response_body"]
            if source_id == "minikube-api-audit"
            else []
        )
        if actual != expected:
            if expected:
                _fail(
                    f"telemetry.sources[{index}].negative_fields",
                    "must contain only the Kubernetes audit collection-scope body exclusions",
                )
            _fail(
                f"telemetry.sources[{index}].negative_fields",
                "blanket telemetry redaction is forbidden",
            )


def _validate_forwarder_policy(policy: Any, path: str) -> None:
    expected = {
        "common": [
            {
                "id_suffix": "auth",
                "path": "/var/log/auth.log",
                "index": "de_linux",
                "sourcetype": "linux:auth",
            },
            {
                "id_suffix": "system",
                "path": "/var/log/syslog",
                "index": "de_linux",
                "sourcetype": "linux:system",
            },
            {
                "id_suffix": "audit-laurel",
                "path": "/var/log/laurel/audit.log",
                "index": "de_linux",
                "sourcetype": "linux:audit:laurel",
            },
        ],
        "profiles": {
            "gitlab": {"required_ids": []},
            "runner": {
                "required_ids": ["runner-registration"],
                "registration_path": "/var/log/detection-engineering/runner-registration.jsonl",
            },
            "workload": {"required_ids": []},
        },
    }
    if policy != expected:
        _fail(path, "must equal the canonical forwarder source/profile policy")


def _matrix_row(rows: list[dict[str, Any]], source_id: str, path: str) -> dict[str, Any]:
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == source_id]
    if len(matches) != 1:
        _fail(path, f"common/profile coverage requires exactly one {source_id} row")
    return matches[0]


def _project_input(row: dict[str, Any], path: str) -> dict[str, Any]:
    return {
        "path": path,
        "index": row["index"],
        "sourcetype": row["sourcetype"],
        "safe_fields": list(row["safe_fields"]),
    }


def project_forwarder_profile(
    profile: str,
    matrix_rows: Any,
    policy: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Project one canonical Linux-only V1 forwarder profile."""

    _validate_forwarder_policy(policy, "contract.forwarder_source_policy")
    if not isinstance(matrix_rows, list):
        _fail("forwarder.matrix", "must be a list")
    validate_telemetry_negative_fields(matrix_rows)
    projected: list[dict[str, Any]] = []
    expected_ids = set()
    for common in policy["common"]:
        source_id = f"{profile}-{common['id_suffix']}"
        expected_ids.add(source_id)
        row = _matrix_row(matrix_rows, source_id, "forwarder.common coverage")
        actual = (row.get("path_or_input"), row.get("index"), row.get("sourcetype"), row.get("reader"))
        expected = (common["path"], common["index"], common["sourcetype"], "forwarder")
        if actual != expected:
            _fail(f"forwarder.canonical.{source_id}", "does not match canonical common path/index/sourcetype/reader")
        projected.append(_project_input(row, common["path"]))

    profile_policy = policy["profiles"][profile]
    expected_ids.update(profile_policy["required_ids"])
    if profile == "runner":
        registration = _matrix_row(matrix_rows, "runner-registration", "forwarder.runner coverage")
        if registration.get("path_or_input") != profile_policy["registration_path"]:
            _fail("forwarder.canonical.runner-registration", "must use the canonical registration path")
        projected.append(_project_input(registration, profile_policy["registration_path"]))
    actual_profile_ids = {
        row["id"]
        for row in matrix_rows
        if isinstance(row, dict) and row.get("vm_role") == profile and row.get("reader") == "forwarder"
    }
    if actual_profile_ids != expected_ids:
        _fail("forwarder.profile coverage", f"expected {sorted(expected_ids)}, got {sorted(actual_profile_ids)}")
    return projected


def combine_apt_package_gates(gates: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and combine the three exact Docker-family package gates."""

    if set(gates) != {"docker", "containerd", "docker_plugins"}:
        _fail("apt.package_gates", "must contain docker, containerd, and docker_plugins")
    observed = {
        name: _verified_gate_observed(
            gates[name], f"apt.package_gates.{name}", [7, 8, 9, 10], _packages
        )
        for name in ("docker", "containerd", "docker_plugins")
    }
    identities = {
        (
            value["repository_url"],
            value["signing_key_url"],
            value["signing_key_fingerprint"],
        )
        for value in observed.values()
    }
    if len(identities) != 1:
        _fail("apt.package_gates", "repository/key identity mismatch")
    packages: list[dict[str, str]] = []
    versions: dict[str, str] = {}
    for gate_name in ("docker", "containerd", "docker_plugins"):
        for package in observed[gate_name]["packages"]:
            existing = versions.get(package["name"])
            if existing is not None and existing != package["version"]:
                _fail(
                    "apt.package_gates",
                    f"conflicting duplicate versions for {package['name']}",
                )
            if existing is None:
                versions[package["name"]] = package["version"]
                packages.append(dict(package))
    repository_url, signing_key_url, fingerprint = next(iter(identities))
    return {
        "packages": packages,
        "repository_url": repository_url,
        "signing_key_url": signing_key_url,
        "signing_key_fingerprint": fingerprint,
    }


def bind_artifact_layouts(
    artifact_gates: Mapping[str, Any],
    layout_gates: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind four full layout gates to four full artifact gates by SHA-256."""

    names = {"minikube", "kubectl", "helm", "otel_host"}
    if set(artifact_gates) != names or set(layout_gates) != names:
        _fail("artifact_layouts", "artifact and layout maps must contain all four runtime tools")
    for name in sorted(names):
        artifact = _verified_gate_observed(
            artifact_gates[name], f"artifact_layouts.{name}.artifact", [7, 8, 9, 10], _artifact
        )
        layout = _verified_gate_observed(
            layout_gates[name], f"artifact_layouts.{name}.layout", [7, 8, 9, 10], _artifact_layout
        )
        if artifact["sha256"] != layout["artifact_sha256"]:
            _fail(f"artifact_layouts.{name}", "artifact/layout SHA mismatch")
    return dict(layout_gates)


def validate_archive_members(layout: Mapping[str, Any], members: Any) -> None:
    """Validate the exact selected tar member without extracting an archive."""

    _artifact_layout(layout, "archive.layout")
    if layout["format"] == "raw":
        if members not in ([], None):
            _fail("archive.members", "raw artifacts must not have archive members")
        return
    if not isinstance(members, list):
        _fail("archive.members", "must be a list")
    seen: set[str] = set()
    matching_regular = 0
    for index, member in enumerate(members):
        item = _keys(member, {"path", "type"}, f"archive.members[{index}]")
        member_path = _string(item["path"], f"archive.members[{index}].path")
        parsed = Path(member_path)
        if parsed.is_absolute() or ".." in parsed.parts:
            _fail(f"archive.members[{index}].path", "must be a safe relative path")
        if member_path in seen:
            _fail(f"archive.members[{index}].path", "duplicate member")
        seen.add(member_path)
        if item["type"] not in {"regular", "directory"}:
            _fail(f"archive.members[{index}].type", "links and special members are forbidden")
        if member_path == layout["member"] and item["type"] == "regular":
            matching_regular += 1
    if matching_regular != 1:
        _fail("archive.members", "must contain exactly one matching regular member")


def _apply_mapping_operation(operation: str, inputs: dict[str, Any], path: str) -> Any:
    if operation == "derive_lab_ip":
        return _lab_ip(inputs["lab_cidr"], inputs["ip_last_octet"], path)

    if operation == "lookup_dependency_host":
        dependency = _planned_vm(inputs["planned_vms"], inputs["role"], path)
        return _string(dependency.get("host_id_template"), f"{path}.dependency.host_id_template")

    if operation == "build_dependency_url":
        dependency = _planned_vm(inputs["planned_vms"], inputs["role"], path)
        host = _string(dependency.get("host_id_template"), f"{path}.dependency.host_id_template")
        scheme = _string(inputs["scheme"], f"{path}.scheme")
        if scheme not in {"http", "https"}:
            _fail(f"{path}.scheme", "must be http or https")
        port = _integer(inputs["port"], f"{path}.port", minimum=1)
        request_path = _string(inputs["path"], f"{path}.path")
        if not request_path.startswith("/"):
            _fail(f"{path}.path", "must be absolute")
        return f"{scheme}://{host}:{port}{request_path}"

    if operation == "map_laurel_read_user":
        return map_laurel_read_user(inputs["profile"])

    if operation == "project_forwarder_inputs":
        return project_forwarder_profile(
            inputs["profile"], inputs["telemetry_sources"], inputs["policy"]
        )

    if operation == "project_runtime_artifact":
        artifact = _keys(
            inputs["artifact"],
            {"version", "build", "url", "sha256", "download_auth_required"},
            f"{path}.artifact",
        )
        return {
            "version": artifact["version"],
            "url": artifact["url"],
            "sha256": artifact["sha256"],
            "download_auth_required": artifact["download_auth_required"],
        }

    if operation in {"combine_apt_package_gates", "project_combined_apt_field"}:
        combined = combine_apt_package_gates(
            {
                "docker": inputs["docker_gate"],
                "containerd": inputs["containerd_gate"],
                "docker_plugins": inputs["docker_plugins_gate"],
            }
        )
        if operation == "combine_apt_package_gates":
            return combined["packages"]
        field = inputs["field"]
        if field not in {"repository_url", "signing_key_url", "signing_key_fingerprint"}:
            _fail(path, "combined apt field is not supported")
        return combined[field]

    if operation == "bind_artifact_layouts":
        return bind_artifact_layouts(
            {
                "minikube": inputs["minikube_artifact_gate"],
                "kubectl": inputs["kubectl_artifact_gate"],
                "helm": inputs["helm_artifact_gate"],
                "otel_host": inputs["otel_host_artifact_gate"],
            },
            {
                "minikube": inputs["minikube_layout_gate"],
                "kubectl": inputs["kubectl_layout_gate"],
                "helm": inputs["helm_layout_gate"],
                "otel_host": inputs["otel_host_layout_gate"],
            },
        )

    _fail(path, f"unsupported mapping operation {operation!r}")


def map_laurel_read_user(profile: Any) -> str:
    """Map each supported host to its actual native Laurel reader account."""

    if profile in {"gitlab", "runner", "workload"}:
        return "splunkfwd"
    if profile == "splunk":
        return "splunk"
    _fail("Laurel host profile", "must be gitlab, runner, workload, or splunk")


def _assignable(value: Any, type_name: str, path: str) -> None:
    if type_name == "bool":
        _boolean(value, path)
    elif type_name == "int":
        _integer(value, path)
    elif type_name == "int|null":
        if value is not None:
            _integer(value, path)
    elif type_name == "str":
        if not isinstance(value, str):
            _fail(path, "must be a string")
    elif type_name == "str|null":
        if value is not None and not isinstance(value, str):
            _fail(path, "must be a string or null")
    elif type_name == "absolute_path":
        if not isinstance(value, str) or not value.startswith("/"):
            _fail(path, "must be an absolute path")
    elif type_name == "linux_user":
        if not isinstance(value, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value):
            _fail(path, "must be a Linux user name")
    elif type_name == "hex40":
        if not re.fullmatch(r"[0-9a-f]{40}", str(value)):
            _fail(path, "must be 40 lowercase hexadecimal characters")
    elif type_name == "https_url":
        _https(value, path)
    elif type_name == "url":
        parsed = urlparse(str(value))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            _fail(path, "must be an HTTP(S) URL")
    elif type_name == "range_template[str]":
        if not isinstance(value, str) or "{{ range_id }}" not in value:
            _fail(path, "must be a range_id template")
    elif type_name == "list[str]":
        _strings(value, path)
    elif type_name == "list[PackagePin]":
        if not isinstance(value, list) or not value:
            _fail(path, "must be a nonempty package-pin list")
        for index, pin in enumerate(value):
            item = _keys(pin, {"name", "version"}, f"{path}[{index}]")
            _string(item["name"], f"{path}[{index}].name")
            _string(item["version"], f"{path}[{index}].version")
    elif type_name == "list[ForwarderInput]":
        if not isinstance(value, list) or not value:
            _fail(path, "must be a nonempty forwarder-input list")
        for index, projected in enumerate(value):
            item = _keys(projected, {"path", "index", "sourcetype", "safe_fields"}, f"{path}[{index}]")
            for key in ("path", "index", "sourcetype"):
                _string(item[key], f"{path}[{index}].{key}")
            _strings(item["safe_fields"], f"{path}[{index}].safe_fields")
    elif type_name == "Artifact":
        _artifact(value, path)
    elif type_name == "RuntimeArtifact":
        item = _keys(value, {"version", "url", "sha256", "download_auth_required"}, path)
        _string(item["version"], f"{path}.version")
        _https(item["url"], f"{path}.url")
        if not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
            _fail(f"{path}.sha256", "must be sha256")
        _boolean(item["download_auth_required"], f"{path}.download_auth_required")
    elif type_name.startswith("enum[") and type_name.endswith("]"):
        allowed = type_name[5:-1].split(",")
        if value not in allowed:
            _fail(path, f"must be one of {allowed}")
    elif type_name == "SplunkTrialCapability":
        _splunk_capability(value, f"{path}<SplunkTrialCapability>")
    elif type_name == "RunnerApiContract":
        _runner_api(value, f"{path}<RunnerApiContract>")
    elif type_name == "GitLabReadinessContract":
        _readiness(value, f"{path}<GitLabReadinessContract>")
    elif type_name == "RunnerJobsContract":
        _runner_jobs(value, f"{path}<RunnerJobsContract>")
    elif type_name == "ForwarderBootstrapGate":
        _verified_gate_observed(value, f"{path}<ForwarderBootstrapGate>", [4, 8, 9, 10], _forwarder_bootstrap)
    elif type_name == "SplunkHecHandoff":
        item = _keys(value, {"delegate_host", "source_path", "input_path", "service_name"}, path)
        if item != {
            "delegate_host": "{{ range_id }}-splunk",
            "source_path": "/etc/detection-engineering/secrets/hec-workload.token",
            "input_path": "/opt/splunk/etc/apps/detection_hec/local/inputs.conf",
            "service_name": "Splunkd.service",
        }:
            _fail(path, "must equal the scoped Splunk HEC handoff")
    elif type_name == "HelmChartPin":
        _chart(value, f"{path}<HelmChartPin>")
    elif type_name == "OtelContract":
        _otel(value, f"{path}<OtelContract>")
    elif type_name == "ArtifactLayoutGateMap":
        if not isinstance(value, dict) or set(value) != {"minikube", "kubectl", "helm", "otel_host"}:
            _fail(path, "must contain four artifact layout gates")
        for name, gate in value.items():
            _verified_gate_observed(
                gate, f"{path}.{name}", [7, 8, 9, 10], _artifact_layout
            )
    else:
        _fail(path, f"unsupported target type {type_name!r}")


def resolve_role_variable_contracts(
    contract: Mapping[str, Any],
    synthetic_sources: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Resolve the bounded Task 1 mappings against explicit synthetic inputs."""

    if "mapping_source_schema" not in contract:
        _fail("contract.mapping_source_schema", "missing source schema")
    mappings = contract.get("role_variable_contracts")
    if not isinstance(mappings, dict):
        _fail("contract.role_variable_contracts", "must be an object")
    resolved: dict[str, dict[str, Any]] = {}
    for role, variables in mappings.items():
        if not isinstance(variables, dict):
            _fail(f"contract.role_variable_contracts.{role}", "must be an object")
        resolved[role] = {}
        for variable, mapping in variables.items():
            path = f"contract.role_variable_contracts.{role}.{variable}"
            if not isinstance(mapping, dict):
                _fail(path, "must be an object")
            if set(mapping) == {"source", "type"}:
                value = _synthetic_source(synthetic_sources, mapping["source"])
            elif set(mapping) == {"value", "type"}:
                value = mapping["value"]
            elif set(mapping) == {"operation", "inputs", "type"}:
                if not isinstance(mapping["inputs"], dict):
                    _fail(f"{path}.inputs", "must be an object")
                operation_inputs = {
                    name: _mapping_input(specification, synthetic_sources, f"{path}.inputs.{name}")
                    for name, specification in mapping["inputs"].items()
                }
                value = _apply_mapping_operation(mapping["operation"], operation_inputs, path)
            else:
                _fail(path, "must declare exactly source/type, value/type, or operation/inputs/type")
            _assignable(value, mapping["type"], path)
            resolved[role][variable] = value
    return resolved


def run_production_include(
    role: str,
    includes: str | Sequence[str],
    variables: Mapping[str, Any],
    fake_bin: str | Path,
) -> subprocess.CompletedProcess[str]:
    """Run production role task includes in an isolated local Ansible play."""

    task_includes = [includes] if isinstance(includes, str) else list(includes)
    if not task_includes:
        raise ValueError("includes must contain at least one production task include")

    role_path = REPOSITORY_ROOT / "ansible" / "roles" / role
    if not role_path.is_dir():
        raise ValueError(f"production role does not exist: {role}")

    missing = [name for name in task_includes if not (role_path / "tasks" / f"{name}.yml").is_file()]
    if missing:
        raise ValueError(f"production task include does not exist for {role}: {missing}")

    fake_bin_path = Path(fake_bin).resolve()
    if not fake_bin_path.is_dir():
        raise ValueError(f"fake_bin is not a directory: {fake_bin_path}")

    with tempfile.TemporaryDirectory(prefix="detection-engineering-ansible-") as work:
        work_path = Path(work)
        inventory = work_path / "inventory.yml"
        playbook = work_path / "playbook.yml"
        local_tmp = work_path / "ansible-local"
        remote_tmp = work_path / "ansible-remote"
        home = work_path / "home"
        for directory in (local_tmp, remote_tmp, home):
            directory.mkdir(mode=0o700)

        inventory.write_text(
            yaml.safe_dump(
                {
                    "all": {
                        "hosts": {
                            "testhost": {
                                "ansible_connection": "local",
                                "ansible_python_interpreter": os.sys.executable,
                            }
                        }
                    }
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        playbook.write_text(
            yaml.safe_dump(
                [
                    {
                        "name": "Exercise production task includes",
                        "hosts": "all",
                        "gather_facts": False,
                        "become": False,
                        "vars": dict(variables),
                        "tasks": [
                            {
                                "name": f"Run {role} {task_include}",
                                "ansible.builtin.include_role": {
                                    "name": role,
                                    "tasks_from": task_include,
                                },
                            }
                            for task_include in task_includes
                        ],
                    }
                ],
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        environment = os.environ.copy()
        environment.update(
            {
                "ANSIBLE_HOME": str(work_path / "ansible-home"),
                "ANSIBLE_LOCAL_TEMP": str(local_tmp),
                "ANSIBLE_REMOTE_TEMP": str(remote_tmp),
                "ANSIBLE_ROLES_PATH": str(REPOSITORY_ROOT / "ansible" / "roles"),
                "HOME": str(home),
                "PATH": f"{fake_bin_path}{os.pathsep}{environment.get('PATH', '')}",
            }
        )
        ansible_playbook = Path(sys.executable).with_name("ansible-playbook")
        return subprocess.run(
            [str(ansible_playbook), "-i", str(inventory), str(playbook)],
            cwd=REPOSITORY_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
