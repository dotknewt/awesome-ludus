"""Strict projection, gate, protection, and publication tests."""

from __future__ import annotations

import copy
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from support import validate_verified_inputs


PROFILES = ("gitlab", "runner", "malcolm", "splunk", "workload")


def _module(root: Path):
    spec = importlib.util.spec_from_file_location("detection_materialize", root / "materialize.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gate(observed: object, status: str = "VERIFIED", unresolved: list[str] | None = None) -> dict:
    return {
        "status": status,
        "source": {"kind": "LUDUS_API_READ", "reference": "synthetic-read-only", "observed_at": "2026-10-18T18:00:00Z"},
        "observed": observed,
        "limitation": "Synthetic target fixture; not deployment evidence.",
        "required_for_deployment": True,
        "unresolved": [] if unresolved is None else unresolved,
    }


def _target_inputs() -> dict:
    template = {
        "name": "debian-12-x64-server-template", "os_type": "linux",
        "distribution": "Debian", "major_version": 12,
        "architecture": "x86_64", "built": True, "inherited_disk_gb": 32,
    }
    return {
        "schema_version": 4,
        "target_range": _gate({
            "name": "thrunt", "range_number": 3, "range_cidr": "10.3.0.0/16",
            "state": "NEVER_DEPLOYED", "vm_count": 0, "testing": False,
        }),
        "templates": {profile: _gate(copy.deepcopy(template)) for profile in PROFILES},
        # Deliberately tiny CPU/storage values prove that no invented 1:1/full-disk
        # threshold is applied; sufficiency is an explicit reviewed decision.
        "capacity": _gate({
            "total_ram_gb": 128, "free_ram_gb": 120, "reported_cpu_cores": 16,
            "current_allocations": {"ram_gb": 0, "cpus": 0, "storage_gb": 0},
            "storage_pools": [
                {"name": "disks", "type": "lvmthin", "size_gb": 931.32, "used_gb": 145.38, "free_gb": 785.94},
                {"name": "local", "type": "dir", "size_gb": 305.76, "used_gb": 16.05, "free_gb": 275.41},
            ],
            "deployment_sufficient": True,
            "decision_basis": "explicit synthetic review decision",
        }),
        "network": _gate({
            "range_cidr": "10.3.0.0/16", "lab_cidr": "10.3.10.0/24",
            "host_bridge": "vmbr3",
            "host_bridge_promiscuous_mode": "USER_MANAGED_NOT_A_PROVISIONING_GATE",
        }),
        "provisioning_identity": _gate({
            "user": "debian", "home": "/home/debian",
            "account_kind": "existing_template_login",
            "documented_default_login": "debian:debian",
            "password_action": "preserve_existing", "create_user": False,
        }),
        "role_inventory": {
            "status": "PRESENCE_OBSERVED_CONTENT_VERIFICATION_WAIVED",
            "source": {"kind": "COMPOSITE", "reference": "synthetic-role-presence-and-user-waiver", "observed_at": None},
            "observed": {"present_roles": [
                "ludus_detection_forwarder", "ludus_detection_forwarder_pipeline",
                "ludus_detection_gitlab",
                "ludus_detection_linux_logging", "ludus_detection_runner",
                "ludus_detection_splunk", "ludus_detection_workload",
                "ludus_install_malcolm", "ludus_install_docker", "ludus_install_minikube",
            ],
            "collections": [
                {"name": "ansible.posix", "version": "2.2.2"},
                {"name": "community.crypto", "version": "3.5.0"},
                {"name": "community.general", "version": "10.3.0"},
            ],
            "content_verification": "USER_WAIVED_NOT_VERIFIED"},
            "waiver": {"decision": "USER_WAIVED_ROLE_VERSION_AND_CONTENT_COMPARISON", "recorded_on": "2026-10-19"},
            "limitation": "Synthetic role-name presence; role versions and contents are intentionally not verified.",
            "required_for_deployment": False,
            "unresolved": [],
        },
    }


def _protected() -> dict:
    return {
        "schema_version": 2,
        "splunk_admin_password": "debian",
        "malcolm_admin_username": "debian",
        "malcolm_admin_password": "debian",
        "hec_workload_state": "present",
    }


def _load_inputs(root: Path) -> tuple[dict, dict, dict, dict]:
    return tuple(
        yaml.safe_load((root / name).read_text())
        for name in ("product-pins.yml", "verified-inputs.yml", "requirements.yml", "range-config.yml")
    )


def _eligible_verified_inputs(
    inputs: dict,
    products: dict,
    target: dict,
    mandatory: set[str],
) -> dict:
    result = copy.deepcopy(inputs)
    for path in mandatory:
        segments = path.split(".")
        parent = result
        for segment in segments[:-1]:
            parent = parent[segment]
        value = copy.deepcopy(parent[segments[-1]])
        parent[segments[-1]] = value
        value["status"] = "VERIFIED"
        section, name = (path.split(".") + [None])[:2]
        if section == "templates":
            value["observed"] = copy.deepcopy(target["templates"][name]["observed"])
        elif section in {"capacity", "network"}:
            value["observed"] = copy.deepcopy(target[section]["observed"])
        else:
            value["observed"] = copy.deepcopy(products[section][name]["observed"])
    return result


def _run(root: Path, target: Path, output: Path, mode: str = "public-save", protected: Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(root / "materialize.py"), "--mode", mode, "--target-inputs", str(target), "--output", str(output)]
    if protected is not None:
        command += ["--protected-inputs", str(protected)]
    return subprocess.run(command, cwd=root, text=True, capture_output=True, check=False)


def test_operator_input_example_is_valid_blocked_schema_v4(blueprint_root: Path) -> None:
    example = yaml.safe_load((blueprint_root / "operator-inputs.example.yml").read_text())
    assert example["schema_version"] == 4
    assert set(example) == {
        "schema_version", "target_range", "templates", "capacity", "network",
        "provisioning_identity", "role_inventory",
    }
    assert all(gate["status"] == "BLOCKED" for gate in example["templates"].values())


def test_thrunt_public_save_is_populated_and_keeps_only_application_passwords_null(blueprint_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "thrunt-save.yml"
    result = _run(blueprint_root, blueprint_root / "target-inputs.thrunt-draft.yml", output)
    assert result.returncode == 0, result.stderr
    config = yaml.safe_load(output.read_text())
    publication = config["ludus_extensions"]["detection_engineering_publication"]
    assert publication["mode"] == "public-save"
    assert publication["save_ready"] is True
    assert publication["contains_protected_credentials"] is False
    assert publication["deployment_authorized"] is False
    assert "deployment_eligible" not in publication
    assert "protected_inputs" not in publication["unresolved_execution_facts"]
    assert "role_inventory" not in publication["unresolved_execution_facts"]
    assert publication["target_network"] == {
        "range_cidr": "10.3.0.0/16",
        "lab_cidr": "10.3.10.0/24",
        "host_bridge": "vmbr3",
        "host_bridge_promiscuous_mode": "USER_MANAGED_NOT_A_PROVISIONING_GATE",
    }
    assert len(config["ludus"]) == 5
    assert all("ludus_detection_guest_firewall" not in str(vm["roles"]) for vm in config["ludus"])
    assert all(not any(key.startswith("detection_firewall_") for key in vm["role_vars"]) for vm in config["ludus"])
    assert sum(vm["ram_gb"] for vm in config["ludus"]) == 108
    assert sum(vm["cpus"] for vm in config["ludus"]) == 26
    assert all("logrotate" in vm["linux"]["packages"] for vm in config["ludus"] if isinstance(vm["linux"], dict))
    malcolm = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-malcolm"))
    assert malcolm["role_vars"]["ludus_install_malcolm_admin_password"] is None
    assert malcolm["role_vars"]["ludus_install_malcolm_admin_username"] == "debian"
    assert malcolm["role_vars"]["ludus_install_malcolm_user"] == "debian"
    assert malcolm["role_vars"]["ludus_install_malcolm_install_dir"] == "/home/debian/Malcolm"
    splunk = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-splunk"))
    assert splunk["role_vars"]["detection_splunk_admin_password"] is None
    assert splunk["role_vars"]["detection_splunk_admin_username"] == "debian"
    workload = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-workload"))
    assert workload["role_vars"]["detection_runtime_token_state"] == "present"
    assert "5601" not in output.read_text()
    assert output.stat().st_mode & 0o777 == 0o600


def test_public_save_is_byte_reproducible_across_hash_seeds(blueprint_root: Path, tmp_path: Path) -> None:
    outputs = []
    for seed in ("1", "2"):
        output = tmp_path / f"thrunt-save-{seed}.yml"
        env = {**os.environ, "PYTHONHASHSEED": seed}
        result = subprocess.run(
            [
                sys.executable,
                str(blueprint_root / "materialize.py"),
                "--mode", "public-save",
                "--target-inputs", str(blueprint_root / "target-inputs.thrunt-draft.yml"),
                "--output", str(output),
            ],
            cwd=blueprint_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        outputs.append(output.read_bytes())
    assert outputs[0] == outputs[1]


def test_draft_divergence_from_pin_projection_is_rejected(blueprint_root: Path) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    draft["ludus"][0]["role_vars"]["detection_forwarder_artifact"]["sha256"] = "0" * 64
    with pytest.raises(materializer.Refusal, match="diverges from product-pins projection"):
        materializer.materialize(_target_inputs(), products, verified, requirements, draft, "public-save")


@pytest.mark.parametrize("mutation", ["missing-product-section", "layout-digest", "collections", "graph"])
def test_incomplete_product_or_graph_contract_is_rejected(blueprint_root: Path, mutation: str) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    if mutation == "missing-product-section":
        del products["downloads"]["helm"]
    elif mutation == "layout-digest":
        products["artifact_layouts"]["helm"]["observed"]["artifact_sha256"] = "0" * 64
    elif mutation == "collections":
        requirements["collections"][0]["version"] = "2.2.1"
    else:
        draft["ludus"][4]["roles"].pop()
    with pytest.raises(materializer.Refusal):
        materializer.materialize(_target_inputs(), products, verified, requirements, draft, "public-save")


def test_private_save_merges_protected_application_credentials_without_deployment_claim(
    blueprint_root: Path, tmp_path: Path
) -> None:
    protected = tmp_path / "protected.yml"
    protected.write_text(yaml.safe_dump(_protected()))
    protected.chmod(0o600)
    output = tmp_path / "private-range.yml"
    result = _run(
        blueprint_root,
        blueprint_root / "target-inputs.thrunt-draft.yml",
        output,
        "private-save",
        protected,
    )
    assert result.returncode == 0, result.stderr
    config = yaml.safe_load(output.read_text())
    publication = config["ludus_extensions"]["detection_engineering_publication"]
    assert publication["mode"] == "private-save"
    assert publication["save_ready"] is True
    assert publication["contains_protected_credentials"] is True
    assert publication["deployment_authorized"] is False
    assert "deployment_eligible" not in publication
    splunk = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-splunk"))
    malcolm = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-malcolm"))
    assert splunk["role_vars"]["detection_splunk_admin_password"] == _protected()["splunk_admin_password"]
    assert malcolm["role_vars"]["ludus_install_malcolm_admin_password"] == _protected()["malcolm_admin_password"]
    assert all("detection_gitlab_root_password" not in vm["role_vars"] for vm in config["ludus"])
    assert output.stat().st_mode & 0o777 == 0o600


def test_private_save_refuses_missing_protected_input_without_output(
    blueprint_root: Path, tmp_path: Path
) -> None:
    output = tmp_path / "private-range.yml"
    result = _run(
        blueprint_root,
        blueprint_root / "target-inputs.thrunt-draft.yml",
        output,
        "private-save",
    )
    assert result.returncode == 2
    assert "requires --protected-inputs" in result.stderr
    assert not output.exists()


def test_protected_machine_application_credentials_may_match_documented_login(blueprint_root: Path, tmp_path: Path) -> None:
    protected = tmp_path / "protected.yml"
    protected.write_text(yaml.safe_dump(_protected()))
    protected.chmod(0o600)
    output = tmp_path / "private-range.yml"
    result = _run(blueprint_root, blueprint_root / "target-inputs.thrunt-draft.yml", output, "private-save", protected)
    assert result.returncode == 0, result.stderr
    config = yaml.safe_load(output.read_text())
    malcolm = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-malcolm"))
    splunk = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-splunk"))
    assert malcolm["role_vars"]["ludus_install_malcolm_admin_username"] == "debian"
    assert malcolm["role_vars"]["ludus_install_malcolm_admin_password"] == "debian"
    assert splunk["role_vars"]["detection_splunk_admin_password"] == "debian"


def test_deployment_mode_enforces_static_selected_product_approval(blueprint_root: Path) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    verified["lifecycle"]["selected_product_contract"]["status"] = "BLOCKED"
    with pytest.raises(materializer.Refusal, match="authoritative deployment gates remain blocked"):
        materializer.materialize(_target_inputs(), products, verified, requirements, draft, "deployment", _protected())


def test_complete_synthetic_deployment_projects_pins_and_exact_graph(blueprint_root: Path) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    target = _target_inputs()
    verified = _eligible_verified_inputs(
        verified, products, target, materializer.MANDATORY_STATIC_PRODUCT_GATES
    )
    validate_verified_inputs(verified)
    config = materializer.materialize(target, products, verified, requirements, draft, "deployment", _protected())
    publication = config["ludus_extensions"]["detection_engineering_publication"]
    assert publication["deployment_eligible"] is True
    assert publication["eligibility_phase"] == "INITIAL_PROVISIONING"
    assert publication["runtime_acceptance"] == "PENDING_POST_PROVISIONING"
    assert publication["outstanding_gates"] == []
    runner = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-runner"))
    assert runner["role_vars"]["detection_runner_packages"] == products["apt"]["runner"]["observed"]["packages"]
    assert runner["role_vars"]["detection_gitlab_readiness_contract"]["transport_base_url"] == "http://localhost"
    gitlab = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-gitlab"))
    assert "detection_gitlab_root_password" not in gitlab["role_vars"]
    malcolm = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-malcolm"))
    assert malcolm["role_vars"]["ludus_install_malcolm_install_dir"] == "/home/debian/Malcolm"
    assert malcolm["role_vars"]["ludus_install_malcolm_capture_interface"] == ""
    workload = next(vm for vm in config["ludus"] if vm["hostname"].endswith("-workload"))
    assert workload["role_vars"]["detection_workload_user"] == "debian"
    assert workload["role_vars"]["detection_workload_home"] == "/home/debian"


def test_role_content_verification_waiver_does_not_block_deployment(blueprint_root: Path) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    target = _target_inputs()
    role_policy = target["role_inventory"]
    assert role_policy["status"] == "PRESENCE_OBSERVED_CONTENT_VERIFICATION_WAIVED"
    assert role_policy["observed"]["content_verification"] == "USER_WAIVED_NOT_VERIFIED"
    config = materializer.materialize(
        target, products, verified, requirements, draft, "deployment", _protected()
    )
    assert "role_inventory" not in config["ludus_extensions"][
        "detection_engineering_publication"
    ]["outstanding_gates"]


@pytest.mark.parametrize(
    ("path", "mutation", "message"),
    [(("downloads", "helm"), lambda observed: observed.update(sha256="0" * 64), "does not equal product-pins")],
)
def test_deployment_rejects_mismatching_authoritative_evidence(
    blueprint_root: Path, path: tuple[str, str | None], mutation, message: str
) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    target = _target_inputs()
    verified = _eligible_verified_inputs(
        verified, products, target, materializer.MANDATORY_STATIC_PRODUCT_GATES
    )
    section, name = path
    gate = verified[section] if name is None else verified[section][name]
    mutation(gate["observed"])
    with pytest.raises(materializer.Refusal, match=message):
        materializer.materialize(
            target, products, verified, requirements, draft, "deployment", _protected()
        )


def test_firewall_inputs_are_not_required_for_deployment_eligibility(blueprint_root: Path) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    target = _target_inputs()
    verified = _eligible_verified_inputs(
        verified, products, target, materializer.MANDATORY_STATIC_PRODUCT_GATES
    )
    config = materializer.materialize(
        target, products, verified, requirements, draft, "deployment", _protected()
    )
    assert config["ludus_extensions"]["detection_engineering_publication"]["deployment_eligible"] is True
    assert "network" not in materializer.MANDATORY_STATIC_PRODUCT_GATES
    serialized = yaml.safe_dump(config)
    for forbidden in (
        "ludus_detection_guest_firewall", "detection_firewall_", "management_cidrs",
        "vpn_cidrs", "public_probe_source", "docker_bridge", "service_ports",
    ):
        assert forbidden not in serialized


def test_initial_provisioning_reuses_acquired_static_product_facts_without_runtime_results(
    blueprint_root: Path,
) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)

    config = materializer.materialize(
        _target_inputs(), products, verified, requirements, draft, "deployment", _protected()
    )

    publication = config["ludus_extensions"]["detection_engineering_publication"]
    assert publication["initial_provisioning_eligible"] is True
    assert publication["runtime_acceptance"] == "PENDING_POST_PROVISIONING"
    assert publication["outstanding_gates"] == []


def test_mandatory_static_product_gates_exclude_target_and_runtime_results(
    blueprint_root: Path,
) -> None:
    materializer = _module(blueprint_root)
    assert not any(
        path == "capacity" or path.startswith("templates.")
        for path in materializer.MANDATORY_STATIC_PRODUCT_GATES
    )
    assert {
        "capabilities.gitlab_readiness_contract",
        "capabilities.runner_jobs_contract",
        "capabilities.forwarder_bootstrap_contract",
    } <= materializer.MANDATORY_STATIC_PRODUCT_GATES
    assert all("runtime" not in path for path in materializer.MANDATORY_STATIC_PRODUCT_GATES)


@pytest.mark.parametrize("phase", ["provisioning_time", "post_provisioning"])
def test_runtime_absence_cannot_be_promoted_to_verified_initial_evidence(
    blueprint_root: Path, phase: str
) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    verified["lifecycle"][phase]["status"] = "VERIFIED"
    verified["lifecycle"][phase]["evidence"] = {"synthetic": True}
    with pytest.raises(materializer.Refusal, match=rf"lifecycle\.{phase} must remain PENDING"):
        materializer.materialize(
            _target_inputs(), products, verified, requirements, draft, "deployment", _protected()
        )


def test_public_save_lists_missing_target_timestamp_as_execution_fact(
    blueprint_root: Path,
) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    target = _target_inputs()
    target["target_range"]["source"]["observed_at"] = None
    config = materializer.materialize(
        target, products, verified, requirements, draft, "public-save"
    )
    assert "target_range.source.observed_at" in config["ludus_extensions"][
        "detection_engineering_publication"
    ]["unresolved_execution_facts"]


@pytest.mark.parametrize("field", ["network", "provisioning_identity"])
def test_deployment_rejects_verified_empty_target_maps(blueprint_root: Path, field: str) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    target = _target_inputs()
    target[field]["observed"] = {}
    with pytest.raises(materializer.Refusal, match=field):
        materializer.materialize(
            target, products, verified, requirements, draft, "deployment", _protected()
        )


def test_deployment_rejects_missing_authoritative_evidence(blueprint_root: Path) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    target = _target_inputs()
    verified = _eligible_verified_inputs(
        verified, products, target, materializer.MANDATORY_STATIC_PRODUCT_GATES
    )
    verified["downloads"]["helm"]["observed"] = None
    with pytest.raises(materializer.Refusal, match=r"static_product\.downloads\.helm"):
        materializer.materialize(
            target, products, verified, requirements, draft, "deployment", _protected()
        )


@pytest.mark.parametrize("mutation", ["docker-repository", "layout-format", "chart-digest", "otel-rbac", "splunk-hec", "runner-endpoint"])
def test_product_projection_rejects_incomplete_or_incoherent_real_schema(
    blueprint_root: Path, mutation: str
) -> None:
    materializer = _module(blueprint_root)
    products, _verified, requirements, _draft = _load_inputs(blueprint_root)
    if mutation == "docker-repository":
        products["apt"]["containerd"]["observed"]["repository_url"] += "/other"
    elif mutation == "layout-format":
        products["artifact_layouts"]["helm"]["observed"]["format"] = "zip"
    elif mutation == "chart-digest":
        products["charts"]["otel"]["observed"]["digest"] = "latest"
    elif mutation == "otel-rbac":
        products["capabilities"]["otel"]["observed"]["required_rbac"] = {}
    elif mutation == "splunk-hec":
        products["capabilities"]["splunk"]["observed"]["hec"] = False
    else:
        products["capabilities"]["runner_api"]["observed"]["manager"]["create_endpoint"] = None
    with pytest.raises(materializer.Refusal):
        materializer._product_projection(products, requirements)


def test_target_range_cidr_interface_and_home_are_bound(blueprint_root: Path) -> None:
    materializer = _module(blueprint_root)
    products, verified, requirements, draft = _load_inputs(blueprint_root)
    for field, value, message in (
        ("network", {**_target_inputs()["network"]["observed"], "lab_cidr": "10.4.10.0/24"}, "subnet"),
        ("network", {**_target_inputs()["network"]["observed"], "host_bridge": "vmbr4"}, "vmbr3"),
        ("network", {**_target_inputs()["network"]["observed"], "lab_cidr": "10.3.11.0/24"}, "VLAN 10"),
        ("provisioning_identity", {**_target_inputs()["provisioning_identity"]["observed"], "home": "relative/home"}, "absolute"),
        ("provisioning_identity", {**_target_inputs()["provisioning_identity"]["observed"], "home": "/home/debian/../root"}, "traversal"),
    ):
        target = _target_inputs()
        target[field]["observed"] = value
        with pytest.raises(materializer.Refusal, match=message):
            materializer.materialize(target, products, verified, requirements, draft, "public-save")


def test_protected_input_mode_and_atomic_no_clobber(blueprint_root: Path, tmp_path: Path) -> None:
    target = tmp_path / "target.yml"
    target.write_text(yaml.safe_dump(_target_inputs()))
    protected = tmp_path / "protected.yml"
    protected.write_text(yaml.safe_dump(_protected()))
    protected.chmod(0o644)
    output = tmp_path / "output.yml"
    rejected = _run(blueprint_root, target, output, "deployment", protected)
    assert rejected.returncode != 0
    assert "mode 0600" in rejected.stderr
    assert not output.exists()

    materializer = _module(blueprint_root)
    output.write_bytes(b"foreign-current-output\n")
    with pytest.raises(materializer.Refusal, match="already exists"):
        materializer._publish_no_clobber(output, {"replacement": True})
    assert output.read_bytes() == b"foreign-current-output\n"
    assert not list(tmp_path.glob(".output.yml.*"))


def test_directory_fsync_failure_reports_publication_uncertainty(
    blueprint_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    materializer = _module(blueprint_root)
    output = tmp_path / "output.yml"
    real_fsync = materializer.os.fsync
    calls = 0

    def fail_directory_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(materializer.os, "fsync", fail_directory_fsync)
    with pytest.raises(materializer.PublicationUncertain, match="inspect output path"):
        materializer._publish_no_clobber(output, {"payload": True})
    assert output.exists()
    assert yaml.safe_load(output.read_text()) == {"payload": True}
