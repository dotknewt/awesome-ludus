from __future__ import annotations

import copy
import hashlib
import io
import json
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

from helpers import calls, make_fixture, run_role


def collector_proof(fixture: dict) -> str:
    unit = Path(fixture["variables"]["detection_systemd_dir"]) / "otel-host.service"
    config = Path(fixture["variables"]["detection_workload_config_dir"]) / "otel-host.yaml"
    return f"{hashlib.sha256(unit.read_bytes()).hexdigest()}:{hashlib.sha256(config.read_bytes()).hexdigest()}"


def test_default_chart_archive_matches_helm_pull_filename() -> None:
    defaults = yaml.safe_load(
        (Path(__file__).parents[1] / "defaults/main.yml").read_text(encoding="utf-8")
    )
    assert defaults["detection_otel_chart_archive_path"] == (
        "{{ detection_cache_dir }}/{{ detection_otel_chart.chart }}-"
        "{{ detection_otel_chart.version }}.tgz"
    )


def test_repository_suite_comes_from_target_os_release(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    source = Path(fixture["variables"]["detection_docker_source_path"]).read_text()
    assert "Suites: synthetic-suite" in source
    assert "Suites: stable" not in source


def test_first_run_stages_metadata_policy_before_exact_minikube_start_and_converges(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    first = run_role(fixture)
    assert first.returncode == 0, first.stdout + first.stderr
    policy_path = Path(fixture["variables"]["detection_audit_policy_stage_path"])
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    assert policy["rules"] == [{"level": "Metadata"}]
    evidence = calls(fixture)
    start = next(line for line in evidence if line.startswith("minikube ") and " start " in line)
    assert any(line.startswith("docker identity=deworkload") and line.endswith(" info") for line in evidence)
    assert "--driver=docker" in start
    assert "--extra-config=apiserver.audit-policy-file=/etc/kubernetes/audit-policy.yaml" in start
    assert "--extra-config=apiserver.audit-log-path=/var/log/kubernetes/audit/audit.log" in start
    assert "level: Request\n" not in policy_path.read_text()
    assert "level: RequestResponse" not in policy_path.read_text()
    before = list(evidence)
    token = Path(fixture["variables"]["detection_host_token_path"]).read_bytes()
    second = run_role(fixture)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert Path(fixture["variables"]["detection_host_token_path"]).read_bytes() == token
    assert not any(line.startswith("minikube ") and " start " in line for line in calls(fixture)[len(before):])
    unit = (Path(fixture["variables"]["detection_systemd_dir"]) / "minikube-detection.service").read_text()
    assert f"User={fixture['variables']['detection_workload_user']}" in unit
    assert f"Environment=HOME={fixture['variables']['detection_workload_home']}" in unit
    assert f"Environment=KUBECONFIG={fixture['variables']['detection_kubeconfig_path']}" in unit


def test_rendered_cluster_manifests_have_exact_rbac_readonly_paths_and_file_secret(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    config = Path(fixture["variables"]["detection_workload_config_dir"])
    rbac_docs = list(yaml.safe_load_all((config / "otel-rbac.yaml").read_text()))
    role = next(document for document in rbac_docs if document and document.get("kind") == "ClusterRole")
    assert {rule["resources"][0]: rule["verbs"] for rule in role["rules"]} == fixture["variables"]["detection_otel_contract"]["required_rbac"]
    values = yaml.safe_load((config / "otel-values.yaml").read_text())
    volumes = values["extraVolumes"]
    assert {(item["name"], item["hostPath"]["path"]) for item in volumes if "hostPath" in item} == {
        ("audit", "/var/log/kubernetes/audit"),
        ("containers", "/var/log/containers"),
        ("pods", "/var/log/pods"),
    }
    secret_volume = next(item for item in volumes if item["name"] == "splunk-hec")
    assert secret_volume["secret"] == {"secretName": "splunk-hec", "defaultMode": 0o400}
    assert all(item["readOnly"] for item in values["extraVolumeMounts"])
    rendered = (config / "otel-values.yaml").read_text()
    assert "/var/run/secrets/detection/hec/token" in rendered
    assert "${file:/var/run/secrets/detection/hec/token}" in rendered
    assert "SYNTHETIC-HEC" not in rendered
    assert "/var/lib/docker" not in rendered
    assert "sample" not in rendered.lower()
    exporters = values["config"]["exporters"]
    assert {exporter["sourcetype"] for exporter in exporters.values()} == {
        "kube:audit",
        "kube:container",
        "kube:node",
    }

    apply_calls = [line for line in calls(fixture) if line.startswith("kubectl ") and " apply-" in line]
    rbac_index = next(index for index, line in enumerate(apply_calls) if line.endswith("apply-rbac"))
    secret_index = next(index for index, line in enumerate(apply_calls) if line.endswith("apply-secret"))
    assert rbac_index < secret_index


def test_host_collector_is_outer_json_only_hardened_and_not_docker_privileged(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    unit = (Path(fixture["variables"]["detection_systemd_dir"]) / "otel-host.service").read_text()
    config = (Path(fixture["variables"]["detection_workload_config_dir"]) / "otel-host.yaml").read_text()
    assert "/var/lib/docker/containers/*/*-json.log" in config
    assert "sourcetype: docker:container" in config
    assert "/var/log/containers" not in config and "/var/log/pods" not in config
    assert "User=deotel" in unit and "NoNewPrivileges=true" in unit and "ProtectSystem=strict" in unit
    assert f"ReadOnlyPaths={fixture['variables']['detection_docker_root']}/containers" in unit
    assert "docker.sock" not in config
    assert "InaccessiblePaths=-/var/run/docker.sock" in unit
    assert "SupplementaryGroups=docker" not in unit
    acl = [line for line in calls(fixture) if line.startswith("setfacl ")]
    assert any("u:deotel:--x" in line and line.endswith("/docker") for line in acl)
    assert any("u:deotel:r-X" in line and line.endswith("/docker/containers") for line in acl)
    token_path = Path(fixture["variables"]["detection_host_token_path"])
    assert stat.S_IMODE(token_path.parent.parent.stat().st_mode) == 0o750
    assert stat.S_IMODE(token_path.parent.stat().st_mode) == 0o750
    assert stat.S_IMODE(token_path.stat().st_mode) == 0o640


@pytest.mark.parametrize(
    "update",
    [
        {"detection_otel_host_artifact": {}},
        {"detection_minikube_artifact": {}},
        {"detection_docker_packages": []},
        {"detection_otel_contract": {}},
        {"detection_otel_chart": {}},
    ],
)
def test_unverified_inputs_fail_before_mutation(tmp_path: Path, update: dict) -> None:
    fixture = make_fixture(tmp_path)
    result = run_role(fixture, **update)
    assert result.returncode != 0
    assert calls(fixture) == []


def test_absent_revokes_only_scoped_splunk_input_and_removes_token_remnants(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    present = run_role(fixture)
    assert present.returncode == 0, present.stdout + present.stderr
    result = run_role(fixture, detection_runtime_token_state="absent")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not fixture["splunk_input"].exists()
    assert not Path(fixture["variables"]["detection_host_token_path"]).exists()
    evidence = "\n".join(calls(fixture))
    assert any("kubectl " in line and "delete secret splunk-hec" in line for line in calls(fixture))
    assert "systemctl restart Splunkd.service" in evidence
    assert "purge" not in evidence and "delete index" not in evidence


def test_secret_canary_never_appears_in_argv_output_or_rendered_files(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    canary = "SYNTHETIC-HEC-TOKEN-NEVER-LOG"
    evidence = result.stdout + result.stderr + "\n".join(calls(fixture))
    assert canary not in evidence
    config_dir = Path(fixture["variables"]["detection_workload_config_dir"])
    assert all(canary not in path.read_text() for path in config_dir.iterdir())


def test_wrong_chart_digest_and_malformed_handoff_fail_closed(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    chart = copy.deepcopy(fixture["variables"]["detection_otel_chart"])
    chart["digest"] = "sha256:" + "0" * 64
    result = run_role(fixture, detection_otel_chart=chart)
    assert result.returncode != 0

    fixture = make_fixture(tmp_path / "second")
    handoff = copy.deepcopy(fixture["variables"]["detection_splunk_hec_handoff"])
    handoff["input_path"] = "/opt/splunk/etc/system/local/inputs.conf"
    result = run_role(fixture, detection_splunk_hec_handoff=handoff)
    assert result.returncode != 0
    assert calls(fixture) == []


def test_all_cluster_commands_use_fresh_workload_identity_and_explicit_context(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    cluster_calls = [line for line in calls(fixture) if line.startswith(("minikube ", "kubectl ", "helm "))]
    assert cluster_calls
    for line in cluster_calls:
        assert "identity=deworkload" in line
        assert f"HOME={fixture['variables']['detection_workload_home']}" in line
        assert f"KUBECONFIG={fixture['variables']['detection_kubeconfig_path']}" in line
    assert all(f"context={fixture['variables']['detection_cluster_name']}" in line for line in cluster_calls if not line.startswith("minikube "))


def test_verified_layouts_install_exact_members_and_versions(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert fixture["variables"]["detection_helm_artifact"]["version"] == "1.2.3-synthetic"
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = "\n".join(calls(fixture))
    with tarfile.open(fixture["variables"]["detection_helm_artifact_path"], "r:gz") as archive:
        assert Path(fixture["variables"]["detection_helm_path"]).read_bytes() == archive.extractfile("linux-amd64/helm").read()
    with tarfile.open(fixture["variables"]["detection_otel_host_artifact_path"], "r:gz") as archive:
        assert Path(fixture["variables"]["detection_otel_host_path"]).read_bytes() == archive.extractfile("otelcol-contrib").read()
    assert "minikube version --short" in evidence
    assert "version --client=true --output=yaml" in evidence
    assert "version --short" in evidence
    assert "otelcol --version" in evidence

    bad = copy.deepcopy(fixture["variables"]["detection_runtime_artifact_layouts"])
    bad["helm"]["observed"]["member"] = "../helm"
    rejected = run_role(fixture, detection_runtime_artifact_layouts=bad)
    assert rejected.returncode != 0


def test_helm_version_preserves_prerelease_and_ignores_cli_build_suffix(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    artifact = copy.deepcopy(fixture["variables"]["detection_helm_artifact"])
    artifact["version"] = "1.2.3-rc.1"
    fixture["state"].joinpath("helm-version-output").write_text("v1.2.3-rc.1+gabc123\n", encoding="utf-8")
    result = run_role(fixture, detection_helm_artifact=artifact)
    assert result.returncode == 0, result.stdout + result.stderr

    malformed = make_fixture(tmp_path / "malformed")
    malformed_artifact = copy.deepcopy(malformed["variables"]["detection_helm_artifact"])
    malformed_artifact["version"] = "1.2.3-rc..1"
    malformed["state"].joinpath("helm-version-output").write_text("v1.2.3-rc..1+gabc123\n", encoding="utf-8")
    rejected = run_role(malformed, detection_helm_artifact=malformed_artifact)
    assert rejected.returncode != 0


@pytest.mark.parametrize("state_flag", ["wrong-kubectl-version", "malformed-kubectl-version", "wrong-helm-version", "malformed-helm-version"])
def test_runtime_version_proof_rejects_wrong_or_malformed_actual_output(tmp_path: Path, state_flag: str) -> None:
    fixture = make_fixture(tmp_path)
    fixture["state"].joinpath(state_flag).touch()
    result = run_role(fixture)
    assert result.returncode != 0
    assert not fixture["state"].joinpath("minikube").exists()


def test_exact_hec_contract_is_virtualized_without_weakening_logical_paths(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    handoff = fixture["variables"]["detection_splunk_hec_handoff"]
    assert handoff == {
        "delegate_host": "testhost",
        "source_path": "/etc/detection-engineering/secrets/hec-workload.token",
        "input_path": "/opt/splunk/etc/apps/detection_hec/local/inputs.conf",
        "service_name": "Splunkd.service",
    }
    defaults = yaml.safe_load((Path(__file__).parents[1] / "defaults/main.yml").read_text())
    assert "detection_fixture_mode" not in defaults
    assert "detection_splunk_delegate_root" not in defaults
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr


def test_present_state_rejects_inaccessible_exact_hec_source(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture["source"].chmod(0o000)
    result = run_role(fixture)
    assert result.returncode != 0
    assert not Path(fixture["variables"]["detection_host_token_path"]).exists()
    assert not fixture["state"].joinpath("kubectl-secret").exists()


def test_deotel_docker_membership_is_removed_and_representative_log_is_read_as_deotel(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture["state"].joinpath("user-deotel").touch()
    fixture["state"].joinpath("deotel-groups").write_text("deotel docker\n", encoding="utf-8")
    systemd = Path(fixture["variables"]["detection_systemd_dir"])
    systemd.mkdir(parents=True, exist_ok=True)
    systemd.joinpath("otel-host.service").write_text("existing unit\n", encoding="utf-8")
    fixture["state"].joinpath("active-otel-host.service").touch()
    fixture["state"].joinpath("process-groups-otel-host.service").write_text("deotel,docker\n", encoding="utf-8")
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    call_list = calls(fixture)
    evidence = "\n".join(call_list)
    assert "gpasswd -d deotel docker" in evidence
    stop_index = call_list.index("systemctl stop otel-host.service")
    remove_index = call_list.index("gpasswd -d deotel docker")
    start_index = call_list.index("systemctl start otel-host.service")
    assert stop_index < remove_index < start_index
    assert fixture["state"].joinpath("process-groups-otel-host.service").read_text().split() == ["deotel"]
    assert "runuser identity=deotel test -r" in evidence
    assert fixture["variables"]["detection_docker_log_probe_path"] in evidence
    unit = systemd.joinpath("otel-host.service").read_text()
    assert "InaccessiblePaths=-/var/run/docker.sock" in unit


def test_clean_account_but_privileged_active_collector_is_refreshed(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    fixture["state"].joinpath("process-groups-otel-host.service").write_text("deotel docker\n", encoding="utf-8")
    before = len(calls(fixture))
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    tail = calls(fixture)[before:]
    assert tail.index("systemctl stop otel-host.service") < tail.index("systemctl start otel-host.service")
    assert fixture["state"].joinpath("deotel-groups").read_text().split() == ["deotel"]
    assert fixture["state"].joinpath("process-groups-otel-host.service").read_text().split() == ["deotel"]


@pytest.mark.parametrize("failure", ["fail-otel-stop", "fail-otel-start", "fail-daemon-reload", "fail-remediation-marker"])
def test_collector_remediation_failure_remains_retryable(tmp_path: Path, failure: str) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    config_dir = Path(fixture["variables"]["detection_workload_config_dir"])
    marker = config_dir / ".otel-host-remediation-v1"
    unit = Path(fixture["variables"]["detection_systemd_dir"]) / "otel-host.service"
    assert marker.read_text(encoding="utf-8").strip() == collector_proof(fixture)

    if failure == "fail-daemon-reload":
        unit.write_text("stale unit requiring reload\n", encoding="utf-8")
    elif failure == "fail-remediation-marker":
        marker.unlink()
    else:
        marker.write_text("stale-proof\n", encoding="utf-8")
    fixture["state"].joinpath(failure).touch()

    failed = run_role(fixture)
    assert failed.returncode != 0
    assert not marker.is_file() or marker.read_text(encoding="utf-8").strip() != collector_proof(fixture)

    fixture["state"].joinpath(failure).unlink()
    if marker.is_dir():
        marker.rmdir()
    before_retry = len(calls(fixture))
    retry = run_role(fixture)
    assert retry.returncode == 0, retry.stdout + retry.stderr
    assert fixture["state"].joinpath("active-otel-host.service").exists()
    assert fixture["state"].joinpath("process-groups-otel-host.service").read_text().split() == ["deotel"]
    assert marker.read_text(encoding="utf-8").strip() == collector_proof(fixture)
    if failure == "fail-daemon-reload":
        assert "systemctl daemon-reload" in calls(fixture)[before_retry:]


def test_absent_never_installed_without_tools_refuses_before_provisioning(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture["state"].joinpath("no-docker-log").touch()
    fixture["source"].unlink()
    unrelated = fixture["splunk_input"].parent / "unrelated.conf"
    unrelated.write_text("preserve\n", encoding="utf-8")

    result = run_role(fixture, detection_runtime_token_state="absent")

    assert result.returncode != 0
    assert calls(fixture) == []
    assert unrelated.exists()
    assert fixture["splunk_input"].exists()
    assert fixture["state"].joinpath("splunk-effective-input").exists()


def test_absent_already_absent_with_available_tools_and_proven_remote_absence_converges(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    assert run_role(fixture, detection_runtime_token_state="absent").returncode == 0
    fixture["state"].joinpath("no-docker-log").touch()
    fixture["source"].unlink()
    before = len(calls(fixture))

    second = run_role(fixture, detection_runtime_token_state="absent")

    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    tail = calls(fixture)[before:]
    assert not any(line.startswith(("apt-get ", "minikube ", "find ", "setfacl ", "getfacl ")) for line in tail)
    assert not any(line.startswith("helm ") and any(action in line for action in ("uninstall", "upgrade", "pull")) for line in tail)
    assert not any(line.startswith("kubectl ") and any(action in line for action in (" apply", " delete", " diff")) for line in tail)


@pytest.mark.parametrize(
    ("tool_variable", "remote_state"),
    [("detection_helm_path", "helm-release.json"), ("detection_kubectl_path", "kubectl-secret")],
)
def test_absent_missing_tool_with_managed_remote_resource_fails_before_teardown(tmp_path: Path, tool_variable: str, remote_state: str) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    Path(fixture["variables"][tool_variable]).unlink()
    result = run_role(fixture, detection_runtime_token_state="absent")
    assert result.returncode != 0
    assert fixture["state"].joinpath(remote_state).exists()
    assert fixture["state"].joinpath("helm-release.json").exists()
    assert fixture["state"].joinpath("kubectl-secret").exists()
    assert fixture["splunk_input"].exists()
    assert Path(fixture["variables"]["detection_host_token_path"]).exists()


@pytest.mark.parametrize("tool_variable", ["detection_helm_path", "detection_kubectl_path"])
def test_absent_missing_tool_refuses_after_local_state_loss_with_remote_resources(tmp_path: Path, tool_variable: str) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    unrelated = fixture["splunk_input"].parent / "unrelated.conf"
    unrelated.write_text("preserve\n", encoding="utf-8")
    shutil.rmtree(fixture["variables"]["detection_etc_dir"])
    Path(fixture["variables"][tool_variable]).unlink()
    before = len(calls(fixture))

    result = run_role(fixture, detection_runtime_token_state="absent")

    assert result.returncode != 0
    assert calls(fixture)[before:] == []
    assert fixture["state"].joinpath("active-otel-host.service").exists()
    assert fixture["state"].joinpath("enabled-otel-host.service").exists()
    assert fixture["state"].joinpath("helm-release.json").exists()
    assert fixture["state"].joinpath("kubectl-secret").exists()
    assert fixture["splunk_input"].exists()
    assert fixture["state"].joinpath("splunk-effective-input").exists()
    assert unrelated.read_text(encoding="utf-8") == "preserve\n"


@pytest.mark.parametrize("probe_failure", ["fail-systemd-probe", "helm-probe-error", "kubectl-secret-probe-error"])
def test_absent_probe_errors_fail_before_any_teardown(tmp_path: Path, probe_failure: str) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    fixture["state"].joinpath(probe_failure).touch()
    result = run_role(fixture, detection_runtime_token_state="absent")
    assert result.returncode != 0
    assert fixture["state"].joinpath("active-otel-host.service").exists()
    assert fixture["state"].joinpath("enabled-otel-host.service").exists()
    assert fixture["state"].joinpath("helm-release.json").exists()
    assert fixture["state"].joinpath("kubectl-secret").exists()
    assert fixture["splunk_input"].exists()
    assert Path(fixture["variables"]["detection_host_token_path"]).exists()


@pytest.mark.parametrize("failure", ["kubectl-apply-nonzero-empty", "kubectl-apply-nonzero-success"])
def test_present_secret_apply_requires_zero_rc_and_recognized_status(tmp_path: Path, failure: str) -> None:
    fixture = make_fixture(tmp_path)
    fixture["state"].joinpath(failure).touch()
    result = run_role(fixture)
    assert result.returncode != 0
    assert not fixture["state"].joinpath("helm-release.json").exists()


@pytest.mark.parametrize("failure", ["kubectl-delete-probe-error", "kubectl-delete-nonzero-success"])
def test_absent_secret_delete_requires_zero_rc_before_host_token_removal(tmp_path: Path, failure: str) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    fixture["state"].joinpath(failure).touch()
    result = run_role(fixture, detection_runtime_token_state="absent")
    assert result.returncode != 0
    assert fixture["state"].joinpath("kubectl-secret").exists()
    assert Path(fixture["variables"]["detection_host_token_path"]).exists()


def test_empty_directory_cleanup_ignores_nonempty_but_fails_eacces(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    nonempty = run_role(fixture, detection_runtime_token_state="absent")
    assert nonempty.returncode == 0, nonempty.stdout + nonempty.stderr

    denied = make_fixture(tmp_path / "denied")
    denied["state"].joinpath("rmdir-eacces").touch()
    result = run_role(
        denied,
        detection_runtime_token_state="absent",
        detection_python=str(denied["rmdir_python"]),
    )
    assert result.returncode != 0


def test_absent_stops_collectors_before_removing_any_credentials(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    before = len(calls(fixture))
    result = run_role(fixture, detection_runtime_token_state="absent")
    assert result.returncode == 0, result.stdout + result.stderr
    tail = calls(fixture)[before:]
    stop = next(index for index, line in enumerate(tail) if "systemctl stop otel-host.service" in line)
    disable = next(index for index, line in enumerate(tail) if "systemctl disable otel-host.service" in line)
    uninstall = next(index for index, line in enumerate(tail) if line.startswith("helm ") and "uninstall otel-runtime" in line)
    secret = next(index for index, line in enumerate(tail) if "delete secret splunk-hec" in line)
    hec = next(index for index, line in enumerate(tail) if "systemctl restart Splunkd.service" in line)
    assert max(stop, disable, uninstall) < min(secret, hec)
    assert not any("systemctl enable otel-host.service" in line for line in tail)


def test_missing_or_drifted_helm_release_reconciles_without_local_file_change(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    fixture["state"].joinpath("helm-release.json").unlink()
    before = len(calls(fixture))
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    assert any(line.startswith("helm ") and "upgrade --install" in line for line in calls(fixture)[before:])


def test_signing_key_requires_exact_single_primary_fingerprint(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture["state"].joinpath("gpg-extra-primary").touch()
    result = run_role(fixture)
    assert result.returncode != 0
    assert not fixture["state"].joinpath("packages").exists()


def test_rendered_processing_preserves_native_content_except_audit_objects(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    result = run_role(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    config_dir = Path(fixture["variables"]["detection_workload_config_dir"])
    host = yaml.safe_load((config_dir / "otel-host.yaml").read_text())
    cluster = yaml.safe_load((config_dir / "otel-values.yaml").read_text())["config"]
    host_operators = host["receivers"]["filelog/docker_outer"]["operators"]
    audit_operators = cluster["receivers"]["filelog/audit"]["operators"]
    assert [operator["id"] for operator in host_operators] == ["docker_envelope", "docker_message"]
    assert audit_operators == [
        {"id": "audit_json", "type": "json_parser", "parse_from": "body", "parse_to": "body"},
        {"id": "drop_request_object", "type": "remove", "field": "body.requestObject"},
        {"id": "drop_response_object", "type": "remove", "field": "body.responseObject"},
    ]
    assert all("operators" not in receiver for name, receiver in cluster["receivers"].items() if name.startswith("filelog/node_"))

    def apply_rendered_operator_model(event: dict, operators: list[dict]) -> dict:
        modeled = copy.deepcopy(event)
        for operator in operators:
            if operator["type"] == "json_parser":
                parsed = json.loads(modeled[operator["parse_from"]])
                if operator.get("parse_to", "attributes") == "body":
                    modeled["body"] = parsed
                else:
                    modeled.setdefault("attributes", {}).update(parsed)
            elif operator["type"] == "move":
                source = operator["from"].split(".", 1)[1]
                modeled[operator["to"]] = modeled["attributes"].pop(source)
            elif operator["type"] == "remove":
                parent, field = operator["field"].split(".", 1)
                modeled[parent].pop(field, None)
        return modeled

    native_application = json.dumps({"message": "kept", "authorization": "native-auth", "token": "native-token", "password": "native-password"})
    docker_event = {"body": json.dumps({"log": native_application, "stream": "stdout", "time": "2026-10-17T00:00:00Z"})}
    audit_event = {
        "body": json.dumps(
            {
                "verb": "create",
                "objectRef": {"resource": "pods"},
                "requestObject": {"token": "excluded-only-with-object"},
                "responseObject": {"password": "excluded-only-with-object"},
                "authorization": "native-auth",
                "token": "native-token",
                "password": "native-password",
            }
        )
    }
    docker_modeled = apply_rendered_operator_model(docker_event, host_operators)
    audit_modeled = apply_rendered_operator_model(audit_event, audit_operators)
    assert docker_modeled == {
        "body": native_application,
        "attributes": {"stream": "stdout", "time": "2026-10-17T00:00:00Z"},
    }
    assert audit_modeled["body"] == {
        "verb": "create",
        "objectRef": {"resource": "pods"},
        "authorization": "native-auth",
        "token": "native-token",
        "password": "native-password",
    }


def test_combined_package_interface_has_no_extra_containerd_or_plugin_inputs(tmp_path: Path) -> None:
    defaults = yaml.safe_load((Path(__file__).parents[1] / "defaults/main.yml").read_text())
    assert "detection_containerd_packages" not in defaults
    assert "detection_docker_plugin_packages" not in defaults
    fixture = make_fixture(tmp_path)
    names = {item["name"] for item in fixture["variables"]["detection_docker_packages"]}
    assert names == {"docker-ce", "containerd.io", "docker-buildx-plugin"}


def test_identical_package_pins_are_deduplicated_and_conflicts_fail_before_mutation(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    packages = copy.deepcopy(fixture["variables"]["detection_docker_packages"])
    packages.insert(1, copy.deepcopy(packages[0]))
    result = run_role(fixture, detection_docker_packages=packages)
    assert result.returncode == 0, result.stdout + result.stderr
    install = next(line for line in calls(fixture) if line.startswith("apt-get install "))
    assert install.split().count("docker-ce=1.2.3-1") == 1

    conflict = make_fixture(tmp_path / "conflict")
    conflicting = copy.deepcopy(conflict["variables"]["detection_docker_packages"])
    conflicting.append({"name": "docker-ce", "version": "9.9.9-conflict"})
    rejected = run_role(conflict, detection_docker_packages=conflicting)
    assert rejected.returncode != 0
    assert calls(conflict) == []


def test_secret_reconciliation_is_status_only_and_acl_prechecks_converge(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    first = run_role(fixture)
    assert first.returncode == 0, first.stdout + first.stderr
    first_calls = calls(fixture)
    assert sum(line.startswith("kubectl ") and " diff -f -" in line for line in first_calls) == 1
    assert any(line.startswith("kubectl ") and line.endswith("apply-secret") for line in first_calls)
    before = len(first_calls)
    second = run_role(fixture)
    assert second.returncode == 0, second.stdout + second.stderr
    tail = calls(fixture)[before:]
    assert not any(line.startswith("setfacl ") for line in tail)
    assert "changed=0" in second.stdout


def test_layout_gate_requires_full_verified_provenance_and_stops_before_mutation(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    layouts = copy.deepcopy(fixture["variables"]["detection_runtime_artifact_layouts"])
    layouts["helm"]["stops"] = [7]
    result = run_role(fixture, detection_runtime_artifact_layouts=layouts)
    assert result.returncode != 0
    assert calls(fixture) == []


def test_unsafe_tar_bundle_is_rejected_without_installing_selected_member(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    archive_path = Path(fixture["variables"]["detection_helm_artifact_path"])
    with tarfile.open(archive_path, "w:gz") as archive:
        good = tarfile.TarInfo("linux-amd64/helm")
        payload = b"safe-looking payload"
        good.size = len(payload)
        archive.addfile(good, io.BytesIO(payload))
        link = tarfile.TarInfo("linux-amd64/alias")
        link.type = tarfile.SYMTYPE
        link.linkname = "helm"
        archive.addfile(link)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    artifact = copy.deepcopy(fixture["variables"]["detection_helm_artifact"])
    artifact["sha256"] = digest
    layouts = copy.deepcopy(fixture["variables"]["detection_runtime_artifact_layouts"])
    layouts["helm"]["observed"]["artifact_sha256"] = digest
    result = run_role(fixture, detection_helm_artifact=artifact, detection_runtime_artifact_layouts=layouts)
    assert result.returncode != 0
    assert not Path(fixture["variables"]["detection_helm_path"]).exists()


def test_absent_teardown_failure_preserves_credentials_and_stops_before_revocation(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    fixture["state"].joinpath("fail-helm-uninstall").touch()
    result = run_role(fixture, detection_runtime_token_state="absent")
    assert result.returncode != 0
    assert Path(fixture["variables"]["detection_host_token_path"]).exists()
    assert fixture["splunk_input"].exists()
    assert fixture["state"].joinpath("splunk-effective-input").exists()
    assert fixture["state"].joinpath("kubectl-secret").exists()
    assert not fixture["state"].joinpath("active-otel-host.service").exists()
    assert not fixture["state"].joinpath("enabled-otel-host.service").exists()


def test_absent_post_hec_mutation_failure_preserves_remaining_credentials(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    unrelated = fixture["splunk_input"].parent / "unrelated.conf"
    unrelated.write_text("preserve\n", encoding="utf-8")
    fixture["state"].joinpath("fail-splunk-restart").touch()
    result = run_role(fixture, detection_runtime_token_state="absent")
    assert result.returncode != 0
    assert not fixture["splunk_input"].exists()
    assert fixture["state"].joinpath("splunk-effective-input").exists()
    assert Path(fixture["variables"]["detection_host_token_path"]).exists()
    assert fixture["state"].joinpath("kubectl-secret").exists()
    assert not fixture["state"].joinpath("helm-release.json").exists()
    pending = fixture["splunk_input"].parent / ".workload-hec-restart-pending"
    assert pending.exists()

    fixture["state"].joinpath("fail-splunk-restart").unlink()
    before = len(calls(fixture))
    retry = run_role(fixture, detection_runtime_token_state="absent")
    assert retry.returncode == 0, retry.stdout + retry.stderr
    assert "systemctl restart Splunkd.service" in "\n".join(calls(fixture)[before:])
    assert not pending.exists()
    assert not fixture["state"].joinpath("splunk-effective-input").exists()
    assert not Path(fixture["variables"]["detection_host_token_path"]).exists()
    assert not fixture["state"].joinpath("kubectl-secret").exists()
    assert not fixture["state"].joinpath("active-otel-host.service").exists()
    assert not fixture["state"].joinpath("enabled-otel-host.service").exists()
    assert unrelated.read_text(encoding="utf-8") == "preserve\n"


def test_artifact_installer_refuses_existing_symlink_destination(tmp_path: Path) -> None:
    artifact = tmp_path / "tool.raw"
    artifact.write_bytes(b"synthetic tool")
    target = tmp_path / "foreign"
    target.write_bytes(artifact.read_bytes())
    destination = tmp_path / "tool"
    destination.symlink_to(target)
    installer = Path(__file__).parents[1] / "files/install_runtime_artifact.py"
    result = subprocess.run(
        [sys.executable, str(installer), "tool", str(artifact), hashlib.sha256(artifact.read_bytes()).hexdigest(), "raw", "-", str(destination), "0755"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert destination.is_symlink()
    assert target.read_bytes() == b"synthetic tool"
