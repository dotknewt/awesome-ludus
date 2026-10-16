from __future__ import annotations

import json
import copy
import stat
from pathlib import Path

import pytest
import yaml
from support import REPOSITORY_ROOT

from helpers import command_calls, maintenance_manifest, make_fixture, run_role, write_manifest


def assert_no_mutation(fixture) -> None:
    calls = command_calls(fixture)
    assert not any(call.startswith("-i ") for call in calls)
    assert not any(" restart" in call or call.startswith("restart") for call in calls)
    assert not any(call.startswith("start ") or call.startswith("enable ") for call in calls)
    for variable in (
        "detection_splunk_indexes_path",
        "detection_splunk_inputs_path",
        "detection_splunk_web_path",
        "detection_splunk_hec_input_path",
        "detection_splunk_provenance_path",
    ):
        assert not Path(fixture["variables"][variable]).exists()


def test_installs_configures_local_telemetry_and_generates_scoped_token_once(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)

    first = run_role(fixture)
    assert first.returncode == 0, first.stdout + first.stderr

    paths = fixture["variables"]
    indexes = Path(paths["detection_splunk_indexes_path"]).read_text(encoding="utf-8")
    inputs = Path(paths["detection_splunk_inputs_path"]).read_text(encoding="utf-8")
    web = Path(paths["detection_splunk_web_path"]).read_text(encoding="utf-8")
    hec = Path(paths["detection_splunk_hec_input_path"]).read_text(encoding="utf-8")
    token_path = Path(paths["detection_splunk_hec_token_path"])
    token = token_path.read_text(encoding="utf-8").strip()
    assert all(f"[{name}]" in indexes for name in ("de_linux", "de_gitlab", "de_runner", "de_runtime"))
    assert "homePath" not in indexes and "maxTotalDataSizeMB" not in indexes
    assert "/var/log/auth.log" in inputs and "linux:auth" in inputs
    assert "/var/log/syslog" in inputs and "linux:system" in inputs
    assert "/var/log/detection-engineering/audit-safe.jsonl" in inputs
    assert "[splunktcp://9997]" in inputs
    assert "10.77.10.14" in web
    assert "[http://detection-workload]" in hec and token in hec
    assert "indexes = de_runtime" in hec and "index = de_runtime" in hec
    assert len(token) >= 43
    assert stat.S_IMODE(token_path.stat().st_mode) == 0o600
    assert not Path(paths["detection_splunk_seed_path"]).exists()
    assert not Path(paths["detection_splunk_maintenance_state_path"]).exists()

    calls_before = command_calls(fixture)
    second = run_role(fixture)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert token_path.read_text(encoding="utf-8").strip() == token
    assert not any(call.startswith("-i ") for call in command_calls(fixture)[len(calls_before):])


def test_bootstrap_secrets_never_enter_argv_or_captured_output(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    canary = fixture["variables"]["detection_splunk_admin_password"]

    result = run_role(fixture)

    assert result.returncode == 0, result.stdout + result.stderr
    evidence = result.stdout + result.stderr + "\n".join(command_calls(fixture))
    assert canary not in evidence
    token = Path(fixture["variables"]["detection_splunk_hec_token_path"]).read_text(encoding="utf-8").strip()
    assert token not in evidence
    assert all("password" not in call.lower() and "token" not in call.lower() for call in command_calls(fixture))


def test_user_approved_trial_with_verified_expiry_is_allowed_when_free_unknown(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)

    result = run_role(fixture, detection_splunk_free_capability={"status": "UNVERIFIED", "observed": None})

    assert result.returncode == 0, result.stdout + result.stderr
    assert fixture["package_state"].read_text(encoding="utf-8").strip() == "install ok installed\t10.6.1.1"


def test_install_provenance_matches_verified_deb(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    artifact = fixture["variables"]["detection_splunk_artifact"]

    result = run_role(fixture)

    assert result.returncode == 0, result.stdout + result.stderr
    provenance = yaml.safe_load(Path(fixture["variables"]["detection_splunk_provenance_path"]).read_text(encoding="utf-8"))
    assert provenance == {
        "schema_version": 1,
        "package": "splunk",
        "version": artifact["version"],
        "build": artifact["build"],
        "architecture": "amd64",
        "sha256": artifact["sha256"],
        "license_decision": {
            "initial_mode": "ENTERPRISE_60_DAY_TRIAL",
            "trial_days_user_confirmed": 60,
            "terms_confirmation": "USER_CONFIRMED_NOT_INDEPENDENTLY_VERIFIED",
        },
    }


@pytest.mark.parametrize("state", ["PREPARED", "REMOVE_FAILED", "POSTCHECK_FAILED"])
def test_nonhealthy_maintenance_state_blocks_ordinary_redeploy(tmp_path: Path, state: str) -> None:
    fixture = make_fixture(tmp_path)
    write_manifest(fixture, state)

    result = run_role(fixture)

    assert result.returncode != 0
    assert "maintenance state" in (result.stdout + result.stderr).lower()
    assert_no_mutation(fixture)


@pytest.mark.parametrize("state", ["ABSENT", "RESTORED_PENDING_ACCEPTANCE"])
def test_restore_requires_absent_and_explicit_intent(tmp_path: Path, state: str) -> None:
    fixture = make_fixture(tmp_path)
    original = write_manifest(fixture, state)

    result = run_role(fixture)

    assert result.returncode != 0
    assert_no_mutation(fixture)
    assert maintenance_manifest(fixture) == original


def test_successful_restore_sets_pending_without_claiming_healthy(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    initial = run_role(fixture)
    assert initial.returncode == 0, initial.stdout + initial.stderr
    original = write_manifest(fixture, "ABSENT")
    fixture["package_state"].unlink()
    fixture["service_state"].unlink()
    fixture["calls"].write_text("", encoding="utf-8")

    result = run_role(fixture, detection_splunk_restore_authorized=True)

    assert result.returncode == 0, result.stdout + result.stderr
    current = maintenance_manifest(fixture)
    assert current["state"] == "RESTORED_PENDING_ACCEPTANCE"
    assert current["state"] != "HEALTHY"
    assert current["baseline"] == original["baseline"]
    assert current["operation_id"] == original["operation_id"]
    assert current["journal"][:-1] == original["journal"]
    assert current["journal"][-1]["from"] == "ABSENT"
    assert current["journal"][-1]["to"] == "RESTORED_PENDING_ACCEPTANCE"


def test_absent_residual_config_package_is_reinstalled_and_preserved_bootstrap_is_started(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    initial = run_role(fixture)
    assert initial.returncode == 0, initial.stdout + initial.stderr
    original = write_manifest(fixture, "ABSENT")
    fixture["package_state"].write_text("deinstall ok config-files\t10.6.1.1\n", encoding="utf-8")
    fixture["service_state"].unlink()
    fixture["service_enabled"].unlink()
    fixture["calls"].write_text("", encoding="utf-8")

    result = run_role(fixture, detection_splunk_restore_authorized=True)

    assert result.returncode == 0, result.stdout + result.stderr
    calls = command_calls(fixture)
    assert any(call.startswith("-i ") for call in calls)
    assert any(call.startswith("enable ") for call in calls)
    assert any(call.startswith("start ") for call in calls)
    assert fixture["service_state"].read_text(encoding="utf-8") == "running"
    assert fixture["service_enabled"].read_text(encoding="utf-8") == "enabled"
    current = maintenance_manifest(fixture)
    assert current["state"] == "RESTORED_PENDING_ACCEPTANCE"
    assert current["baseline"] == original["baseline"]
    assert current["operation_id"] == original["operation_id"]
    assert current["journal"][:-1] == original["journal"]


def test_installed_matching_version_is_not_reinstalled(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture["package_state"].write_text(
        "install ok installed\t10.6.1.1\n", encoding="utf-8"
    )

    result = run_role(fixture)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not any(call.startswith("-i ") for call in command_calls(fixture))


def test_installed_wrong_version_is_refused_without_reinstall(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture["package_state"].write_text(
        "install ok installed\t9.9.9\n", encoding="utf-8"
    )

    result = run_role(fixture)

    assert result.returncode != 0
    assert_no_mutation(fixture)


def malformed_manifests(valid: dict) -> list[dict]:
    cases = []
    for mutate in (
        lambda value: value.update(extra="unexpected"),
        lambda value: value.update(operation_id="not-a-uuid"),
        lambda value: value.update(startup_paths="Splunkd.service"),
        lambda value: value.update(baseline={"captured_at": "bad"}),
        lambda value: value.update(journal="not-a-list"),
        lambda value: value["journal"][0].update(at="not-rfc3339"),
        lambda value: value["journal"][0].update(extra="unexpected"),
        lambda value: value.update(acceptance={"run_id": "missing-fields"}),
        lambda value: value["acceptance"].update(summary_sha256="short"),
        lambda value: value.update(operation_id=None),
        lambda value: value.update(baseline=None),
        lambda value: value.update(journal=[]),
        lambda value: value["journal"][-1].update(to="HEALTHY"),
        lambda value: value["baseline"]["paths"].append(
            {
                "path": "relative",
                "type": "file",
                "owner": "root",
                "group": "root",
                "mode": "0600",
                "content_sha256": "b" * 64,
            }
        ),
    ):
        case = copy.deepcopy(valid)
        mutate(case)
        cases.append(case)
    return cases


@pytest.mark.parametrize("case_index", range(14))
def test_malformed_manifest_blocks_before_any_mutation_and_remains_byte_exact(
    tmp_path: Path, case_index: int
) -> None:
    fixture = make_fixture(tmp_path)
    valid = write_manifest(fixture, "ABSENT")
    malformed = malformed_manifests(valid)[case_index]
    path = Path(fixture["variables"]["detection_splunk_maintenance_state_path"])
    path.write_text(json.dumps(malformed, separators=(",", ":")), encoding="utf-8")
    original_bytes = path.read_bytes()

    result = run_role(fixture, detection_splunk_restore_authorized=True)

    assert result.returncode != 0
    assert path.read_bytes() == original_bytes
    assert command_calls(fixture) == []
    assert_no_mutation(fixture)


@pytest.mark.parametrize("token", [b"", b"short\n", b"valid-looking-line\nsecond-line\n"])
def test_corrupt_existing_hec_token_refuses_without_regeneration_or_service_mutation(
    tmp_path: Path, token: bytes
) -> None:
    fixture = make_fixture(tmp_path)
    token_path = Path(fixture["variables"]["detection_splunk_hec_token_path"])
    token_path.parent.mkdir(parents=True)
    token_path.write_bytes(token)
    token_path.chmod(0o600)
    bootstrap = Path(fixture["variables"]["detection_splunk_bootstrap_state_path"])
    bootstrap.parent.mkdir(parents=True)
    bootstrap.write_text("configured\n", encoding="utf-8")
    fixture["package_state"].write_text(
        "install ok installed\t10.6.1.1\n", encoding="utf-8"
    )
    original = token_path.read_bytes()

    result = run_role(fixture)

    assert result.returncode != 0
    assert token_path.read_bytes() == original
    assert not fixture["service_state"].exists()
    assert not any(call.startswith("restart ") or call.startswith("start ") for call in command_calls(fixture))


def test_authorized_pending_reapply_is_idempotent_and_stays_pending(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    initial = run_role(fixture)
    assert initial.returncode == 0, initial.stdout + initial.stderr
    original = write_manifest(fixture, "RESTORED_PENDING_ACCEPTANCE")
    fixture["calls"].write_text("", encoding="utf-8")

    first = run_role(fixture, detection_splunk_restore_authorized=True)
    assert first.returncode == 0, first.stdout + first.stderr
    after_first = maintenance_manifest(fixture)
    calls_before = command_calls(fixture)
    second = run_role(fixture, detection_splunk_restore_authorized=True)

    assert second.returncode == 0, second.stdout + second.stderr
    assert after_first == original
    assert maintenance_manifest(fixture) == original
    all_calls = command_calls(fixture)
    assert not any(call.startswith("-i ") for call in all_calls[len(calls_before):])
    forbidden = ("reset", "renew", "free", "uninstall", "remove", "purge")
    assert not any(word in call.lower() for call in all_calls for word in forbidden)


def test_authorized_restore_refuses_missing_preserved_bootstrap_marker_before_mutation(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    original = write_manifest(fixture, "ABSENT")

    result = run_role(fixture, detection_splunk_restore_authorized=True)

    assert result.returncode != 0
    assert maintenance_manifest(fixture) == original
    assert command_calls(fixture) == []
    assert_no_mutation(fixture)


@pytest.mark.parametrize(
    "updates",
    [
        {"detection_splunk_artifact": {}},
        {"detection_splunk_hec_supported": False},
        {"detection_splunk_search_api_supported": False},
        {"detection_splunk_license": {}},
        {"detection_splunk_admin_password": ""},
    ],
)
def test_missing_or_unverified_product_inputs_refuse_before_mutation(tmp_path: Path, updates: dict) -> None:
    fixture = make_fixture(tmp_path)

    result = run_role(fixture, **updates)

    assert result.returncode != 0
    assert_no_mutation(fixture)


def test_authenticated_download_refuses_world_readable_credential_file_before_mutation(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    auth = fixture["root"] / "download.authorization"
    auth.write_text("Bearer DOWNLOAD-CANARY\n", encoding="utf-8")
    auth.chmod(0o644)
    artifact = dict(fixture["variables"]["detection_splunk_artifact"])
    artifact["download_auth_required"] = True

    result = run_role(
        fixture,
        detection_splunk_artifact=artifact,
        detection_splunk_download_auth_path=str(auth),
    )

    assert result.returncode != 0
    assert "0600" in result.stdout + result.stderr
    assert "DOWNLOAD-CANARY" not in result.stdout + result.stderr
    assert_no_mutation(fixture)


def test_protected_download_credential_never_enters_process_or_output_evidence(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    auth = fixture["root"] / "download.authorization"
    canary = "Bearer DOWNLOAD-CANARY"
    auth.write_text(canary + "\n", encoding="utf-8")
    auth.chmod(0o600)
    artifact = dict(fixture["variables"]["detection_splunk_artifact"])
    artifact["download_auth_required"] = True

    result = run_role(
        fixture,
        detection_splunk_artifact=artifact,
        detection_splunk_download_auth_path=str(auth),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    evidence = result.stdout + result.stderr + "\n".join(command_calls(fixture))
    assert canary not in evidence


def test_healthy_manifest_allows_ordinary_convergence_without_rewriting_history(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    initial = run_role(fixture)
    assert initial.returncode == 0, initial.stdout + initial.stderr
    original = write_manifest(fixture, "HEALTHY")
    fixture["calls"].write_text("", encoding="utf-8")

    result = run_role(fixture)

    assert result.returncode == 0, result.stdout + result.stderr
    assert maintenance_manifest(fixture) == original


def test_role_contains_no_maintenance_or_unrelated_product_actions() -> None:
    role = REPOSITORY_ROOT / "ansible/roles/ludus_detection_splunk"
    production = "\n".join(
        path.read_text(encoding="utf-8")
        for path in role.rglob("*")
        if path.is_file() and "tests" not in path.parts
    ).lower()
    assert "dpkg -r" not in production
    assert "apt autoremove" not in production
    assert "firewall" not in production
    assert "delete index" not in production
    assert "trial-reset" not in production
    assert "apps install" not in production
