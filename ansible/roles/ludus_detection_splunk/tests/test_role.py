from __future__ import annotations

import json
import copy
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml
from support import REPOSITORY_ROOT

from helpers import command_calls, maintenance_manifest, make_fixture, run_role, write_manifest
from local_logging_support import inject_stock_failure, save_stock, stock_host


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


def assert_no_downstream_bootstrap(fixture) -> None:
    assert not Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).exists()
    assert not any(call.startswith("start") or call.startswith("enable boot-start") for call in command_calls(fixture))


def assert_no_producer_execution_or_mutation(fixture, before) -> None:
    assert "stock-helper:start" not in command_calls(fixture)
    assert stock_host(fixture).policy_state() == before
    state = fixture["local_logging_state"]
    assert (state / "audit-enabled").read_text(encoding="utf-8") == "no\n"
    assert (state / "audit-active").read_text(encoding="utf-8") == "no\n"
    assert (state / "audit-rules").read_text(encoding="utf-8") == ""


def test_local_logging_identity_adapter_requires_package_markers(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    state = fixture["local_logging_state"]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(fixture["python_adapter"])
    command = [
        os.sys.executable,
        "-c",
        "import grp, pwd; pwd.getpwnam('splunk'); grp.getgrnam('splunk')",
    ]

    assert subprocess.run(command, env=environment, check=False).returncode != 0
    (state / "splunk-account").touch()
    assert subprocess.run(command, env=environment, check=False).returncode != 0
    (state / "splunk-group").touch()
    assert subprocess.run(command, env=environment, check=False).returncode == 0


def test_local_logging_audit_restart_adapter_rejects_missing_unit_after_provisioning(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    initial = run_role(fixture)
    assert initial.returncode == 0, initial.stdout + initial.stderr
    state = fixture["local_logging_state"]
    unit = state / "audit-unit"
    unit.unlink()
    (state / "audit-active").write_text("no\n", encoding="utf-8")
    command = [str(fixture["fake_bin"] / "systemctl"), "restart", "auditd"]

    refused = subprocess.run(command, check=False)

    assert refused.returncode != 0
    assert (state / "audit-active").read_text(encoding="utf-8") == "no\n"
    unit.touch()
    accepted = subprocess.run(command, check=False)
    assert accepted.returncode == 0
    assert (state / "audit-active").read_text(encoding="utf-8") == "yes\n"


def test_local_logging_precedes_fresh_splunk_bootstrap(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    state = fixture["local_logging_state"]
    assert not (state / "splunk-account").exists()

    result = run_role(fixture)

    assert result.returncode == 0, result.stdout + result.stderr
    calls = command_calls(fixture)
    assert (state / "splunk-account").is_file()
    assert next(i for i, call in enumerate(calls) if call.startswith("-i ")) < calls.index("stock-helper:start")
    stock_done = next(i for i, call in enumerate(calls) if call == "stock-helper:exit:0")
    laurel_read = next(i for i, call in enumerate(calls) if "var/log/laurel/audit.log" in call and " -r " in call)
    splunk_start = next(i for i, call in enumerate(calls) if call.startswith("start --accept-license"))
    assert stock_done < laurel_read < splunk_start
    inputs = Path(fixture["variables"]["detection_splunk_inputs_path"]).read_text(encoding="utf-8")
    assert len(re.findall(r"^\[monitor://", inputs, re.MULTILINE)) == 3
    assert "splunkforwarder" not in inputs.lower() and "tcpout" not in inputs.lower()


def test_local_logging_runs_for_matching_installed_package(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture["package_state"].write_text("install ok installed\t10.6.1.1\n", encoding="utf-8")
    for name in ("splunk-account", "splunk-group", "splunk-unit"):
        (fixture["local_logging_state"] / name).touch()

    result = run_role(fixture)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not any(call.startswith("-i ") for call in command_calls(fixture))
    assert "stock-helper:start" in command_calls(fixture)
    assert any("var/log/laurel/audit.log" in call and " -r " in call for call in command_calls(fixture))


def test_local_logging_second_run_is_unchanged(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    first = run_role(fixture)
    assert first.returncode == 0, first.stdout + first.stderr
    token = Path(fixture["variables"]["detection_splunk_hec_token_path"]).read_bytes()
    before = len(command_calls(fixture))

    second = run_role(fixture)

    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    later = command_calls(fixture)[before:]
    assert not any(call.startswith("-i ") or call.startswith("restart ") or call.startswith("start ") for call in later)
    assert Path(fixture["variables"]["detection_splunk_hec_token_path"]).read_bytes() == token


@pytest.mark.parametrize("case", ["missing-account", "missing-group", "root", "adm", "wrong-reader", "owner-mismatch"])
def test_local_logging_rejects_invalid_reader(tmp_path: Path, case: str) -> None:
    fixture = make_fixture(tmp_path)
    updates = {}
    if case in {"root", "adm", "wrong-reader"}:
        updates["detection_laurel_read_user"] = {"root": "root", "adm": "adm", "wrong-reader": "splunkfwd"}[case]
    elif case == "owner-mismatch":
        updates["detection_splunk_file_owner"] = "root"
    else:
        fixture["package_state"].write_text("install ok installed\t10.6.1.1\n", encoding="utf-8")
        state = fixture["local_logging_state"]
        (state / "splunk-unit").touch()
        if case != "missing-account": (state / "splunk-account").touch()
        if case != "missing-group": (state / "splunk-group").touch()

    result = run_role(fixture, **updates)

    assert result.returncode != 0
    assert_no_downstream_bootstrap(fixture)


@pytest.mark.parametrize("case", ["audit-package", "audit-tool", "audit-unit", "inactive-rsyslog", "unsupported-rsyslog", "missing-logrotate", "missing-auth", "nonregular-syslog"])
def test_local_logging_rejects_missing_prerequisites(tmp_path: Path, case: str) -> None:
    fixture = make_fixture(tmp_path)
    state = fixture["local_logging_state"]
    unsupported_sources = None
    if case == "audit-package": (state / "audit-package").unlink()
    elif case == "audit-tool": Path(fixture["variables"]["detection_auditd_auditctl_command"]).unlink()
    elif case == "audit-unit": (state / "audit-unit").unlink()
    elif case == "inactive-rsyslog":
        host = stock_host(fixture); host.producer = fixture["stock_model"].ProducerObservation(False, False); save_stock(fixture, host)
    elif case == "unsupported-rsyslog":
        unsupported_sources = {
            name: (fixture["root"] / "var/log" / name).read_bytes()
            for name in ("auth.log", "syslog")
        }
        host = stock_host(fixture)
        host.running_executable = "/usr/local/sbin/unsupported-rsyslogd"
        save_stock(fixture, host)
    elif case == "missing-logrotate":
        host = stock_host(fixture); host.packages.remove("logrotate"); save_stock(fixture, host)
    elif case == "missing-auth": (fixture["root"] / "var/log/auth.log").unlink()
    elif case == "nonregular-syslog":
        path = fixture["root"] / "var/log/syslog"; path.unlink(); path.mkdir()

    result = run_role(fixture)

    assert result.returncode != 0
    assert_no_downstream_bootstrap(fixture)
    if unsupported_sources is not None:
        calls = command_calls(fixture)
        assert "stock-helper:start" in calls
        assert any(call.startswith("stock-helper:exit:") and call != "stock-helper:exit:0" for call in calls)
        assert stock_host(fixture).producer.active is True
        assert {
            name: (fixture["root"] / "var/log" / name).read_bytes()
            for name in ("auth.log", "syslog")
        } == unsupported_sources


@pytest.mark.parametrize("case", ["before-mutation", "after-stock", "rsyslog", "audit-rules", "audit-restart", "missing-output", "unreadable-output", "staging-cleanup"])
def test_local_logging_failure_blocks_fresh_bootstrap(tmp_path: Path, case: str) -> None:
    fixture = make_fixture(tmp_path)
    state = fixture["local_logging_state"]
    if case == "before-mutation": (state / "audit-package").unlink()
    elif case == "after-stock": inject_stock_failure(fixture, "group-auth-after")
    elif case == "rsyslog": inject_stock_failure(fixture, "restart-before")
    elif case == "audit-rules": (state / "fail-audit-rules").touch()
    elif case == "audit-restart": (state / "fail-audit-restart").touch()
    elif case == "missing-output": (state / "missing-laurel-output").touch()
    elif case == "unreadable-output": (state / "unreadable-laurel-output").touch()
    elif case == "staging-cleanup": (state / "fail-staging-cleanup").touch()

    result = run_role(fixture)

    assert result.returncode != 0
    assert_no_downstream_bootstrap(fixture)
    assert not fixture["service_enabled"].exists()
    assert not fixture["service_state"].exists()
    assert not Path(fixture["variables"]["detection_splunk_seed_path"]).exists()
    assert fixture["package_state"].is_file()
    stock_marker = fixture["root"] / "var/lib/detection-engineering/stock-log-access/applied.json"
    laurel_marker = fixture["root"] / "var/lib/detection-engineering/laurel-apply.sha256"
    assert stock_host(fixture).producer.active is True
    assert stock_marker.exists() is (case in {
        "audit-rules", "audit-restart", "missing-output", "unreadable-output", "staging-cleanup",
    })
    assert not laurel_marker.exists()
    expected_audit = {
        "before-mutation": ("no\n", "no\n", ""),
        "after-stock": ("no\n", "no\n", ""),
        "rsyslog": ("no\n", "no\n", ""),
        "audit-rules": ("yes\n", "no\n", ""),
        "audit-restart": (
            "yes\n", "no\n",
            "-a always,exit -F arch=b64 -S execve -F key=detection_process\n",
        ),
        "missing-output": (
            "yes\n", "yes\n",
            "-a always,exit -F arch=b64 -S execve -F key=detection_process\n",
        ),
        "unreadable-output": (
            "yes\n", "yes\n",
            "-a always,exit -F arch=b64 -S execve -F key=detection_process\n",
        ),
        "staging-cleanup": ("no\n", "no\n", ""),
    }
    assert (
        (state / "audit-enabled").read_text(encoding="utf-8"),
        (state / "audit-active").read_text(encoding="utf-8"),
        (state / "audit-rules").read_text(encoding="utf-8"),
    ) == expected_audit[case]


def test_local_logging_failure_preserves_running_splunk(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    assert run_role(fixture).returncode == 0
    write_manifest(fixture, "HEALTHY")
    protected = {
        "service": fixture["service_state"].read_bytes(),
        "token": Path(fixture["variables"]["detection_splunk_hec_token_path"]).read_bytes(),
        "bootstrap": Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).read_bytes(),
        "authority": Path(fixture["variables"]["detection_splunk_maintenance_state_path"]).read_bytes(),
        "unrelated": fixture["unrelated"].read_bytes(),
    }
    host = stock_host(fixture)
    marker = fixture["root"] / "var/lib/detection-engineering/stock-log-access/applied.json"
    marker.unlink()
    for logical in ("/var/log/auth.log", "/var/log/syslog"):
        facts = host.files[logical]
        host.files[logical] = fixture["stock_model"].FileFacts(**{**facts.__dict__, "gid": host.groups["adm"].gid})
    host.fail_once("group_auth", "after")
    save_stock(fixture, host)

    result = run_role(fixture)

    assert result.returncode != 0
    assert fixture["service_state"].read_bytes() == protected["service"]
    assert Path(fixture["variables"]["detection_splunk_hec_token_path"]).read_bytes() == protected["token"]
    assert Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).read_bytes() == protected["bootstrap"]
    assert Path(fixture["variables"]["detection_splunk_maintenance_state_path"]).read_bytes() == protected["authority"]
    assert fixture["unrelated"].read_bytes() == protected["unrelated"]


def test_local_logging_shared_parent_converges(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    parent = fixture["root"] / "var/lib/detection-engineering"
    parent.mkdir(); parent.chmod(0o750)
    sibling = parent / "sibling.marker"; sibling.write_bytes(b"sibling-bytes")
    seed_parent = Path(fixture["variables"]["detection_splunk_seed_path"]).parent
    seed_parent.mkdir(parents=True); seed_parent.chmod(0o750)

    first = run_role(fixture)
    second = run_role(fixture)

    assert first.returncode == 0, first.stdout + first.stderr
    assert second.returncode == 0, second.stdout + second.stderr
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert sibling.read_bytes() == b"sibling-bytes"
    assert stat.S_IMODE(seed_parent.stat().st_mode) == 0o750
    assert "changed=0" in second.stdout


def test_local_logging_refuses_untrusted_parent(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    parent = fixture["root"] / "var/lib/detection-engineering"
    parent.mkdir(); parent.chmod(0o777)

    result = run_role(fixture)

    assert result.returncode != 0
    assert_no_downstream_bootstrap(fixture)


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
    assert re.findall(r"^\[monitor://([^]]+)\]$", inputs, re.MULTILINE) == [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/laurel/audit.log",
    ]
    assert "[monitor:///var/log/auth.log]\ndisabled = false\nindex = de_linux\nsourcetype = linux:auth" in inputs
    assert "[monitor:///var/log/syslog]\ndisabled = false\nindex = de_linux\nsourcetype = linux:system" in inputs
    assert "[monitor:///var/log/laurel/audit.log]\ndisabled = false\nindex = de_linux\nsourcetype = linux:audit:laurel" in inputs
    assert "/var/log/detection-engineering/audit-safe.jsonl" not in inputs
    assert "linux:audit:safe" not in inputs
    assert all(token not in inputs.lower() for token in ("[tcpout", "forward-server", "splunkfwd"))
    assert all(token not in inputs.upper() for token in ("TRANSFORMS-", "SEDCMD-", "FIELDALIAS-"))
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


def test_first_start_stages_requested_username_and_six_character_policy_then_cleans_both(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    result = run_role(
        fixture,
        detection_splunk_admin_username="debian",
        detection_splunk_admin_password="debian",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not Path(fixture["variables"]["detection_splunk_initial_auth_policy_path"]).exists()
    seed = Path(fixture["variables"]["detection_splunk_seed_path"])
    assert not seed.exists()
    assert any(call.startswith("start --accept-license") for call in command_calls(fixture))
    assert Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).exists()
    second = run_role(
        fixture,
        detection_splunk_admin_username="debian",
        detection_splunk_admin_password="debian",
    )
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert not Path(fixture["variables"]["detection_splunk_initial_auth_policy_path"]).exists()


def test_failed_first_start_cleans_seed_policy_and_does_not_claim_bootstrap(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    (fixture["root"] / "fail-splunk-start").touch()

    result = run_role(
        fixture,
        detection_splunk_admin_username="debian",
        detection_splunk_admin_password="debian",
    )

    assert result.returncode != 0
    assert not fixture["service_state"].exists()
    assert not Path(fixture["variables"]["detection_splunk_seed_path"]).exists()
    assert not Path(fixture["variables"]["detection_splunk_initial_auth_policy_path"]).exists()
    assert not Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).exists()


def test_unmarked_initialized_password_database_refuses_seed_before_first_start(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    password_file = Path(fixture["variables"]["detection_splunk_password_file_path"])
    password_file.parent.mkdir(parents=True)
    password_file.write_text("initialized password database\n", encoding="utf-8")

    result = run_role(
        fixture,
        detection_splunk_admin_username="debian",
        detection_splunk_admin_password="debian",
    )

    assert result.returncode != 0
    assert "user-seed.conf would be ignored" in result.stdout
    assert not Path(fixture["variables"]["detection_splunk_seed_path"]).exists()
    assert not Path(fixture["variables"]["detection_splunk_initial_auth_policy_path"]).exists()
    assert not Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).exists()
    assert not any(call.startswith("start --accept-license") for call in command_calls(fixture))


@pytest.mark.parametrize(
    ("config_name", "content", "mode"),
    [
        ("authentication.conf", b"[splunk_auth]\nminPasswordLength = 14\ncustomSetting = preserve\n", 0o640),
        ("user-seed.conf", b"[user_info]\nUSERNAME = operator\nPASSWORD = private\n", 0o600),
    ],
)
def test_unmarked_preexisting_first_start_config_is_refused_and_preserved(
    tmp_path: Path, config_name: str, content: bytes, mode: int
) -> None:
    fixture = make_fixture(tmp_path)
    paths = {
        "authentication.conf": Path(fixture["variables"]["detection_splunk_initial_auth_policy_path"]),
        "user-seed.conf": Path(fixture["variables"]["detection_splunk_seed_path"]),
    }
    target = paths[config_name]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    target.chmod(mode)

    result = run_role(
        fixture,
        detection_splunk_admin_username="debian",
        detection_splunk_admin_password="debian",
    )

    assert result.returncode != 0
    assert "preexisting user-seed.conf or authentication.conf" in result.stdout
    assert target.read_bytes() == content
    assert stat.S_IMODE(target.stat().st_mode) == mode
    assert_no_mutation(fixture)
    assert not Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).exists()


def test_competing_file_created_after_preflight_is_never_overwritten(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    real_python = fixture["variables"]["detection_splunk_python"]
    config = Path(fixture["variables"]["detection_splunk_initial_auth_policy_path"])
    wrapper = fixture["fake_bin"] / "race-python"
    wrapper.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        f"real = {real_python!r}\n"
        f"target = {str(config)!r}\n"
        f"marker = {str(fixture['root'] / 'inject-competing-create')!r}\n"
        "if len(sys.argv) > 3 and sys.argv[2] == 'stage' and sys.argv[sys.argv.index('--path') + 1] == target and os.path.exists(marker):\n"
        "    os.unlink(marker)\n"
        "    with open(target, 'xb') as stream: stream.write(b'[splunk_auth]\\ncustomSetting = competing-writer\\n')\n"
        "os.execv(real, [real, *sys.argv[1:]])\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    fixture["variables"]["detection_splunk_python"] = str(wrapper)
    (fixture["root"] / "inject-competing-create").touch()

    result = run_role(fixture)

    assert result.returncode != 0
    assert config.read_bytes() == b"[splunk_auth]\ncustomSetting = competing-writer\n"
    assert not Path(fixture["variables"]["detection_splunk_seed_path"]).exists()
    assert not Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).exists()
    lock = Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).parent / "splunk-first-start.lock"
    assert not lock.exists(), result.stdout + result.stderr


def test_replaced_staged_policy_is_preserved_and_reports_recovery(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    (fixture["root"] / "replace-auth-before-cleanup").touch()

    result = run_role(fixture)

    config = Path(fixture["variables"]["detection_splunk_initial_auth_policy_path"])
    assert result.returncode != 0
    assert "recover the unmarked install explicitly" in result.stdout
    assert config.read_bytes() == b"[splunk_auth]\ncustomSetting = competing-writer\n"
    lock = Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).parent / "splunk-first-start.lock"
    assert not lock.exists(), result.stdout + result.stderr
    assert not Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).exists()


def test_seed_consumed_during_first_start_is_a_normal_cleanup_case(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    (fixture["root"] / "consume-seed-during-start").touch()

    result = run_role(fixture)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not Path(fixture["variables"]["detection_splunk_seed_path"]).exists()
    assert not Path(fixture["variables"]["detection_splunk_initial_auth_policy_path"]).exists()
    lock = Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).parent / "splunk-first-start.lock"
    assert not lock.exists()
    assert Path(fixture["variables"]["detection_splunk_bootstrap_state_path"]).exists()


def test_invalid_admin_username_refuses_before_any_package_or_seed_mutation(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)

    result = run_role(fixture, detection_splunk_admin_username="debian\nPASSWORD = injected")

    assert result.returncode != 0
    assert_no_mutation(fixture)
    assert_no_downstream_bootstrap(fixture)


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
    producer_before = stock_host(fixture).policy_state()

    result = run_role(fixture)

    assert result.returncode != 0
    assert "maintenance state" in (result.stdout + result.stderr).lower()
    assert_no_mutation(fixture)
    assert_no_producer_execution_or_mutation(fixture, producer_before)


@pytest.mark.parametrize("state", ["ABSENT", "RESTORED_PENDING_ACCEPTANCE"])
def test_restore_requires_absent_and_explicit_intent(tmp_path: Path, state: str) -> None:
    fixture = make_fixture(tmp_path)
    original = write_manifest(fixture, state)
    producer_before = stock_host(fixture).policy_state()

    result = run_role(fixture)

    assert result.returncode != 0
    assert_no_mutation(fixture)
    assert_no_producer_execution_or_mutation(fixture, producer_before)
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
    for name in ("splunk-account", "splunk-group", "splunk-unit"):
        (fixture["local_logging_state"] / name).touch()

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
