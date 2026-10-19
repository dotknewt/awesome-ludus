"""Offline composition tests for the real forwarder pipeline entrypoint."""

from pathlib import Path
import re
import subprocess

import pytest

from support import PipelineFixture


PRODUCER_WRAPPER_TASK = "Produce native Linux audit telemetry"
PRODUCER_DEFAULT_TASK = "ludus_detection_linux_logging : Configure native auditd and Laurel logging"
STOCK_HELPER_TASK = "ludus_detection_linux_logging : Execute the fixed stock-log access policy"
ACTIVATION_WRAPPER_TASK = "Activate the forwarder after producer readiness"
ACTIVATION_VALIDATE_TASK = "ludus_detection_forwarder : Validate all forwarder activation contracts before target mutation"


def _task_names(result) -> set[str]:
    return set(re.findall(r"^TASK \[(.+?)\] \*+$", result.stdout, flags=re.MULTILINE))


def _assert_producer_not_entered(result) -> None:
    names = _task_names(result)
    assert PRODUCER_WRAPPER_TASK not in names
    assert PRODUCER_DEFAULT_TASK not in names


def _assert_activation_not_entered(result) -> None:
    names = _task_names(result)
    assert ACTIVATION_WRAPPER_TASK not in names
    assert ACTIVATION_VALIDATE_TASK not in names


def _assert_no_downstream_activation_calls(fixture: PipelineFixture, calls: list[str] | None = None) -> None:
    observed = fixture.calls_since() if calls is None else calls
    assert not any(
        " start --accept-license" in call
        or call in {"restart SplunkForwarder.service", "enable SplunkForwarder.service", "start SplunkForwarder.service"}
        for call in observed
    )


def _assert_no_activation(fixture: PipelineFixture) -> None:
    state = fixture.snapshot()
    assert state["transaction"] is None
    assert state["seed"] is None
    assert state["bootstrap_marker"] is None
    assert state["unit"] is None
    assert state["service"] is None
    assert state["forwarder_bootstrapped"] is None
    assert state["forwarder_enabled"] is None
    assert state["inputs"] is None
    assert state["outputs"] is None
    _assert_no_downstream_activation_calls(fixture)


@pytest.mark.parametrize(("profile", "count"), [("gitlab", 3), ("runner", 4), ("workload", 3)])
def test_fresh_entrypoint_composes_prepare_native_producer_and_activate(tmp_path: Path, profile: str, count: int) -> None:
    fixture = PipelineFixture(tmp_path, profile)
    result = fixture.run()
    assert result.returncode == 0, result.stdout + result.stderr
    state = fixture.snapshot()
    assert all(state[name] is not None for name in ("package", "provenance", "laurel_binary", "laurel_config", "laurel_output", "laurel_marker", "bootstrap_marker", "unit", "inputs", "service"))
    assert state["transaction"] is None
    assert state["package_account"] is not None
    assert state["laurel_account"] is not None
    assert state["audit_enabled"] == b"yes\n"
    assert state["audit_active"] == b"yes\n"
    assert b"key=detection_process" in state["audit_rules"]
    assert state["forwarder_bootstrapped"] is not None
    assert state["forwarder_enabled"] is not None
    assert state["outputs"] is not None
    assert fixture.actual("/var/lib/detection-engineering").stat().st_mode & 0o777 == 0o700
    assert fixture.actual("/opt/splunkforwarder/etc/system/local").stat().st_mode & 0o777 == 0o750
    rendered = state["inputs"].decode()
    assert rendered.count("[monitor://") == count
    assert "monitor:///var/log/laurel/audit.log" in rendered
    assert "sourcetype = linux:audit:laurel" in rendered
    calls = fixture.calls_since()
    install = next(i for i, call in enumerate(calls) if call.startswith("-i "))
    native_probe = next(i for i, call in enumerate(calls) if call == "is-active rsyslog")
    group_auth = next(i for i, call in enumerate(calls) if call.startswith("stock-model:group:/var/log/auth.log:"))
    restart_rsyslog = next(i for i, call in enumerate(calls) if call == "stock-model:restart")
    producer = next(i for i, call in enumerate(calls) if call == "restart auditd")
    bootstrap = next(i for i, call in enumerate(calls) if " start --accept-license" in call)
    assert install < native_probe < group_auth < restart_rsyslog < producer < bootstrap
    stock = fixture.stock_host()
    reader_gid = stock.groups[stock.reader].gid
    assert {stock.files[path].gid for path in ("/var/log/auth.log", "/var/log/syslog")} == {reader_gid}
    assert stock.loaded_action_groups == {
        "/var/log/auth.log": reader_gid,
        "/var/log/syslog": reader_gid,
    }
    assert state["stock_marker"] is not None
    assert all(
        not row.startswith(f"{fixture.actual(logical)}|")
        for logical in ("/var/log/auth.log", "/var/log/syslog")
        for row in fixture.readable.read_text(encoding="utf-8").splitlines()
    )
    names = _task_names(result)
    assert {PRODUCER_WRAPPER_TASK, PRODUCER_DEFAULT_TASK, STOCK_HELPER_TASK, ACTIVATION_WRAPPER_TASK, ACTIVATION_VALIDATE_TASK} <= names
    fixture.assert_unrelated()


def test_active_rerun_converges_without_reinstall_reapply_or_rebootstrap(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    first = fixture.run()
    assert first.returncode == 0, first.stdout + first.stderr
    before_state = fixture.snapshot()
    call_count = len(fixture.calls_since())
    second = fixture.run()
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert fixture.snapshot() == before_state
    assert fixture.actual("/var/lib/detection-engineering").stat().st_mode & 0o777 == 0o700
    assert fixture.actual("/opt/splunkforwarder/etc/system/local").stat().st_mode & 0o777 == 0o750
    assert fixture.actual("/opt/splunkforwarder/etc/system/local/user-seed.conf").exists() is False
    later = fixture.calls_since(call_count)
    assert not any(call.startswith("-i ") or call == "restart auditd" or " start --accept-license" in call for call in later)
    assert not any(call in {"stock-model:restart", "stock-model:publish:/etc/rsyslog.conf"} for call in later)
    _assert_no_downstream_activation_calls(fixture, later)
    fixture.assert_unrelated()


def test_inactive_native_producer_is_started_before_stock_log_access(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    stock = fixture.stock_host()
    stock.producer = type(stock.producer)(False, stock.producer.identity_valid)
    fixture.save_stock(stock)

    result = fixture.run()

    assert result.returncode == 0, result.stdout + result.stderr
    calls = fixture.calls_since()
    native_start = calls.index("enable --now rsyslog")
    group_auth = next(i for i, call in enumerate(calls) if call.startswith("stock-model:group:/var/log/auth.log:"))
    assert native_start < group_auth
    assert fixture.stock_host().producer.active is True


@pytest.mark.parametrize(
    "failure",
    ["unextracted-laurel", "wrong-plugin-context", "wrong-plugin-path", "wrong-plugin-args", "wrong-laurel-config"],
)
def test_producer_executes_extracted_plugin_and_rejects_wrong_runtime_context(tmp_path: Path, failure: str) -> None:
    fixture = PipelineFixture(tmp_path)
    (fixture.state / failure).touch()
    result = fixture.run()
    assert result.returncode != 0
    calls = fixture.calls_since()
    assert any(call.startswith("laurel-exec:") for call in calls)
    state = fixture.snapshot()
    assert state["package_account"] is not None
    assert state["laurel_account"] is not None
    assert state["laurel_marker"] is None
    assert state["laurel_output"] is None
    assert state["audit_active"] == b"no\n"
    _assert_activation_not_entered(result)
    _assert_no_activation(fixture)
    fixture.assert_unrelated()


@pytest.mark.parametrize("updates", [{"detection_forwarder_profile": "invalid"}, {"detection_laurel_read_user": "splunk"}])
def test_shared_guards_refuse_before_any_role_mutation(tmp_path: Path, updates: dict) -> None:
    fixture = PipelineFixture(tmp_path)
    before = fixture.snapshot()
    result = fixture.run(**updates)
    assert result.returncode != 0
    assert "pipeline requires" in result.stdout + result.stderr
    assert fixture.snapshot() == before
    assert fixture.calls_since() == []
    _assert_producer_not_entered(result)
    _assert_activation_not_entered(result)
    fixture.assert_unrelated()


def test_prepare_validation_failure_precedes_package_and_producer_mutation(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    contract = dict(fixture.variables["detection_forwarder_bootstrap_contract"])
    contract.update(status="BLOCKED", observed=None)
    result = fixture.run(detection_forwarder_bootstrap_contract=contract)
    assert result.returncode != 0
    state = fixture.snapshot()
    assert state["package"] is None
    assert state["package_account"] is None
    assert state["laurel_binary"] is None
    _assert_producer_not_entered(result)
    _assert_activation_not_entered(result)
    _assert_no_activation(fixture)
    fixture.assert_unrelated()


def test_prepare_failure_after_package_mutation_stops_before_producer(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    (fixture.lifecycle / "fail-provenance").touch()
    result = fixture.run()
    assert result.returncode != 0
    state = fixture.snapshot()
    assert state["package"] is not None
    assert state["package_account"] is not None
    assert state["provenance"] is None
    assert state["laurel_binary"] is None
    _assert_producer_not_entered(result)
    _assert_activation_not_entered(result)
    _assert_no_activation(fixture)
    fixture.assert_unrelated()


def test_prepare_rejects_absent_package_owned_account_before_producer(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    (fixture.lifecycle / "omit-package-account").touch()
    result = fixture.run()
    assert result.returncode != 0
    state = fixture.snapshot()
    assert state["package"] is not None
    assert state["package_account"] is None
    assert "splunkfwd" not in fixture.stock_host().users
    assert "splunkfwd" not in fixture.stock_host().groups
    assert state["provenance"] is not None
    assert state["laurel_account"] is None
    _assert_producer_not_entered(result)
    _assert_activation_not_entered(result)
    _assert_no_activation(fixture)
    fixture.assert_unrelated()


@pytest.mark.parametrize("failure", ["audit-package", "audit-tools", "audit-unit", "common-source"])
def test_producer_prerequisite_failure_preserves_prepared_forwarder_and_stops_activation(tmp_path: Path, failure: str) -> None:
    fixture = PipelineFixture(tmp_path)
    if failure == "common-source":
        fixture.deny_read(fixture.actual("/var/log/auth.log"))
    elif failure == "audit-tools":
        (fixture.bin / "augenrules").unlink()
    else:
        (fixture.state / failure).unlink()
    result = fixture.run()
    assert result.returncode != 0
    state = fixture.snapshot()
    assert state["package"] is not None and state["provenance"] is not None
    assert state["package_account"] is not None
    assert state["laurel_account"] is None
    assert state["audit_enabled"] == b"no\n"
    assert state["audit_active"] == b"no\n"
    assert state["audit_rules"] == b""
    assert {PRODUCER_WRAPPER_TASK, PRODUCER_DEFAULT_TASK} <= _task_names(result)
    _assert_activation_not_entered(result)
    assert state["laurel_binary"] is None
    _assert_no_activation(fixture)
    fixture.assert_unrelated()


@pytest.mark.parametrize("failure", ["fail-rules", "fail-audit-restart"])
def test_producer_failure_after_mutation_leaves_no_success_marker_or_activation(tmp_path: Path, failure: str) -> None:
    fixture = PipelineFixture(tmp_path)
    (fixture.state / failure).touch()
    result = fixture.run()
    assert result.returncode != 0
    state = fixture.snapshot()
    assert state["package"] is not None and state["provenance"] is not None
    assert state["laurel_binary"] is not None and state["laurel_config"] is not None
    assert state["laurel_marker"] is None
    assert state["laurel_account"] is not None
    assert state["audit_enabled"] == b"yes\n"
    if failure == "fail-rules":
        assert state["audit_rules"] == b""
        assert state["audit_active"] == b"no\n"
    else:
        assert b"key=detection_process" in state["audit_rules"]
        assert state["audit_active"] == b"no\n"
    assert {PRODUCER_WRAPPER_TASK, PRODUCER_DEFAULT_TASK} <= _task_names(result)
    _assert_activation_not_entered(result)
    _assert_no_activation(fixture)
    fixture.assert_unrelated()


def test_activation_refusal_preserves_native_success_and_credentials(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path, "runner")
    source = fixture.actual("/var/log/detection-engineering/runner-registration.jsonl")
    fixture.deny_read(source)
    result = fixture.run()
    assert result.returncode != 0
    state = fixture.snapshot()
    assert state["laurel_output"] is not None and state["laurel_marker"] is not None
    assert state["audit_active"] == b"yes\n"
    assert state["transaction"] is None
    assert state["bootstrap_marker"] is None and state["unit"] is None and state["service"] is None
    assert not fixture.actual("/opt/splunkforwarder/etc/system/local/user-seed.conf").exists()
    assert {PRODUCER_WRAPPER_TASK, PRODUCER_DEFAULT_TASK, ACTIVATION_WRAPPER_TASK, ACTIVATION_VALIDATE_TASK} <= _task_names(result)
    fixture.assert_unrelated()


def test_activation_failure_propagates_without_cross_role_rollback(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    (fixture.lifecycle / "fail-unit").touch()
    result = fixture.run()
    assert result.returncode != 0
    state = fixture.snapshot()
    assert state["laurel_output"] is not None and state["laurel_marker"] is not None
    assert state["transaction"] is not None
    assert state["bootstrap_marker"] is None and state["unit"] is None and state["service"] is None
    assert not fixture.actual("/opt/splunkforwarder/etc/system/local/user-seed.conf").exists()
    fixture.assert_unrelated()


def test_runuser_command_forms_share_identical_modeled_dac_and_inode_resolution(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    installed = fixture.run()
    assert installed.returncode == 0, installed.stdout + installed.stderr
    source = fixture.actual("/var/log/auth.log")
    forms = (["-u", "splunkfwd", "--"], ["splunkfwd", "--"])
    for prefix in forms:
        allowed = subprocess.run([fixture.bin / "runuser", *prefix, "test", "-r", source], check=False)
        assert allowed.returncode == 0
    stock = fixture.stock_host()
    stock.physical_inodes["/var/log/auth.log"] += 1
    fixture.save_stock(stock)
    for prefix in forms:
        denied = subprocess.run([fixture.bin / "runuser", *prefix, "test", "-r", source], check=False)
        assert denied.returncode != 0


@pytest.mark.parametrize(
    ("mutation", "expected_stage"),
    [
        ("missing-unit", "preflight"),
        ("wrong-context", "preflight"),
        ("group-auth-before", "group_auth"),
        ("group-auth-after", "group_auth"),
        ("publish-before", "publish_config"),
        ("publish-after", "publish_config"),
        ("restart-before", "restart"),
        ("restart-after", "restart"),
        ("marker-before", "write_applied"),
        ("marker-after", "write_applied"),
        ("helper-cleanup", "cleanup"),
    ],
)
def test_stock_access_failure_blocks_activation_and_reports_truthful_partial_state(
    tmp_path: Path, mutation: str, expected_stage: str,
) -> None:
    fixture = PipelineFixture(tmp_path)
    fixture.inject_stock_failure(mutation)
    before = fixture.snapshot()
    result = fixture.run()
    assert result.returncode != 0
    assert f'"stage": "{expected_stage}"' in result.stdout + result.stderr
    stock = fixture.stock_host()
    reader_gid = stock.groups.get(stock.reader).gid if stock.reader in stock.groups else None
    if mutation in {"missing-unit", "wrong-context", "group-auth-before"}:
        assert {stock.files[path].gid for path in ("/var/log/auth.log", "/var/log/syslog")} == {4}
        assert fixture.actual("/etc/rsyslog.conf").read_bytes() == before["stock_config"]
    elif mutation == "group-auth-after":
        assert stock.files["/var/log/auth.log"].gid == reader_gid
        assert stock.files["/var/log/syslog"].gid == 4
    else:
        assert {stock.files[path].gid for path in ("/var/log/auth.log", "/var/log/syslog")} == {reader_gid}
    state = fixture.snapshot()
    if mutation == "publish-before":
        assert state["stock_config"] == before["stock_config"]
    elif mutation in {"publish-after", "restart-before", "restart-after", "marker-before", "marker-after", "helper-cleanup"}:
        assert state["stock_config"] != before["stock_config"]
    if mutation in {"marker-after", "helper-cleanup"}:
        assert state["stock_marker"] is not None
    else:
        assert state["stock_marker"] is None
    if mutation == "restart-before":
        assert stock.loaded_action_groups == {}
    elif mutation in {"restart-after", "marker-before", "marker-after", "helper-cleanup"}:
        assert set(stock.loaded_action_groups.values()) == {reader_gid}
    _assert_activation_not_entered(result)
    _assert_no_activation(fixture)
    fixture.assert_unrelated()


@pytest.mark.parametrize("mutation", ["group-auth-after", "publish-after", "restart-after", "marker-after"])
def test_interrupted_active_rerun_preserves_consumer_authority_and_credentials(tmp_path: Path, mutation: str) -> None:
    fixture = PipelineFixture(tmp_path)
    first = fixture.run()
    assert first.returncode == 0, first.stdout + first.stderr
    active = fixture.snapshot()
    fixture.prepare_active_stock_reapplication(mutation)
    before_calls = len(fixture.calls_since())
    failed = fixture.run()
    assert failed.returncode != 0
    state = fixture.snapshot()
    for name in ("bootstrap_marker", "unit", "inputs", "outputs", "forwarder_bootstrapped", "forwarder_enabled", "service"):
        assert state[name] == active[name]
    assert state["seed"] is None
    later = fixture.calls_since(before_calls)
    assert not any(" start --accept-license" in call for call in later)
    assert not any(call in {"restart SplunkForwarder.service", "enable SplunkForwarder.service", "start SplunkForwarder.service"} for call in later)
    _assert_activation_not_entered(failed)
    fixture.assert_unrelated()


def test_stock_recreation_and_rotation_preserve_rendered_group_real_inode_and_dac(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    installed = fixture.run()
    assert installed.returncode == 0, installed.stdout + installed.stderr
    host = fixture.stock_host()
    logical = "/var/log/auth.log"
    source = fixture.actual(logical)
    expected_gid = host.loaded_action_groups[logical]

    source.unlink()
    host.files.pop(logical)
    host.physical_inodes.pop(logical)
    host.hup_reopen()
    recreated_inode = source.stat().st_ino
    assert host.files[logical].gid == expected_gid
    assert host.files[logical].mode == 0o640
    assert host.physical_inodes[logical] == recreated_inode
    fixture.save_stock(host)
    assert subprocess.run([fixture.bin / "runuser", "-u", host.reader, "--", "test", "-r", source], check=False).returncode == 0

    source.write_bytes(b"new generation\n")
    fixture.save_stock(host)
    host.rotate(logical)
    assert fixture.actual(logical + ".1").stat().st_ino == recreated_inode
    assert host.files[logical].gid == expected_gid
    assert host.files[logical].mode == 0o640
    assert host.physical_inodes[logical] == source.stat().st_ino
    fixture.save_stock(host)
    assert subprocess.run([fixture.bin / "runuser", host.reader, "--", "/usr/bin/test", "-r", source], check=False).returncode == 0
    fixture.assert_unrelated()


def test_retained_bootstrap_transaction_refuses_wrapper_rerun_without_replaying_or_mutating_producer(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    (fixture.lifecycle / "fail-unit").touch()
    first = fixture.run()
    assert first.returncode != 0
    failed_state = fixture.snapshot()
    assert failed_state["transaction"] is not None
    assert failed_state["forwarder_bootstrapped"] is not None
    before_calls = len(fixture.calls_since())
    (fixture.lifecycle / "fail-unit").unlink()

    rerun = fixture.run()
    assert rerun.returncode != 0
    assert fixture.snapshot() == failed_state
    later = fixture.calls_since(before_calls)
    assert not any(" start --accept-license" in call or call == "restart auditd" for call in later)
    _assert_no_downstream_activation_calls(fixture, later)
    _assert_producer_not_entered(rerun)
    _assert_activation_not_entered(rerun)
    fixture.assert_unrelated()


def test_late_forwarder_restart_failure_preserves_marker_and_recovers_on_wrapper_rerun(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    (fixture.state / "fail-forwarder-restart").touch()
    first = fixture.run()
    assert first.returncode != 0
    failed = fixture.snapshot()
    assert failed["seed"] is None
    assert failed["transaction"] is None
    assert failed["bootstrap_marker"] is not None
    assert failed["unit"] is not None
    assert failed["inputs"] is not None and failed["outputs"] is not None
    assert failed["forwarder_enabled"] is None
    assert failed["service"] is None
    assert failed["laurel_marker"] is not None and failed["audit_active"] == b"yes\n"
    fixture.assert_unrelated()

    (fixture.state / "fail-forwarder-restart").unlink()
    before_calls = len(fixture.calls_since())
    recovered = fixture.run()
    assert recovered.returncode == 0, recovered.stdout + recovered.stderr
    state = fixture.snapshot()
    assert state["bootstrap_marker"] == failed["bootstrap_marker"]
    assert state["transaction"] is None and state["seed"] is None
    assert state["forwarder_enabled"] is not None and state["service"] is not None
    assert not any(" start --accept-license" in call or call == "restart auditd" for call in fixture.calls_since(before_calls))
    fixture.assert_unrelated()


def test_active_rerun_source_refusal_preserves_legal_service_and_complete_state(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path)
    first = fixture.run()
    assert first.returncode == 0, first.stdout + first.stderr
    active = fixture.snapshot()
    source = fixture.actual("/var/log/auth.log")
    fixture.deny_read(source)
    expected = fixture.snapshot()
    before_calls = len(fixture.calls_since())
    refused = fixture.run()
    assert refused.returncode != 0
    assert fixture.snapshot() == expected
    assert expected["service"] == active["service"]
    assert expected["forwarder_enabled"] == active["forwarder_enabled"]
    later = fixture.calls_since(before_calls)
    assert {PRODUCER_WRAPPER_TASK, PRODUCER_DEFAULT_TASK} <= _task_names(refused)
    _assert_activation_not_entered(refused)
    assert "restart auditd" not in later
    assert not any(call in {"restart SplunkForwarder.service", "enable SplunkForwarder.service", "start SplunkForwarder.service"} for call in later)
    fixture.assert_unrelated()
