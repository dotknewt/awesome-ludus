"""Offline composition tests for the real forwarder pipeline entrypoint."""

from pathlib import Path
import re
import subprocess

import pytest

from support import PipelineFixture


PRODUCER_WRAPPER_TASK = "Produce native Linux audit telemetry"
PRODUCER_DEFAULT_TASK = "ludus_detection_linux_logging : Configure native auditd and Laurel logging"
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
    rendered = state["inputs"].decode()
    assert rendered.count("[monitor://") == count
    assert "monitor:///var/log/laurel/audit.log" in rendered
    assert "sourcetype = linux:audit:laurel" in rendered
    calls = fixture.calls_since()
    install = next(i for i, call in enumerate(calls) if call.startswith("-i "))
    producer = next(i for i, call in enumerate(calls) if call == "restart auditd")
    bootstrap = next(i for i, call in enumerate(calls) if " start --accept-license" in call)
    assert install < producer < bootstrap
    names = _task_names(result)
    assert {PRODUCER_WRAPPER_TASK, PRODUCER_DEFAULT_TASK, ACTIVATION_WRAPPER_TASK, ACTIVATION_VALIDATE_TASK} <= names
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
    later = fixture.calls_since(call_count)
    assert not any(call.startswith("-i ") or call == "restart auditd" or " start --accept-license" in call for call in later)
    fixture.assert_unrelated()


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
        fixture.readable.write_text("", encoding="utf-8")
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


def test_runuser_command_forms_share_identical_inode_and_acl_resolution(tmp_path: Path) -> None:
    fixture = PipelineFixture(tmp_path, "runner")
    installed = fixture.run()
    assert installed.returncode == 0, installed.stdout + installed.stderr
    source = fixture.actual("/var/log/detection-engineering/runner-registration.jsonl")
    fixture._remove_readable(source)
    fixture.grant_acl(source, "splunkfwd")
    forms = (["-u", "splunkfwd", "--"], ["--user", "splunkfwd", "--"])
    for prefix in forms:
        allowed = subprocess.run([fixture.bin / "runuser", *prefix, "test", "-r", source], check=False)
        assert allowed.returncode == 0
    fixture.deny_read(source)
    for prefix in forms:
        denied = subprocess.run([fixture.bin / "runuser", *prefix, "test", "-r", source], check=False)
        assert denied.returncode != 0


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
