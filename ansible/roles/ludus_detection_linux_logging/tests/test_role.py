import json
import os
import resource
import subprocess
from pathlib import Path

import pytest

from support import run_production_include


ROLE = Path(__file__).resolve().parents[1]
PROTOCOL = "auditd-string-newline-v1"
PACKAGE = "1:4.0.2-2+deb13u1"


def _dispatch():
    return {"package_version": PACKAGE, "plugin_protocol": PROTOCOL,
            "write_logs_false": True, "fail_closed": True}


def _audit_line(serial="3"):
    return (f'type=SYSCALL msg=audit(1.2:{serial}): pid=42 uid=1000 '
            'exe="/usr/bin/curl" comm="curl" key="process"')


def _run_sanitizer(tmp_path, payload, *, existing_mode=None, output_name="audit-safe.jsonl"):
    output = tmp_path / output_name
    if existing_mode is not None:
        output.write_text("", encoding="utf-8")
        output.chmod(existing_mode)
    result = subprocess.run(
        ["python3", str(ROLE / "files/audit_sanitize.py"), "--output", str(output),
         "--owner", str(os.getuid()), "--group", str(os.getgid())],
        input=payload, text=True, capture_output=True,
    )
    return result, output


def test_audit_newline_records_are_incremental_and_secret_records_never_persist(tmp_path):
    payload = "\n".join([
        _audit_line("3"),
        'type=EXECVE msg=audit(1.2:3): argc=2 a0="curl" a1="CANARY_SECRET"',
        'type=PROCTITLE msg=audit(1.2:3): proctitle=43414E4152595F534543524554',
        _audit_line("4"),
    ]) + "\n"
    result, output = _run_sanitizer(tmp_path, payload, existing_mode=0o666)
    assert result.returncode == 0, result.stderr
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert [record["audit_serial"] for record in records] == ["3", "4"]
    assert all(record["pid"] == "42" and record["exe"] == "/usr/bin/curl" for record in records)
    assert "CANARY_SECRET" not in output.read_text() and "PROCTITLE" not in output.read_text()
    assert output.stat().st_mode & 0o777 == 0o640
    assert (output.stat().st_uid, output.stat().st_gid) == (os.getuid(), os.getgid())


@pytest.mark.parametrize("payload", [
    "not an audit record\n",
    _audit_line() + "\npartial-without-newline",
])
def test_malformed_or_partial_stream_fails_without_raw_fallback(tmp_path, payload):
    result, output = _run_sanitizer(tmp_path, payload)
    assert result.returncode != 0
    assert not output.exists() or payload not in output.read_text()


def test_output_open_and_write_failures_are_nonzero(tmp_path):
    missing = tmp_path / "missing" / "audit.jsonl"
    open_failure = subprocess.run(
        ["python3", str(ROLE / "files/audit_sanitize.py"), "--output", str(missing)],
        input=_audit_line() + "\n", text=True, capture_output=True,
    )
    assert open_failure.returncode != 0
    write_failure = subprocess.run(
        ["python3", str(ROLE / "files/audit_sanitize.py"), "--output", "/dev/full"],
        input=_audit_line() + "\n", text=True, capture_output=True,
    )
    assert write_failure.returncode != 0
    limited = tmp_path / "limited.jsonl"
    midstream = subprocess.run(
        ["python3", str(ROLE / "files/audit_sanitize.py"), "--output", str(limited),
         "--owner", str(os.getuid()), "--group", str(os.getgid())],
        input=_audit_line("1") + "\n" + _audit_line("2") + "\n",
        text=True, capture_output=True,
        preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (32, 32)),
    )
    assert midstream.returncode != 0
    assert "CANARY_SECRET" not in limited.read_text(errors="ignore")


def _root_fixture(tmp_path, *, active_plugin=None):
    root = tmp_path / "root"
    for relative in ("etc/audit/plugins.d", "var/log"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "etc/audit/auditd.conf").write_text(
        "write_logs = yes\nplugin_dir = /etc/audit/plugins.d\nlog_file = /var/log/audit/audit.log\n"
    )
    (root / "var/log/auth.log").touch()
    (root / "var/log/syslog").touch()
    if active_plugin:
        (root / "etc/audit/plugins.d/other.conf").write_text(
            f"active = yes\npath = {active_plugin}\ntype = always\nformat = string\n"
        )
    return root


def _role_vars(root):
    return {
        "detection_linux_host_id": "synthetic-host",
        "detection_audit_dispatch": _dispatch(),
        "detection_logging_root": str(root),
        "detection_logging_apply": False,
        "detection_audit_output_owner": os.getuid(),
        "detection_audit_output_group": os.getgid(),
    }


def test_positive_rooted_fixture_configures_safe_sources_and_plugin(tmp_path):
    root = _root_fixture(tmp_path)
    fake = tmp_path / "bin"; fake.mkdir()
    output = root / "var/log/detection-engineering/audit-safe.jsonl"
    output.parent.mkdir(parents=True)
    output.write_text("")
    output.chmod(0o666)
    result = run_production_include(
        "ludus_detection_linux_logging", "configure", _role_vars(root), fake,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "write_logs = no" in (root / "etc/audit/auditd.conf").read_text()
    assert "format = string" in (root / "etc/audit/plugins.d/detection-engineering.conf").read_text()
    assert "$FileCreateMode" not in (root / "etc/rsyslog.d/30-detection-engineering.conf").read_text()
    assert output.stat().st_mode & 0o777 == 0o640
    installed = root / "usr/local/libexec/detection-engineering/audit_sanitize.py"
    canary = _audit_line() + "\n" + 'type=EXECVE msg=audit(1.2:3): a0="DURABLE_CANARY"\n'
    dispatch = subprocess.run(
        [str(installed), "--output", str(output), "--owner", str(os.getuid()),
         "--group", str(os.getgid())], input=canary, text=True, capture_output=True,
    )
    assert dispatch.returncode == 0, dispatch.stderr
    assert "DURABLE_CANARY" not in output.read_text()
    assert json.loads(output.read_text())["comm"] == "curl"
    assert not (root / "var/log/audit/audit.log").exists()


def test_active_unreviewed_plugin_refuses_before_safe_config_mutation(tmp_path):
    root = _root_fixture(tmp_path, active_plugin="/usr/bin/raw-forwarder")
    fake = tmp_path / "bin"; fake.mkdir()
    before = (root / "etc/audit/auditd.conf").read_bytes()
    result = run_production_include(
        "ludus_detection_linux_logging", "configure", _role_vars(root), fake,
    )
    assert result.returncode != 0
    assert "unreviewed active audit plugin" in result.stdout + result.stderr
    assert (root / "etc/audit/auditd.conf").read_bytes() == before


def test_alternate_effective_plugin_dir_is_preflighted(tmp_path):
    root = _root_fixture(tmp_path)
    alternate = root / "etc/audit/alternate"
    alternate.mkdir()
    (root / "etc/audit/auditd.conf").write_text(
        "write_logs = yes\nplugin_dir = /etc/audit/alternate\n"
    )
    (alternate / ".hidden.conf").write_text("active = yes\n")
    (alternate / "ignored.extra.conf").write_text("active = yes\n")
    (alternate / "inactive.conf").write_text("active = no\n")
    (alternate / "raw.conf").write_text(
        "active = yes\npath = /usr/bin/raw-forwarder\ntype = always\nformat = string\n"
    )
    fake = tmp_path / "bin"; fake.mkdir()
    result = run_production_include(
        "ludus_detection_linux_logging", "configure", _role_vars(root), fake,
    )
    assert result.returncode != 0
    assert "unreviewed active audit plugin" in result.stdout + result.stderr


def test_existing_raw_audit_log_or_rotation_refuses(tmp_path):
    root = _root_fixture(tmp_path)
    raw_dir = root / "var/log/audit"
    raw_dir.mkdir()
    (raw_dir / "audit.log.1").write_text("type=EXECVE CANARY_RAW\n")
    fake = tmp_path / "bin"; fake.mkdir()
    result = run_production_include(
        "ludus_detection_linux_logging", "configure", _role_vars(root), fake,
    )
    assert result.returncode != 0
    assert "existing raw audit durable sink" in result.stdout + result.stderr


def test_absent_plugin_directory_does_not_bypass_raw_log_refusal(tmp_path):
    root = _root_fixture(tmp_path)
    (root / "etc/audit/plugins.d").rmdir()
    raw_dir = root / "var/log/audit"
    raw_dir.mkdir()
    (raw_dir / "audit.log").write_text("type=EXECVE CANARY_RETAINED\n")
    fake = tmp_path / "bin"; fake.mkdir()
    result = run_production_include(
        "ludus_detection_linux_logging", "configure", _role_vars(root), fake,
    )
    assert result.returncode != 0
    assert "operator disposition" in result.stdout + result.stderr
    assert (raw_dir / "audit.log").read_text() == "type=EXECVE CANARY_RETAINED\n"


@pytest.mark.parametrize(
    "altered_field", ["direction", "args"],
)
def test_same_name_plugin_requires_exact_direction_and_arguments(tmp_path, altered_field):
    root = _root_fixture(tmp_path)
    expected_args = (f"--output {root}/var/log/detection-engineering/audit-safe.jsonl "
                     f"--owner {os.getuid()} --group {os.getgid()}")
    direction = "in" if altered_field == "direction" else "out"
    plugin_args = "--output /tmp/wrong" if altered_field == "args" else expected_args
    plugin = root / "etc/audit/plugins.d/detection-engineering.conf"
    plugin.write_text(
        "active = yes\n"
        f"direction = {direction}\n"
        f"path = {root}/usr/local/libexec/detection-engineering/audit_sanitize.py\n"
        "type = always\n"
        f"args = {plugin_args}\n"
        "format = string\n"
    )
    fake = tmp_path / "bin"; fake.mkdir()
    result = run_production_include(
        "ludus_detection_linux_logging", "configure", _role_vars(root), fake,
    )
    assert result.returncode != 0
    assert "unsafe effective configuration" in result.stdout + result.stderr


def _modeled_systemctl(tmp_path, *, stop_succeeds, becomes_inactive=True):
    state = tmp_path / "auditd-state"
    state.write_text("active")
    calls = tmp_path / "systemctl-calls"
    command = tmp_path / "systemctl"
    if stop_succeeds:
        stop_action = f'echo inactive > {state}; exit 0' if becomes_inactive else "exit 0"
    else:
        stop_action = "exit 7"
    command.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> {calls}\n'
        f'case "$1" in is-active) [ "$(cat {state})" = active ] && exit 0 || exit 3;; '
        f'stop) {stop_action};; *) exit 9;; esac\n'
    )
    command.chmod(0o755)
    return command, calls


def test_active_auditd_is_stopped_and_confirmed_inactive_before_sink_scan(tmp_path):
    root = _root_fixture(tmp_path)
    (root / "etc/audit/plugins.d").rmdir()
    raw_dir = root / "var/log/audit"
    raw_dir.mkdir()
    (raw_dir / "audit.log").touch()
    command, calls = _modeled_systemctl(tmp_path, stop_succeeds=True)
    variables = _role_vars(root) | {
        "detection_logging_apply": True,
        "detection_logging_service_command": str(command),
    }
    result = run_production_include(
        "ludus_detection_linux_logging", ["quiesce", "preflight"], variables, tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text().splitlines() == [
        "is-active --quiet auditd", "stop auditd", "is-active --quiet auditd",
    ]


def test_auditd_stop_failure_refuses_before_sink_scan(tmp_path):
    root = _root_fixture(tmp_path)
    command, calls = _modeled_systemctl(tmp_path, stop_succeeds=False)
    variables = _role_vars(root) | {
        "detection_logging_apply": True,
        "detection_logging_service_command": str(command),
    }
    result = run_production_include(
        "ludus_detection_linux_logging", ["quiesce", "preflight"], variables, tmp_path,
    )
    assert result.returncode != 0
    assert calls.read_text().splitlines() == ["is-active --quiet auditd", "stop auditd"]


def test_auditd_still_active_after_successful_stop_command_refuses(tmp_path):
    root = _root_fixture(tmp_path)
    command, calls = _modeled_systemctl(
        tmp_path, stop_succeeds=True, becomes_inactive=False,
    )
    variables = _role_vars(root) | {
        "detection_logging_apply": True,
        "detection_logging_service_command": str(command),
    }
    result = run_production_include(
        "ludus_detection_linux_logging", ["quiesce", "preflight"], variables, tmp_path,
    )
    assert result.returncode != 0
    assert "did not become inactive" in result.stdout + result.stderr
    assert calls.read_text().splitlines() == [
        "is-active --quiet auditd", "stop auditd", "is-active --quiet auditd",
    ]


def test_missing_auth_or_system_source_refuses(tmp_path):
    root = _root_fixture(tmp_path)
    (root / "var/log/syslog").unlink()
    fake = tmp_path / "bin"; fake.mkdir()
    result = run_production_include(
        "ludus_detection_linux_logging", "configure", _role_vars(root), fake,
    )
    assert result.returncode != 0
    assert "required auth/system log sources" in result.stdout + result.stderr


def test_unknown_dispatch_capability_refuses_before_mutation(tmp_path):
    fake = tmp_path / "bin"; fake.mkdir()
    calls = tmp_path / "unexpected-service-call"
    service = tmp_path / "service"
    service.write_text(f"#!/bin/sh\necho called > {calls}\nexit 0\n")
    service.chmod(0o755)
    result = run_production_include(
        "ludus_detection_linux_logging", "configure",
        {
            "detection_linux_host_id": "synthetic-host",
            "detection_audit_dispatch": {"package_version": PACKAGE, "plugin_protocol": "unknown", "write_logs_false": True, "fail_closed": True},
            "detection_logging_root": str(tmp_path / "root"),
            "detection_logging_apply": True,
            "detection_logging_service_command": str(service),
        }, fake,
    )
    assert result.returncode != 0
    assert "verified fail-closed audit dispatch" in result.stdout + result.stderr
    assert not (tmp_path / "root").exists()
    assert not calls.exists()


def test_restart_include_invokes_only_modeled_services(tmp_path):
    fake_service = tmp_path / "service"
    calls = tmp_path / "calls"
    fake_service.write_text(f'#!/bin/sh\ncase "$1:$2" in restart:auditd|restart:rsyslog) echo "$1:$2" >> {calls};; *) exit 9;; esac\n')
    fake_service.chmod(0o755)
    result = run_production_include(
        "ludus_detection_linux_logging", "restart",
        {"detection_logging_apply": True, "detection_logging_service_command": str(fake_service)},
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text().splitlines() == ["restart:auditd", "restart:rsyslog"]
