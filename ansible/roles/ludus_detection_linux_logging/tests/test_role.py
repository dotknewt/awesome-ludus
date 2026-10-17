import hashlib
import io
import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from support import run_production_include


ROLE = Path(__file__).resolve().parents[1]


def _artifact(tmp_path, *, extra_member=False, member_mtime=0):
    tmp_path.mkdir(parents=True, exist_ok=True)
    archive = tmp_path / ("unsafe.tar.gz" if extra_member else "laurel.tar.gz")
    binary = b"#!/bin/sh\nprintf 'synthetic laurel fixture\\n'\n"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("laurel")
        member.mode = 0o755
        member.mtime = member_mtime
        member.size = len(binary)
        bundle.addfile(member, io.BytesIO(binary))
        if extra_member:
            extra = b"not allowed"
            member = tarfile.TarInfo("../escape")
            member.size = len(extra)
            bundle.addfile(member, io.BytesIO(extra))
    return archive, hashlib.sha256(archive.read_bytes()).hexdigest()


def _fixture(
    tmp_path,
    *,
    reader="splunkfwd",
    reader_exists=True,
    readable=True,
    auditd_installed=True,
    auditd_status="installed",
    auditd_tools=True,
    auditd_unit=True,
    root_owned_laurel=False,
    fail_rule_load_once=False,
    fail_restart_once=False,
    no_output=False,
    no_reader_access=False,
    chown_noop=False,
):
    root = tmp_path / "root"
    for relative in ("etc/audit/plugins.d", "etc/audit/rules.d", "var/log"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    for name in ("auth.log", "syslog"):
        path = root / "var/log" / name
        path.write_text(f"retained {name}\n")
        path.chmod(0o644 if readable else 0o600)

    state = tmp_path / "state"
    state.mkdir()
    accounts = state / "accounts"
    other_reader = "splunk" if reader == "splunkfwd" else "splunkfwd"
    accounts.write_text((f"{reader}\n{other_reader}\n") if reader_exists else "")
    (state / "enabled").write_text("no")
    (state / "active").write_text("no")
    (state / "rules").write_text("")
    (state / "ownership").write_text("")
    (state / "acl").write_text("")
    if auditd_installed:
        (state / "package-status").write_text(auditd_status)
    if auditd_unit:
        (state / "unit").touch()
    for flag, enabled in {
        "fail-rule-load-once": fail_rule_load_once,
        "fail-restart-once": fail_restart_once,
        "no-output": no_output,
        "no-reader-access": no_reader_access,
        "chown-noop": chown_noop,
    }.items():
        if enabled:
            (state / flag).touch()

    output_dir = root / "var/log/laurel"
    if root_owned_laurel:
        output_dir.mkdir(parents=True)
        (output_dir / "audit.log").write_text('{"old":"retained"}\n')
        (output_dir / "audit.log").chmod(0o600)
        (state / "ownership").write_text(
            f"{output_dir}:root\n{output_dir}/audit.log:root\n"
        )

    calls = tmp_path / "calls"
    fake = tmp_path / "bin"
    fake.mkdir()

    (fake / "dpkg-query").write_text(
        f'''#!/usr/bin/env python3
import pathlib
import sys

expected = ["--show", "--showformat=${{db:Status-Status}}", "auditd"]
pathlib.Path({str(calls)!r}).open("a").write("dpkg-query:" + repr(sys.argv[1:]) + "\\n")
if sys.argv[1:] != expected:
    raise SystemExit(9)
status = pathlib.Path({str(state / "package-status")!r})
if not status.is_file():
    raise SystemExit(1)
sys.stdout.write(status.read_text())
'''
    )
    (fake / "getent").write_text(
        f'''#!/bin/sh
[ "$1" = passwd ] || exit 9
grep -qx "$2" {accounts} || exit 2
printf '%s:x:999:999::/nonexistent:/usr/sbin/nologin\\n' "$2"
'''
    )
    (fake / "useradd").write_text(
        f'''#!/bin/sh
[ "$*" = "--system --home-dir {root}/var/log/laurel --create-home _laurel" ] || exit 9
grep -qx _laurel {accounts} || echo _laurel >> {accounts}
if [ ! -d {root}/var/log/laurel ]; then
  mkdir -p {root}/var/log/laurel
  echo "{root}/var/log/laurel:_laurel" >> {state}/ownership
fi
echo "useradd:$*" >> {calls}
'''
    )
    (fake / "chown").write_text(
        f'''#!/bin/sh
[ "$1" = --changes ] || exit 9
[ "$2" = _laurel:_laurel ] || exit 9
grep -qx _laurel {accounts} || exit 8
echo "chown:$*" >> {calls}
[ -f {state}/chown-noop ] && exit 0
grep -Fxq "$3:_laurel" {state}/ownership && exit 0
grep -v "^$3:" {state}/ownership > {state}/ownership.tmp || true
mv {state}/ownership.tmp {state}/ownership
echo "$3:_laurel" >> {state}/ownership
echo "changed ownership of '$3'"
'''
    )
    (fake / "runuser").write_text(
        rf'''#!/bin/sh
[ "$1" = -u ] && grep -qx "$2" {accounts} || exit 8
[ "$3" = -- ] && [ "$4" = test ] && [ "$5" = -r ] || exit 9
path=$6
mode=$(stat -c %a "$path") || exit 7
case "${{mode#??}}" in
  4|5|6|7) cat "$path" >/dev/null;;
  *) grep -Fxq "$path:$2" {state}/acl && cat "$path" >/dev/null || exit 6;;
esac
echo "read:$2:$path" >> {calls}
'''
    )
    (fake / "systemctl").write_text(
        rf'''#!/bin/sh
echo "systemctl:$*" >> {calls}
case "$1" in
  show)
    [ -f {state}/unit ] && echo loaded || echo not-found
    ;;
  is-enabled)
    [ "$(cat {state}/enabled)" = yes ]
    ;;
  is-active)
    [ "$(cat {state}/active)" = yes ]
    ;;
  enable)
    [ -f {state}/unit ] || exit 5
    echo yes > {state}/enabled
    ;;
  restart)
    [ "$2" = auditd ] && [ -f {state}/unit ] && [ -f {state}/package-status ] || exit 5
    [ "$(cat {state}/enabled)" = yes ] || exit 4
    [ -s {state}/rules ] || exit 3
    [ -x {root}/usr/local/sbin/laurel ] || exit 8
    [ -f {root}/etc/laurel/config.toml ] || exit 7
    [ -f {root}/etc/audit/plugins.d/laurel.conf ] || exit 6
    grep -Fxq "{root}/var/log/laurel:_laurel" {state}/ownership || exit 12
    [ "$(stat -c %a {root}/var/log/laurel)" = 750 ] || exit 13
    output={root}/var/log/laurel/audit.log
    if [ -f "$output" ]; then
      grep -Fxq "$output:_laurel" {state}/ownership || exit 16
      [ "$(stat -c %a "$output")" = 640 ] || exit 17
    fi
    if [ -f {state}/fail-restart-once ]; then rm {state}/fail-restart-once; exit 14; fi
    echo yes > {state}/active
    if [ ! -f {state}/no-output ]; then
      printf '{{"EXECVE":{{"ARGV":["native","ordinary"]}},"ENV":{{"LD_PRELOAD":"/tmp/native.so"}}}}\n' > "$output"
      chmod 640 "$output"
      grep -v "^$output:" {state}/ownership > {state}/ownership.tmp || true
      mv {state}/ownership.tmp {state}/ownership
      echo "$output:_laurel" >> {state}/ownership
      if [ ! -f {state}/no-reader-access ]; then
        reader=$(sed -n 's/^read-users = \[ "\([^"]*\)" \]/\1/p' {root}/etc/laurel/config.toml)
        echo "$output:$reader" >> {state}/acl
      fi
    fi
    ;;
  *) exit 9;;
esac
'''
    )
    augenrules = fake / "augenrules"
    auditctl = fake / "auditctl"
    if auditd_tools:
        augenrules.write_text(
            f'''#!/bin/sh
echo "augenrules:$*" >> {calls}
[ "$1" = --load ] || exit 9
if [ -f {state}/fail-rule-load-once ]; then rm {state}/fail-rule-load-once; exit 15; fi
grep -q detection_process {root}/etc/audit/rules.d/99-detection-laurel.rules || exit 8
echo '-a always,exit -F arch=b64 -S execve -F key=detection_process' > {state}/rules
'''
        )
        auditctl.write_text(
            f'''#!/bin/sh
echo "auditctl:$*" >> {calls}
[ "$1" = -l ] || exit 9
cat {state}/rules
'''
        )

    for command in fake.iterdir():
        command.chmod(0o755)
    return root, fake, state, calls


def _variables(root, fake, archive, digest, *, reader="splunkfwd"):
    return {
        "detection_linux_host_id": "synthetic-host",
        "detection_laurel_artifact": {
            "version": "synthetic-version",
            "url": archive.as_uri(),
            "sha256": digest,
            "download_auth_required": False,
        },
        "detection_laurel_read_user": reader,
        "detection_laurel_rotate_size": 5000000,
        "detection_laurel_rotate_generations": 10,
        "detection_logging_root": str(root),
        "detection_logging_dpkg_query_command": str(fake / "dpkg-query"),
        "detection_logging_getent_command": str(fake / "getent"),
        "detection_logging_useradd_command": str(fake / "useradd"),
        "detection_logging_chown_command": str(fake / "chown"),
        "detection_logging_runuser_command": str(fake / "runuser"),
        "detection_logging_service_command": str(fake / "systemctl"),
        "detection_auditd_augenrules_command": str(fake / "augenrules"),
        "detection_auditd_auditctl_command": str(fake / "auditctl"),
        "detection_laurel_output_wait_timeout": 1,
    }


def _run_main(variables, fake):
    return run_production_include(
        "ludus_detection_linux_logging", "main", variables, fake,
    )


def _valid(tmp_path, **fixture_options):
    archive, digest = _artifact(tmp_path)
    root, fake, state, calls = _fixture(tmp_path, **fixture_options)
    reader = fixture_options.get("reader", "splunkfwd")
    return root, fake, state, calls, _variables(root, fake, archive, digest, reader=reader)


def test_missing_artifact_refuses_before_mutation(tmp_path):
    root, fake, _state, calls, variables = _valid(tmp_path)
    variables["detection_laurel_artifact"] = None
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert "checksum-pinned Laurel RuntimeArtifact" in result.stdout + result.stderr
    assert not (root / "etc/laurel").exists()
    assert not calls.exists()


@pytest.mark.parametrize("missing", ["package", "tools", "unit"])
def test_missing_auditd_prerequisite_refuses_before_role_mutation(tmp_path, missing):
    options = {
        "auditd_installed": missing != "package",
        "auditd_tools": missing != "tools",
        "auditd_unit": missing != "unit",
    }
    root, fake, state, _calls, variables = _valid(tmp_path, **options)
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert "Task 8 must provision distro auditd" in result.stdout + result.stderr
    assert "_laurel" not in (state / "accounts").read_text()
    assert not (root / "etc/laurel").exists()
    assert not (root / "usr/local/sbin/laurel").exists()
    assert not (root / "var/cache/detection-engineering").exists()


@pytest.mark.parametrize("status", ["not-installed", "config-files", "unpacked"])
def test_non_installed_auditd_status_refuses_before_role_mutation(tmp_path, status):
    root, fake, state, calls, variables = _valid(tmp_path, auditd_status=status)
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert "Task 8 must provision distro auditd" in result.stdout + result.stderr
    assert "_laurel" not in (state / "accounts").read_text()
    assert not (root / "etc/laurel").exists()
    assert not (root / "usr/local/sbin/laurel").exists()
    assert "--showformat=${db:Status-Status}" in calls.read_text()


def test_laurel_read_user_exists_before_configuration(tmp_path):
    root, fake, state, calls, variables = _valid(tmp_path, reader_exists=False)
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert "reader account must exist" in result.stdout + result.stderr
    assert "_laurel" not in (state / "accounts").read_text()
    assert not (root / "etc/laurel").exists()
    assert "useradd:" not in calls.read_text()


@pytest.mark.parametrize("reader", ["splunkfwd", "splunk"])
def test_fresh_install_applies_rules_starts_service_and_materializes_native_output(tmp_path, reader):
    root, fake, state, calls, variables = _valid(tmp_path, reader=reader)
    result = _run_main(variables, fake)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (state / "enabled").read_text() == "yes\n"
    assert (state / "active").read_text() == "yes\n"
    assert "detection_process" in (state / "rules").read_text()
    output = root / "var/log/laurel/audit.log"
    event = json.loads(output.read_text())
    assert event["EXECVE"]["ARGV"] == ["native", "ordinary"]
    assert f"{output}:{reader}" in (state / "acl").read_text()
    assert f"read:{reader}:{output}" in calls.read_text()
    assert (root / "var/lib/detection-engineering/laurel-apply.sha256").is_file()

    unauthorized = subprocess.run(
        [
            str(fake / "runuser"), "-u",
            "splunk" if reader == "splunkfwd" else "splunkfwd",
            "--", "test", "-r", str(output),
        ],
        text=True, capture_output=True,
    )
    assert unauthorized.returncode != 0


def test_second_run_converges_without_restart_churn(tmp_path):
    root, fake, _state, calls, variables = _valid(tmp_path)
    first = _run_main(variables, fake)
    assert first.returncode == 0, first.stdout + first.stderr
    restarts_before = calls.read_text().count("systemctl:restart auditd")
    second = _run_main(variables, fake)
    assert second.returncode == 0, second.stdout + second.stderr
    assert calls.read_text().count("systemctl:restart auditd") == restarts_before == 1
    assert "changed=0" in second.stdout


def test_checksum_change_reapplies_even_when_binary_content_is_unchanged(tmp_path):
    root, fake, _state, calls, variables = _valid(tmp_path)
    first = _run_main(variables, fake)
    assert first.returncode == 0, first.stdout + first.stderr
    marker = root / "var/lib/detection-engineering/laurel-apply.sha256"
    old_marker = marker.read_text()

    replacement, replacement_digest = _artifact(
        tmp_path / "replacement", member_mtime=1,
    )
    assert replacement_digest != variables["detection_laurel_artifact"]["sha256"]
    variables["detection_laurel_artifact"] = {
        "version": "synthetic-replacement",
        "url": replacement.as_uri(),
        "sha256": replacement_digest,
        "download_auth_required": False,
    }
    second = _run_main(variables, fake)
    assert second.returncode == 0, second.stdout + second.stderr
    assert calls.read_text().count("systemctl:restart auditd") == 2
    assert marker.read_text() != old_marker


def test_modeled_post_write_interruption_reapplies_new_config_from_old_marker(tmp_path):
    root, fake, _state, calls, variables = _valid(tmp_path)
    first = _run_main(variables, fake)
    assert first.returncode == 0, first.stdout + first.stderr
    marker = root / "var/lib/detection-engineering/laurel-apply.sha256"
    old_marker = marker.read_text()

    config = root / "etc/laurel/config.toml"
    config.write_text(config.read_text().replace(
        'read-users = [ "splunkfwd" ]', 'read-users = [ "splunk" ]',
    ))
    variables["detection_laurel_read_user"] = "splunk"

    rerun = _run_main(variables, fake)
    assert rerun.returncode == 0, rerun.stdout + rerun.stderr
    assert calls.read_text().count("systemctl:restart auditd") == 2
    assert marker.read_text() != old_marker
    assert f"read:splunk:{root}/var/log/laurel/audit.log" in calls.read_text()


@pytest.mark.parametrize("stale_marker", ["native-auditd-laurel-v1\n", "malformed\n"])
def test_legacy_or_malformed_marker_forces_reapplication(tmp_path, stale_marker):
    root, fake, _state, calls, variables = _valid(tmp_path)
    first = _run_main(variables, fake)
    assert first.returncode == 0, first.stdout + first.stderr
    marker = root / "var/lib/detection-engineering/laurel-apply.sha256"
    marker.write_text(stale_marker)

    rerun = _run_main(variables, fake)
    assert rerun.returncode == 0, rerun.stdout + rerun.stderr
    assert calls.read_text().count("systemctl:restart auditd") == 2
    persisted = marker.read_text().strip()
    assert len(persisted) == 64
    int(persisted, 16)


@pytest.mark.parametrize("failure", ["fail_rule_load_once", "fail_restart_once"])
def test_failed_native_apply_retries_with_unchanged_files(tmp_path, failure):
    root, fake, state, calls, variables = _valid(tmp_path, **{failure: True})
    first = _run_main(variables, fake)
    assert first.returncode != 0
    config_hash = hashlib.sha256((root / "etc/laurel/config.toml").read_bytes()).hexdigest()
    assert not (root / "var/lib/detection-engineering/laurel-apply.sha256").exists()

    second = _run_main(variables, fake)
    assert second.returncode == 0, second.stdout + second.stderr
    assert hashlib.sha256((root / "etc/laurel/config.toml").read_bytes()).hexdigest() == config_hash
    assert (state / "active").read_text() == "yes\n"
    assert "detection_process" in (state / "rules").read_text()
    expected = 2 if failure == "fail_restart_once" else 1
    assert calls.read_text().count("systemctl:restart auditd") == expected


def test_existing_root_owned_laurel_directory_and_output_are_repaired(tmp_path):
    root, fake, state, _calls, variables = _valid(tmp_path, root_owned_laurel=True)
    result = _run_main(variables, fake)
    assert result.returncode == 0, result.stdout + result.stderr
    output_dir = root / "var/log/laurel"
    output = output_dir / "audit.log"
    ownership = (state / "ownership").read_text()
    assert f"{output_dir}:_laurel" in ownership
    assert f"{output}:_laurel" in ownership
    assert output_dir.stat().st_mode & 0o777 == 0o750
    assert output.stat().st_mode & 0o777 == 0o640


def test_privilege_drop_write_failure_is_not_masked(tmp_path):
    root, fake, _state, _calls, variables = _valid(
        tmp_path, root_owned_laurel=True, chown_noop=True,
    )
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert not (root / "var/lib/detection-engineering/laurel-apply.sha256").exists()


@pytest.mark.parametrize("condition", ["missing", "unreadable"])
def test_post_start_native_output_failure_refuses_health(tmp_path, condition):
    options = {"no_output": condition == "missing", "no_reader_access": condition == "unreadable"}
    root, fake, _state, _calls, variables = _valid(tmp_path, **options)
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert not (root / "var/lib/detection-engineering/laurel-apply.sha256").exists()


def test_checksum_archive_and_common_source_failures_remain_fail_closed(tmp_path):
    archive, _digest = _artifact(tmp_path)
    root, fake, state, _calls = _fixture(tmp_path / "checksum")
    variables = _variables(root, fake, archive, "f" * 64)
    bad = _run_main(variables, fake)
    assert bad.returncode != 0
    assert "_laurel" not in (state / "accounts").read_text()

    unsafe, unsafe_digest = _artifact(tmp_path, extra_member=True)
    root2, fake2, state2, _calls2 = _fixture(tmp_path / "archive")
    rejected = _run_main(_variables(root2, fake2, unsafe, unsafe_digest), fake2)
    assert rejected.returncode != 0
    assert "exactly one regular root member named laurel" in rejected.stdout + rejected.stderr
    assert "_laurel" not in (state2 / "accounts").read_text()

    root3, fake3, state3, calls3, variables3 = _valid(tmp_path / "source", readable=False)
    source_failure = _run_main(variables3, fake3)
    assert source_failure.returncode != 0
    assert "reader cannot read required auth/system source" in source_failure.stdout + source_failure.stderr
    assert "_laurel" not in (state3 / "accounts").read_text()
    assert "useradd:" not in calls3.read_text()
