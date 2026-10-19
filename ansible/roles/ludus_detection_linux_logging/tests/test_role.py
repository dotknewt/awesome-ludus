import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

from support import REPOSITORY_ROOT, run_production_include
from stock_access_model import FileFacts, ModelHost, ProducerObservation


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
        if not extra_member:
            companions = [
                ("laurel2audit", False), ("INSTALL.md", False), ("README.md", False),
                ("performance.md", False), ("man", True), ("man/laurel.8", False),
                ("man/.gitignore", False), ("man/laurel-about.7", False),
                ("man/laurel2audit.8", False), ("man/laurel.8.md", False),
                ("man/laurel2audit.8.md", False), ("man/Makefile", False),
                ("man/laurel-about.7.md", False),
            ]
            for name, is_directory in companions:
                companion = tarfile.TarInfo(name)
                if is_directory:
                    companion.type = tarfile.DIRTYPE
                    bundle.addfile(companion)
                else:
                    content = b"harmless companion"
                    companion.size = len(content)
                    bundle.addfile(companion, io.BytesIO(content))
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
    stock_failure=None,
    stock_restart_result=True,
    record_stock_stage=False,
):
    root = tmp_path / "root"
    for relative in (
        "etc/audit/plugins.d", "etc/audit/rules.d", "etc/rsyslog.d",
        "etc/logrotate.d", "usr/lib/rsyslog", "var/lib", "var/log",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    for name in ("auth.log", "syslog"):
        path = root / "var/log" / name
        path.write_text(f"retained {name}\n")
        path.chmod(0o640 if readable else 0o600)

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

    profile = ROLE / "files/stock-log-profiles/bookworm"
    manifest = json.loads((profile / "manifest.json").read_text())
    modeled = ModelHost(root, reader)
    for index, entry in enumerate(manifest["required"], start=1):
        destination = root / entry["target"].lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(profile / entry["bundle"], destination)
        destination.chmod(0o755 if entry["target"] == "/usr/lib/rsyslog/rsyslog-rotate" else 0o644)
        modeled.add_file(entry["target"], gid=0, ino=200 + index)
    for index, name in enumerate(("auth.log", "syslog"), start=1):
        modeled.add_file(
            f"/var/log/{name}", gid=4, ino=100 + index,
            mode=0o640 if readable else 0o600,
        )
    modeled.capture_rotation_profile(profile)
    if stock_failure is not None:
        operation, when = stock_failure
        modeled.fail_once(operation, when)
    modeled.restart_result = stock_restart_result
    modeled.save(state / "stock-model.json")
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
        f'''#!/usr/bin/python3
import json
from pathlib import Path
import sys

args = sys.argv[1:]
if len(args) == 6 and args[0] == "-u" and args[2] == "--":
    user, command, flag, raw_path = args[1], args[3], args[4], args[5]
elif len(args) == 5 and args[1] == "--":
    user, command, flag, raw_path = args[0], args[2], args[3], args[4]
else:
    raise SystemExit(9)
if Path(command).name != "test" or flag != "-r":
    raise SystemExit(9)
if user not in Path({str(accounts)!r}).read_text().splitlines():
    raise SystemExit(8)
path = Path(raw_path)
payload = json.loads(Path({str(state / "stock-model.json")!r}).read_text())
root = Path({str(root)!r})
try:
    logical = "/" + str(path.relative_to(root))
except ValueError:
    raise SystemExit(7)
facts = payload["files"].get(logical)
allowed = False
if facts is not None and user == payload["reader"]:
    uid = 2201 if user == "splunkfwd" else 2202
    gid = uid
    inode_matches = path.is_file() and path.stat().st_ino == payload["physical_inodes"].get(logical)
    allowed = inode_matches and ((uid == facts["uid"] and facts["mode"] & 0o400) or
                                 (gid == facts["gid"] and facts["mode"] & 0o040) or
                                 facts["mode"] & 0o004)
if not allowed:
    allowed = f"{{path}}:{{user}}" in Path({str(state / "acl")!r}).read_text().splitlines()
if not allowed:
    raise SystemExit(6)
Path({str(calls)!r}).open("a").write(f"read:{{user}}:{{path}}\\n")
'''
    )
    (fake / "stock-python").write_text(
        f'''#!/usr/bin/python3
from pathlib import Path
import sys
sys.path.insert(0, {str(ROLE / "tests")!r})
from stock_access_model import run_staged_entrypoint
rc = run_staged_entrypoint(
    sys.argv[1:], Path({str(state / "stock-model.json")!r}),
    Path({str(ROLE / "files/configure_stock_log_access.py")!r}),
)
if {record_stock_stage!r}:
    Path({str(state / "stock-stage-path")!r}).write_text(str(Path(sys.argv[1]).parent))
raise SystemExit(rc)
'''
    )
    (fake / "rsyslogd").write_text("#!/bin/sh\nexit 99\n")
    (fake / "systemctl").write_text(
        rf'''#!/bin/sh
echo "systemctl:$*" >> {calls}
if [ "$2" = rsyslog ] || [ "${{3:-}}" = rsyslog ]; then
  case "$1" in
    is-enabled) exit 0 ;;
    is-active)
      /usr/bin/python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); raise SystemExit(0 if p["producer"]["active"] else 1)' {state}/stock-model.json
      exit $?
      ;;
    enable)
      /usr/bin/python3 -c 'import json,sys; f=sys.argv[1]; p=json.load(open(f)); p["producer"]["active"]=True; open(f,"w").write(json.dumps(p))' {state}/stock-model.json
      exit 0
      ;;
  esac
fi
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
        "detection_logging_python_command": str(fake / "stock-python"),
        "detection_logging_rsyslogd_command": str(fake / "rsyslogd"),
        "detection_auditd_augenrules_command": str(fake / "augenrules"),
        "detection_auditd_auditctl_command": str(fake / "auditctl"),
        "detection_laurel_output_wait_timeout": 1,
    }


def _run_main(variables, fake, *, action_plugins=None):
    previous = os.environ.get("ANSIBLE_ACTION_PLUGINS")
    try:
        if action_plugins is not None:
            os.environ["ANSIBLE_ACTION_PLUGINS"] = str(action_plugins)
        return run_production_include(
            "ludus_detection_linux_logging", "main", variables, fake,
        )
    finally:
        if previous is None:
            os.environ.pop("ANSIBLE_ACTION_PLUGINS", None)
        else:
            os.environ["ANSIBLE_ACTION_PLUGINS"] = previous


def _valid(tmp_path, **fixture_options):
    archive, digest = _artifact(tmp_path)
    root, fake, state, calls = _fixture(tmp_path, **fixture_options)
    reader = fixture_options.get("reader", "splunkfwd")
    return root, fake, state, calls, _variables(root, fake, archive, digest, reader=reader)


def _stock_host(root, state):
    return ModelHost.load(root, state / "stock-model.json")


def _stock_payload(state):
    payload = json.loads((state / "stock-model.json").read_text())
    reader = payload["reader"]
    gid = 2201 if reader == "splunkfwd" else 2202
    payload.setdefault("users", {reader: {"name": reader, "uid": gid, "gid": gid}})
    payload.setdefault("groups", {
        reader: {"name": reader, "uid": gid, "gid": gid},
        "root": {"name": "root", "uid": 0, "gid": 0},
        "adm": {"name": "adm", "uid": 4, "gid": 4},
    })
    payload.setdefault("packages", ["logrotate", "rsyslog"])
    payload.setdefault("configured_argv", ["/usr/sbin/rsyslogd", "-n", "-iNONE"])
    payload.setdefault("running_argv", ["/usr/sbin/rsyslogd", "-n", "-iNONE"])
    payload.setdefault("running_executable", "/usr/sbin/rsyslogd")
    payload.setdefault("drop_ins", [])
    payload.setdefault("root_directory", "")
    payload.setdefault("root_image", "")
    payload.setdefault("mount_matches", True)
    payload.setdefault("command_records", 1)
    payload.setdefault("command_record_recognized", True)
    payload.setdefault("observation_error", False)
    payload.setdefault("observation_transition", False)
    payload.setdefault("observation_sequence", [])
    payload.setdefault("state_uid_overrides", {})
    payload.setdefault("group_close_error_for", None)
    payload.setdefault("primitive_faults", {})
    payload.setdefault("rotation_profile_hashes", {})
    return payload


def _write_stock_payload(state, payload):
    (state / "stock-model.json").write_text(json.dumps(payload, sort_keys=True))


def _stage_cleanup_fault_plugin(tmp_path, state):
    plugins = tmp_path / "action-plugins"
    plugins.mkdir()
    (plugins / "file.py").write_text(
        f'''from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        marker = Path({str(state / "stock-stage-path")!r})
        target = str(self._task.args.get("path", ""))
        if (self._task.args.get("state") == "absent" and marker.is_file()
                and target == marker.read_text()):
            return {{"failed": True, "changed": False,
                    "msg": "injected invocation-owned staging cleanup failure: " + target}}
        return self._execute_module(
            module_name="ansible.builtin.file", module_args=self._task.args,
            task_vars=task_vars, tmp=tmp,
        )
'''
    )
    return plugins


def _run_main_with_fqcn_cleanup_fault(tmp_path, variables, fake, state):
    """Run actual main while wrapping only the resolved builtin file action."""
    work = tmp_path / "fqcn-cleanup-harness"
    work.mkdir()
    inventory = work / "inventory.yml"
    playbook = work / "playbook.yml"
    launcher = work / "launch.py"
    local_tmp = work / "ansible-local"
    remote_tmp = work / "ansible-remote"
    home = work / "home"
    for directory in (local_tmp, remote_tmp, home):
        directory.mkdir(mode=0o700)
    inventory.write_text(yaml.safe_dump({
        "all": {"hosts": {"testhost": {
            "ansible_connection": "local",
            "ansible_python_interpreter": sys.executable,
        }}},
    }, sort_keys=False))
    playbook.write_text(yaml.safe_dump([{
        "name": "Exercise production main with scoped FQCN cleanup fault",
        "hosts": "all",
        "gather_facts": False,
        "become": False,
        "vars": dict(variables),
        "tasks": [{
            "name": "Run ludus_detection_linux_logging main",
            "ansible.builtin.include_role": {
                "name": "ludus_detection_linux_logging", "tasks_from": "main",
            },
        }],
    }], sort_keys=False))
    launcher.write_text(f'''import sys
from pathlib import Path
from ansible.cli.playbook import main
from ansible.executor.task_executor import TaskExecutor

marker = Path({str(state / "stock-stage-path")!r})
original_action_selection = TaskExecutor._get_action_handler_with_module_context

def scoped_action_selection(self, templar):
    handler, module = original_action_selection(self, templar)
    if self._task.action == "ansible.builtin.file":
        builtin_run = handler.run
        def scoped_run(tmp=None, task_vars=None):
            target = str(self._task.args.get("path", ""))
            if (self._task.args.get("state") == "absent" and marker.is_file()
                    and target == marker.read_text()):
                return {{"failed": True, "changed": False,
                        "msg": "injected invocation-owned staging cleanup failure: " + target}}
            return builtin_run(tmp=tmp, task_vars=task_vars)
        handler.run = scoped_run
    return handler, module

TaskExecutor._get_action_handler_with_module_context = scoped_action_selection
raise SystemExit(main())
''')
    environment = os.environ.copy()
    environment.update({
        "ANSIBLE_HOME": str(work / "ansible-home"),
        "ANSIBLE_LOCAL_TEMP": str(local_tmp),
        "ANSIBLE_REMOTE_TEMP": str(remote_tmp),
        "ANSIBLE_ROLES_PATH": str(REPOSITORY_ROOT / "ansible/roles"),
        "HOME": str(home),
        "PATH": f"{Path(fake).resolve()}{os.pathsep}{environment.get('PATH', '')}",
    })
    return subprocess.run(
        [sys.executable, str(launcher), "-i", str(inventory), str(playbook)],
        cwd=REPOSITORY_ROOT, env=environment, text=True, capture_output=True,
    )


def _remove_owned_stage(state):
    marker = state / "stock-stage-path"
    if marker.is_file():
        stage = Path(marker.read_text())
        if stage.is_dir() and stage.name.startswith("detection-stock-log-access-"):
            shutil.rmtree(stage)


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


def test_existing_role_private_parent_is_hardened_without_replacement(tmp_path):
    root, fake, state, _calls, variables = _valid(tmp_path)
    baseline = _run_main(variables, fake)
    assert baseline.returncode == 0, baseline.stdout + baseline.stderr
    parent = root / "var/lib/detection-engineering"
    parent.chmod(0o750)
    marker = parent / "laurel-apply.sha256"
    unrelated = parent / "unrelated-state"
    unrelated.write_text("retained unrelated\n")
    marker_bytes = marker.read_bytes()
    inode = parent.stat().st_ino

    first = _run_main(variables, fake)
    assert first.returncode == 0, first.stdout + first.stderr
    assert parent.stat().st_ino == inode
    assert parent.stat().st_mode & 0o777 == 0o700
    assert unrelated.read_text() == "retained unrelated\n"
    assert marker.read_bytes() == marker_bytes

    second = _run_main(variables, fake)
    assert second.returncode == 0, second.stdout + second.stderr
    assert parent.stat().st_ino == inode
    assert unrelated.read_text() == "retained unrelated\n"
    assert "changed=0" in second.stdout


def test_prerequisite_failure_does_not_prepare_private_parent(tmp_path):
    root, fake, _state, _calls, variables = _valid(tmp_path, auditd_installed=False)
    parent = root / "var/lib/detection-engineering"
    parent.mkdir()
    parent.chmod(0o750)
    inode = parent.stat().st_ino
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert parent.stat().st_ino == inode
    assert parent.stat().st_mode & 0o777 == 0o750


def test_private_parent_preparation_is_retained_when_helper_refuses(tmp_path):
    root, fake, state, _calls, variables = _valid(
        tmp_path, stock_failure=("snapshot_recheck", "before"),
    )
    parent = root / "var/lib/detection-engineering"
    parent.mkdir()
    parent.chmod(0o750)
    unrelated = parent / "unrelated-state"
    unrelated.write_text("retained unrelated\n")
    marker = parent / "laurel-apply.sha256"
    marker.write_text("retained old marker\n")
    inode = parent.stat().st_ino
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert parent.stat().st_ino == inode
    assert parent.stat().st_mode & 0o777 == 0o700
    assert unrelated.read_text() == "retained unrelated\n"
    assert marker.read_text() == "retained old marker\n"
    assert "Stock-log access helper failed" in result.stdout + result.stderr


def test_model_policy_state_round_trips_without_valid_default_reconstruction(tmp_path):
    root, _fake, state, _calls, _variables = _valid(tmp_path)
    host = _stock_host(root, state)
    host.users = {}
    host.groups.pop("splunkfwd")
    host.packages = {"logrotate"}
    host.configured_argv = ["/usr/sbin/rsyslogd", "-f", "/tmp/other.conf"]
    host.running_argv = ["/tmp/wrapper"]
    host.running_executable = "/tmp/wrapper"
    host.drop_ins = ["/etc/systemd/system/rsyslog.service.d/override.conf"]
    host.root_directory = "/srv/chroot"
    host.root_image = "/srv/image.raw"
    host.mount_matches = False
    host.command_records = 2
    host.command_record_recognized = False
    host.observation_error = True
    host.observation_transition = True
    host.observation_sequence = [ProducerObservation(None, False, 999, "999:1")]
    host.state_uid_overrides = {"/var/lib/detection-engineering": 77}
    host.group_close_error_for = "/var/log/auth.log"
    host.primitive_faults = {"candidate_unlink": 1}
    host.validator_available = False
    host.validator_accepts = False
    host.restart_result = False
    host.restart_observation = None
    host.consumer_running = False
    host.loaded_action_groups = {"/var/log/auth.log": 2201}
    host.save(state / "roundtrip.json")
    restored = ModelHost.load(root, state / "roundtrip.json")
    assert restored.policy_state() == host.policy_state()

    host.callbacks[("snapshot_recheck", "before")] = lambda: None
    with pytest.raises(ValueError, match="callbacks are test-process-only"):
        host.save(state / "callbacks.json")


@pytest.mark.parametrize(
    "mutation",
    ["missing_user", "missing_group", "missing_package", "invalid_unit", "wrong_context", "transition"],
)
def test_persisted_invalid_policy_state_refuses_staged_helper_and_laurel(tmp_path, mutation):
    root, fake, state, _calls, variables = _valid(tmp_path)
    payload = _stock_payload(state)
    if mutation == "missing_user":
        payload["users"] = {}
    elif mutation == "missing_group":
        payload["groups"].pop("splunkfwd")
    elif mutation == "missing_package":
        payload["packages"] = ["logrotate"]
    elif mutation == "invalid_unit":
        payload["configured_argv"] = ["/usr/sbin/rsyslogd", "-f", "/tmp/other.conf"]
    elif mutation == "wrong_context":
        payload["mount_matches"] = False
    else:
        payload["observation_transition"] = True
    _write_stock_payload(state, payload)
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert "Stock-log access helper failed" in result.stdout + result.stderr
    assert set((state / "accounts").read_text().splitlines()) == {"splunkfwd", "splunk"}
    assert not (root / "usr/local/sbin/laurel").exists()
    assert not (root / "var/lib/detection-engineering/laurel-apply.sha256").exists()


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
    stock = _stock_host(root, state)
    selected_gid = 2201 if reader == "splunkfwd" else 2202
    assert {stock.files[path].gid for path in ("/var/log/auth.log", "/var/log/syslog")} == {selected_gid}
    assert stock.consumer_running
    assert stock.loaded_action_groups == {
        "/var/log/auth.log": selected_gid,
        "/var/log/syslog": selected_gid,
    }
    assert (root / "etc/logrotate.conf").read_bytes() == (
        ROLE / "files/stock-log-profiles/bookworm/logrotate.conf"
    ).read_bytes()
    assert (root / "etc/logrotate.d/rsyslog").read_bytes() == (
        ROLE / "files/stock-log-profiles/bookworm/rsyslog.logrotate"
    ).read_bytes()

    unauthorized = subprocess.run(
        [
            str(fake / "runuser"), "-u",
            "splunk" if reader == "splunkfwd" else "splunkfwd",
            "--", "test", "-r", str(output),
        ],
        text=True, capture_output=True,
    )
    assert unauthorized.returncode != 0

    alternate_form = subprocess.run(
        [str(fake / "runuser"), reader, "--", "/usr/bin/test", "-r", str(root / "var/log/auth.log")],
        text=True, capture_output=True,
    )
    assert alternate_form.returncode == 0


def test_second_run_converges_without_restart_churn(tmp_path):
    root, fake, _state, calls, variables = _valid(tmp_path)
    first = _run_main(variables, fake)
    assert first.returncode == 0, first.stdout + first.stderr
    restarts_before = calls.read_text().count("systemctl:restart auditd")
    second = _run_main(variables, fake)
    assert second.returncode == 0, second.stdout + second.stderr
    assert calls.read_text().count("systemctl:restart auditd") == restarts_before == 1
    stock = _stock_host(root, _state)
    assert stock.operations.count("restart") == 1
    assert stock.operations.count("publish:/etc/rsyslog.conf") == 1
    assert "changed=0" in second.stdout


def test_recreation_rotation_and_hup_follow_applied_rendered_state(tmp_path):
    root, fake, state, _calls, variables = _valid(tmp_path)
    result = _run_main(variables, fake)
    assert result.returncode == 0, result.stdout + result.stderr
    applied = _stock_host(root, state)
    expected_gid = applied.groups["splunkfwd"].gid
    assert applied.loaded_action_groups == {
        "/var/log/auth.log": expected_gid,
        "/var/log/syslog": expected_gid,
    }

    config = root / "etc/rsyslog.conf"
    config.write_bytes(config.read_bytes().replace(b"$FileGroup splunkfwd\n", b"$FileGroup adm\n"))
    auth = root / "var/log/auth.log"
    old_content = auth.read_bytes()
    auth.unlink()
    applied.files.pop("/var/log/auth.log")
    applied.physical_inodes.pop("/var/log/auth.log")
    applied.hup_reopen()
    assert applied.loaded_action_groups["/var/log/auth.log"] == expected_gid
    assert auth.is_file()
    assert applied.files["/var/log/auth.log"].uid == 0
    assert applied.files["/var/log/auth.log"].gid == expected_gid
    assert applied.files["/var/log/auth.log"].mode == 0o640
    assert applied.physical_inodes["/var/log/auth.log"] == auth.stat().st_ino
    assert applied.reader_can_read("/var/log/auth.log", auth, expected_gid, expected_gid, "runuser", "splunkfwd")

    loaded_before_restart = dict(applied.loaded_action_groups)
    applied.hup_reopen()
    assert applied.loaded_action_groups == loaded_before_restart
    assert applied.restart_producer(str(fake / "systemctl"))
    assert applied.loaded_action_groups == {"/var/log/auth.log": 4, "/var/log/syslog": 4}

    before = applied.files["/var/log/auth.log"]
    auth.write_bytes(old_content)
    unrelated_archive = root / "var/log/auth.log.9"
    unrelated_archive.write_bytes(b"unrelated archive\n")
    old_inode = auth.stat().st_ino
    applied.rotate("/var/log/auth.log")
    assert applied.files["/var/log/auth.log.1"] == before
    assert applied.files["/var/log/auth.log"].uid == before.uid == 0
    assert applied.files["/var/log/auth.log"].gid == before.gid == expected_gid
    assert applied.files["/var/log/auth.log"].mode == before.mode == 0o640
    assert (root / "var/log/auth.log.1").read_bytes() == old_content
    assert auth.is_file() and auth.read_bytes() == b""
    assert (root / "var/log/auth.log.1").stat().st_ino == old_inode
    assert applied.physical_inodes["/var/log/auth.log"] == auth.stat().st_ino
    assert unrelated_archive.read_bytes() == b"unrelated archive\n"


@pytest.mark.parametrize("condition", ["physical_exists", "wrong_context", "missing_producer"])
def test_recreation_rejects_impossible_transitions(tmp_path, condition):
    root, fake, state, _calls, variables = _valid(tmp_path)
    result = _run_main(variables, fake)
    assert result.returncode == 0, result.stdout + result.stderr
    host = _stock_host(root, state)
    logical = "/var/log/auth.log"
    physical = root / logical.lstrip("/")
    host.files.pop(logical)
    host.physical_inodes.pop(logical)
    if condition != "physical_exists":
        physical.unlink()
    if condition == "wrong_context":
        host.mount_matches = False
    elif condition == "missing_producer":
        host.producer = ProducerObservation(False, False)
    with pytest.raises(OSError, match="recreation"):
        host.recreate(logical)


def test_rotation_rejects_missing_source_and_changed_profile(tmp_path):
    root, fake, state, _calls, variables = _valid(tmp_path)
    result = _run_main(variables, fake)
    assert result.returncode == 0, result.stdout + result.stderr
    host = _stock_host(root, state)
    (root / "etc/logrotate.conf").write_text("create 0666 root root\n")
    with pytest.raises(OSError, match="rotation"):
        host.rotate("/var/log/auth.log")
    (root / "var/log/syslog").unlink()
    host.files.pop("/var/log/syslog")
    host.physical_inodes.pop("/var/log/syslog")
    with pytest.raises(OSError, match="rotation"):
        host.rotate("/var/log/syslog")


def test_successful_helper_staging_cleanup_failure_blocks_downstream(tmp_path):
    root, fake, state, calls, variables = _valid(tmp_path, record_stock_stage=True)
    unrelated = root / "var/log/unrelated.log"
    unrelated.write_text("retained unrelated\n")
    try:
        result = _run_main_with_fqcn_cleanup_fault(tmp_path, variables, fake, state)
        stage = Path((state / "stock-stage-path").read_text())
        assert result.returncode != 0
        assert "staging cleanup failed" in result.stdout + result.stderr
        assert (root / "var/lib/detection-engineering/stock-log-access/applied.json").is_file()
        assert set((state / "accounts").read_text().splitlines()) == {"splunkfwd", "splunk"}
        assert _stock_host(root, state).consumer_running
        assert unrelated.read_text() == "retained unrelated\n"
        assert f"read:splunkfwd:{root}/var/log/auth.log" not in calls.read_text()
        assert stage.is_dir()
        assert sorted(path.name for path in stage.iterdir()) == [
            "__pycache__", "bookworm", "configure_stock_log_access.py",
        ]
    finally:
        _remove_owned_stage(state)


def test_primary_helper_and_staging_cleanup_failures_retain_both_diagnostics(tmp_path):
    root, fake, state, calls, variables = _valid(
        tmp_path, stock_failure=("snapshot_recheck", "before"), record_stock_stage=True,
    )
    unrelated = root / "var/log/unrelated.log"
    unrelated.write_text("retained unrelated\n")
    try:
        result = _run_main_with_fqcn_cleanup_fault(tmp_path, variables, fake, state)
        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert "snapshot_recheck" in output
        assert "stage\": \"preflight" in output
        assert "injected invocation-owned staging cleanup failure" in output
        assert set((state / "accounts").read_text().splitlines()) == {"splunkfwd", "splunk"}
        assert _stock_host(root, state).consumer_running
        assert unrelated.read_text() == "retained unrelated\n"
        assert f"read:splunkfwd:{root}/var/log/auth.log" not in calls.read_text()
        stage = Path((state / "stock-stage-path").read_text())
        assert stage.is_dir()
        assert sorted(path.name for path in stage.iterdir()) == [
            "__pycache__", "bookworm", "configure_stock_log_access.py",
        ]
    finally:
        _remove_owned_stage(state)


def test_helper_owned_cleanup_failure_json_blocks_main_with_valid_marker(tmp_path):
    root, fake, state, calls, variables = _valid(tmp_path)
    unrelated = root / "var/log/unrelated.log"
    unrelated.write_text("retained unrelated\n")
    payload = _stock_payload(state)
    payload["primitive_faults"] = {"candidate_unlink": 1}
    _write_stock_payload(state, payload)
    result = _run_main(variables, fake)
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert '"stage": "cleanup"' in output
    assert '"cleanup_errors"' in output
    assert (root / "var/lib/detection-engineering/stock-log-access/applied.json").is_file()
    candidates = list((root / "var/lib/detection-engineering/stock-log-access").glob("candidate-*"))
    assert len(candidates) == 1
    assert sorted(path.name for path in candidates[0].parent.iterdir()) == [
        "applied.json", candidates[0].name, "lock",
    ]
    assert set((state / "accounts").read_text().splitlines()) == {"splunkfwd", "splunk"}
    assert _stock_host(root, state).consumer_running
    assert unrelated.read_text() == "retained unrelated\n"
    assert f"read:splunkfwd:{root}/var/log/auth.log" not in calls.read_text()
    assert not (root / "usr/local/sbin/laurel").exists()


def test_production_cleanup_fqcn_ignores_short_name_collision_plugin(tmp_path):
    root, fake, state, _calls, variables = _valid(tmp_path, record_stock_stage=True)
    plugins = _stage_cleanup_fault_plugin(tmp_path, state)
    result = _run_main(variables, fake, action_plugins=plugins)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "injected invocation-owned staging cleanup failure" not in result.stdout + result.stderr
    assert not Path((state / "stock-stage-path").read_text()).exists()
    assert (root / "var/lib/detection-engineering/laurel-apply.sha256").is_file()
    tasks = (ROLE / "tasks/stock_log_access.yml").read_text()
    assert "      ansible.builtin.file:\n" in tasks
    assert "intentional short action name" not in tasks


@pytest.mark.parametrize(
    "mutation",
    ["wrong_group", "missing_restore", "duplicate_action", "conflicting_create"],
)
def test_model_rejects_invalid_rendered_producer_mutations(tmp_path, mutation):
    root, fake, state, _calls, variables = _valid(tmp_path)
    result = _run_main(variables, fake)
    assert result.returncode == 0, result.stdout + result.stderr
    candidate = (root / "etc/rsyslog.conf").read_bytes()
    if mutation == "wrong_group":
        candidate = candidate.replace(b"$FileGroup splunkfwd\n", b"$FileGroup adm\n", 1)
    elif mutation == "missing_restore":
        candidate = candidate.replace(b"$FileGroup adm\n", b"", 1)
    elif mutation == "duplicate_action":
        candidate += b"auth,authpriv.*\t\t\t/var/log/auth.log\n"
    else:
        candidate = candidate.replace(b"$FileCreateMode 0640\n", b"$FileCreateMode 0660\n")
    invalid = tmp_path / f"{mutation}.conf"
    invalid.write_bytes(candidate)
    assert not _stock_host(root, state).validate_candidate(
        invalid, str(fake / "rsyslogd"), str(fake / "runuser"), "splunkfwd",
    )


@pytest.mark.parametrize(
    "failure",
    [
        ("snapshot_recheck", "before"),
        ("group_auth", "after"),
        ("group_syslog", "after"),
        ("publish_replace", "after"),
        ("restart", "before"),
        ("marker_replace", "after"),
    ],
)
def test_stock_access_failure_stops_before_laurel_mutation(tmp_path, failure):
    root, fake, state, _calls, variables = _valid(tmp_path, stock_failure=failure)
    unrelated = root / "var/log/unrelated.log"
    unrelated.write_bytes(b"unrelated retained\n")
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert "Stock-log access helper failed" in result.stdout + result.stderr
    assert set((state / "accounts").read_text().splitlines()) == {"splunkfwd", "splunk"}
    assert not (root / "usr/local/sbin/laurel").exists()
    assert not (root / "var/lib/detection-engineering/laurel-apply.sha256").exists()
    assert not (root / "var/lib/detection-engineering/stock-log-access/applied.json").exists()
    assert unrelated.read_bytes() == b"unrelated retained\n"
    stock = _stock_host(root, state)
    assert stock.consumer_running
    selected = stock.groups["splunkfwd"].gid
    expected_groups = {
        ("snapshot_recheck", "before"): (4, 4),
        ("group_auth", "after"): (selected, 4),
        ("group_syslog", "after"): (selected, selected),
        ("publish_replace", "after"): (selected, selected),
        ("restart", "before"): (selected, selected),
        ("marker_replace", "after"): (selected, selected),
    }
    assert (stock.files["/var/log/auth.log"].gid, stock.files["/var/log/syslog"].gid) == expected_groups[failure]
    published = failure in {
        ("publish_replace", "after"), ("restart", "before"), ("marker_replace", "after"),
    }
    assert (root / "etc/rsyslog.conf").read_bytes().count(b"$FileGroup splunkfwd\n") == (2 if published else 0)
    assert stock.producer.pid == (411 if failure == ("marker_replace", "after") else 410)


def test_stock_restart_failure_preserves_partial_state_and_blocks_laurel(tmp_path):
    root, fake, state, _calls, variables = _valid(tmp_path, stock_restart_result=False)
    result = _run_main(variables, fake)
    assert result.returncode != 0
    stock = _stock_host(root, state)
    assert stock.consumer_running
    assert stock.producer.active is True
    assert not (root / "var/lib/detection-engineering/laurel-apply.sha256").exists()
    assert "_laurel" not in (state / "accounts").read_text().splitlines()


def test_missing_canonical_source_refuses_without_synthetic_log(tmp_path):
    root, fake, state, _calls, variables = _valid(tmp_path)
    missing = root / "var/log/syslog"
    missing.unlink()
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert not missing.exists()
    assert "_laurel" not in (state / "accounts").read_text().splitlines()


def test_canonical_path_redirection_refuses_before_command_primitives(tmp_path):
    root, fake, _state, calls, variables = _valid(tmp_path)
    variables["detection_linux_auth_log_path"] = "/tmp/redirected-auth.log"
    result = _run_main(variables, fake)
    assert result.returncode != 0
    assert "canonical source" in result.stdout + result.stderr
    assert not calls.exists()
    assert not (root / "var/lib/detection-engineering").exists()


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

    replacement, replacement_digest = _artifact(
        tmp_path / "interrupted-replacement", member_mtime=2,
    )
    assert replacement_digest != variables["detection_laurel_artifact"]["sha256"]
    variables["detection_laurel_artifact"] = {
        "version": "synthetic-interrupted-replacement",
        "url": replacement.as_uri(),
        "sha256": replacement_digest,
        "download_auth_required": False,
    }

    rerun = _run_main(variables, fake)
    assert rerun.returncode == 0, rerun.stdout + rerun.stderr
    assert calls.read_text().count("systemctl:restart auditd") == 2
    assert marker.read_text() != old_marker
    assert f"read:splunkfwd:{root}/var/log/laurel/audit.log" in calls.read_text()


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
    assert "unsafe member path" in rejected.stdout + rejected.stderr
    assert "_laurel" not in (state2 / "accounts").read_text()

    root3, fake3, state3, calls3, variables3 = _valid(tmp_path / "source", readable=False)
    source_failure = _run_main(variables3, fake3)
    assert source_failure.returncode != 0
    assert "unsafe canonical source" in source_failure.stdout + source_failure.stderr
    assert "_laurel" not in (state3 / "accounts").read_text()
    assert "useradd:" not in calls3.read_text()
