"""Composed, stateful sandbox for the forwarder pipeline role tests."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_shared = _load("pipeline_blueprint_support", ROOT / "blueprints/detection-engineering/tests/support.py")
_linux_role = ROOT / "ansible/roles/ludus_detection_linux_logging"
_stock = _load("pipeline_stock_access_model", _linux_role / "tests/stock_access_model.py")
_this_support = sys.modules[__name__]
sys.modules["support"] = _shared
try:
    _forwarder = _load("pipeline_forwarder_tests", ROOT / "ansible/roles/ludus_detection_forwarder/tests/test_role.py")
finally:
    sys.modules["support"] = _this_support
run_production_include = _shared.run_production_include


def _executable(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\nset -eu\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def _artifact(path: Path) -> tuple[Path, str]:
    archive = path / "laurel.tar.gz"
    payload = b'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys
import tomllib

if len(sys.argv) != 3 or sys.argv[1] != "--config":
    raise SystemExit(71)
if os.environ.get("MODELED_PLUGIN_START_IDENTITY") != "root":
    raise SystemExit(72)
config_path = pathlib.Path(sys.argv[2])
root = pathlib.Path(os.environ["MODELED_ROOT"])
state = pathlib.Path(os.environ["MODELED_STATE"])
readable = pathlib.Path(os.environ["MODELED_READABLE"])
with config_path.open("rb") as stream:
    config = tomllib.load(stream)
auditlog = config.get("auditlog", {})
if config.get("directory") != "/var/log/laurel" or config.get("user") != "_laurel":
    raise SystemExit(73)
if not (state / "laurel-account").is_file():
    raise SystemExit(74)
if auditlog != {
    "file": "audit.log", "size": 5000000, "generations": 10,
    "read-users": ["splunkfwd"],
}:
    raise SystemExit(75)
output = pathlib.Path(str(root) + config["directory"]) / auditlog["file"]
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"EXECVE": {"ARGV": ["modeled", "not-selected-laurel"]}}) + "\\n")
output.chmod(0o640)
def replace_record(path, prefix, value):
    rows = path.read_text().splitlines() if path.exists() else []
    path.write_text("\\n".join([row for row in rows if not row.startswith(prefix)] + [value]) + "\\n")
replace_record(state / "ownership", str(output) + ":", str(output) + ":_laurel")
replace_record(state / "acl", str(output) + ":", str(output) + ":splunkfwd")
replace_record(readable, str(output) + "|", str(output) + "|" + str(output.stat().st_ino))
'''
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("laurel")
        member.mode = 0o755
        member.size = len(payload)
        bundle.addfile(member, io.BytesIO(payload))
    return archive, hashlib.sha256(archive.read_bytes()).hexdigest()


class PipelineFixture:
    """One shared target model consumed by both real producer roles."""

    def __init__(self, tmp_path: Path, profile: str = "workload") -> None:
        base = _forwarder._fixture(tmp_path, profile)
        self.root: Path = base["root"]
        self.bin: Path = base["bin"]
        self.calls: Path = base["calls"]
        self.lifecycle: Path = base["lifecycle"]
        self.readable: Path = base["readable"]
        self.package_state: Path = base["package_state"]
        self.variables = copy.deepcopy(base["variables"])
        self.state = self.root / "pipeline-state"
        self.state.mkdir()
        (self.root / "var/lib").mkdir(parents=True, exist_ok=True)
        for name, value in {"audit-enabled": "no\n", "audit-active": "no\n", "rules": "", "ownership": "", "acl": ""}.items():
            (self.state / name).write_text(value, encoding="utf-8")
        (self.state / "audit-package").write_text("installed\n", encoding="utf-8")
        (self.state / "audit-unit").touch()
        self.unrelated = self.root / "unrelated-resource"
        self.unrelated.write_text("preserve\n", encoding="utf-8")
        self.unrelated_service = self.lifecycle / "unrelated-service"
        self.unrelated_service.write_text("active\n", encoding="utf-8")

        self.stock_state = self.state / "stock-model.json"
        self.stock_profile = _linux_role / "files/stock-log-profiles/bookworm"
        self.stock_helper = _linux_role / "files/configure_stock_log_access.py"
        self.actual("/etc/rsyslog.d").mkdir(parents=True, exist_ok=True)
        manifest = json.loads((self.stock_profile / "manifest.json").read_text(encoding="utf-8"))
        stock = _stock.ModelHost(self.root, "splunkfwd")
        stock.users.pop("splunkfwd")
        stock.groups.pop("splunkfwd")
        for index, entry in enumerate(manifest["required"], start=1):
            destination = self.actual(entry["target"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.stock_profile / entry["bundle"], destination)
            destination.chmod(0o755 if entry["target"] == "/usr/lib/rsyslog/rsyslog-rotate" else 0o644)
            stock.add_file(entry["target"], gid=0, ino=200 + index)
        for index, logical in enumerate(("/var/log/auth.log", "/var/log/syslog"), start=1):
            self.actual(logical).chmod(0o640)
            stock.add_file(logical, gid=4, ino=100 + index, mode=0o640)
            self._remove_readable(self.actual(logical))
        stock.capture_rotation_profile(self.stock_profile)
        stock.save(self.stock_state)

        laurel = self.actual("/var/log/laurel/audit.log")
        if laurel.exists():
            laurel.unlink()
        self._remove_readable(laurel)
        archive, digest = _artifact(tmp_path)
        self.variables.update({
            "detection_linux_host_id": f"synthetic-alpha-{profile}",
            "detection_laurel_artifact": {
                "version": "synthetic-version", "url": archive.as_uri(),
                "sha256": digest, "download_auth_required": False,
            },
            "detection_laurel_read_user": "splunkfwd",
            "detection_laurel_rotate_size": 5000000,
            "detection_laurel_rotate_generations": 10,
            "detection_logging_root": str(self.root),
            "detection_logging_dpkg_query_command": str(self.bin / "dpkg-query"),
            "detection_logging_getent_command": str(self.bin / "getent"),
            "detection_logging_useradd_command": str(self.bin / "useradd"),
            "detection_logging_chown_command": str(self.bin / "chown"),
            "detection_logging_runuser_command": str(self.bin / "runuser"),
            "detection_logging_service_command": str(self.bin / "systemctl"),
            "detection_logging_python_command": str(self.bin / "stock-python"),
            "detection_logging_rsyslogd_command": str(self.bin / "rsyslogd"),
            "detection_auditd_augenrules_command": str(self.bin / "augenrules"),
            "detection_auditd_auditctl_command": str(self.bin / "auditctl"),
            "detection_laurel_output_wait_timeout": 1,
        })
        self._install_fakes()

    def actual(self, logical: str) -> Path:
        return Path(str(self.root) + logical)

    def _remove_readable(self, path: Path) -> None:
        rows = [line for line in self.readable.read_text(encoding="utf-8").splitlines() if not line.startswith(f"{path}|")]
        self.readable.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")

    def grant_acl(self, path: Path, user: str) -> None:
        rows = [line for line in (self.state / "acl").read_text(encoding="utf-8").splitlines() if not line.startswith(f"{path}:")]
        (self.state / "acl").write_text("\n".join(rows + [f"{path}:{user}"]) + "\n", encoding="utf-8")

    def deny_read(self, path: Path) -> None:
        self._remove_readable(path)
        try:
            logical = "/" + str(path.relative_to(self.root))
        except ValueError:
            logical = ""
        if logical in {"/var/log/auth.log", "/var/log/syslog"}:
            host = self.stock_host()
            facts = host.files[logical]
            host.files[logical] = _stock.FileFacts(**{**facts.__dict__, "mode": 0o600})
            self.save_stock(host)
        rows = [line for line in (self.state / "acl").read_text(encoding="utf-8").splitlines() if not line.startswith(f"{path}:")]
        (self.state / "acl").write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")

    def _install_fakes(self) -> None:
        log = f"printf '%s\\n' \"$*\" >> {self.calls}"
        dpkg = self.bin / "dpkg"
        dpkg_text = dpkg.read_text(encoding="utf-8").replace(
            f"touch {self.lifecycle}/package-installed",
            f"touch {self.lifecycle}/package-installed\n"
            f"[ -f {self.lifecycle}/omit-package-account ] || touch {self.lifecycle}/package-account",
        )
        dpkg.write_text(dpkg_text, encoding="utf-8")
        dpkg.chmod(0o755)
        identity = self.bin / "id"
        identity_text = identity.read_text(encoding="utf-8").replace(
            f"[ -f {self.lifecycle}/package-installed ] || exit 61",
            f"[ -f {self.lifecycle}/package-account ] || exit 61",
        )
        identity.write_text(identity_text, encoding="utf-8")
        identity.chmod(0o755)
        splunk = self.bin / "splunk"
        splunk_text = splunk.read_text(encoding="utf-8").replace(
            "  start)\n",
            "  start)\n    [ \"${MODELED_FORWARDER_IDENTITY:-}\" = splunkfwd ] || exit 39\n",
        )
        splunk.write_text(splunk_text, encoding="utf-8")
        splunk.chmod(0o755)
        _executable(self.bin / "dpkg-query", f'''{log}
if [ "$1" = --show ] && [ "$3" = auditd ]; then
  [ -f {self.state}/audit-package ] && cat {self.state}/audit-package || exit 1
elif [ "$3" = splunkforwarder ]; then
  [ -f {self.package_state} ] && cat {self.package_state} || exit 1
else exit 9; fi''')
        _executable(self.bin / "getent", f'''{log}
[ "$1" = passwd ] || exit 9
case "$2" in
  splunkfwd) [ -f {self.lifecycle}/package-account ] && [ ! -f {self.lifecycle}/missing-account ] && [ ! -f {self.lifecycle}/wrong-account-uid ] && [ ! -f {self.lifecycle}/wrong-account-group ] || exit 2 ;;
  _laurel) [ -f {self.state}/laurel-account ] || exit 2 ;;
  *) exit 2 ;;
esac
printf '%s:x:{os.getuid()}:{os.getgid()}::/nonexistent:/usr/sbin/nologin\\n' "$2"''')
        _executable(self.bin / "useradd", f'''{log}
[ "$1" = --system ] && [ "$2" = --home-dir ] && [ "$4" = --create-home ] && [ "$5" = _laurel ] || exit 9
[ -f {self.lifecycle}/package-installed ] || exit 8
touch {self.state}/laurel-account
mkdir -p "$3"''')
        _executable(self.bin / "chown", f'''{log}
[ "$1" = --changes ] && [ "$2" = _laurel:_laurel ] || exit 9
[ -f {self.state}/laurel-account ] || exit 8
grep -Fqx "$3:_laurel" {self.state}/ownership && exit 0
grep -Fvx "$3:_laurel" {self.state}/ownership > {self.state}/ownership.tmp || true
mv {self.state}/ownership.tmp {self.state}/ownership
printf '%s:_laurel\\n' "$3" >> {self.state}/ownership
printf "changed ownership of '%s'\\n" "$3"''')
        runuser = f'''#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, {str(_linux_role / "tests")!r})
from stock_access_model import ModelHost

args = sys.argv[1:]
Path({str(self.calls)!r}).open("a").write(" ".join(args) + "\\n")
if len(args) >= 3 and args[0] in ("-u", "--user") and args[2] == "--":
    form, user, command = args[0], args[1], args[3:]
elif len(args) >= 2 and args[1] == "--":
    form, user, command = "bare", args[0], args[2:]
else:
    raise SystemExit(89)
lifecycle = Path({str(self.lifecycle)!r})
if (not (lifecycle / "package-account").is_file() or user != "splunkfwd" or
        any((lifecycle / flag).is_file() for flag in ("missing-account", "wrong-account-uid", "wrong-account-group"))):
    raise SystemExit(82)
if command and Path(command[0]).name == "test":
    if len(command) != 3 or command[1] != "-r":
        raise SystemExit(83)
    path = Path(command[2])
    try:
        logical = "/" + str(path.relative_to(Path({str(self.root)!r})))
    except ValueError:
        raise SystemExit(84)
    if logical in ("/var/log/auth.log", "/var/log/syslog"):
        host = ModelHost.load(Path({str(self.root)!r}), Path({str(self.stock_state)!r}))
        identity = host.users.get(user)
        group = host.groups.get(user)
        allowed = bool(identity and group and logical in host.files and
                       host.reader_can_read(logical, path, identity.uid, group.gid, "runuser", user))
    else:
        inode = path.stat().st_ino if path.is_file() else None
        readable = Path({str(self.readable)!r}).read_text().splitlines()
        acl = Path({str(self.state / "acl")!r}).read_text().splitlines()
        allowed = f"{{path}}|{{inode}}" in readable or f"{{path}}:{{user}}" in acl
    raise SystemExit(0 if allowed else 85)
if form != "--user":
    raise SystemExit(86)
env = os.environ.copy()
env["MODELED_FORWARDER_IDENTITY"] = user
raise SystemExit(subprocess.run(command, env=env, check=False).returncode)
'''
        (self.bin / "runuser").write_text(runuser, encoding="utf-8")
        (self.bin / "runuser").chmod(0o755)
        stock_python = f'''#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, {str(_linux_role / "tests")!r})
from stock_access_model import Identity, ModelHost, run_staged_entrypoint

state_path = Path({str(self.stock_state)!r})
root = Path({str(self.root)!r})
lifecycle = Path({str(self.lifecycle)!r})
calls = Path({str(self.calls)!r})
host = ModelHost.load(root, state_path)
if (lifecycle / "package-account").is_file():
    identity = Identity(host.reader, {os.getuid()}, {os.getgid()})
    host.users[host.reader] = identity
    host.groups[host.reader] = identity
else:
    host.users.pop(host.reader, None)
    host.groups.pop(host.reader, None)
host.save(state_path)
before = len(host.operations)
calls.open("a").write("stock-helper:start\\n")
rc = run_staged_entrypoint(sys.argv[1:], state_path, Path({str(self.stock_helper)!r}))
after = ModelHost.load(root, state_path)
with calls.open("a") as stream:
    for operation in after.operations[before:]:
        stream.write("stock-model:" + operation + "\\n")
    stream.write(f"stock-helper:exit:{{rc}}\\n")
raise SystemExit(rc)
'''
        (self.bin / "stock-python").write_text(stock_python, encoding="utf-8")
        (self.bin / "stock-python").chmod(0o755)
        _executable(self.bin / "rsyslogd", "exit 99")
        _executable(self.bin / "augenrules", f'''{log}
[ "$1" = --load ] || exit 9
[ -f {self.state}/fail-rules ] && exit 15
grep -q detection_process {self.root}/etc/audit/rules.d/99-detection-laurel.rules || exit 8
printf '%s\\n' '-a always,exit -F arch=b64 -S execve -F key=detection_process' > {self.state}/rules''')
        _executable(self.bin / "auditctl", f'''{log}
[ "$1" = -l ] || exit 9
cat {self.state}/rules''')
        unit = self.actual("/etc/systemd/system/SplunkForwarder.service")
        systemctl = f'''#!/usr/bin/env python3
import json
import os
import pathlib
import shlex
import subprocess
import sys

root = pathlib.Path({str(self.root)!r})
state = pathlib.Path({str(self.state)!r})
lifecycle = pathlib.Path({str(self.lifecycle)!r})
readable = pathlib.Path({str(self.readable)!r})
calls = pathlib.Path({str(self.calls)!r})
unit = pathlib.Path({str(unit)!r})
args = sys.argv[1:]
calls.open("a").write(" ".join(args) + "\\n")
if len(args) < 2:
    raise SystemExit(52)
action = args[0]
service = args[-1] if action == "enable" and "--now" in args else args[1]
if service == "auditd":
    if action == "show":
        print("loaded" if (state / "audit-unit").is_file() else "not-found", end="")
    elif action == "is-enabled":
        raise SystemExit(0 if (state / "audit-enabled").read_text().strip() == "yes" else 1)
    elif action == "is-active":
        raise SystemExit(0 if (state / "audit-active").read_text().strip() == "yes" else 1)
    elif action == "enable":
        if not (state / "audit-unit").is_file(): raise SystemExit(5)
        (state / "audit-enabled").write_text("yes\\n")
    elif action == "restart":
        if not (state / "audit-unit").is_file() or not (state / "audit-package").is_file(): raise SystemExit(5)
        if (state / "audit-enabled").read_text().strip() != "yes" or not (state / "rules").read_text().strip(): raise SystemExit(4)
        if (state / "fail-audit-restart").is_file(): raise SystemExit(14)
        plugin = root / "etc/audit/plugins.d/laurel.conf"
        values = {{}}
        for raw in plugin.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1); values[key.strip()] = value.strip()
        command = [values.get("path", "")] + shlex.split(values.get("args", ""))
        calls.open("a").write("laurel-exec:" + repr(command) + "\\n")
        if (state / "unextracted-laurel").is_file() and pathlib.Path(command[0]).exists(): pathlib.Path(command[0]).unlink()
        if (state / "wrong-plugin-path").is_file(): command[0] += ".wrong"
        if (state / "wrong-plugin-args").is_file(): command[1:] = ["--wrong", command[-1]]
        if (state / "wrong-laurel-config").is_file(): pathlib.Path(command[-1]).write_text('directory = "/wrong"\\nuser = "_laurel"\\n')
        env = os.environ.copy()
        env.update({{
            "MODELED_PLUGIN_START_IDENTITY": "_laurel" if (state / "wrong-plugin-context").is_file() else "root",
            "MODELED_ROOT": str(root), "MODELED_STATE": str(state), "MODELED_READABLE": str(readable),
        }})
        try:
            completed = subprocess.run(command, env=env, check=False)
        except (FileNotFoundError, PermissionError):
            raise SystemExit(8)
        if completed.returncode != 0: raise SystemExit(completed.returncode)
        (state / "audit-active").write_text("yes\\n")
    else:
        raise SystemExit(52)
elif service == "rsyslog":
    model = pathlib.Path({str(self.stock_state)!r})
    payload = json.loads(model.read_text())
    if action == "is-enabled": raise SystemExit(0)
    if action == "is-active": raise SystemExit(0 if payload["producer"]["active"] else 1)
    if action == "enable" and "--now" in args:
        payload["producer"]["active"] = True
        model.write_text(json.dumps(payload))
    else: raise SystemExit(52)
elif service == "SplunkForwarder.service":
    if action == "show":
        if not unit.is_file(): raise SystemExit(50)
        if len(args) < 5: raise SystemExit(54)
        if args[3] == "User": print("splunkfwd", end="")
        elif args[3] == "FragmentPath": print("/etc/systemd/system/SplunkForwarder.service", end="")
        else: raise SystemExit(55)
    elif action in ("restart", "start"):
        if not unit.is_file() or not (lifecycle / "bootstrapped").is_file() or not (lifecycle / "package-account").is_file(): raise SystemExit(50)
        if action == "restart" and (state / "fail-forwarder-restart").is_file(): raise SystemExit(56)
        (lifecycle / "service").write_text("running")
    elif action == "enable":
        if not unit.is_file() or not (lifecycle / "package-account").is_file(): raise SystemExit(50)
        (lifecycle / "enabled").write_text("enabled")
    elif action == "is-active":
        raise SystemExit(0 if (lifecycle / "service").is_file() else 1)
    elif action == "is-enabled":
        raise SystemExit(0 if (lifecycle / "enabled").is_file() else 1)
    else:
        raise SystemExit(52)
else:
    raise SystemExit(52)
'''
        (self.bin / "systemctl").write_text(systemctl, encoding="utf-8")
        (self.bin / "systemctl").chmod(0o755)

    def run(self, **updates):
        variables = copy.deepcopy(self.variables)
        variables.update(updates)
        return run_production_include("ludus_detection_forwarder_pipeline", "main", variables, self.bin)

    def calls_since(self, index: int = 0) -> list[str]:
        return self.calls.read_text(encoding="utf-8").splitlines()[index:]

    def stock_host(self):
        return _stock.ModelHost.load(self.root, self.stock_state)

    def save_stock(self, host) -> None:
        host.save(self.stock_state)

    def inject_stock_failure(self, mutation: str) -> None:
        host = self.stock_host()
        if mutation == "missing-unit":
            host.producer = _stock.ProducerObservation(False, False)
        elif mutation == "wrong-context":
            host.mount_matches = False
        elif mutation.startswith("group-auth-"):
            host.fail_once("group_auth", mutation.rsplit("-", 1)[1])
        elif mutation.startswith("publish-"):
            host.fail_once("publish_config", mutation.rsplit("-", 1)[1])
        elif mutation.startswith("restart-"):
            host.fail_once("restart", mutation.rsplit("-", 1)[1])
        elif mutation.startswith("marker-"):
            host.fail_once("write_applied", mutation.rsplit("-", 1)[1])
        elif mutation == "helper-cleanup":
            host.primitive_faults["candidate_unlink"] = 1
        else:
            raise ValueError(f"unknown stock failure {mutation}")
        self.save_stock(host)

    def prepare_active_stock_reapplication(self, mutation: str) -> None:
        marker = self.actual("/var/lib/detection-engineering/stock-log-access/applied.json")
        marker.unlink()
        host = self.stock_host()
        if mutation == "group-auth-after":
            for logical in ("/var/log/auth.log", "/var/log/syslog"):
                facts = host.files[logical]
                host.files[logical] = _stock.FileFacts(**{**facts.__dict__, "gid": host.groups["adm"].gid})
        elif mutation == "publish-after":
            shutil.copyfile(self.stock_profile / "rsyslog.conf", self.actual("/etc/rsyslog.conf"))
        self.save_stock(host)
        self.inject_stock_failure(mutation)

    def snapshot(self) -> dict[str, bytes | None]:
        paths = {
            "package": self.package_state,
            "package_account": self.lifecycle / "package-account",
            "provenance": self.actual("/etc/detection-engineering/forwarder-install-provenance.yml"),
            "laurel_account": self.state / "laurel-account",
            "laurel_binary": self.actual("/usr/local/sbin/laurel"),
            "laurel_config": self.actual("/etc/laurel/config.toml"),
            "laurel_output": self.actual("/var/log/laurel/audit.log"),
            "laurel_marker": self.actual("/var/lib/detection-engineering/laurel-apply.sha256"),
            "stock_marker": self.actual("/var/lib/detection-engineering/stock-log-access/applied.json"),
            "stock_config": self.actual("/etc/rsyslog.conf"),
            "audit_unit": self.state / "audit-unit",
            "audit_enabled": self.state / "audit-enabled",
            "audit_active": self.state / "audit-active",
            "audit_rules": self.state / "rules",
            "ownership": self.state / "ownership",
            "acl": self.state / "acl",
            "readability": self.readable,
            "transaction": self.actual("/var/lib/detection-engineering/forwarder-bootstrap-in-progress.yml"),
            "seed": self.actual("/opt/splunkforwarder/etc/system/local/user-seed.conf"),
            "bootstrap_marker": self.actual("/var/lib/detection-engineering/forwarder-bootstrap.yml"),
            "unit": self.actual("/etc/systemd/system/SplunkForwarder.service"),
            "inputs": self.actual("/opt/splunkforwarder/etc/apps/detection_forwarder/local/inputs.conf"),
            "outputs": self.actual("/opt/splunkforwarder/etc/apps/detection_forwarder/local/outputs.conf"),
            "forwarder_bootstrapped": self.lifecycle / "bootstrapped",
            "forwarder_enabled": self.lifecycle / "enabled",
            "service": self.lifecycle / "service",
        }
        return {name: path.read_bytes() if path.is_file() else None for name, path in paths.items()}

    def assert_unrelated(self) -> None:
        assert self.unrelated.read_text(encoding="utf-8") == "preserve\n"
        assert self.unrelated_service.read_text(encoding="utf-8") == "active\n"
