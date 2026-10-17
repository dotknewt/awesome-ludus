"""Composed, stateful sandbox for the forwarder pipeline role tests."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_shared = _load("pipeline_blueprint_support", ROOT / "blueprints/detection-engineering/tests/support.py")
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
        for name, value in {"audit-enabled": "no\n", "audit-active": "no\n", "rules": "", "ownership": "", "acl": ""}.items():
            (self.state / name).write_text(value, encoding="utf-8")
        (self.state / "audit-package").write_text("installed\n", encoding="utf-8")
        (self.state / "audit-unit").touch()
        self.unrelated = self.root / "unrelated-resource"
        self.unrelated.write_text("preserve\n", encoding="utf-8")
        self.unrelated_service = self.lifecycle / "unrelated-service"
        self.unrelated_service.write_text("active\n", encoding="utf-8")

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
printf '%s:x:999:999::/nonexistent:/usr/sbin/nologin\\n' "$2"''')
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
        _executable(self.bin / "runuser", f'''{log}
case "$1" in
  -u|--user) ;;
  *) exit 89 ;;
esac
[ "$2" = splunkfwd ] && [ "$3" = -- ] || exit 80
[ -f {self.lifecycle}/package-account ] || exit 81
[ ! -f {self.lifecycle}/missing-account ] && [ ! -f {self.lifecycle}/wrong-account-uid ] && [ ! -f {self.lifecycle}/wrong-account-group ] || exit 82
if [ "$4" = test ]; then
  [ "$#" -eq 6 ] && [ "$5" = -r ] || exit 83
  path=$6
  [ -f "$path" ] || exit 84
  inode=$(stat -c %i "$path")
  grep -Fqx "$path|$inode" {self.readable} || grep -Fqx "$path:splunkfwd" {self.state}/acl || exit 85
else
  [ "$1" = --user ] || exit 86
  shift 3
  MODELED_FORWARDER_IDENTITY=splunkfwd exec "$@"
fi''')
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
action, service = args[:2]
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
