"""Stateful sandbox adapters for Splunk-local native Linux logging tests.

Identity, DAC, package, service, rsyslog, auditd, and Laurel execution are
explicitly modeled here because the test process is unprivileged.  Production
tasks and the accepted stock-log helper bytes are still executed unchanged.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
from typing import Any


ROOT = Path(__file__).resolve().parents[4]
LINUX_ROLE = ROOT / "ansible/roles/ludus_detection_linux_logging"


def _load_stock_model():
    path = LINUX_ROLE / "tests/stock_access_model.py"
    spec = importlib.util.spec_from_file_location("splunk_local_stock_access_model", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


STOCK = _load_stock_model()


def _executable(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\nset -eu\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def _laurel_artifact(parent: Path) -> tuple[Path, str]:
    archive = parent / "laurel.tar.gz"
    payload = b'''#!/usr/bin/env python3
import json, os, pathlib, sys, tomllib
if len(sys.argv) != 3 or sys.argv[1] != "--config": raise SystemExit(71)
if os.environ.get("MODELED_PLUGIN_START_IDENTITY") != "root": raise SystemExit(72)
config_path = pathlib.Path(sys.argv[2])
root = pathlib.Path(os.environ["MODELED_ROOT"])
state = pathlib.Path(os.environ["MODELED_LOCAL_LOGGING_STATE"])
with config_path.open("rb") as stream: config = tomllib.load(stream)
auditlog = config.get("auditlog", {})
if config.get("directory") != "/var/log/laurel" or config.get("user") != "_laurel": raise SystemExit(73)
if auditlog != {"file": "audit.log", "size": 5000000, "generations": 10, "read-users": ["splunk"]}: raise SystemExit(74)
if not (state / "laurel-account").is_file(): raise SystemExit(75)
if (state / "unextracted-laurel").is_file(): pathlib.Path(sys.argv[0]).unlink(); raise SystemExit(76)
if (state / "missing-laurel-output").is_file(): raise SystemExit(0)
output = pathlib.Path(str(root) + config["directory"]) / auditlog["file"]
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"EXECVE": {"ARGV": ["modeled", "not-live"]}}) + "\\n")
output.chmod(0o640)
with (state / "laurel-ownership").open("a") as stream: stream.write(str(output) + ":_laurel\\n")
if not (state / "unreadable-laurel-output").is_file():
    (state / "laurel-readable").write_text(str(output) + "|" + str(output.stat().st_ino) + "\\n")
'''
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("laurel")
        member.mode = 0o755
        member.size = len(payload)
        bundle.addfile(member, io.BytesIO(payload))
        for name, is_dir in (
            ("laurel2audit", False), ("INSTALL.md", False), ("README.md", False),
            ("performance.md", False), ("man", True), ("man/laurel.8", False),
            ("man/.gitignore", False), ("man/laurel-about.7", False),
            ("man/laurel2audit.8", False), ("man/laurel.8.md", False),
            ("man/laurel2audit.8.md", False), ("man/Makefile", False),
            ("man/laurel-about.7.md", False),
        ):
            item = tarfile.TarInfo(name)
            if is_dir:
                item.type = tarfile.DIRTYPE
                bundle.addfile(item)
            else:
                data = b"harmless companion"
                item.size = len(data)
                bundle.addfile(item, io.BytesIO(data))
    return archive, hashlib.sha256(archive.read_bytes()).hexdigest()


def configure_local_logging(fixture: dict[str, Any]) -> None:
    """Augment an existing Splunk fixture in place with coherent Linux state."""
    root: Path = fixture["root"]
    fake: Path = fixture["fake_bin"]
    calls: Path = fixture["calls"]
    state = root / "modeled-local-logging"
    state.mkdir()
    fixture["local_logging_state"] = state
    stock_state = state / "stock-model.json"
    fixture["stock_state"] = stock_state
    fixture["stock_model"] = STOCK
    fixture["identity_translation"] = "simulated splunk NSS identity maps to the unprivileged test uid/gid only in the sandbox adapter"

    for relative in ("etc/rsyslog.d", "etc/logrotate.d", "usr/lib/rsyslog", "var/lib", "var/log"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    for name in ("auth.log", "syslog"):
        path = root / "var/log" / name
        path.write_text(f"retained {name}\n", encoding="utf-8")
        path.chmod(0o640)
    for name, value in {
        "audit-package": "installed\n", "audit-enabled": "no\n",
        "audit-active": "no\n", "audit-rules": "", "laurel-readable": "",
    }.items():
        (state / name).write_text(value, encoding="utf-8")
    (state / "audit-unit").touch()
    unrelated = root / "unrelated-resource"
    unrelated.write_bytes(b"preserve unrelated bytes\n")
    fixture["unrelated"] = unrelated

    profile = LINUX_ROLE / "files/stock-log-profiles/bookworm"
    manifest = json.loads((profile / "manifest.json").read_text(encoding="utf-8"))
    host = STOCK.ModelHost(root, "splunk")
    host.users.pop("splunk", None)
    host.groups.pop("splunk", None)
    for index, entry in enumerate(manifest["required"], start=1):
        destination = root / entry["target"].lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(profile / entry["bundle"], destination)
        destination.chmod(0o755 if entry["target"] == "/usr/lib/rsyslog/rsyslog-rotate" else 0o644)
        host.add_file(entry["target"], gid=0, ino=200 + index)
    for index, logical in enumerate(("/var/log/auth.log", "/var/log/syslog"), start=1):
        host.add_file(logical, gid=4, ino=100 + index, mode=0o640)
    host.capture_rotation_profile(profile)
    host.save(stock_state)

    archive, digest = _laurel_artifact(root)
    authority = root / "var/lib/detection-engineering"
    variables = fixture["variables"]
    variables.update({
        "detection_splunk_file_owner": "splunk",
        "detection_splunk_file_group": "splunk",
        "detection_splunk_maintenance_state_path": str(authority / "splunk-maintenance-state.json"),
        "detection_splunk_bootstrap_state_path": str(authority / "splunk-bootstrap-complete"),
        "detection_linux_host_id": "synthetic-splunk-local",
        "detection_laurel_artifact": {
            "version": "synthetic-version", "url": archive.as_uri(),
            "sha256": digest, "download_auth_required": False,
        },
        "detection_laurel_read_user": "splunk",
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
    })

    log = f"printf '%s\\n' \"$*\" >> {calls}"
    package_state: Path = fixture["package_state"]
    _executable(fake / "dpkg-query", f'''{log}
if [ "$1" = --show ] && [ "$3" = auditd ]; then
  [ -f {state}/audit-package ] && cat {state}/audit-package || exit 1
elif [ "$3" = splunk ]; then
  [ -f {package_state} ] && cat {package_state} || exit 1
else exit 9; fi''')
    _executable(fake / "dpkg", f'''{log}
[ "$1" = -i ] || exit 9
printf 'install ok installed\\t%s\\n' 10.6.1.1 > {package_state}
touch {state}/splunk-account {state}/splunk-group {state}/splunk-unit''')
    _executable(fake / "getent", f'''{log}
[ "$1" = passwd ] || exit 9
case "$2" in
  splunk) [ -f {state}/splunk-account ] && [ -f {state}/splunk-group ] || exit 2 ;;
  _laurel) [ -f {state}/laurel-account ] || exit 2 ;;
  *) exit 2 ;;
esac
printf '%s:x:{os.getuid()}:{os.getgid()}::/nonexistent:/usr/sbin/nologin\\n' "$2"''')
    _executable(fake / "useradd", f'''{log}
[ "$1" = --system ] && [ "$2" = --home-dir ] && [ "$4" = --create-home ] && [ "$5" = _laurel ] || exit 9
[ -f {state}/splunk-account ] || exit 8
touch {state}/laurel-account
mkdir -p "$3"''')
    _executable(fake / "chown", f'''{log}
[ "$1" = --changes ] && [ "$2" = _laurel:_laurel ] && [ -f {state}/laurel-account ] || exit 9
record={state}/laurel-ownership
touch "$record"
grep -Fqx "${{3}}:_laurel" "$record" && exit 0
printf '%s:_laurel\\n' "${{3}}" >> "$record"
printf "changed ownership of '%s'\\n" "$3"''')

    runuser = f'''#!/usr/bin/env python3
from pathlib import Path
import sys
sys.path.insert(0, {str(LINUX_ROLE / "tests")!r})
from stock_access_model import ModelHost
args = sys.argv[1:]
Path({str(calls)!r}).open("a").write(" ".join(args) + "\\n")
if len(args) != 6 or args[0] != "-u" or args[1] != "splunk" or args[2] != "--" or Path(args[3]).name != "test" or args[4] != "-r": raise SystemExit(89)
state = Path({str(state)!r}); path = Path(args[5]); root = Path({str(root)!r})
if not (state / "splunk-account").is_file() or not (state / "splunk-group").is_file(): raise SystemExit(82)
logical = "/" + str(path.relative_to(root))
if logical in ("/var/log/auth.log", "/var/log/syslog"):
    host = ModelHost.load(root, Path({str(stock_state)!r})); identity = host.users.get("splunk"); group = host.groups.get("splunk")
    allowed = bool(identity and group and logical in host.files and host.reader_can_read(logical, path, identity.uid, group.gid, "runuser", "splunk"))
elif logical == "/var/log/laurel/audit.log":
    allowed = (state / "laurel-readable").read_text().strip() == str(path) + "|" + str(path.stat().st_ino) if path.is_file() else False
else: allowed = False
raise SystemExit(0 if allowed else 85)
'''
    (fake / "runuser").write_text(runuser, encoding="utf-8")
    (fake / "runuser").chmod(0o755)

    stock_python = f'''#!/usr/bin/env python3
from pathlib import Path
import os, sys
sys.path.insert(0, {str(LINUX_ROLE / "tests")!r})
from stock_access_model import Identity, ModelHost, run_staged_entrypoint
state_path=Path({str(stock_state)!r}); root=Path({str(root)!r}); state=Path({str(state)!r}); calls=Path({str(calls)!r})
host=ModelHost.load(root,state_path)
if (state/"splunk-account").is_file() and (state/"splunk-group").is_file():
 identity=Identity("splunk",{os.getuid()},{os.getgid()}); host.users["splunk"]=identity; host.groups["splunk"]=identity
else: host.users.pop("splunk",None); host.groups.pop("splunk",None)
host.save(state_path); before=len(host.operations); calls.open("a").write("stock-helper:start\\n")
rc=run_staged_entrypoint(sys.argv[1:],state_path,Path({str(LINUX_ROLE / "files/configure_stock_log_access.py")!r}))
after=ModelHost.load(root,state_path)
with calls.open("a") as stream:
 [stream.write("stock-model:"+operation+"\\n") for operation in after.operations[before:]]; stream.write(f"stock-helper:exit:{{rc}}\\n")
raise SystemExit(rc)
'''
    (fake / "stock-python").write_text(stock_python, encoding="utf-8")
    (fake / "stock-python").chmod(0o755)
    _executable(fake / "rsyslogd", "exit 99")
    _executable(fake / "augenrules", f'''{log}
[ "$1" = --load ] || exit 9
[ ! -f {state}/fail-audit-rules ] || exit 15
grep -q detection_process {root}/etc/audit/rules.d/99-detection-laurel.rules || exit 8
printf '%s\\n' '-a always,exit -F arch=b64 -S execve -F key=detection_process' > {state}/audit-rules''')
    _executable(fake / "auditctl", f'''{log}
[ "$1" = -l ] || exit 9
cat {state}/audit-rules''')

    systemctl = f'''#!/usr/bin/env python3
import json, os, pathlib, shlex, subprocess, sys
root=pathlib.Path({str(root)!r}); state=pathlib.Path({str(state)!r}); calls=pathlib.Path({str(calls)!r}); args=sys.argv[1:]
calls.open("a").write(" ".join(args)+"\\n")
if len(args)<2: raise SystemExit(52)
action=args[0]
service=args[-1] if action=="enable" and "--now" in args else ((args[2]) if action=="is-active" and args[1]=="--quiet" and len(args)>2 else args[1])
if service in ("auditd","auditd.service"):
 if action=="show": print("loaded" if (state/"audit-unit").is_file() else "not-found",end="")
 elif action=="is-enabled": raise SystemExit(0 if (state/"audit-enabled").read_text().strip()=="yes" else 1)
 elif action=="is-active": raise SystemExit(0 if (state/"audit-active").read_text().strip()=="yes" else 1)
 elif action=="enable":
  if not (state/"audit-unit").is_file(): raise SystemExit(5)
  (state/"audit-enabled").write_text("yes\\n")
 elif action=="restart":
  plugin=root/"etc/audit/plugins.d/laurel.conf"; config=root/"etc/laurel/config.toml"; binary=root/"usr/local/sbin/laurel"
  if (not (state/"audit-unit").is_file() or
      not (state/"audit-package").is_file() or (state/"audit-package").read_text().strip()!="installed" or
      (state/"audit-enabled").read_text().strip()!="yes" or not (state/"audit-rules").read_text().strip() or
      not (state/"laurel-account").is_file() or not plugin.is_file() or not config.is_file() or
      not binary.is_file() or not os.access(binary,os.X_OK)): raise SystemExit(5)
  if (state/"fail-audit-restart").is_file(): raise SystemExit(14)
  values={{}}
  for raw in plugin.read_text().splitlines():
   if raw.strip() and not raw.lstrip().startswith("#") and "=" in raw: key,value=raw.split("=",1); values[key.strip()]=value.strip()
  command=[values.get("path","")]+shlex.split(values.get("args","")); calls.open("a").write("laurel-exec:"+repr(command)+"\\n")
  env=os.environ.copy(); env.update({{"MODELED_PLUGIN_START_IDENTITY":"root","MODELED_ROOT":str(root),"MODELED_LOCAL_LOGGING_STATE":str(state)}})
  try: completed=subprocess.run(command,env=env,check=False)
  except (FileNotFoundError,PermissionError): raise SystemExit(8)
  if completed.returncode: raise SystemExit(completed.returncode)
  (state/"audit-active").write_text("yes\\n")
 else: raise SystemExit(52)
elif service=="rsyslog":
 model=pathlib.Path({str(fixture['stock_state'])!r})
 payload=json.loads(model.read_text())
 if action=="is-enabled": raise SystemExit(0)
 if action=="is-active": raise SystemExit(0 if payload["producer"]["active"] else 1)
 if action=="enable" and "--now" in args:
  payload["producer"]["active"]=True; model.write_text(json.dumps(payload))
 else: raise SystemExit(52)
elif service=="Splunkd.service":
 if not (state/"splunk-unit").is_file() or not (state/"splunk-account").is_file(): raise SystemExit(50)
 if action=="is-enabled": raise SystemExit(0 if pathlib.Path({str(fixture['service_enabled'])!r}).is_file() else 1)
 if action=="is-active": raise SystemExit(0 if pathlib.Path({str(fixture['service_state'])!r}).is_file() else 1)
 if action=="enable": pathlib.Path({str(fixture['service_enabled'])!r}).write_text("enabled")
 elif action in ("start","restart"): pathlib.Path({str(fixture['service_state'])!r}).write_text("running")
else: raise SystemExit(52)
'''
    (fake / "systemctl").write_text(systemctl, encoding="utf-8")
    (fake / "systemctl").chmod(0o755)

    splunk = fake / "splunk"
    splunk.write_text(splunk.read_text(encoding="utf-8").replace(
        'case "${1:-}" in', f'[ -f {state}/splunk-account ] && [ -f {state}/splunk-unit ] || exit 61\ncase "${{1:-}}" in'
    ), encoding="utf-8")
    splunk.chmod(0o755)

    adapter = root / "python-adapter"
    adapter.mkdir()
    (adapter / "sitecustomize.py").write_text(f'''import grp, os, pwd, shutil
_pw=pwd.getpwnam; _gr=grp.getgrnam; _rm=shutil.rmtree
_state={str(state)!r}
def _modeled_getpwnam(name):
 if name != "splunk": return _pw(name)
 if not os.path.isfile(os.path.join(_state,"splunk-account")): raise KeyError(name)
 return pwd.getpwuid(os.getuid())
def _modeled_getgrnam(name):
 if name != "splunk": return _gr(name)
 if not os.path.isfile(os.path.join(_state,"splunk-group")): raise KeyError(name)
 return grp.getgrgid(os.getgid())
pwd.getpwnam=_modeled_getpwnam
grp.getgrnam=_modeled_getgrnam
def _modeled_rmtree(path,*args,**kwargs):
 if os.environ.get("MODELED_STAGING_CLEANUP_FAILURE") == "1" and "detection-stock-log-access-" in str(path): raise OSError(5,"modeled staging cleanup failure")
 return _rm(path,*args,**kwargs)
shutil.rmtree=_modeled_rmtree
''', encoding="utf-8")
    fixture["python_adapter"] = adapter


def stock_host(fixture: dict[str, Any]):
    return STOCK.ModelHost.load(fixture["root"], fixture["stock_state"])


def save_stock(fixture: dict[str, Any], host: Any) -> None:
    host.save(fixture["stock_state"])


def inject_stock_failure(fixture: dict[str, Any], mutation: str) -> None:
    host = stock_host(fixture)
    if mutation.startswith("group-auth-"):
        host.fail_once("group_auth", mutation.rsplit("-", 1)[1])
    elif mutation.startswith("restart-"):
        host.fail_once("restart", mutation.rsplit("-", 1)[1])
    elif mutation == "untrusted-parent":
        host.state_uid_overrides["/var/lib/detection-engineering"] = 31337
    else:
        raise ValueError(mutation)
    save_stock(fixture, host)
