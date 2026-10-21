from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


ROLE_DIR = Path(
    os.environ.get(
        "LUDUS_CONFIGURE_BRIDGE_ROLE_DIR",
        Path(__file__).resolve().parents[1],
    )
)
ROLES_DIR = ROLE_DIR.parent
ANSIBLE_PLAYBOOK = os.environ.get("ANSIBLE_PLAYBOOK", "ansible-playbook")


def make_fixture(
    tmp_path: Path,
    *,
    bridge: str = "vmbr1002",
    kind: str = "bridge",
    ageing_centiseconds: int = 30_000,
    promiscuous: bool = False,
) -> dict[str, Path]:
    root = tmp_path / "host"
    bin_dir = root / "usr" / "sbin"
    hook_dir = root / "etc" / "network" / "if-up.d"
    config_dir = root / "etc" / "network" / "ifupdown2"
    state_dir = root / "state"
    for directory in (bin_dir, hook_dir, config_dir, state_dir):
        directory.mkdir(parents=True, exist_ok=True)

    state = state_dir / "link.json"
    state.write_text(
        json.dumps(
            {
                "ifname": bridge,
                "kind": kind,
                "ageing_time": ageing_centiseconds,
                "promiscuous": promiscuous,
            }
        ),
        encoding="utf-8",
    )
    calls = state_dir / "calls.log"
    become_calls = state_dir / "become-calls.log"

    ip = bin_dir / "ip"
    ip.write_text(
        f"""#!/usr/bin/env python3
import json
import sys
from pathlib import Path

state_path = Path({str(state)!r})
calls_path = Path({str(calls)!r})
args = sys.argv[1:]
with calls_path.open("a", encoding="utf-8") as stream:
    stream.write(" ".join(args) + "\\n")
data = json.loads(state_path.read_text(encoding="utf-8"))

if args == ["-d", "-j", "link", "show", "dev", data["ifname"]]:
    flags = ["BROADCAST", "MULTICAST", "UP"]
    if data["promiscuous"]:
        flags.append("PROMISC")
    print(json.dumps([{{
        "ifname": data["ifname"],
        "flags": flags,
        "linkinfo": {{
            "info_kind": data["kind"],
            "info_data": {{"ageing_time": data["ageing_time"]}},
        }},
    }}]))
elif len(args) == 8 and args[:5] == ["link", "set", "dev", data["ifname"], "type"] and args[5] == "bridge" and args[6] == "ageing_time":
    data["ageing_time"] = int(args[7])
    state_path.write_text(json.dumps(data), encoding="utf-8")
elif len(args) == 6 and args[:4] == ["link", "set", "dev", data["ifname"]] and args[4] == "promisc" and args[5] in ("on", "off"):
    data["promiscuous"] = args[5] == "on"
    state_path.write_text(json.dumps(data), encoding="utf-8")
else:
    print("unsupported fake ip invocation: " + " ".join(args), file=sys.stderr)
    raise SystemExit(2)
""",
        encoding="utf-8",
    )
    ip.chmod(0o755)

    ifquery = bin_dir / "ifquery"
    ifquery.write_text("#!/bin/sh\nprintf '%s\\n' 'ifupdown2:3.0.0-1+pmx9'\n", encoding="utf-8")
    ifquery.chmod(0o755)

    effective_id = bin_dir / "id"
    effective_id.write_text("#!/bin/sh\nprintf '%s\\n' '0'\n", encoding="utf-8")
    effective_id.chmod(0o755)

    config = config_dir / "ifupdown2.conf"
    config.write_text("addon_scripts_support=1\n", encoding="utf-8")

    fake_sudo = bin_dir / "sudo"
    fake_sudo.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        f"with open({str(become_calls)!r}, 'a', encoding='utf-8') as stream:\n"
        "    stream.write(' '.join(sys.argv[1:]) + '\\n')\n"
        "os.execv('/bin/sh', ['/bin/sh', '-c', sys.argv[-1]])\n",
        encoding="utf-8",
    )
    fake_sudo.chmod(0o755)

    return {
        "root": root,
        "ip": ip,
        "ifquery": ifquery,
        "id": effective_id,
        "hook_dir": hook_dir,
        "config": config,
        "state": state,
        "calls": calls,
        "become_calls": become_calls,
        "sudo": fake_sudo,
    }


def run_role(
    tmp_path: Path,
    fixture: dict[str, Path],
    *,
    variables: dict[str, Any] | None = None,
    omit_range_metadata: bool = False,
) -> subprocess.CompletedProcess[str]:
    values: dict[str, Any] = {
        "range_second_octet": 2,
        "ludus_cluster_mode": False,
        "_ludus_configure_bridge_ip_command": str(fixture["ip"]),
        "_ludus_configure_bridge_ifquery_command": str(fixture["ifquery"]),
        "_ludus_configure_bridge_id_command": str(fixture["id"]),
        "_ludus_configure_bridge_ifupdown2_config_path": str(fixture["config"]),
        "_ludus_configure_bridge_hook_dir": str(fixture["hook_dir"]),
        "_ludus_configure_bridge_hook_owner": __import__("pwd").getpwuid(os.getuid()).pw_name,
        "_ludus_configure_bridge_hook_group": __import__("grp").getgrgid(os.getgid()).gr_name,
        "ansible_become_exe": str(fixture["sudo"]),
        "ansible_become_flags": "",
    }
    if variables:
        values.update(variables)
    if omit_range_metadata:
        del values["range_second_octet"]

    inventory = tmp_path / "inventory.yml"
    invalid_python = tmp_path / "must-not-run-python"
    inventory.write_text(
        "---\n"
        "all:\n"
        "  hosts:\n"
        "    guest:\n"
        "      ansible_connection: local\n"
        f"      ansible_python_interpreter: {invalid_python}\n"
        "    localhost:\n"
        "      ansible_connection: local\n"
        f"      ansible_python_interpreter: {invalid_python}\n",
        encoding="utf-8",
    )

    playbook = tmp_path / "playbook.yml"
    playbook.write_text(
        "---\n"
        "- name: Exercise bridge role from a guest target\n"
        "  hosts: guest\n"
        "  gather_facts: false\n"
        "  roles:\n"
        "    - role: ludus_configure_bridge\n",
        encoding="utf-8",
    )
    extra_vars = tmp_path / "vars.json"
    extra_vars.write_text(json.dumps(values), encoding="utf-8")
    env = os.environ.copy()
    env["ANSIBLE_ROLES_PATH"] = str(ROLES_DIR)
    env["ANSIBLE_LOCAL_TEMP"] = str(tmp_path / "ansible-local")
    env["ANSIBLE_REMOTE_TEMP"] = str(tmp_path / "ansible-remote")
    return subprocess.run(
        [
            ANSIBLE_PLAYBOOK,
            "--inventory",
            str(inventory),
            "--extra-vars",
            f"@{extra_vars}",
            str(playbook),
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def link_state(fixture: dict[str, Path]) -> dict[str, Any]:
    return json.loads(fixture["state"].read_text(encoding="utf-8"))


def calls(fixture: dict[str, Path]) -> list[str]:
    path = fixture["calls"]
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def become_calls(fixture: dict[str, Path]) -> list[str]:
    path = fixture["become_calls"]
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []
