from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from helpers import calls, link_state, make_fixture, run_role


ROLE_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_DIR = ROLE_DIR.parents[2]
BLUEPRINT_DIR = REPOSITORY_DIR / "blueprints" / "constructing-defense"


def _fenced_block(document: str, heading: str, language: str) -> str:
    match = re.search(
        rf"^## {re.escape(heading)}\s+```{language}\n(.*?)^```$",
        document,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return match.group(1)


def _retirement_script() -> str:
    readme = (ROLE_DIR / "README.md").read_text(encoding="utf-8")
    marked = readme.split("<!-- bridge-retirement-snippet-start -->", 1)[1].split(
        "<!-- bridge-retirement-snippet-end -->", 1
    )[0]
    match = re.search(r"```sh\n(.*?)```", marked, flags=re.DOTALL)
    assert match is not None
    return match.group(1)


def test_constructing_defense_configures_bridge_before_malcolm() -> None:
    range_config = yaml.safe_load(
        (BLUEPRINT_DIR / "range-config.yml").read_text(encoding="utf-8")
    )
    pcap = next(vm for vm in range_config["ludus"] if vm["vm_name"] == "pcap")

    assert pcap["roles"] == ["ludus_configure_bridge", "ludus_install_malcolm"]
    assert "ludus_configure_bridge_promiscuous" not in pcap.get("role_vars", {})
    assert "ludus_configure_bridge_ageing_time" not in pcap.get("role_vars", {})


def test_constructing_defense_documents_automatic_persistent_bridge_setup() -> None:
    readme = (BLUEPRINT_DIR / "README.md").read_text(encoding="utf-8")
    manual_script = (
        BLUEPRINT_DIR / "manual-scripts" / "enable-promisquous-mode.sh"
    ).read_text(encoding="utf-8")

    assert "vmbr{{ 1000 + range_second_octet }}" in readme
    assert "interface-up hook" in readme
    assert "retirement procedure" in readme
    assert "ludus_configure_bridge now automates these settings" in manual_script
    assert "brctl setageing vmbr1002 0" in manual_script
    assert "ip link set vmbr1002 promisc on" in manual_script


def test_readme_example_uses_ludus_sibling_role_properties() -> None:
    readme = (ROLE_DIR / "README.md").read_text(encoding="utf-8")
    example = yaml.safe_load(_fenced_block(readme, "Example range role assignment", "yaml"))

    assert example == {
        "roles": ["ludus_configure_bridge"],
        "role_vars": {
            "ludus_configure_bridge_promiscuous": False,
            "ludus_configure_bridge_ageing_time": 3000,
        },
    }
    assert set(example) <= {"roles", "role_vars"}
    assert "does **not** disappear automatically" in readme
    assert "Never use a wildcard" in readme
    assert re.search(r"does not restore the bridge's current live\s+settings", readme)


def test_documented_retirement_removes_only_the_validated_range_hook(
    tmp_path: Path,
) -> None:
    fixture = make_fixture(tmp_path)
    installed = run_role(tmp_path, fixture)
    assert installed.returncode == 0, installed.stdout + installed.stderr

    target = fixture["hook_dir"] / "ludus-configure-bridge-vmbr1002"
    unrelated = fixture["hook_dir"] / "ludus-configure-bridge-vmbr1003"
    unrelated.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    unrelated.chmod(0o755)
    script = tmp_path / "remove-bridge-hook.sh"
    script.write_text(_retirement_script(), encoding="utf-8")
    script.chmod(0o755)
    fake_bin = tmp_path / "retirement-bin"
    fake_bin.mkdir()
    sudo = fake_bin / "sudo"
    sudo.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
    sudo.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "LUDUS_CONFIGURE_BRIDGE_HOOK_DIR": str(fixture["hook_dir"]),
    }

    removed = subprocess.run(
        [str(script), "2"], env=env, text=True, capture_output=True, check=False
    )

    assert removed.returncode == 0, removed.stdout + removed.stderr
    assert not target.exists()
    assert unrelated.exists()
    fixture["calls"].write_text("", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        subprocess.run([str(target)], env={**env, "IFACE": "vmbr1002"}, check=False)
    assert calls(fixture) == []
    assert link_state(fixture)["ifname"] == "vmbr1002"


@pytest.mark.parametrize("invalid_allocation", ["0", "255", "02", "range-two", "../../1002"])
def test_documented_retirement_rejects_invalid_allocation_before_file_removal(
    tmp_path: Path, invalid_allocation: str
) -> None:
    hook_dir = tmp_path / "hooks"
    hook_dir.mkdir()
    sentinel = hook_dir / "ludus-configure-bridge-vmbr1002"
    sentinel.write_text("keep", encoding="utf-8")
    script = tmp_path / "remove-bridge-hook.sh"
    script.write_text(_retirement_script(), encoding="utf-8")
    script.chmod(0o755)

    result = subprocess.run(
        [str(script), invalid_allocation],
        env={**os.environ, "LUDUS_CONFIGURE_BRIDGE_HOOK_DIR": str(hook_dir)},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "decimal integer from 1 through 254" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"
