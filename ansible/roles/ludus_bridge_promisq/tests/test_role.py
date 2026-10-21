from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from helpers import become_calls, calls, link_state, make_fixture, run_role


def test_role_uses_host_delegation_root_escalation_and_local_python(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)

    result = run_role(tmp_path, fixture)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "guest -> localhost" in result.stdout
    assert become_calls(fixture)


@pytest.mark.parametrize("command", ["ip", "ifquery"])
def test_symlinked_host_executable_converges_and_is_idempotent(
    tmp_path: Path, command: str
) -> None:
    fixture = make_fixture(tmp_path)
    executable = fixture[command]
    target = executable.with_name(f"{command}-target")
    executable.rename(target)
    executable.symlink_to(target.name)

    first = run_role(tmp_path, fixture)

    assert first.returncode == 0, first.stdout + first.stderr
    assert link_state(fixture)["ageing_time"] == 0
    assert link_state(fixture)["promiscuous"] is True
    assert (fixture["hook_dir"] / "ludus-configure-bridge-vmbr1002").is_file()

    second = run_role(tmp_path, fixture)

    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout


@pytest.mark.parametrize("command", ["ip", "ifquery"])
@pytest.mark.parametrize("target_kind", ["missing", "directory", "nonexecutable"])
def test_invalid_host_executable_symlink_is_rejected_before_mutation(
    tmp_path: Path, command: str, target_kind: str
) -> None:
    fixture = make_fixture(tmp_path)
    executable = fixture[command]
    target = executable.with_name(f"{command}-target")
    executable.unlink()
    if target_kind == "directory":
        target.mkdir()
    elif target_kind == "nonexecutable":
        target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        target.chmod(0o644)
    executable.symlink_to(target.name)

    result = run_role(tmp_path, fixture)

    assert result.returncode != 0
    assert f"executable {command} command" in result.stdout + result.stderr
    assert calls(fixture) == []
    assert list(fixture["hook_dir"].iterdir()) == []


@pytest.mark.parametrize(
    ("range_number", "bridge"),
    [(2, "vmbr1002"), (254, "vmbr1254")],
)
def test_range_allocation_derives_bridge_and_corrects_drift(
    tmp_path: Path, range_number: int, bridge: str
) -> None:
    fixture = make_fixture(tmp_path, bridge=bridge)

    result = run_role(tmp_path, fixture, variables={"range_second_octet": range_number})

    assert result.returncode == 0, result.stdout + result.stderr
    assert link_state(fixture) == {
        "ifname": bridge,
        "kind": "bridge",
        "ageing_time": 0,
        "promiscuous": True,
    }
    assert (fixture["hook_dir"] / f"ludus-configure-bridge-{bridge}").is_file()
    assert not (fixture["hook_dir"] / f"ludus-configure-bridge-{bridge}.sh").exists()
    assert any(f"dev {bridge} type bridge ageing_time 0" in call for call in calls(fixture))
    assert any(f"dev {bridge} promisc on" in call for call in calls(fixture))


@pytest.mark.parametrize(
    "invalid_value",
    [None, "two", 0, 255, True, 2.5],
)
def test_invalid_range_metadata_is_rejected_before_host_inspection(
    tmp_path: Path, invalid_value: object
) -> None:
    fixture = make_fixture(tmp_path)
    variables = {"range_second_octet": invalid_value}

    result = run_role(tmp_path, fixture, variables=variables)

    assert result.returncode != 0
    assert "range_second_octet" in result.stdout + result.stderr
    assert calls(fixture) == []


def test_missing_range_metadata_is_rejected_before_host_inspection(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)

    result = run_role(tmp_path, fixture, omit_range_metadata=True)

    assert result.returncode != 0
    assert "range_second_octet" in result.stdout + result.stderr
    assert calls(fixture) == []


def test_cluster_mode_is_rejected_before_host_inspection(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)

    result = run_role(tmp_path, fixture, variables={"ludus_cluster_mode": True})

    assert result.returncode != 0
    assert "single-node" in (result.stdout + result.stderr).lower()
    assert calls(fixture) == []


@pytest.mark.parametrize("invalid_value", ["false", 0, 1, None])
def test_nonboolean_cluster_metadata_is_rejected_before_host_inspection(
    tmp_path: Path, invalid_value: object
) -> None:
    fixture = make_fixture(tmp_path)

    result = run_role(
        tmp_path, fixture, variables={"ludus_cluster_mode": invalid_value}
    )

    assert result.returncode != 0
    assert "must be a boolean" in result.stdout + result.stderr
    assert calls(fixture) == []


def test_non_bridge_interface_is_rejected_without_mutation(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path, kind="dummy")

    result = run_role(tmp_path, fixture)

    assert result.returncode != 0
    assert "linux bridge" in (result.stdout + result.stderr).lower()
    assert all(" link set " not in f" {call} " for call in calls(fixture))


def test_hook_only_changes_matching_iface_and_propagates_errors(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    result = run_role(tmp_path, fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    hook = fixture["hook_dir"] / "ludus-configure-bridge-vmbr1002"

    fixture["calls"].write_text("", encoding="utf-8")
    missing_iface_env = os.environ.copy()
    missing_iface_env.pop("IFACE", None)
    missing_iface = subprocess.run(
        [str(hook)],
        env=missing_iface_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert missing_iface.returncode == 0
    assert calls(fixture) == []

    nonmatch = subprocess.run(
        [str(hook)],
        env={**os.environ, "IFACE": "vmbr1003"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert nonmatch.returncode == 0
    assert calls(fixture) == []

    matching = subprocess.run(
        [str(hook)],
        env={**os.environ, "IFACE": "vmbr1002"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert matching.returncode == 0, matching.stdout + matching.stderr
    assert calls(fixture) == [
        "link set dev vmbr1002 type bridge ageing_time 0",
        "link set dev vmbr1002 promisc on",
    ]

    fixture["ip"].write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
    failed = subprocess.run(
        [str(hook)],
        env={**os.environ, "IFACE": "vmbr1002"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert failed.returncode == 23


def test_nondefault_state_converges_and_second_run_is_idempotent(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path, ageing_centiseconds=0, promiscuous=True)
    variables = {
        "ludus_configure_bridge_promiscuous": False,
        "ludus_configure_bridge_ageing_time": 3000,
    }

    first = run_role(tmp_path, fixture, variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    assert link_state(fixture)["ageing_time"] == 3000
    assert link_state(fixture)["promiscuous"] is False
    assert any("ageing_time 3000" in call for call in calls(fixture))
    assert any("promisc off" in call for call in calls(fixture))

    fixture["state"].write_text(
        '{"ifname":"vmbr1002","kind":"bridge",'
        '"ageing_time":0,"promiscuous":true}',
        encoding="utf-8",
    )
    fixture["calls"].write_text("", encoding="utf-8")
    hook = fixture["hook_dir"] / "ludus-configure-bridge-vmbr1002"
    hook_result = subprocess.run(
        [str(hook)],
        env={**os.environ, "IFACE": "vmbr1002"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert hook_result.returncode == 0, hook_result.stdout + hook_result.stderr
    assert link_state(fixture)["ageing_time"] == 3000
    assert link_state(fixture)["promiscuous"] is False
    assert calls(fixture) == [
        "link set dev vmbr1002 type bridge ageing_time 3000",
        "link set dev vmbr1002 promisc off",
    ]

    fixture["calls"].write_text("", encoding="utf-8")
    second = run_role(tmp_path, fixture, variables=variables)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert not any(" link set " in f" {call} " for call in calls(fixture))


@pytest.mark.parametrize(
    "variables",
    [
        {"ludus_configure_bridge_promiscuous": "false"},
        {"ludus_configure_bridge_ageing_time": True},
        {"ludus_configure_bridge_ageing_time": -1},
        {"ludus_configure_bridge_ageing_time": 4_294_967_296},
    ],
)
def test_invalid_public_values_are_rejected(tmp_path: Path, variables: dict[str, object]) -> None:
    fixture = make_fixture(tmp_path)

    result = run_role(tmp_path, fixture, variables=variables)

    assert result.returncode != 0
    assert "ludus_configure_bridge_" in result.stdout + result.stderr
    assert calls(fixture) == []


def test_disabled_ifupdown2_script_support_is_rejected(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture["config"].write_text("addon_scripts_support=0\n", encoding="utf-8")

    result = run_role(tmp_path, fixture)

    assert result.returncode != 0
    assert "addon_scripts_support=1" in result.stdout + result.stderr
    assert all(" link set " not in f" {call} " for call in calls(fixture))


def test_non_root_host_execution_is_rejected_before_network_inspection(tmp_path: Path) -> None:
    fixture = make_fixture(tmp_path)
    fixture["id"].write_text("#!/bin/sh\nprintf '%s\\n' '1000'\n", encoding="utf-8")

    result = run_role(tmp_path, fixture)

    assert result.returncode != 0
    assert "root" in (result.stdout + result.stderr).lower()
    assert calls(fixture) == []
