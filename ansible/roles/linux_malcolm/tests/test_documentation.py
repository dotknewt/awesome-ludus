from __future__ import annotations

import re
from pathlib import Path

import yaml


ROLE_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_DIR = ROLE_DIR.parents[2]
BLUEPRINT_DIR = REPOSITORY_DIR / "blueprints" / "constructing-defense"
PUBLIC_VARIABLE_PATTERN = re.compile(r"\bludus_install_malcolm_[a-zA-Z0-9_]+\b")


def test_public_role_interface_is_declared_and_documented() -> None:
    defaults = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    production_text = "\n".join(
        path.read_text(encoding="utf-8")
        for pattern in ("*.yml", "*.j2")
        for path in ROLE_DIR.glob(f"**/{pattern}")
        if "tests" not in path.parts
    )
    used_variables = set(PUBLIC_VARIABLE_PATTERN.findall(production_text))
    documented = (ROLE_DIR / "README.md").read_text(encoding="utf-8")

    assert used_variables == set(defaults)
    assert all(f"`{name}`" in documented for name in defaults)
    assert "`ludus_install_docker_user`" in documented


def test_blueprint_supplies_explicit_pcap_lab_inputs_and_collections() -> None:
    range_config = yaml.safe_load((BLUEPRINT_DIR / "range-config.yml").read_text(encoding="utf-8"))
    pcap = next(vm for vm in range_config["ludus"] if vm["vm_name"] == "pcap")

    assert pcap["role_vars"] == {
        "ludus_install_malcolm_admin_username": "condef",
        "ludus_install_malcolm_admin_password": "Temp1234!!",
        "ludus_install_malcolm_capture_enabled": True,
    }

    requirements = yaml.safe_load((BLUEPRINT_DIR / "requirements.yml").read_text(encoding="utf-8"))
    collections = {item["name"]: item["version"] for item in requirements["collections"]}
    assert collections == {
        "ansible.posix": ">=2.2.2",
        "community.crypto": ">=3.4.0",
    }


def test_local_suite_has_no_machine_specific_scratch_paths() -> None:
    test_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROLE_DIR / "tests").glob("*.py")
        if path != Path(__file__)
    )

    assert "/tmp/opencode" not in test_sources


def test_vm_acceptance_material_tracks_every_unrun_live_check() -> None:
    playbook = ROLE_DIR / "tests" / "vm-acceptance.yml"
    checklist = ROLE_DIR / "tests" / "VM_ACCEPTANCE.md"

    assert playbook.exists()
    text = checklist.read_text(encoding="utf-8")
    for required_phrase in (
        "Debian 12",
        "Debian 13",
        "second-run convergence",
        "secret fingerprints",
        "secondary principal",
        "interrupted recovery",
        "reboot",
        "PCAP ingestion",
        "not yet been run",
        "complete backend-file loss",
        "complete forwarding CA-set loss",
    ):
        assert required_phrase in text


def test_source_and_recovery_guarantees_match_production_behavior() -> None:
    readme = (ROLE_DIR / "README.md").read_text(encoding="utf-8")

    assert re.search(r"does not require a particular\s+remote URL", readme)
    assert re.search(r"durable\s+per-artifact initialization evidence", readme)
    assert "complete loss" in readme
    assert "Restore the missing authoritative artifact" in readme
    assert re.search(r"nonempty persistent\s+data", readme)
    assert re.search(r"valid established administrator\s+crypt", readme)
    assert re.search(r"final persisted value is read back and validated", readme)

    acceptance = (ROLE_DIR / "tests" / "VM_ACCEPTANCE.md").read_text(encoding="utf-8")
    assert "legacy complete backend-file loss" in acceptance
    assert "legacy primary-credential loss" in acceptance
