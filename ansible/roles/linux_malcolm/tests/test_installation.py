from __future__ import annotations

import getpass
import os
from pathlib import Path
import subprocess

import pytest
import yaml

from helpers import PINNED_COMMIT, upstream_source


ROLE_DIR = Path(__file__).resolve().parents[1]
PREFLIGHT = ROLE_DIR / "tasks" / "preflight.yml"
INSTALL = ROLE_DIR / "tasks" / "install.yml"
DEFAULTS = ROLE_DIR / "defaults" / "main.yml"
DOCKER_ROLE = ROLE_DIR.parent / "ludus_install_docker"
ANSIBLE_PLAYBOOK = Path(os.environ.get("ANSIBLE_PLAYBOOK", "ansible-playbook"))
DEFAULT_VALUES = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))


def pinned_mirror(tmp_path: Path) -> Path:
    mirror = tmp_path / "malcolm-pinned-mirror.git"
    if mirror.exists():
        return mirror
    subprocess.run(
        [
            "git",
            "clone",
            "--bare",
            "--depth",
            "1",
            "--branch",
            "v26.08.0",
            upstream_source().as_uri(),
            str(mirror),
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    mirrored_commit = subprocess.run(
        ["git", f"--git-dir={mirror}", "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    if mirrored_commit != PINNED_COMMIT:
        raise RuntimeError(f"Pinned mirror resolved to unexpected commit {mirrored_commit}")
    return mirror


def run_preflight(
    tmp_path: Path,
    *,
    facts: dict[str, object] | None = None,
    variables: dict[str, object] | None = None,
) -> subprocess.CompletedProcess[str]:
    sentinel = tmp_path / "preflight-complete"
    playbook = tmp_path / "preflight.yml"
    play = [
        {
            "name": "Exercise Malcolm preflight",
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars": {
                **DEFAULT_VALUES,
                "ansible_distribution": "Debian",
                "ansible_distribution_major_version": "12",
                "ansible_architecture": "x86_64",
                "ansible_interfaces": ["eth0", "lo"],
                "ansible_default_ipv4": {"interface": "eth0"},
                "ludus_install_malcolm_user": getpass.getuser(),
                "ludus_install_malcolm_install_dir": str(tmp_path / "Malcolm"),
                "ludus_install_malcolm_admin_password": "test-only-password",
                **(facts or {}),
                **(variables or {}),
            },
            "tasks": [
                {"name": "Run production preflight", "include_tasks": str(PREFLIGHT)},
                {
                    "name": "Record successful preflight",
                    "copy": {"content": "ok\n", "dest": str(sentinel), "mode": "0600"},
                },
            ],
        }
    ]
    playbook.write_text(yaml.safe_dump(play, sort_keys=False), encoding="utf-8")
    env = os.environ.copy()
    env["ANSIBLE_NOCOLOR"] = "1"
    env["ANSIBLE_LOCAL_TEMP"] = str(tmp_path / ".ansible-local")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [str(ANSIBLE_PLAYBOOK), "-i", "localhost,", str(playbook)],
        cwd=ROLE_DIR,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def run_installation(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    upstream = pinned_mirror(tmp_path)
    playbook = tmp_path / "install.yml"
    play = [
        {
            "name": "Exercise Malcolm source installation",
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars": {
                **DEFAULT_VALUES,
                "ansible_distribution": "Debian",
                "ansible_distribution_major_version": "12",
                "ansible_architecture": "x86_64",
                "ansible_interfaces": ["eth0", "lo"],
                "ansible_default_ipv4": {"interface": "eth0"},
                "ludus_install_malcolm_user": getpass.getuser(),
                "ludus_install_malcolm_install_dir": str(tmp_path / "Malcolm"),
                "ludus_install_malcolm_admin_password": "test-only-password",
            },
            "tasks": [
                {"name": "Run production preflight", "include_tasks": str(PREFLIGHT)},
                {"name": "Run production installation", "include_tasks": str(INSTALL)},
            ],
        }
    ]
    playbook.write_text(yaml.safe_dump(play, sort_keys=False), encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / ".ansible-local"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"url.{upstream.as_uri()}.insteadOf",
            "GIT_CONFIG_VALUE_0": "https://github.com/cisagov/Malcolm.git",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return subprocess.run(
        [str(ANSIBLE_PLAYBOOK), "-i", "localhost,", str(playbook)],
        cwd=ROLE_DIR,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize("debian_release", ["12", "13"])
def test_supported_debian_reaches_source_inspection(tmp_path: Path, debian_release: str) -> None:
    result = run_preflight(
        tmp_path,
        facts={"ansible_distribution_major_version": debian_release},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "preflight-complete").read_text(encoding="utf-8") == "ok\n"


@pytest.mark.parametrize(
    ("facts", "variables", "message"),
    [
        ({"ansible_distribution": "Ubuntu"}, {}, "Debian 12 or 13"),
        ({"ansible_architecture": "aarch64"}, {}, "amd64"),
        ({}, {"ludus_install_malcolm_admin_password": ""}, "admin password"),
        (
            {},
            {
                "ludus_install_malcolm_version": "main",
                "ludus_install_malcolm_commit": "deadbeef",
            },
            "v26.08.0",
        ),
    ],
)
def test_unsupported_inputs_fail_before_source_changes(
    tmp_path: Path,
    facts: dict[str, object],
    variables: dict[str, object],
    message: str,
) -> None:
    source = tmp_path / "Malcolm"
    source.mkdir()
    evidence = source / "keep-me"
    evidence.write_text("unchanged\n", encoding="utf-8")

    result = run_preflight(tmp_path, facts=facts, variables=variables)

    assert result.returncode != 0
    assert message.lower() in (result.stdout + result.stderr).lower()
    assert evidence.read_text(encoding="utf-8") == "unchanged\n"
    assert not (tmp_path / "preflight-complete").exists()


def test_missing_capture_interface_is_rejected(tmp_path: Path) -> None:
    result = run_preflight(
        tmp_path,
        variables={
            "ludus_install_malcolm_capture_enabled": True,
            "ludus_install_malcolm_capture_interface": "enp99s0",
        },
    )

    assert result.returncode != 0
    assert "enp99s0" in result.stdout + result.stderr
    assert not (tmp_path / "preflight-complete").exists()


def test_mismatched_existing_release_is_rejected_without_mutation(tmp_path: Path) -> None:
    source = tmp_path / "Malcolm"
    (source / "scripts").mkdir(parents=True)
    (source / "scripts" / "malcolm_constants.py").write_text(
        'MALCOLM_VERSION = "26.07.0"\n', encoding="utf-8"
    )
    (source / "docker-compose.yml").write_text(
        "services:\n  api:\n    image: ghcr.io/idaholab/malcolm/api:26.07.0\n",
        encoding="utf-8",
    )
    before = {path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file()}

    result = run_preflight(tmp_path)

    after = {path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file()}
    assert result.returncode != 0
    assert "26.07.0" in result.stdout + result.stderr
    assert after == before


def test_unidentifiable_existing_directory_is_rejected_without_mutation(tmp_path: Path) -> None:
    source = tmp_path / "Malcolm"
    source.mkdir()
    evidence = source / "unrelated.txt"
    evidence.write_text("not Malcolm\n", encoding="utf-8")

    result = run_preflight(tmp_path)

    assert result.returncode != 0
    assert "immutable" in (result.stdout + result.stderr).lower()
    assert evidence.read_text(encoding="utf-8") == "not Malcolm\n"
    assert list(source.iterdir()) == [evidence]


def test_untrusted_partial_clone_marker_does_not_authorize_removal(tmp_path: Path) -> None:
    partial = tmp_path / "Malcolm.ludus-partial"
    partial.mkdir()
    evidence = partial / "keep-me"
    evidence.write_text("unrelated\n", encoding="utf-8")
    (tmp_path / "Malcolm.ludus-partial-owner").write_text(
        "not the role marker\n", encoding="utf-8"
    )

    result = run_preflight(tmp_path)

    assert result.returncode != 0
    assert "left untouched" in (result.stdout + result.stderr).lower()
    assert evidence.read_text(encoding="utf-8") == "unrelated\n"


def test_stale_valid_marker_does_not_authorize_partial_tree_removal(tmp_path: Path) -> None:
    partial = tmp_path / "Malcolm.ludus-partial"
    partial.mkdir()
    evidence = partial / "keep-me"
    evidence.write_text("unrelated\n", encoding="utf-8")
    (tmp_path / "Malcolm.ludus-partial-owner").write_text(
        "Malcolm source staging owned by role_malcolm_install\n", encoding="utf-8"
    )

    result = run_preflight(tmp_path)

    assert result.returncode != 0
    assert "partial" in (result.stdout + result.stderr).lower()
    assert evidence.read_text(encoding="utf-8") == "unrelated\n"


def test_non_git_mixed_source_is_rejected_without_false_provenance(tmp_path: Path) -> None:
    source = tmp_path / "Malcolm"
    (source / "scripts").mkdir(parents=True)
    (source / "scripts" / "malcolm_constants.py").write_text(
        'MALCOLM_VERSION = "26.08.0"\n', encoding="utf-8"
    )
    (source / "docker-compose.yml").write_text(
        "services:\n"
        "  api:\n    image: ghcr.io/idaholab/malcolm/api:26.08.0\n"
        "  arkime:\n    image: ghcr.io/idaholab/malcolm/arkime:latest\n",
        encoding="utf-8",
    )

    result = run_preflight(tmp_path)

    assert result.returncode != 0
    assert "immutable" in (result.stdout + result.stderr).lower()
    assert not (tmp_path / "Malcolm.ludus-release.yml").exists()


def test_installation_uses_exact_source_and_second_run_converges(tmp_path: Path) -> None:
    first = run_installation(tmp_path)

    assert first.returncode == 0, first.stdout + first.stderr
    source = tmp_path / "Malcolm"
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    assert head == PINNED_COMMIT
    subprocess.run(
        [str(source / ".venv" / "bin" / "python"), "-c", "import dotenv, ruamel.yaml"],
        check=True,
    )

    second = run_installation(tmp_path)

    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout


def test_clean_partial_git_clone_resumes_without_recursive_deletion(tmp_path: Path) -> None:
    partial = tmp_path / "Malcolm.ludus-partial"
    subprocess.run(
        ["git", "clone", "--no-checkout", str(pinned_mirror(tmp_path)), str(partial)],
        text=True,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(partial),
            "remote",
            "set-url",
            "origin",
            "https://github.com/cisagov/Malcolm.git",
        ],
        check=True,
    )
    evidence = partial / "resume-evidence"
    evidence.write_text("preserved\n", encoding="utf-8")

    result = run_installation(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "Malcolm" / "resume-evidence").read_text(encoding="utf-8") == "preserved\n"
    assert not partial.exists()


def test_clean_partial_at_wrong_head_is_rejected_without_mutation(tmp_path: Path) -> None:
    partial = tmp_path / "Malcolm.ludus-partial"
    subprocess.run(
        ["git", "clone", str(pinned_mirror(tmp_path)), str(partial)],
        text=True,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(partial),
            "remote",
            "set-url",
            "origin",
            "https://github.com/cisagov/Malcolm.git",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(partial),
            "-c",
            "user.name=Malcolm role test",
            "-c",
            "user.email=malcolm-role-test@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "wrong partial head",
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    wrong_head = subprocess.run(
        ["git", "-C", str(partial), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    evidence = partial / "README.md"
    before = evidence.read_bytes()

    result = run_preflight(tmp_path)

    after_head = subprocess.run(
        ["git", "-C", str(partial), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    assert result.returncode != 0
    assert wrong_head != PINNED_COMMIT
    assert "left untouched" in (result.stdout + result.stderr).lower()
    assert after_head == wrong_head
    assert evidence.read_bytes() == before


def test_rejected_malcolm_input_precedes_docker_role_mutation(tmp_path: Path) -> None:
    roles = tmp_path / "roles"
    roles.mkdir()
    (roles / "role_malcolm_install").symlink_to(ROLE_DIR, target_is_directory=True)
    fake_docker = roles / "ludus_install_docker" / "tasks"
    fake_docker.mkdir(parents=True)
    sentinel = tmp_path / "docker-role-ran"
    (fake_docker / "main.yml").write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Record Docker role mutation",
                    "ansible.builtin.copy": {
                        "content": "mutated\n",
                        "dest": str(sentinel),
                        "mode": "0600",
                    },
                }
            ],
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    playbook = tmp_path / "rejected-before-docker.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Reject Malcolm before Docker",
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": {
                        **DEFAULT_VALUES,
                        "ansible_distribution": "Debian",
                        "ansible_distribution_major_version": "12",
                        "ansible_architecture": "x86_64",
                        "ansible_interfaces": ["eth0", "lo"],
                        "ansible_default_ipv4": {"interface": "eth0"},
                        "ludus_install_malcolm_user": getpass.getuser(),
                        "ludus_install_malcolm_install_dir": str(tmp_path / "Malcolm"),
                        "ludus_install_malcolm_admin_password": "",
                    },
                    "roles": ["role_malcolm_install"],
                }
            ],
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        {
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / ".ansible-local"),
            "ANSIBLE_ROLES_PATH": os.pathsep.join((str(roles), str(ROLE_DIR.parent))),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )

    result = subprocess.run(
        [str(ANSIBLE_PLAYBOOK), "-i", "localhost,", str(playbook)],
        cwd=ROLE_DIR,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "admin password" in (result.stdout + result.stderr).lower()
    assert not sentinel.exists()


def test_docker_role_is_reused_after_preflight_for_selected_account() -> None:
    defaults = yaml.safe_load((DOCKER_ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    tasks = yaml.safe_load((DOCKER_ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    meta = yaml.safe_load((ROLE_DIR / "meta" / "main.yml").read_text(encoding="utf-8"))
    packages = yaml.safe_load((ROLE_DIR / "tasks" / "packages.yml").read_text(encoding="utf-8"))
    user_task = next(task for task in tasks if "ansible.builtin.user" in task)
    user_args = user_task["ansible.builtin.user"]

    assert defaults["ludus_install_docker_user"] == "debian"
    assert user_args == {
        "name": "{{ ludus_install_docker_user }}",
        "groups": ["docker"],
        "append": True,
    }
    assert meta["dependencies"] == []
    assert packages[0] == {
        "name": "Install Docker for the selected Malcolm account",
        "ansible.builtin.include_role": {"name": "ludus_install_docker"},
        "vars": {"ludus_install_docker_user": "{{ ludus_install_malcolm_user }}"},
    }
