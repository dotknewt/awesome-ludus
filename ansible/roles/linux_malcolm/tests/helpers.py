from __future__ import annotations

import getpass
import os
from pathlib import Path
import shutil
import subprocess
import sys

import yaml


ROLE_DIR = Path(__file__).resolve().parents[1]
ANSIBLE_PLAYBOOK = Path(os.environ.get("ANSIBLE_PLAYBOOK", "ansible-playbook"))
TEST_VENV = Path(os.environ.get("MALCOLM_TEST_VENV", sys.prefix)).resolve()
DEFAULTS = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
PINNED_COMMIT = "07bbccdfe2732fb5c5147070cdfca2857b85bacc"


def upstream_source() -> Path:
    configured = os.environ.get("MALCOLM_UPSTREAM_SOURCE")
    if not configured:
        raise RuntimeError(
            "Set MALCOLM_UPSTREAM_SOURCE to a checkout of cisagov/Malcolm "
            f"at {PINNED_COMMIT} (tag v26.08.0)"
        )
    source = Path(configured).expanduser().resolve()
    if not (source / "docker-compose.yml").is_file():
        raise RuntimeError(f"MALCOLM_UPSTREAM_SOURCE is not a Malcolm checkout: {source}")
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    if head != PINNED_COMMIT:
        raise RuntimeError(
            f"MALCOLM_UPSTREAM_SOURCE HEAD is {head}, expected {PINNED_COMMIT}"
        )
    return source


def make_source(tmp_path: Path) -> Path:
    upstream = upstream_source()
    source = tmp_path / "Malcolm"
    shutil.copytree(upstream / "config", source / "config")
    shutil.copy2(upstream / "docker-compose.yml", source / "docker-compose.yml")
    shutil.copytree(upstream / "opensearch", source / "opensearch")
    for directory in ("nginx", "htadmin", "logstash", "filebeat"):
        (source / directory).mkdir(exist_ok=True)
    return source


def run_tasks(
    tmp_path: Path,
    task_files: list[Path],
    *,
    variables: dict[str, object] | None = None,
    environment: dict[str, str] | None = None,
    production_handler: bool = False,
) -> subprocess.CompletedProcess[str]:
    source = tmp_path / "Malcolm"
    playbook = tmp_path / "behavior.yml"
    play = [
        {
            "name": "Exercise production Malcolm tasks",
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars": {
                **DEFAULTS,
                "ludus_install_malcolm_user": getpass.getuser(),
                "ludus_install_malcolm_install_dir": str(source),
                "ludus_install_malcolm_venv_dir": str(TEST_VENV),
                "ludus_install_malcolm_systemd_unit_path": str(source / ".test-malcolm.service"),
                "ludus_install_malcolm_admin_username": "admin",
                "ludus_install_malcolm_admin_password": "test-password-one",
                "ludus_install_malcolm_tls_dhparam_size": 512,
                "_ludus_install_malcolm_uid": os.getuid(),
                "_ludus_install_malcolm_gid": os.getgid(),
                "_ludus_install_malcolm_capture_interface": "eth0",
                "_ludus_install_malcolm_source_verified": True,
                **(variables or {}),
            },
            "tasks": [
                {"name": f"Run {task_file.name}", "include_tasks": str(task_file)}
                for task_file in task_files
            ],
            "handlers": (
                [
                    {
                        "name": "Restart Malcolm",
                        "include_tasks": str(ROLE_DIR / "handlers" / "main.yml"),
                    }
                ]
                if production_handler
                else [{"name": "Restart Malcolm", "debug": {"msg": "restart requested"}}]
            ),
        }
    ]
    playbook.write_text(yaml.safe_dump(play, sort_keys=False), encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / ".ansible-local"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    env.update(environment or {})
    return subprocess.run(
        [str(ANSIBLE_PLAYBOOK), "-i", "localhost,", str(playbook)],
        cwd=ROLE_DIR,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def env_value(path: Path, key: str) -> str:
    prefix = f"{key}="
    return next(line[len(prefix) :] for line in path.read_text(encoding="utf-8").splitlines() if line.startswith(prefix))
