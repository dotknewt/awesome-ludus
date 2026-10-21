from __future__ import annotations

import os
from pathlib import Path

import yaml

from helpers import ROLE_DIR, make_source, run_tasks


SERVICE_VALIDATE = ROLE_DIR / "tasks" / "service_validate.yml"
SERVICE_HEALTH = ROLE_DIR / "tasks" / "service_health.yml"
SERVICE_LIFECYCLE = ROLE_DIR / "tasks" / "service_lifecycle.yml"


def test_compose_validation_executes_and_rejects_wrong_image_tags(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker_log = tmp_path / "docker.log"
    docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$DOCKER_LOG"\nexit 0\n', encoding="utf-8")
    docker.chmod(0o755)

    valid = run_tasks(
        tmp_path,
        [SERVICE_VALIDATE],
        environment={"PATH": f"{fake_bin}:/usr/bin:/bin", "DOCKER_LOG": str(docker_log)},
    )
    assert valid.returncode == 0, valid.stdout + valid.stderr
    assert docker_log.read_text(encoding="utf-8").splitlines() == [
        f"compose --file {source / 'docker-compose.yml'} --profile malcolm config"
    ]

    compose = source / "docker-compose.yml"
    compose.write_text(compose.read_text(encoding="utf-8").replace(":26.08.0", ":latest", 1), encoding="utf-8")
    invalid = run_tasks(
        tmp_path,
        [SERVICE_VALIDATE],
        environment={"PATH": f"{fake_bin}:/usr/bin:/bin", "DOCKER_LOG": str(docker_log)},
    )
    assert invalid.returncode != 0
    assert "26.08.0" in invalid.stdout + invalid.stderr


def test_role_orchestration_and_service_unit_contract() -> None:
    main = yaml.safe_load((ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8"))
    includes = [task["ansible.builtin.include_tasks"] for task in main]
    assert includes == [
        "preflight.yml",
        "packages.yml",
        "system.yml",
        "install.yml",
        "configure.yml",
        "authentication.yml",
        "service.yml",
    ]
    assert not (ROLE_DIR / "tasks" / "vm_power.yml").exists()
    documentation = (ROLE_DIR / "README.md").read_text(encoding="utf-8")
    assert "guest VM must already be powered on and reachable" in documentation
    assert "Ludus owns VM lifecycle management" in documentation
    unit = (ROLE_DIR / "templates" / "malcolm.service.j2").read_text(encoding="utf-8")
    for expected in (
        "Type=oneshot",
        "RemainAfterExit=yes",
        "After=network-online.target docker.service",
        "Requires=docker.service",
        "WorkingDirectory={{ ludus_install_malcolm_install_dir }}",
        "User={{ ludus_install_malcolm_user }}",
        "Group={{ _ludus_install_malcolm_gid }}",
        "{{ ludus_install_malcolm_venv_dir }}/bin/python",
        "--start true --quiet true",
        "--stop true --quiet true",
    ):
        assert expected in unit


def _fake_docker(tmp_path: Path, *, terminal_failure: bool = False) -> tuple[Path, Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    counter = tmp_path / "health-counter"
    docker_log = tmp_path / "health-docker.log"
    mode = "terminal" if terminal_failure else "sequence"
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$HEALTH_DOCKER_LOG\"\n"
        "case \"$*\" in\n"
        "  *\"config --services\") printf 'api\\nworker\\nscheduler\\n' ;;\n"
        "  *\"ps --all --format json\")\n"
        "    count=0; [ -f \"$HEALTH_COUNTER\" ] && count=$(cat \"$HEALTH_COUNTER\")\n"
        "    count=$((count + 1)); printf '%s' \"$count\" > \"$HEALTH_COUNTER\"\n"
        f"    if [ \"{mode}\" = terminal ]; then\n"
        "      printf '[{\"Service\":\"api\",\"State\":\"running\",\"Health\":\"starting\"},{\"Service\":\"worker\",\"State\":\"exited\",\"Health\":\"\",\"ExitCode\":42}]\\n'\n"
        "    elif [ \"$count\" -lt 2 ]; then\n"
        "      printf '[{\"Service\":\"api\",\"State\":\"running\",\"Health\":\"starting\"},{\"Service\":\"worker\",\"State\":\"running\",\"Health\":\"\"},{\"Service\":\"scheduler\",\"State\":\"running\",\"Health\":\"healthy\"}]\\n'\n"
        "    else\n"
        "      printf '[{\"Service\":\"api\",\"State\":\"running\",\"Health\":\"healthy\"},{\"Service\":\"worker\",\"State\":\"running\",\"Health\":\"\"},{\"Service\":\"scheduler\",\"State\":\"running\",\"Health\":\"healthy\"}]\\n'\n"
        "    fi ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return fake_bin, counter, docker_log


def test_health_poll_retries_starting_until_healthy(tmp_path: Path) -> None:
    make_source(tmp_path)
    fake_bin, counter, docker_log = _fake_docker(tmp_path)

    result = run_tasks(
        tmp_path,
        [SERVICE_HEALTH],
        variables={
            "ludus_install_malcolm_readiness_timeout_seconds": 3,
            "ludus_install_malcolm_health_poll_interval_seconds": 1,
        },
        environment={
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "HEALTH_COUNTER": str(counter),
            "HEALTH_DOCKER_LOG": str(docker_log),
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert counter.read_text(encoding="utf-8") == "2"
    assert sum("ps --all --format json" in line for line in docker_log.read_text(encoding="utf-8").splitlines()) == 2


def test_health_poll_shares_timeout_and_reports_exited_and_missing_services(tmp_path: Path) -> None:
    make_source(tmp_path)
    fake_bin, counter, docker_log = _fake_docker(tmp_path, terminal_failure=True)

    result = run_tasks(
        tmp_path,
        [SERVICE_HEALTH],
        variables={
            "ludus_install_malcolm_readiness_timeout_seconds": 2,
            "ludus_install_malcolm_health_poll_interval_seconds": 1,
        },
        environment={
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "HEALTH_COUNTER": str(counter),
            "HEALTH_DOCKER_LOG": str(docker_log),
        },
    )

    assert result.returncode != 0
    assert 2 <= int(counter.read_text(encoding="utf-8")) <= 3
    assert "starting" in result.stdout + result.stderr
    assert "worker" in result.stdout + result.stderr
    assert "exited" in result.stdout + result.stderr
    assert "42" in result.stdout + result.stderr
    assert "scheduler" in result.stdout + result.stderr
    assert "missing" in result.stdout + result.stderr
    assert all("ps --all --format json" in line for line in docker_log.read_text(encoding="utf-8").splitlines()[1:])


def test_systemd_reload_and_restart_are_change_driven(tmp_path: Path) -> None:
    make_source(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    systemctl_log = tmp_path / "systemctl.log"
    systemctl_state = tmp_path / "systemctl.state"
    systemctl = fake_bin / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$SYSTEMCTL_LOG\"\n"
        "case \"$1\" in\n"
        "  show) if [ -f \"$SYSTEMCTL_STATE\" ]; then active=active; sub=exited; else active=inactive; sub=dead; fi; "
        "printf 'LoadState=loaded\\nActiveState=%s\\nSubState=%s\\nUnitFileState=enabled\\n' \"$active\" \"$sub\" ;;\n"
        "  is-enabled) printf 'enabled\\n' ;;\n"
        "  start|restart) : > \"$SYSTEMCTL_STATE\" ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    variables = {
        "ludus_install_malcolm_systemd_unit_path": str(tmp_path / "malcolm.service"),
        "_ludus_install_malcolm_service_template": str(ROLE_DIR / "templates" / "malcolm.service.j2"),
        "_ludus_install_malcolm_service_unit_owner": str(os.getuid()),
        "_ludus_install_malcolm_service_unit_group": str(os.getgid()),
    }
    environment = {
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "SYSTEMCTL_LOG": str(systemctl_log),
        "SYSTEMCTL_STATE": str(systemctl_state),
    }

    first = run_tasks(tmp_path, [SERVICE_LIFECYCLE], variables=variables, environment=environment, production_handler=True)
    assert first.returncode == 0, first.stdout + first.stderr
    first_log = systemctl_log.read_text(encoding="utf-8").splitlines()
    assert sum("daemon-reload" in line for line in first_log) == 1
    assert sum(line.startswith("restart ") for line in first_log) == 0
    assert sum(line.startswith("start ") for line in first_log) == 1

    systemctl_log.write_text("", encoding="utf-8")
    second = run_tasks(tmp_path, [SERVICE_LIFECYCLE], variables=variables, environment=environment, production_handler=True)
    assert second.returncode == 0, second.stdout + second.stderr
    second_log = systemctl_log.read_text(encoding="utf-8").splitlines()
    assert not any("daemon-reload" in line or line.startswith("restart ") for line in second_log)

    systemctl_log.write_text("", encoding="utf-8")
    changed = run_tasks(
        tmp_path,
        [SERVICE_LIFECYCLE],
        variables={**variables, "ludus_install_malcolm_start_timeout_seconds": 1799},
        environment=environment,
        production_handler=True,
    )
    assert changed.returncode == 0, changed.stdout + changed.stderr
    changed_log = systemctl_log.read_text(encoding="utf-8").splitlines()
    assert sum("daemon-reload" in line for line in changed_log) == 1
    assert sum(line.startswith("restart ") for line in changed_log) == 1
