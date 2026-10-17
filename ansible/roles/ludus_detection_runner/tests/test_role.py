"""Offline lifecycle tests for the dispatch-disabled runner manager role."""

from __future__ import annotations

import json
import os
import pwd
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

from support import REPOSITORY_ROOT


ROLE = "ludus_detection_runner"
BOOTSTRAP_CANARY = "bootstrap-task6-canary"
MANAGER_CANARY = "manager-task6-canary"


def _contract() -> dict:
    return {
        "bootstrap_auth": {
            "credential_type": "personal_access_token",
            "scopes": ["synthetic_create_runner", "synthetic_manage_runner"],
            "expiration_days": 1,
            "creation_argv": ["gitlab-rails", "runner", "-"],
            "protected_path": "/etc/detection-engineering/secrets/runner-api-bootstrap.token",
            "mode": "0600",
            "revoke_endpoint": "/api/v4/personal_access_tokens/self",
            "revoke_method": "DELETE",
        },
        "manager": {
            "runner_type": "instance_type",
            "create_scope": "synthetic_create_runner",
            "manage_scope": "synthetic_manage_runner",
            "create_endpoint": "/api/v4/user/runners",
            "create_method": "POST",
            "lookup_endpoint": "/api/v4/runners/all",
            "lookup_method": "GET",
            "detail_endpoint": "/api/v4/runners/:id",
            "detail_method": "GET",
            "update_endpoint": "/api/v4/runners/:id",
            "update_method": "PUT",
            "request_fields": ["runner_type", "description", "paused"],
            "response_token_field": "token",
            "local_verify_command": ["gitlab-runner", "verify"],
            "pause_at_create": True,
        },
    }


@pytest.fixture
def fake_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({
        "identity": {
            "id": 7,
            "runner_type": "instance_type",
            "description": "synthetic-alpha-runner",
            "paused": True,
        },
        "jobs": [],
        "revocation_statuses": [204],
        "service": {"exists": False, "active": False, "enabled": False, "masked": False},
        "events": [],
    }))
    monkeypatch.setenv("DETECTION_FAKE_RUNNER_STATE", str(state_path))

    (fake_bin / "curl").write_text(
        """#!/usr/bin/env python3
import json, os, re, sys
from pathlib import Path
p = Path(os.environ['DETECTION_FAKE_RUNNER_STATE']); s = json.loads(p.read_text())
config = sys.stdin.read()
def value(name, required=True):
    match = re.search(r'^' + re.escape(name) + r' = "(.*)"$', config, re.M)
    if not match and required: raise SystemExit('missing curl config ' + name)
    return match.group(1) if match else None
url, method, output = value('url'), value('request'), value('output')
headers = re.findall(r'^header = "(.*)"$', config, re.M)
if not headers or headers[0] != 'Authorization: Bearer bootstrap-task6-canary':
    raise SystemExit('missing protected bearer input')
s['events'].append({
    'kind': 'api', 'method': method, 'url': url, 'argv': sys.argv[1:],
    'output': output,
    'env_has_canary': any('task6-canary' in value for value in os.environ.values()),
})
if method == 'GET' and url.endswith('/runners/all'):
    response = [s['identity']]
elif method == 'PUT' and url.endswith('/runners/7'):
    s['identity']['paused'] = True; response = s['identity']
elif method == 'GET' and url.endswith('/runners/7/jobs'):
    response = s['jobs']
elif method == 'GET' and url.endswith('/runners/7'):
    response = s['identity']
elif method == 'DELETE' and url.endswith('/personal_access_tokens/self'):
    statuses = s.setdefault('revocation_statuses', [204])
    status = statuses.pop(0) if len(statuses) > 1 else statuses[0]
    response = {}; sys.stdout.write(str(status))
else:
    raise SystemExit('unexpected method/url')
Path(output).write_text(json.dumps(response)); p.write_text(json.dumps(s))
""",
        encoding="utf-8",
    )
    (fake_bin / "curl").chmod(0o755)

    (fake_bin / "gitlab-runner").write_text(
        """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p = Path(os.environ['DETECTION_FAKE_RUNNER_STATE']); s = json.loads(p.read_text())
assert sys.argv[1:] == ['verify']
assert s['identity']['paused'] is True
assert Path(os.environ['DETECTION_FAKE_CONFIG']).read_text().find('manager-task6-canary') >= 0
s['events'].append({
    'kind': 'verify', 'argv': sys.argv[1:],
    'env_has_canary': any('task6-canary' in value for value in os.environ.values()),
})
p.write_text(json.dumps(s))
raise SystemExit(17 if s.get('registration_failure') else 0)
""",
        encoding="utf-8",
    )
    (fake_bin / "gitlab-runner").chmod(0o755)

    (fake_bin / "systemctl").write_text(
        """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p = Path(os.environ['DETECTION_FAKE_RUNNER_STATE']); s = json.loads(p.read_text())
argv = sys.argv[1:]; op = argv[0] if argv else ''
s['events'].append({
    'kind': 'systemctl', 'argv': argv,
    'env_has_canary': any('task6-canary' in value for value in os.environ.values()),
})
failures = s.setdefault('systemctl_failures', {})
remaining = failures.get(op, 0)
if remaining:
    failures[op] = remaining - 1; p.write_text(json.dumps(s)); raise SystemExit(19)
counts = s.setdefault('systemctl_counts', {}); counts[op] = counts.get(op, 0) + 1
if counts[op] in s.setdefault('systemctl_fail_on', {}).get(op, []):
    p.write_text(json.dumps(s)); raise SystemExit(19)
service = s['service']
if op == 'stop':
    if not service['exists']: p.write_text(json.dumps(s)); raise SystemExit(5)
    service['active'] = False
elif op == 'disable':
    if not service['exists']: p.write_text(json.dumps(s)); raise SystemExit(1)
    service['enabled'] = False
elif op == 'mask': service['masked'] = True; service['enabled'] = False
elif op == 'unmask': service['masked'] = False
elif op == 'start':
    if not service['exists']: p.write_text(json.dumps(s)); raise SystemExit(5)
    service['active'] = True
elif op == 'is-active':
    print('active' if service['active'] else 'inactive'); p.write_text(json.dumps(s)); raise SystemExit(0 if service['active'] else 3)
elif op == 'is-enabled':
    print('masked' if service['masked'] else ('enabled' if service['enabled'] else 'disabled'))
    p.write_text(json.dumps(s)); raise SystemExit(0 if service['masked'] or service['enabled'] else 1)
p.write_text(json.dumps(s))
""",
        encoding="utf-8",
    )
    (fake_bin / "systemctl").chmod(0o755)

    (fake_bin / "apt-get").write_text(
        """#!/usr/bin/env python3
import json, os, subprocess, sys
from pathlib import Path
p = Path(os.environ['DETECTION_FAKE_RUNNER_STATE']); s = json.loads(p.read_text())
policy = os.environ['DETECTION_FAKE_POLICY']
blocked = subprocess.run([policy, 'gitlab-runner', 'start'], check=False).returncode
unrelated = subprocess.run([policy, 'cron', 'restart'], check=False).returncode
if s.get('replace_policy_during_install'):
    replacement = Path(policy).read_bytes() + b'\\n# foreign replacement with copied marker\\n'
    Path(policy).unlink(); Path(policy).write_bytes(replacement); Path(policy).chmod(0o755)
s['events'].append({
    'kind': 'apt', 'argv': sys.argv[1:], 'blocked': blocked, 'unrelated': unrelated,
    'env_has_canary': any('task6-canary' in value for value in os.environ.values()),
})
s['service']['exists'] = True
if blocked != 101: s['service']['active'] = True
p.write_text(json.dumps(s))
if s.get('package_failure'): raise SystemExit(31)
""",
        encoding="utf-8",
    )
    (fake_bin / "apt-get").chmod(0o755)
    return fake_bin, state_path


def _variables(tmp_path: Path) -> dict:
    source = tmp_path / "gitlab-source"
    local = tmp_path / "runner-local"
    source.mkdir(exist_ok=True)
    local.mkdir(exist_ok=True)
    bootstrap = source / "runner-api-bootstrap.token"
    manager = source / "runner-auth.token"
    if not bootstrap.exists():
        bootstrap.write_text(BOOTSTRAP_CANARY)
        bootstrap.chmod(0o600)
    if not manager.exists():
        manager.write_text(MANAGER_CANARY)
        manager.chmod(0o600)
    readiness = source / "gitlab-readiness.json"
    readiness.write_text(json.dumps({
        "schema_version": 1,
        "status": "READY",
        "endpoint": "/synthetic-ready",
        "method": "GET",
        "http_status": 200,
        "attempts_used": 1,
    }))
    readiness.chmod(0o644)
    helper = local / "runner-policy-transaction"
    helper.write_bytes((REPOSITORY_ROOT / "ansible/roles/ludus_detection_runner/files/runner_policy_transaction.py").read_bytes())
    helper.chmod(0o755)
    return {
        "range_id": "synthetic-alpha",
        "detection_runner_description": "synthetic-alpha-runner",
        "detection_gitlab_host": "http://gitlab.synthetic.invalid",
        "detection_gitlab_delegate_host": "gitlabhost",
        "detection_runner_api_contract": _contract(),
        "detection_runner_jobs_contract": {
            "endpoint": "/api/v4/runners/:id/jobs",
            "method": "GET",
        },
        "detection_gitlab_readiness_contract": {
            "endpoint": "/synthetic-ready",
            "method": "GET",
            "success_statuses": [200],
            "attempts": 3,
            "delay_seconds": 0,
        },
        "detection_runner_packages": [{"name": "gitlab-runner", "version": "99.0.0.synthetic"}],
        "detection_runner_repository_url": "https://packages.synthetic.invalid/runner",
        "detection_runner_signing_key_url": "https://packages.synthetic.invalid/key.gpg",
        "detection_runner_signing_key_fingerprint": "A" * 40,
        "detection_runner_bootstrap_path": str(bootstrap),
        "detection_runner_source_manager_path": str(manager),
        "detection_runner_gitlab_readiness_path": str(readiness),
        "detection_runner_config_path": str(local / "config.toml"),
        "detection_runner_state_dir": str(local),
        "detection_runner_registration_failed_marker": str(local / "runner-registration-failed"),
        "detection_runner_cleanup_failed_marker": str(local / "runner-bootstrap-cleanup-failed"),
        "detection_runner_api_work_dir": str(local / "api"),
        "detection_runner_revoke_work_dir": str(source / "revoke-work"),
        "detection_runner_registration_log_path": str(local / "runner-registration.jsonl"),
        "detection_runner_expected_source_uid": os.getuid(),
        "detection_runner_expected_source_owner": pwd.getpwuid(os.getuid()).pw_name,
        "detection_runner_expected_local_uid": os.getuid(),
        "detection_runner_expected_local_owner": pwd.getpwuid(os.getuid()).pw_name,
        "detection_runner_policy_path": str(local / "policy-rc.d"),
        "detection_runner_policy_transaction_dir": str(local / ".policy-transaction"),
        "detection_runner_policy_helper_path": str(helper),
    }


def _run_include(
    include: str,
    variables: dict,
    fake_bin: Path,
    *,
    skip_tags: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="task6-inventory-") as work:
        root = Path(work)
        inventory = root / "inventory.yml"
        playbook = root / "playbook.yml"
        inventory.write_text(yaml.safe_dump({
            "all": {"hosts": {
                "runnerhost": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable},
                "gitlabhost": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable},
            }}
        }))
        playbook.write_text(yaml.safe_dump([{
            "name": "Exercise Task 6 production include",
            "hosts": "runnerhost",
            "gather_facts": False,
            "become": False,
            "vars": variables,
            "tasks": [{"ansible.builtin.include_role": {"name": ROLE, "tasks_from": include}}],
        }], sort_keys=False))
        env = os.environ.copy()
        for name in ("home", "local", "remote"):
            (root / name).mkdir(mode=0o700)
        env.update({
            "ANSIBLE_HOME": str(root / "home"),
            "ANSIBLE_LOCAL_TEMP": str(root / "local"),
            "ANSIBLE_REMOTE_TEMP": str(root / "remote"),
            "ANSIBLE_ROLES_PATH": str(REPOSITORY_ROOT / "ansible/roles"),
            "HOME": str(root / "home"),
            "PATH": f"{fake_bin}{os.pathsep}{env.get('PATH', '')}",
            "DETECTION_FAKE_CONFIG": variables.get("detection_runner_config_path", "missing"),
            "DETECTION_FAKE_POLICY": variables.get("detection_runner_policy_path", "missing"),
        })
        command = [str(Path(sys.executable).with_name("ansible-playbook")), "-i", str(inventory)]
        if skip_tags:
            command.extend(["--skip-tags", ",".join(skip_tags)])
        command.append(str(playbook))
        return subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )


def _state(path: Path) -> dict:
    return json.loads(path.read_text())


def _assert_marker(path: Path, outcome: str, status_value: str | None = None) -> None:
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert path.stat().st_uid == os.getuid()
    value = json.loads(path.read_text())
    assert set(value) == {"registration_outcome", "status", "timestamp"}
    assert value["registration_outcome"] == outcome
    assert value["status"]
    if status_value is not None:
        assert value["status"] == status_value
    assert value["timestamp"].endswith("Z")


def _assert_service_guarded(state: dict) -> None:
    assert state["service"]["active"] is False
    assert state["service"]["enabled"] is False
    assert state["service"]["masked"] is True


def test_package_install_cannot_autostart_runner(fake_boundary, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_bin, state_path = fake_boundary
    install = (REPOSITORY_ROOT / "ansible/roles/ludus_detection_runner/tasks/install-package.yml").read_text()
    policy = (REPOSITORY_ROOT / "ansible/roles/ludus_detection_runner/templates/policy-rc.d.j2").read_text()
    assert install.index("Enforce inactive masked service state") < install.index("Install exact pinned runner package with apt-get")
    assert "runner_policy_transaction" in install
    assert "always:" in install and "Capture public policy first" in install
    assert "gitlab-runner" in policy and "exit 101" in policy
    assert "original-policy" in policy
    variables = _variables(tmp_path)
    policy_path = Path(variables["detection_runner_policy_path"])
    original = b"#!/bin/sh\nexit 42\n"
    policy_path.write_bytes(original); policy_path.chmod(0o755)
    monkeypatch.setenv("DETECTION_FAKE_POLICY", str(policy_path))
    result = _run_include("install-package", variables, fake_bin)
    assert result.returncode == 0, result.stdout + result.stderr
    assert policy_path.read_bytes() == original
    transaction = Path(variables["detection_runner_policy_transaction_dir"])
    assert not (transaction / "state.json").exists()
    assert not (transaction / "original-policy").exists()
    events = _state(state_path)["events"]
    mask = next(i for i, event in enumerate(events) if event["kind"] == "systemctl" and "mask" in event["argv"])
    apt = next(i for i, event in enumerate(events) if event["kind"] == "apt")
    assert mask < apt
    assert events[apt]["blocked"] == 101
    assert events[apt]["unrelated"] == 42
    assert _state(state_path)["service"]["exists"] is True
    _assert_service_guarded(_state(state_path))


def test_new_identity_is_paused_before_local_registration(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    result = _run_include("lifecycle", _variables(tmp_path), fake_bin)
    assert result.returncode == 0, result.stdout + result.stderr
    events = _state(state_path)["events"]
    detail_index = next(i for i, event in enumerate(events) if event["kind"] == "api" and event["url"].endswith("/runners/7"))
    verify_index = next(i for i, event in enumerate(events) if event["kind"] == "verify")
    assert detail_index < verify_index


def test_preexisting_unpaused_identity_is_paused_before_transfer(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    state = _state(state_path); state["identity"]["paused"] = False; state_path.write_text(json.dumps(state))
    result = _run_include("lifecycle", _variables(tmp_path), fake_bin)
    assert result.returncode == 0, result.stdout + result.stderr
    events = _state(state_path)["events"]
    assert next(i for i, e in enumerate(events) if e["method"] == "PUT") < next(i for i, e in enumerate(events) if e["kind"] == "verify")
    lifecycle = (REPOSITORY_ROOT / "ansible/roles/ludus_detection_runner/tasks/lifecycle.yml").read_text()
    assert lifecycle.index("Pause a preexisting unpaused identity") < lifecycle.index("Transfer stable manager token")


def test_second_run_preserves_identity_and_manager_token(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    source_manager = Path(variables["detection_runner_source_manager_path"])
    stable = source_manager.read_bytes()
    first = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))
    assert first.returncode == 0, first.stdout + first.stderr
    Path(variables["detection_runner_bootstrap_path"]).write_text(BOOTSTRAP_CANARY)
    Path(variables["detection_runner_bootstrap_path"]).chmod(0o600)
    second = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))
    assert second.returncode == 0, second.stdout + second.stderr
    assert source_manager.read_bytes() == stable
    assert not any(event["method"] == "POST" for event in _state(state_path)["events"] if event["kind"] == "api")
    _assert_service_guarded(_state(state_path))


def test_verified_cli_handshake_precedes_bootstrap_revocation(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    result = _run_include("lifecycle", _variables(tmp_path), fake_bin)
    assert result.returncode == 0, result.stdout + result.stderr
    events = _state(state_path)["events"]
    assert next(i for i, e in enumerate(events) if e["kind"] == "verify") < next(i for i, e in enumerate(events) if e.get("method") == "DELETE")


@pytest.mark.parametrize("accepted", [200, 204, 404])
def test_success_success_deletes_credential_and_markers(fake_boundary, tmp_path: Path, accepted: int) -> None:
    fake_bin, state_path = fake_boundary
    state = _state(state_path); state["revocation_statuses"] = [accepted]; state_path.write_text(json.dumps(state))
    variables = _variables(tmp_path)
    for key in ("detection_runner_registration_failed_marker", "detection_runner_cleanup_failed_marker"):
        Path(variables[key]).write_text("stale")
    result = _run_include("lifecycle", variables, fake_bin)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not Path(variables["detection_runner_bootstrap_path"]).exists()
    assert not Path(variables["detection_runner_registration_failed_marker"]).exists()
    assert not Path(variables["detection_runner_cleanup_failed_marker"]).exists()


def test_registration_failure_cleanup_success_deletes_credential_and_marks_registration(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    state = _state(state_path); state["registration_failure"] = True; state_path.write_text(json.dumps(state))
    variables = _variables(tmp_path)
    result = _run_include("lifecycle", variables, fake_bin)
    assert result.returncode != 0
    assert not Path(variables["detection_runner_bootstrap_path"]).exists()
    _assert_marker(
        Path(variables["detection_runner_registration_failed_marker"]),
        "failed",
        "local_registration_or_postcheck_failed",
    )
    assert not Path(variables["detection_runner_cleanup_failed_marker"]).exists()


def test_revocation_failure_retains_only_protected_credential_and_cleanup_marker(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    state = _state(state_path); state["revocation_statuses"] = [500, 500, 500]; state_path.write_text(json.dumps(state))
    variables = _variables(tmp_path)
    result = _run_include("lifecycle", variables, fake_bin)
    assert result.returncode != 0
    credential = Path(variables["detection_runner_bootstrap_path"])
    assert credential.read_text() == BOOTSTRAP_CANARY
    assert stat.S_IMODE(credential.stat().st_mode) == 0o600
    _assert_marker(Path(variables["detection_runner_cleanup_failed_marker"]), "succeeded")
    assert not Path(variables["detection_runner_registration_failed_marker"]).exists()
    assert len([e for e in _state(state_path)["events"] if e.get("method") == "DELETE"]) == 3


def test_registration_and_revocation_failure_retries_cleanup_before_any_registration(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    state = _state(state_path)
    state["registration_failure"] = True
    state["revocation_statuses"] = [500, 500, 500]
    state_path.write_text(json.dumps(state))
    variables = _variables(tmp_path)
    first = _run_include("lifecycle", variables, fake_bin)
    assert first.returncode != 0
    cleanup = Path(variables["detection_runner_cleanup_failed_marker"])
    _assert_marker(cleanup, "failed")
    assert not Path(variables["detection_runner_registration_failed_marker"]).exists()
    state = _state(state_path)
    previous_events = len(state["events"])
    state["revocation_statuses"] = [204]
    state_path.write_text(json.dumps(state))
    minimal = {key: variables[key] for key in (
        "detection_gitlab_delegate_host", "detection_gitlab_host", "detection_runner_api_contract",
        "detection_runner_bootstrap_path", "detection_runner_state_dir",
        "detection_runner_registration_failed_marker", "detection_runner_cleanup_failed_marker",
            "detection_runner_api_work_dir", "detection_runner_registration_log_path",
            "detection_runner_revoke_work_dir", "detection_runner_expected_source_uid",
            "detection_runner_expected_source_owner", "detection_runner_expected_local_uid",
            "detection_runner_expected_local_owner",
    )}
    second = _run_include("main", minimal, fake_bin)
    assert second.returncode != 0
    assert not cleanup.exists()
    _assert_marker(
        Path(variables["detection_runner_registration_failed_marker"]),
        "failed",
        "bootstrap_revocation_failed_after_3_tries",
    )
    retry_events = _state(state_path)["events"][previous_events:]
    assert [event["method"] for event in retry_events if event["kind"] == "api"] == ["DELETE"]


@pytest.mark.parametrize("prior_outcome,expect_success", [("succeeded", True), ("failed", False)])
def test_cleanup_first_retry_uses_recorded_registration_outcome(fake_boundary, tmp_path: Path, prior_outcome: str, expect_success: bool) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    cleanup = Path(variables["detection_runner_cleanup_failed_marker"])
    cleanup.write_text(json.dumps({"registration_outcome": prior_outcome, "status": "revocation_failed", "timestamp": "2026-10-17T00:00:00Z"}))
    cleanup.chmod(0o644)
    # Deliberately omit all ordinary package/readiness inputs: cleanup must still run first.
    minimal = {key: variables[key] for key in (
        "detection_gitlab_delegate_host", "detection_gitlab_host", "detection_runner_api_contract",
        "detection_runner_bootstrap_path", "detection_runner_state_dir",
        "detection_runner_registration_failed_marker", "detection_runner_cleanup_failed_marker",
            "detection_runner_api_work_dir", "detection_runner_registration_log_path",
            "detection_runner_revoke_work_dir", "detection_runner_expected_source_uid",
            "detection_runner_expected_source_owner", "detection_runner_expected_local_uid",
            "detection_runner_expected_local_owner",
    )}
    result = _run_include("main", minimal, fake_bin)
    assert (result.returncode == 0) is expect_success
    assert not cleanup.exists()
    assert not Path(variables["detection_runner_bootstrap_path"]).exists()
    events = _state(state_path)["events"]
    assert [event["method"] for event in events if event["kind"] == "api"] == ["DELETE"]
    _assert_service_guarded(_state(state_path))
    registration = Path(variables["detection_runner_registration_failed_marker"])
    assert registration.exists() is (not expect_success)
    if registration.exists(): _assert_marker(registration, "failed")


@pytest.mark.parametrize("malformed", [b"", b"partial\nforeign"])
def test_malformed_token_refusal_preserves_handle_without_api_or_registration(fake_boundary, tmp_path: Path, malformed: bytes) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    handle = Path(variables["detection_runner_bootstrap_path"]); handle.write_bytes(malformed); handle.chmod(0o600)
    result = _run_include("lifecycle", variables, fake_bin)
    assert result.returncode != 0
    assert handle.read_bytes() == malformed
    assert _state(state_path)["events"] == []


def test_protected_material_canaries_never_enter_argv_query_env_or_stdout(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    result = _run_include("lifecycle", variables, fake_bin)
    combined = result.stdout + result.stderr
    assert BOOTSTRAP_CANARY not in combined and MANAGER_CANARY not in combined
    for event in _state(state_path)["events"]:
        exposed = json.dumps({"argv": event.get("argv"), "url": event.get("url")})
        assert BOOTSTRAP_CANARY not in exposed and MANAGER_CANARY not in exposed
        assert "?" not in event.get("url", "")
    assert BOOTSTRAP_CANARY not in json.dumps(dict(os.environ))
    assert MANAGER_CANARY not in json.dumps(dict(os.environ))


def test_jobs_or_unpaused_postcheck_blocks_success(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    state = _state(state_path); state["jobs"] = [{"id": 99}]; state_path.write_text(json.dumps(state))
    variables = _variables(tmp_path)
    result = _run_include("lifecycle", variables, fake_bin)
    assert result.returncode != 0
    _assert_marker(Path(variables["detection_runner_registration_failed_marker"]), "failed")
    assert not Path(variables["detection_runner_bootstrap_path"]).exists()


def test_unsafe_or_missing_local_verify_capability_is_refused(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    for command in ([], ["sh", "-c", "gitlab-runner verify"]):
        variables = _variables(tmp_path)
        variables["detection_runner_api_contract"]["manager"]["local_verify_command"] = command
        result = _run_include("lifecycle", variables, fake_bin)
        assert result.returncode != 0
        assert _state(state_path)["events"] == []


@pytest.mark.parametrize("failure,expected_status", [
    ("preflight", "preflight_failed"),
    ("package", "package_install_failed"),
    ("local_setup", "local_registration_or_postcheck_failed"),
    ("registration", "local_registration_or_postcheck_failed"),
    ("service_proof", "service_proof_failed"),
])
def test_real_main_failure_completes_guard_revoke_and_markers(
    fake_boundary, tmp_path: Path, failure: str, expected_status: str
) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    state = _state(state_path)
    if failure == "preflight":
        variables["detection_runner_packages"][0]["version"] = "*"
    elif failure == "package":
        state["package_failure"] = True
    elif failure == "local_setup":
        Path(variables["detection_runner_api_work_dir"]).write_text("not-a-directory")
    elif failure == "registration":
        state["registration_failure"] = True
    else:
        state["systemctl_fail_on"] = {"is-active": [3]}
    state_path.write_text(json.dumps(state))

    result = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))

    assert result.returncode != 0
    assert not Path(variables["detection_runner_bootstrap_path"]).exists()
    _assert_marker(Path(variables["detection_runner_registration_failed_marker"]), "failed", expected_status)
    assert not Path(variables["detection_runner_cleanup_failed_marker"]).exists()
    final_state = _state(state_path)
    _assert_service_guarded(final_state)
    events = final_state["events"]
    revoke_index = max(i for i, event in enumerate(events) if event.get("method") == "DELETE")
    guard_indices = [i for i, event in enumerate(events) if event["kind"] == "systemctl"]
    assert guard_indices and max(guard_indices) < revoke_index
    if failure == "package":
        assert not Path(variables["detection_runner_policy_path"]).exists()
        assert not (Path(variables["detection_runner_policy_transaction_dir"]) / "state.json").exists()


def test_real_main_revocation_failure_keeps_handle_and_cleanup_marker_after_guard(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    state = _state(state_path)
    state["registration_failure"] = True
    state["revocation_statuses"] = [500, 500, 500]
    state_path.write_text(json.dumps(state))

    result = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))

    assert result.returncode != 0
    handle = Path(variables["detection_runner_bootstrap_path"])
    assert handle.read_bytes() == BOOTSTRAP_CANARY.encode()
    assert stat.S_IMODE(handle.stat().st_mode) == 0o600
    _assert_marker(
        Path(variables["detection_runner_cleanup_failed_marker"]),
        "failed",
        "bootstrap_revocation_failed_after_3_tries",
    )
    assert not Path(variables["detection_runner_registration_failed_marker"]).exists()
    final_state = _state(state_path)
    _assert_service_guarded(final_state)
    assert len([event for event in final_state["events"] if event.get("method") == "DELETE"]) == 3


def test_real_main_guard_failure_does_not_skip_revoke_markers_or_secret_clear(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    state = _state(state_path)
    state["registration_failure"] = True
    state["systemctl_failures"] = {"stop": 2, "disable": 2, "mask": 2}
    state_path.write_text(json.dumps(state))

    result = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))

    assert result.returncode != 0
    assert not Path(variables["detection_runner_bootstrap_path"]).exists()
    _assert_marker(
        Path(variables["detection_runner_registration_failed_marker"]),
        "failed",
        "initial_service_guard_failed+service_guard_failed",
    )
    assert not Path(variables["detection_runner_cleanup_failed_marker"]).exists()
    events = _state(state_path)["events"]
    assert any(event.get("method") == "DELETE" for event in events)
    revoke_index = next(i for i, event in enumerate(events) if event.get("method") == "DELETE")
    assert max(i for i, event in enumerate(events) if event["kind"] == "systemctl") < revoke_index
    for operation in ("stop", "disable", "mask"):
        assert len([event for event in events if event["kind"] == "systemctl" and event["argv"][0] == operation]) == 2
    assert BOOTSTRAP_CANARY not in result.stdout + result.stderr
    assert MANAGER_CANARY not in result.stdout + result.stderr


@pytest.mark.parametrize("unsafe", ["symlink", "mode"])
def test_cleanup_marker_identity_is_validated_before_json_or_revocation(fake_boundary, tmp_path: Path, unsafe: str) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    marker = Path(variables["detection_runner_cleanup_failed_marker"])
    marker.unlink(missing_ok=True)
    content = json.dumps({
        "registration_outcome": "succeeded",
        "status": "bootstrap_revocation_failed_after_3_tries",
        "timestamp": "2026-10-17T00:00:00Z",
    })
    if unsafe == "symlink":
        target = tmp_path / "foreign-marker"
        target.write_text(content); target.chmod(0o644)
        marker.symlink_to(target)
    else:
        marker.write_text(content); marker.chmod(0o600)

    result = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))

    assert result.returncode != 0
    assert Path(variables["detection_runner_bootstrap_path"]).read_bytes() == BOOTSTRAP_CANARY.encode()
    assert not any(event.get("method") == "DELETE" for event in _state(state_path)["events"])
    _assert_service_guarded(_state(state_path))
    if unsafe == "symlink":
        assert marker.is_symlink()
    else:
        assert stat.S_IMODE(marker.stat().st_mode) == 0o600


def test_policy_concurrent_marker_copy_is_preserved_with_original_quarantined(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    policy_path = Path(variables["detection_runner_policy_path"])
    original = b"#!/bin/sh\nexit 42\n"
    policy_path.write_bytes(original); policy_path.chmod(0o755)
    state = _state(state_path); state["replace_policy_during_install"] = True
    state_path.write_text(json.dumps(state))

    result = _run_include("install-package", variables, fake_bin)

    assert result.returncode != 0
    replacement = policy_path.read_bytes()
    assert b"runner_package_transaction" in replacement
    assert replacement != original
    transaction = Path(variables["detection_runner_policy_transaction_dir"])
    preserved = [path.read_bytes() for path in transaction.iterdir() if path.is_file()]
    assert original in preserved


def test_fake_boundaries_and_unprotected_outputs_are_secret_free(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    result = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))
    assert result.returncode == 0, result.stdout + result.stderr
    artifacts = [
        result.stdout,
        result.stderr,
        Path(variables["detection_runner_registration_log_path"]).read_text(),
        state_path.read_text(),
    ]
    for artifact in artifacts:
        assert BOOTSTRAP_CANARY not in artifact
        assert MANAGER_CANARY not in artifact
    for event in _state(state_path)["events"]:
        assert event.get("env_has_canary", False) is False
        if event["kind"] == "api":
            assert event["output"].startswith((
                variables["detection_runner_api_work_dir"],
                variables["detection_runner_revoke_work_dir"],
            ))


def test_cleanup_first_delete_failure_still_writes_registration_authority(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    cleanup_dir = tmp_path / "readonly-cleanup-marker"
    cleanup_dir.mkdir()
    cleanup = cleanup_dir / "runner-bootstrap-cleanup-failed"
    cleanup.write_text(json.dumps({
        "registration_outcome": "failed",
        "status": "bootstrap_revocation_failed_after_3_tries",
        "timestamp": "2026-10-17T00:00:00Z",
    }))
    cleanup.chmod(0o644)
    variables["detection_runner_cleanup_failed_marker"] = str(cleanup)
    cleanup_bytes = cleanup.read_bytes()
    cleanup_dir.chmod(0o555)
    try:
        result = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))
        assert result.returncode != 0
        assert not Path(variables["detection_runner_bootstrap_path"]).exists()
        assert cleanup.read_bytes() == cleanup_bytes
        _assert_marker(
            Path(variables["detection_runner_registration_failed_marker"]),
            "failed",
            "bootstrap_revocation_failed_after_3_tries",
        )
        _assert_service_guarded(_state(state_path))
        assert BOOTSTRAP_CANARY not in result.stdout + result.stderr
    finally:
        cleanup_dir.chmod(0o755)


def test_registration_remove_failure_still_writes_cleanup_authority(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    registration_dir = tmp_path / "readonly-registration-marker"
    registration_dir.mkdir()
    registration = registration_dir / "runner-registration-failed"
    registration.write_text(json.dumps({
        "registration_outcome": "failed",
        "status": "prior-registration-failed",
        "timestamp": "2026-10-17T00:00:00Z",
    }))
    registration.chmod(0o644)
    variables["detection_runner_registration_failed_marker"] = str(registration)
    registration_bytes = registration.read_bytes()
    state = _state(state_path)
    state["revocation_statuses"] = [500, 500, 500]
    state_path.write_text(json.dumps(state))
    registration_dir.chmod(0o555)
    try:
        result = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))
        assert result.returncode != 0
        assert Path(variables["detection_runner_bootstrap_path"]).read_bytes() == BOOTSTRAP_CANARY.encode()
        assert registration.read_bytes() == registration_bytes
        _assert_marker(
            Path(variables["detection_runner_cleanup_failed_marker"]),
            "succeeded",
            "bootstrap_revocation_failed_after_3_tries",
        )
        _assert_service_guarded(_state(state_path))
        assert BOOTSTRAP_CANARY not in result.stdout + result.stderr
    finally:
        registration_dir.chmod(0o755)


def test_authoritative_marker_write_failure_is_explicitly_fail_closed(fake_boundary, tmp_path: Path) -> None:
    fake_bin, state_path = fake_boundary
    variables = _variables(tmp_path)
    registration_dir = tmp_path / "readonly-authoritative-marker"
    registration_dir.mkdir()
    variables["detection_runner_registration_failed_marker"] = str(
        registration_dir / "runner-registration-failed"
    )
    state = _state(state_path)
    state["registration_failure"] = True
    state_path.write_text(json.dumps(state))
    registration_dir.chmod(0o555)
    try:
        result = _run_include("main", variables, fake_bin, skip_tags=("detection_runner_live_repository",))
        assert result.returncode != 0
        assert not Path(variables["detection_runner_bootstrap_path"]).exists()
        assert not Path(variables["detection_runner_registration_failed_marker"]).exists()
        assert not Path(variables["detection_runner_cleanup_failed_marker"]).exists()
        telemetry = [json.loads(line) for line in Path(variables["detection_runner_registration_log_path"]).read_text().splitlines()]
        assert telemetry[-1]["markers_finalized"] is False
        assert "markers_finalized=False" in result.stdout + result.stderr
        _assert_service_guarded(_state(state_path))
    finally:
        registration_dir.chmod(0o755)
