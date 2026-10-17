"""Offline production-include tests for the range-local GitLab role."""

from __future__ import annotations

import json
import os
import pwd
import re
import stat
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from support import REPOSITORY_ROOT, run_production_include


ROLE = "ludus_detection_gitlab"
CANARY_QUERY = "query-canary-secret"
CANARY_AUTH = "authorization-canary-secret"


def _contract() -> dict:
    """Clearly synthetic selected-version contract, never vendor evidence."""

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


def _readiness_contract() -> dict:
    return {
        "endpoint": "/synthetic-selected-version-readiness",
        "method": "GET",
        "success_statuses": [200],
        "attempts": 3,
        "delay_seconds": 0,
    }


def _log_contract() -> dict:
    return {
        "paths": {"application": "/var/log/gitlab/gitlab-rails/application_json.log"},
        "producer_safe_fields": {
            "access": ["time", "identity", "method", "path", "status"],
            "application": ["time", "severity", "correlation_id", "message"],
        },
        "query_and_auth_excluded": True,
        "unavailable_classes": ["audit"],
    }


@pytest.fixture
def fake_gitlab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state_path = tmp_path / "api-state.json"
    state_path.write_text(json.dumps({
        "next_id": 1, "token_counter": 0, "identities": [], "calls": [],
        "readiness_failures_remaining": 0, "active_pats": [],
    }))
    monkeypatch.setenv("DETECTION_FAKE_GITLAB_STATE", str(state_path))

    (fake_bin / "gitlab-rails").write_text(
        """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p = Path(os.environ['DETECTION_FAKE_GITLAB_STATE']); s = json.loads(p.read_text())
operation = sys.stdin.read()
s.setdefault('rails_calls', []).append({'argv': sys.argv[1:], 'stdin': operation})
failure = s.get('rails_persist_failure')
exclusive_before_pat = operation.index('File.open') < operation.index('personal_access_tokens.create!')
out = Path(os.environ['DETECTION_RUNNER_API_BOOTSTRAP_PATH'])
if failure == 'foreign_appearance':
    out.write_text('foreign-concurrent-revocation-handle'); out.chmod(0o600)
    if exclusive_before_pat:
        p.write_text(json.dumps(s)); raise SystemExit(23)
if failure == 'open' and exclusive_before_pat:
    p.write_text(json.dumps(s)); raise SystemExit(23)
s['token_counter'] += 1; token = f"bootstrap-canary-{s['token_counter']}"
pat = {'token': token, 'expires_on': (__import__('datetime').datetime.now(__import__('datetime').timezone.utc).date() + __import__('datetime').timedelta(days=1)).isoformat()}
s['active_pats'].append(pat)
if failure in {'write', 'fsync', 'replacement_during_failure_cleanup'}:
    out.write_text('partial-' + token); out.chmod(0o600)
if failure:
    if all(marker in operation for marker in ('credential.destroy!', 'file.fsync', 'owned_inode')):
        s['active_pats'].remove(pat)
        if failure == 'replacement_during_failure_cleanup':
            out.unlink()
            out.write_bytes(b'foreign-replacement-revocation-handle')
            out.chmod(0o600)
        if 'File.delete(path)' in operation and out.exists(): out.unlink()
    elif 'File.delete(path)' in operation and out.exists():
        s['active_pats'].remove(pat); out.unlink()
    p.write_text(json.dumps(s)); raise SystemExit(23)
out.write_text(token); out.chmod(0o600)
s.setdefault('bootstrap_tokens', []).append(token)
p.write_text(json.dumps(s))
""", encoding="utf-8")
    (fake_bin / "gitlab-rails").chmod(0o755)

    (fake_bin / "curl").write_text(
        """#!/usr/bin/env python3
import json, os, re, sys
from pathlib import Path
p = Path(os.environ['DETECTION_FAKE_GITLAB_STATE']); s = json.loads(p.read_text())
config = sys.stdin.read()
def value(name, required=True):
    m = re.search(r'^' + re.escape(name) + r' = "(.*)"$', config, re.M)
    if not m and required: raise SystemExit('missing curl config ' + name)
    return m.group(1) if m else None
url, method, output = value('url'), value('request'), value('output', False)
headers = re.findall(r'^header = "(.*)"$', config, re.M)
body = {}
m = re.search(r'^data = "@(.*)"$', config, re.M)
if m: body = json.loads(Path(m.group(1)).read_text())
call = {'url': url, 'method': method, 'headers': headers, 'body': body}
s['calls'].append(call)
if url.endswith('/synthetic-selected-version-readiness'):
    if s['readiness_failures_remaining'] > 0:
        s['readiness_failures_remaining'] -= 1; p.write_text(json.dumps(s)); raise SystemExit(22)
    response = {'ready': True}; sys.stdout.write('200')
else:
    if not any(h.startswith('Authorization: Bearer bootstrap-canary-') for h in headers):
        raise SystemExit('missing Authorization header')
    failure = s.get('fail_' + method.lower())
    if failure: p.write_text(json.dumps(s)); raise SystemExit(22)
    if method == 'GET' and url.endswith('/runners/all'):
        response = s['identities']
    elif method == 'GET' and '/runners/' in url:
        ident_id = int(url.rsplit('/', 1)[1])
        response = s.get('detail_response_override', next(item for item in s['identities'] if item['id'] == ident_id))
    elif method == 'POST':
        ident = {'id': s['next_id'], **body}; s['identities'].append(ident)
        response = {'id': s['next_id'], 'token': f"manager-canary-{s['next_id']}", 'token_expires_at': None}
        response = s.get('create_response_override', response)
        s['next_id'] += 1
    elif method == 'PUT':
        ident_id = int(url.rsplit('/', 1)[1]); ident = next(i for i in s['identities'] if i['id'] == ident_id)
        ident.update(body); response = ident
    else: raise SystemExit('unexpected method/url')
if output: Path(output).write_text(json.dumps(response))
p.write_text(json.dumps(s))
""", encoding="utf-8")
    (fake_bin / "curl").chmod(0o755)
    return fake_bin, state_path


def _variables(tmp_path: Path) -> dict:
    secret_dir = tmp_path / "secrets"
    return {
        "range_id": "synthetic-alpha",
        "detection_gitlab_external_url": "http://gitlab.synthetic.invalid",
        "detection_runner_api_contract": _contract(),
        "detection_gitlab_secret_dir": str(secret_dir),
        "detection_runner_api_bootstrap_path": str(secret_dir / "runner-api-bootstrap.token"),
        "detection_runner_auth_path": str(secret_dir / "runner-auth.token"),
        "detection_gitlab_api_work_dir": str(tmp_path / "api-work"),
        "detection_gitlab_expected_secret_uid": os.getuid(),
        "detection_gitlab_expected_secret_owner": pwd.getpwuid(os.getuid()).pw_name,
    }


def _preflight_variables(tmp_path: Path) -> dict:
    return {
        **_variables(tmp_path),
        "detection_gitlab_packages": [{"name": "gitlab-ce", "version": "99.0.0-ce.0.synthetic"}],
        "detection_gitlab_repository_url": "https://packages.synthetic.invalid/gitlab-ce",
        "detection_gitlab_signing_key_url": "https://packages.synthetic.invalid/key.gpg",
        "detection_gitlab_signing_key_fingerprint": "A" * 40,
        "detection_gitlab_root_password": "synthetic-not-a-real-password",
        "detection_gitlab_log_contract": _log_contract(),
        "detection_gitlab_readiness_contract": _readiness_contract(),
    }


def _run_bootstrap(tmp_path: Path, fake_bin: Path):
    return run_production_include(ROLE, "bootstrap", _variables(tmp_path), fake_bin)


def test_readiness_retries_bounded_verified_endpoint(fake_gitlab, tmp_path: Path) -> None:
    fake_bin, state_path = fake_gitlab
    state = json.loads(state_path.read_text()); state["readiness_failures_remaining"] = 2
    state_path.write_text(json.dumps(state))
    readiness_path = tmp_path / "gitlab-readiness.json"
    result = run_production_include(ROLE, "readiness", {
        "detection_gitlab_external_url": "http://gitlab.synthetic.invalid",
        "detection_gitlab_readiness_contract": _readiness_contract(),
        "detection_gitlab_api_work_dir": str(tmp_path / "ready-work"),
        "detection_gitlab_expected_secret_owner": pwd.getpwuid(os.getuid()).pw_name,
        "detection_gitlab_readiness_path": str(readiness_path),
    }, fake_bin)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = json.loads(state_path.read_text())["calls"]
    assert [(c["method"], c["url"]) for c in calls] == [
        ("GET", "http://gitlab.synthetic.invalid/synthetic-selected-version-readiness")
    ] * 3
    readiness = json.loads(readiness_path.read_text())
    assert readiness == {
        "schema_version": 1,
        "status": "READY",
        "endpoint": "/synthetic-selected-version-readiness",
        "method": "GET",
        "http_status": 200,
        "attempts_used": 3,
    }


def test_readiness_timeout_blocks(fake_gitlab, tmp_path: Path) -> None:
    fake_bin, state_path = fake_gitlab
    state = json.loads(state_path.read_text()); state["readiness_failures_remaining"] = 4
    state_path.write_text(json.dumps(state))
    contract = _readiness_contract(); contract["attempts"] = 2
    readiness_path = tmp_path / "gitlab-readiness.json"
    readiness_path.write_text('{"status":"READY"}')
    result = run_production_include(ROLE, "readiness", {
        "detection_gitlab_external_url": "http://gitlab.synthetic.invalid",
        "detection_gitlab_readiness_contract": contract,
        "detection_gitlab_api_work_dir": str(tmp_path / "ready-work"),
        "detection_gitlab_expected_secret_owner": pwd.getpwuid(os.getuid()).pw_name,
        "detection_gitlab_readiness_path": str(readiness_path),
    }, fake_bin)
    assert result.returncode != 0
    assert len(json.loads(state_path.read_text())["calls"]) == 2
    assert not readiness_path.exists()


def test_main_orders_readiness_before_root_and_bootstrap() -> None:
    main = (REPOSITORY_ROOT / "ansible/roles/ludus_detection_gitlab/tasks/main.yml").read_text()
    assert main.index("readiness.yml") < main.index("Set the fixed isolated-lab root password")
    assert main.index("Set the fixed isolated-lab root password") < main.index("bootstrap.yml")


def test_fresh_scoped_date_limited_credential_and_created_identity_detail(tmp_path, fake_gitlab) -> None:
    fake_bin, state_path = fake_gitlab
    result = _run_bootstrap(tmp_path, fake_bin)
    assert result.returncode == 0, result.stdout + result.stderr
    state = json.loads(state_path.read_text())
    rails = state["rails_calls"][0]
    assert rails["argv"] == ["runner", "-"]
    assert "Time.now.utc.to_date + 1" in rails["stdin"]
    assert "%i[synthetic_create_runner synthetic_manage_runner]" in rails["stdin"]
    assert "File::EXCL" in rails["stdin"]
    assert "file.flush" in rails["stdin"] and "file.fsync" in rails["stdin"]
    assert "credential.destroy!" in rails["stdin"]
    assert rails["stdin"].index("File.open") < rails["stdin"].index("personal_access_tokens.create!")
    assert "File.delete(path)" not in rails["stdin"]
    assert "bootstrap-canary" not in result.stdout + result.stderr
    assert [(c["method"], c["url"].rsplit("/", 1)[-1]) for c in state["calls"]] == [
        ("GET", "all"), ("POST", "runners"), ("GET", "1")
    ]
    assert Path(_variables(tmp_path)["detection_runner_auth_path"]).read_text() == "manager-canary-1"
    assert state["identities"] == [{
        "id": 1, "runner_type": "instance_type", "description": "synthetic-alpha-runner", "paused": True,
    }]
    assert state["active_pats"] == [{
        "token": "bootstrap-canary-1",
        "expires_on": (datetime.now(UTC).date() + timedelta(days=1)).isoformat(),
    }]
    assert list(Path(_variables(tmp_path)["detection_gitlab_api_work_dir"]).glob("*.json")) == []


@pytest.mark.parametrize("failure", ["fail_get", "fail_post", "fail_put"])
def test_api_lookup_creation_and_update_fail_closed_and_clean_transients(tmp_path, fake_gitlab, failure) -> None:
    fake_bin, state_path = fake_gitlab
    state = json.loads(state_path.read_text())
    if failure == "fail_put":
        state["identities"] = [{
            "id": 9, "runner_type": "instance_type", "description": "synthetic-alpha-runner", "paused": False,
        }]
        variables = _variables(tmp_path); manager = Path(variables["detection_runner_auth_path"])
        manager.parent.mkdir(); manager.write_text("stable-existing-token"); manager.chmod(0o600)
    state[failure] = True; state_path.write_text(json.dumps(state))
    result = _run_bootstrap(tmp_path, fake_bin)
    assert result.returncode != 0
    assert list(Path(_variables(tmp_path)["detection_gitlab_api_work_dir"]).glob("*.json")) == []


@pytest.mark.parametrize("override", [
    {"id": 1, "token": "manager-canary-1"},
    {"id": "1", "token": "manager-canary-1", "token_expires_at": None},
])
def test_malformed_create_response_never_persists_manager_token(tmp_path, fake_gitlab, override) -> None:
    fake_bin, state_path = fake_gitlab
    state = json.loads(state_path.read_text()); state["create_response_override"] = override
    state_path.write_text(json.dumps(state))
    assert _run_bootstrap(tmp_path, fake_bin).returncode != 0
    assert not Path(_variables(tmp_path)["detection_runner_auth_path"]).exists()


def test_created_identity_detail_mismatch_never_persists_manager_token(tmp_path, fake_gitlab) -> None:
    fake_bin, state_path = fake_gitlab
    state = json.loads(state_path.read_text()); state["detail_response_override"] = {
        "id": 1, "runner_type": "instance_type", "description": "wrong-runner", "paused": True,
    }
    state_path.write_text(json.dumps(state))
    assert _run_bootstrap(tmp_path, fake_bin).returncode != 0
    assert not Path(_variables(tmp_path)["detection_runner_auth_path"]).exists()


def test_duplicate_identity_lookup_is_rejected(tmp_path, fake_gitlab) -> None:
    fake_bin, state_path = fake_gitlab
    state = json.loads(state_path.read_text()); state["identities"] = [
        {"id": n, "runner_type": "instance_type", "description": "synthetic-alpha-runner", "paused": True}
        for n in (3, 4)
    ]; state_path.write_text(json.dumps(state))
    assert _run_bootstrap(tmp_path, fake_bin).returncode != 0
    assert not any(c["method"] == "POST" for c in json.loads(state_path.read_text())["calls"])


@pytest.mark.parametrize("failure", ["open", "write", "fsync"])
def test_pat_persistence_failure_rolls_back_only_newly_created_pat(tmp_path, fake_gitlab, failure) -> None:
    fake_bin, state_path = fake_gitlab
    preserved = {"token": "preexisting-unrelated-pat", "expires_on": "2099-01-01"}
    state = json.loads(state_path.read_text()); state["rails_persist_failure"] = failure
    state["active_pats"] = [preserved]
    state_path.write_text(json.dumps(state))
    assert _run_bootstrap(tmp_path, fake_bin).returncode != 0
    state = json.loads(state_path.read_text())
    assert state["token_counter"] == (0 if failure == "open" else 1)
    assert state["active_pats"] == [preserved]
    handle = Path(_variables(tmp_path)["detection_runner_api_bootstrap_path"])
    if failure == "open":
        assert not handle.exists()
    else:
        assert handle.read_bytes() == b"partial-bootstrap-canary-1"
        assert stat.S_IMODE(handle.stat().st_mode) == 0o600
        retry = _run_bootstrap(tmp_path, fake_bin)
        assert retry.returncode != 0
        assert handle.read_bytes() == b"partial-bootstrap-canary-1"
        assert json.loads(state_path.read_text())["active_pats"] == [preserved]


def test_replacement_during_persistence_failure_cleanup_is_never_unlinked(tmp_path, fake_gitlab) -> None:
    fake_bin, state_path = fake_gitlab
    preserved = {"token": "preexisting-unrelated-pat", "expires_on": "2099-01-01"}
    state = json.loads(state_path.read_text())
    state["rails_persist_failure"] = "replacement_during_failure_cleanup"
    state["active_pats"] = [preserved]
    state_path.write_text(json.dumps(state))

    assert _run_bootstrap(tmp_path, fake_bin).returncode != 0
    state = json.loads(state_path.read_text())
    assert state["token_counter"] == 1
    assert state["active_pats"] == [preserved]
    handle = Path(_variables(tmp_path)["detection_runner_api_bootstrap_path"])
    assert handle.read_bytes() == b"foreign-replacement-revocation-handle"
    retry = _run_bootstrap(tmp_path, fake_bin)
    assert retry.returncode != 0
    assert handle.read_bytes() == b"foreign-replacement-revocation-handle"
    assert json.loads(state_path.read_text())["active_pats"] == [preserved]


def test_concurrent_foreign_handle_is_preserved_without_new_pat_orphan(tmp_path, fake_gitlab) -> None:
    fake_bin, state_path = fake_gitlab
    preserved = {"token": "preexisting-unrelated-pat", "expires_on": "2099-01-01"}
    state = json.loads(state_path.read_text())
    state["rails_persist_failure"] = "foreign_appearance"
    state["active_pats"] = [preserved]
    state_path.write_text(json.dumps(state))

    assert _run_bootstrap(tmp_path, fake_bin).returncode != 0
    state = json.loads(state_path.read_text())
    assert state["token_counter"] == 0
    assert state["active_pats"] == [preserved]
    handle = Path(_variables(tmp_path)["detection_runner_api_bootstrap_path"])
    assert handle.read_bytes() == b"foreign-concurrent-revocation-handle"


@pytest.mark.parametrize("scopes", [
    ["synthetic_create_runner", "synthetic_manage_runner", "synthetic_extra_scope"],
    ["synthetic_create_runner", "synthetic_create_runner"],
])
def test_nonexact_or_duplicate_bootstrap_scopes_are_rejected_before_mint(tmp_path, fake_gitlab, scopes) -> None:
    fake_bin, state_path = fake_gitlab
    variables = _variables(tmp_path)
    variables["detection_runner_api_contract"]["bootstrap_auth"]["scopes"] = scopes
    result = run_production_include(ROLE, "bootstrap", variables, fake_bin)
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["active_pats"] == []


@pytest.mark.parametrize("mutation", [
    "missing_classification", "duplicate_unavailable", "field_key_mismatch",
    "missing_statuses", "empty_statuses", "duplicate_statuses",
])
def test_preflight_reuses_exhaustive_log_and_readiness_validation(tmp_path, fake_gitlab, mutation) -> None:
    fake_bin, _ = fake_gitlab; variables = _preflight_variables(tmp_path)
    if mutation == "missing_classification":
        variables["detection_gitlab_log_contract"]["unavailable_classes"] = []
    elif mutation == "duplicate_unavailable":
        variables["detection_gitlab_log_contract"]["unavailable_classes"] = ["audit", "audit"]
    elif mutation == "field_key_mismatch":
        variables["detection_gitlab_log_contract"]["producer_safe_fields"]["audit"] = ["time"]
    elif mutation == "missing_statuses":
        variables["detection_gitlab_readiness_contract"].pop("success_statuses")
    elif mutation == "empty_statuses":
        variables["detection_gitlab_readiness_contract"]["success_statuses"] = []
    else:
        variables["detection_gitlab_readiness_contract"]["success_statuses"] = [200, 200]
    assert run_production_include(ROLE, "preflight", variables, fake_bin).returncode != 0


def test_real_main_stops_malformed_contract_before_install_or_mutation(tmp_path, fake_gitlab) -> None:
    fake_bin, state_path = fake_gitlab; variables = _preflight_variables(tmp_path)
    variables["detection_gitlab_readiness_contract"]["success_statuses"] = [200, 200]
    result = run_production_include(ROLE, "main", variables, fake_bin)
    assert result.returncode != 0
    assert "Install prerequisites for the verified GitLab repository" not in result.stdout
    state = json.loads(state_path.read_text())
    assert state.get("rails_calls", []) == []
    assert state["calls"] == []


def test_cleanup_pending_bootstrap_handle_is_preserved_and_refuses_remint(tmp_path, fake_gitlab) -> None:
    fake_bin, state_path = fake_gitlab
    state = json.loads(state_path.read_text())
    state["active_pats"] = [{"token": "unrevoked-bootstrap-handle", "expires_on": "2099-01-01"}]
    state_path.write_text(json.dumps(state))
    variables = _variables(tmp_path); path = Path(variables["detection_runner_api_bootstrap_path"])
    path.parent.mkdir(); path.write_text("unrevoked-bootstrap-handle"); path.chmod(0o600)
    result = _run_bootstrap(tmp_path, fake_bin)
    assert result.returncode != 0
    assert path.read_text() == "unrevoked-bootstrap-handle"
    state = json.loads(state_path.read_text())
    assert state.get("rails_calls", []) == []
    assert state["active_pats"] == [{"token": "unrevoked-bootstrap-handle", "expires_on": "2099-01-01"}]


def test_retry_after_task6_cleanup_preserves_identity_and_manager_token(tmp_path, fake_gitlab) -> None:
    fake_bin, state_path = fake_gitlab
    assert _run_bootstrap(tmp_path, fake_bin).returncode == 0
    variables = _variables(tmp_path); manager = Path(variables["detection_runner_auth_path"])
    stable = manager.read_bytes()
    Path(variables["detection_runner_api_bootstrap_path"]).unlink()  # models Task 6 revoke+cleanup
    state = json.loads(state_path.read_text()); state["identities"][0]["paused"] = False
    state["active_pats"] = []  # models Task 6 revocation before protected-handle deletion
    state_path.write_text(json.dumps(state))
    second = _run_bootstrap(tmp_path, fake_bin)
    assert second.returncode == 0, second.stdout + second.stderr
    state = json.loads(state_path.read_text())
    assert len(state["identities"]) == 1
    assert len([c for c in state["calls"] if c["method"] == "POST"]) == 1
    assert state["identities"][0]["paused"] is True
    assert manager.read_bytes() == stable
    assert state["active_pats"] == [{
        "token": "bootstrap-canary-2",
        "expires_on": (datetime.now(UTC).date() + timedelta(days=1)).isoformat(),
    }]


@pytest.mark.parametrize("mutation", ["missing_application", "missing_audit", "conflicting_audit", "unknown_class"])
def test_application_and_audit_classes_are_totally_exclusively_classified(tmp_path, fake_gitlab, mutation) -> None:
    fake_bin, _ = fake_gitlab; contract = _log_contract()
    if mutation == "missing_application":
        contract["paths"].pop("application")
    elif mutation == "missing_audit":
        contract["unavailable_classes"] = []
    elif mutation == "conflicting_audit":
        contract["paths"]["audit"] = "/var/log/gitlab/audit.log"
        contract["producer_safe_fields"]["audit"] = ["time", "message"]
    else:
        contract["unavailable_classes"].append("mystery")
    result = run_production_include(ROLE, "configure", {
        "detection_gitlab_log_contract": contract,
        "detection_gitlab_nginx_config_path": str(tmp_path / "unused.conf"),
        "detection_gitlab_config_path": str(tmp_path / "gitlab.rb"),
        "detection_gitlab_capability_path": str(tmp_path / "capability.json"),
        "detection_gitlab_external_url": "http://gitlab.synthetic.invalid",
        "detection_gitlab_apply_reconfigure": False,
    }, fake_bin)
    assert result.returncode != 0


def test_effective_gitlab_rb_transforms_canary_request_to_safe_useful_event(tmp_path, fake_gitlab) -> None:
    fake_bin, _ = fake_gitlab; gitlab_rb = tmp_path / "gitlab.rb"; capability = tmp_path / "capability.json"
    result = run_production_include(ROLE, "configure", {
        "detection_gitlab_log_contract": _log_contract(),
        "detection_gitlab_nginx_config_path": str(tmp_path / "format-reference.conf"),
        "detection_gitlab_config_path": str(gitlab_rb),
        "detection_gitlab_capability_path": str(capability),
        "detection_gitlab_external_url": "http://gitlab.synthetic.invalid",
        "detection_gitlab_apply_reconfigure": False,
    }, fake_bin)
    assert result.returncode == 0, result.stdout + result.stderr
    rendered = gitlab_rb.read_text()
    match = re.search(r"nginx\['log_format'\] = (\".*\")", rendered)
    assert match
    log_format = json.loads(match.group(1))
    request = {
        "$time_iso8601": "2026-10-17T12:00:00+00:00", "$remote_addr": "10.10.10.44",
        "$request_method": "GET", "$uri": "/safe/path",
        "$request_uri": f"/safe/path?secret={CANARY_QUERY}", "$status": "204",
        "$http_authorization": f"Bearer {CANARY_AUTH}",
    }
    event = log_format
    for variable, value in request.items():
        event = event.replace(variable, value)
    assert event == (
        "time=2026-10-17T12:00:00+00:00 identity=10.10.10.44 "
        "method=GET path=/safe/path status=204"
    )
    assert CANARY_QUERY not in event and CANARY_AUTH not in event
    facts = json.loads(capability.read_text())
    assert facts["available"]["application"].endswith("application_json.log")
    assert facts["unavailable"] == ["audit"]


@pytest.mark.parametrize("gpg_output", [
    "pub:u:2048:1:AAA:0:0::::::\nfpr:::::::::EXPECTED:\npub:u:2048:1:BBB:0:0::::::\nfpr:::::::::EXTRA:\n",
    "pub:u:2048:1:AAA:0:0::::::\nfpr:::::::::OTHER:\nsub:u:2048:1:BBB:0:0::::::\nfpr:::::::::EXPECTED:\n",
])
def test_signing_key_rejects_bundle_and_subkey_only_match(tmp_path, monkeypatch, gpg_output) -> None:
    fake_bin = tmp_path / "bin"; fake_bin.mkdir(); monkeypatch.setenv("FAKE_GPG_OUTPUT", gpg_output)
    (fake_bin / "gpg").write_text("""#!/usr/bin/env python3
import os, sys
if '--show-keys' in sys.argv: print(os.environ['FAKE_GPG_OUTPUT'], end='')
else: raise SystemExit('dearmor must not run after failed identity validation')
"""); (fake_bin / "gpg").chmod(0o755)
    key = tmp_path / "key.asc"; key.write_text("synthetic key material")
    result = run_production_include(ROLE, "verify_signing_key", {
        "detection_gitlab_key_download_path": str(key),
        "detection_gitlab_keyring_path": str(tmp_path / "key.gpg"),
        "detection_gitlab_signing_key_fingerprint": "EXPECTED",
        "detection_gitlab_key_verifier_path": str(tmp_path / "verify.py"),
    }, fake_bin)
    assert result.returncode != 0


def test_signing_key_accepts_only_exact_single_primary(tmp_path, monkeypatch) -> None:
    fake_bin = tmp_path / "bin"; fake_bin.mkdir()
    monkeypatch.setenv("FAKE_GPG_OUTPUT", "pub:u:2048:1:AAA:0:0::::::\nfpr:::::::::EXPECTED:\nsub:u:2048:1:BBB:0:0::::::\nfpr:::::::::SUBKEY:\n")
    (fake_bin / "gpg").write_text("""#!/usr/bin/env python3
import os, shutil, sys
if '--show-keys' in sys.argv: print(os.environ['FAKE_GPG_OUTPUT'], end='')
else:
    out = sys.argv[sys.argv.index('--output') + 1]; shutil.copyfile(sys.argv[-1], out)
"""); (fake_bin / "gpg").chmod(0o755)
    key = tmp_path / "key.asc"; key.write_text("one synthetic primary and its subkey")
    keyring = tmp_path / "key.gpg"
    result = run_production_include(ROLE, "verify_signing_key", {
        "detection_gitlab_key_download_path": str(key),
        "detection_gitlab_keyring_path": str(keyring),
        "detection_gitlab_signing_key_fingerprint": "EXPECTED",
        "detection_gitlab_key_verifier_path": str(tmp_path / "verify.py"),
    }, fake_bin)
    assert result.returncode == 0, result.stdout + result.stderr
    assert keyring.read_text() == key.read_text()


def test_install_source_uses_detected_distribution_suite() -> None:
    install = (REPOSITORY_ROOT / "ansible/roles/ludus_detection_gitlab/tasks/install.yml").read_text()
    assert "ansible_distribution_release" in install
