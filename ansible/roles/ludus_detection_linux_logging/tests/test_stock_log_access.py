from __future__ import annotations

import importlib.util
import itertools
import json
from dataclasses import replace
import errno
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace

import pytest

from stock_access_model import FileFacts, Identity, ModelHost, ProducerObservation, snapshot


REPO = Path(__file__).resolve().parents[4]
HELPER_PATH = Path(__file__).parents[1] / "files/configure_stock_log_access.py"
PROFILE = Path(__file__).parents[1] / "files/stock-log-profiles/bookworm"
REFERENCES = REPO / ".superpowers/sdd/2026-10-18-stock-log-access/reference-inputs"


def load_helper():
    spec = importlib.util.spec_from_file_location("configure_stock_log_access", HELPER_PATH)
    assert spec is not None and spec.loader is not None, "production helper scaffold is missing"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_root(tmp_path: Path, reader: str = "splunkfwd", generated: bool = False):
    root = tmp_path / "root"
    mapping = {
        "rsyslog.conf.txt": "etc/rsyslog.conf",
        "logrotate.conf.txt": "etc/logrotate.conf",
        "rsyslog.logrotate.txt": "etc/logrotate.d/rsyslog",
        "rsyslog-rotate.txt": "usr/lib/rsyslog/rsyslog-rotate",
    }
    for source, target in mapping.items():
        destination = root / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((REFERENCES / source).read_bytes())
    (root / "etc/rsyslog.d").mkdir(parents=True)
    (root / "var/log").mkdir(parents=True)
    (root / "var/lib").mkdir(parents=True)
    (root / "var/log/auth.log").write_bytes(b"auth-canary\n")
    (root / "var/log/syslog").write_bytes(b"syslog-canary\n")
    (root / "var/log/auth.log.1").write_bytes(b"old-auth\n")
    (root / "var/log/unrelated.log").write_bytes(b"unrelated\n")
    host = ModelHost(root, reader)
    for logical in mapping.values():
        host.add_file("/" + logical, gid=0 if logical != "etc/rsyslog.conf" else 0)
    host.add_file("/var/log/auth.log")
    host.add_file("/var/log/syslog")
    if generated:
        helper = load_helper()
        (root / "etc/rsyslog.conf").write_bytes(helper.render_candidate((root / "etc/rsyslog.conf").read_bytes(), reader))
    return root, host


def invoke(root: Path, host: ModelHost, reader: str = "splunkfwd", helper=None):
    helper = load_helper() if helper is None else helper
    argv = helper_argv(root, reader)
    result = helper.run(argv, host=host)
    assert set(result) >= {"changed", "stage", "changed_paths", "producer_active"}
    return result


def helper_argv(root: Path, reader: str = "splunkfwd"):
    return [
        "--root", str(root), "--reader", reader, "--profile-dir", str(PROFILE),
        "--dpkg-query", "/usr/bin/dpkg-query", "--getent", "/usr/bin/getent",
        "--systemctl", "/usr/bin/systemctl", "--rsyslogd", "/usr/sbin/rsyslogd",
        "--runuser", "/usr/sbin/runuser",
    ]


def invoke_main_json(helper, root: Path, host: ModelHost, capsys, reader: str = "splunkfwd"):
    code = helper.main(helper_argv(root, reader), host=host)
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    return code, json.loads(lines[0])


@pytest.mark.parametrize("reader", ["splunkfwd", "splunk"])
def test_candidate_preserves_original_actions_and_unrelated_bytes(tmp_path, reader):
    helper = load_helper()
    original = (REFERENCES / "rsyslog.conf.txt").read_bytes()
    candidate = helper.render_candidate(original, reader)
    assert candidate.count(f"$FileGroup {reader}\n".encode()) == 2
    assert candidate.count(b"$FileGroup adm\n") == 3  # stock default plus two restores
    for selector in [b"*.*;auth,authpriv.none\t\t-/var/log/syslog\n", b"auth,authpriv.*\t\t\t/var/log/auth.log\n"]:
        assert selector in candidate
    stripped = candidate
    for selector in [b"*.*;auth,authpriv.none\t\t-/var/log/syslog\n", b"auth,authpriv.*\t\t\t/var/log/auth.log\n"]:
        stripped = stripped.replace(
            f"$FileGroup {reader}\n".encode() + selector + b"$FileGroup adm\n",
            selector,
        )
    assert stripped == original
    assert helper.render_candidate(candidate, reader) == candidate
    other = "splunk" if reader == "splunkfwd" else "splunkfwd"
    with pytest.raises(helper.PolicyError):
        helper.render_candidate(candidate, other)


def test_profile_rejects_unknown_effective_inputs(tmp_path):
    helper = load_helper()
    root, host = make_root(tmp_path)
    assert helper.validate_profile(root, PROFILE).source_kind == "original"
    optional = ["apt", "dpkg", "alternatives", "btmp", "wtmp"]
    for mask in range(1 << len(optional)):
        case = tmp_path / f"optional-{mask}"
        shutil.copytree(root, case)
        for bit, name in enumerate(optional):
            if mask & (1 << bit):
                shutil.copyfile(PROFILE / f"logrotate.{name}", case / "etc/logrotate.d" / name)
        assert helper.validate_profile(case, PROFILE).source_kind == "original"
    mutations = []
    for target in ["etc/rsyslog.conf", "etc/logrotate.conf", "etc/logrotate.d/rsyslog", "usr/lib/rsyslog/rsyslog-rotate"]:
        mutations.append((target, None))
        mutations.append((target, b"changed\n"))
    mutations += [
        ("etc/logrotate.d/apt", b"changed-known-optional\n"),
        ("etc/rsyslog.d/unknown.conf", b"action(type=\"omfile\" file=\"/tmp/x\")\n"),
        ("etc/logrotate.d/unknown", b"/tmp/x {}\n"),
        ("etc/logrotate.d/nested/x", b"/tmp/x {}\n"),
    ]
    for number, (target, content) in enumerate(mutations):
        case = tmp_path / f"reject-{number}"
        shutil.copytree(root, case)
        path = case / target
        if content is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        with pytest.raises(helper.PolicyError):
            helper.validate_profile(case, PROFILE)


def test_application_accepts_all_exact_optional_rotation_fragments(tmp_path):
    root, host = make_root(tmp_path)
    for name in ["apt", "dpkg", "alternatives", "btmp", "wtmp"]:
        target = root / "etc/logrotate.d" / name
        shutil.copyfile(PROFILE / f"logrotate.{name}", target)
        host.add_file(f"/etc/logrotate.d/{name}", gid=0)
    assert invoke(root, host)["stage"] == "complete"


@pytest.mark.parametrize("tamper", [
    "rehashed_bundle", "traversal", "mapping", "extra_entry", "duplicate_entry", "extra_field",
])
def test_profile_manifest_is_pinned_before_manifest_defined_policy(tmp_path, tamper):
    helper = load_helper()
    profile = tmp_path / "profile"
    shutil.copytree(PROFILE, profile)
    manifest = json.loads((profile / "manifest.json").read_text())
    if tamper == "rehashed_bundle":
        changed = (profile / "rsyslog.conf").read_bytes() + b"# malicious\n"
        (profile / "rsyslog.conf").write_bytes(changed)
        import hashlib
        manifest["required"][0]["sha256"] = hashlib.sha256(changed).hexdigest()
    elif tamper == "traversal":
        escaped = profile.parent / "escaped"
        escaped.write_bytes((profile / "rsyslog.conf").read_bytes())
        manifest["required"][0]["bundle"] = "../escaped"
    elif tamper == "mapping":
        manifest["required"][0]["target"] = "/etc/not-rsyslog.conf"
    elif tamper == "extra_entry":
        manifest["optional_rotation"].append(dict(manifest["optional_rotation"][0]))
        manifest["optional_rotation"][-1]["target"] = "/etc/logrotate.d/extra"
    elif tamper == "duplicate_entry":
        manifest["required"].append(dict(manifest["required"][0]))
    elif tamper == "extra_field":
        manifest["policy"] = "caller-controlled"
    (profile / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(helper.PolicyError):
        helper._load_manifest(profile)


@pytest.mark.parametrize("defect", [
    "missing_user", "alias_root", "alias_adm", "missing_source", "wrong_mode", "wrong_owner",
    "wrong_group", "symlink", "hardlink", "shared_inode", "acl", "untrusted_parent",
    "validator_missing", "validator_invalid", "producer_inactive", "producer_unknown", "snapshot_change",
])
def test_preflight_preserves_operational_state(tmp_path, defect):
    root, host = make_root(tmp_path)
    reader = "splunkfwd"
    if defect == "missing_user": host.users.pop(reader)
    elif defect == "alias_root": host.users[reader] = Identity(reader, 0, 0)
    elif defect == "alias_adm": host.groups[reader] = Identity(reader, 2201, 4)
    elif defect == "missing_source": host.files.pop("/var/log/auth.log"); (root / "var/log/auth.log").unlink()
    elif defect == "wrong_mode": host.files["/var/log/auth.log"] = FileFacts(mode=0o644)
    elif defect == "wrong_owner": host.files["/var/log/auth.log"] = FileFacts(uid=1)
    elif defect == "wrong_group": host.files["/var/log/auth.log"] = FileFacts(gid=99)
    elif defect == "symlink": host.files["/var/log/auth.log"] = FileFacts(regular=False, symlink=True)
    elif defect == "hardlink": host.files["/var/log/auth.log"] = FileFacts(nlink=2)
    elif defect == "shared_inode": host.files["/var/log/syslog"] = FileFacts(ino=host.files["/var/log/auth.log"].ino)
    elif defect == "acl": host.files["/var/log/auth.log"] = FileFacts(extended_acl=True)
    elif defect == "untrusted_parent": host.files["/var/log/auth.log"] = FileFacts(trusted_parents=False)
    elif defect == "validator_missing": host.validator_available = False
    elif defect == "validator_invalid": host.validator_accepts = False
    elif defect == "producer_inactive": host.producer = ProducerObservation(False, False)
    elif defect == "producer_unknown": host.observation_error = True
    elif defect == "snapshot_change":
        host.callbacks[("snapshot_recheck", "before")] = lambda: (
            root / "etc/rsyslog.conf"
        ).write_bytes((root / "etc/rsyslog.conf").read_bytes() + b"# concurrent change\n")
    before = snapshot(root, host)
    result = invoke(root, host)
    assert result["stage"] != "complete"
    after = snapshot(root, host)
    if defect == "snapshot_change":
        assert after["bytes"]["etc/rsyslog.conf"] != before["bytes"]["etc/rsyslog.conf"]
        after["bytes"].pop("etc/rsyslog.conf")
        before["bytes"].pop("etc/rsyslog.conf")
    assert after == before
    assert not any(op.startswith(("group:", "publish:", "restart")) for op in host.operations)
    assert not (root / "var/lib/detection-engineering/stock-log-access/applied.json").exists()


@pytest.mark.parametrize("defect,expected", [
    ("configured_argv", None), ("alternate_f", None), ("running_argv", None), ("wrapper", None),
    ("multiple", None), ("unrecognized", None), ("override", None), ("root", None),
    ("mount", None), ("query", None), ("transition", None), ("identity_change", None),
    ("inactive", False), ("failed", False),
])
def test_producer_observation_binds_config_and_restart(tmp_path, defect, expected):
    root, host = make_root(tmp_path)
    if defect == "configured_argv": host.configured_argv[-1] = "-iNONE2"
    elif defect == "alternate_f": host.configured_argv += ["-f", "/etc/other.conf"]
    elif defect == "running_argv": host.running_argv[-1] = "-iNONE2"
    elif defect == "wrapper": host.running_executable = "/bin/sh"
    elif defect == "multiple": host.command_records = 2
    elif defect == "unrecognized": host.command_record_recognized = False
    elif defect == "override": host.drop_ins = ["/etc/systemd/system/rsyslog.service.d/x.conf"]
    elif defect == "root": host.root_directory = "/srv/chroot"
    elif defect == "mount": host.mount_matches = False
    elif defect == "query": host.observation_error = True
    elif defect == "transition": host.observation_transition = True
    elif defect == "identity_change":
        host.observation_sequence = [
            ProducerObservation(True, True, 410, "410:9001"),
            ProducerObservation(True, True, 411, "411:9002"),
        ]
    elif defect in {"inactive", "failed"}: host.producer = ProducerObservation(False, False)
    result = invoke(root, host)
    assert result["producer_active"] is expected
    assert result["stage"] != "complete"
    assert not any(op.startswith(("group:", "publish:", "restart")) for op in host.operations)


@pytest.mark.parametrize("restart_observation", [True, False, None])
def test_unknown_restart_state_requires_fresh_active_preflight(tmp_path, restart_observation):
    root, host = make_root(tmp_path)
    host.restart_result = False
    host.restart_observation = restart_observation
    first = invoke(root, host)
    assert first["stage"] == "restart"
    assert first["producer_active"] is restart_observation
    marker = root / "var/lib/detection-engineering/stock-log-access/applied.json"
    assert not marker.exists()
    restarts = host.operations.count("restart")
    host.restart_result = True
    host.producer = ProducerObservation(restart_observation, restart_observation is True)
    second = invoke(root, host)
    if restart_observation is not True:
        assert second["stage"] == "preflight"
        assert host.operations.count("restart") == restarts
    host.producer = ProducerObservation(True, True)
    third = invoke(root, host)
    assert third["stage"] == "complete"
    assert marker.exists()


@pytest.mark.parametrize("reader", ["splunkfwd", "splunk"])
@pytest.mark.parametrize("operation,when", list(itertools.product(
    ["invalidate_applied", "group_auth", "group_syslog", "publish_config", "restart", "write_applied"],
    ["before", "after"],
)))
def test_apply_and_recover_partial_states(tmp_path, reader, operation, when):
    root, host = make_root(tmp_path, reader)
    before_bytes = snapshot(root, host)["bytes"]
    host.fail_once(operation, when)
    failed = invoke(root, host, reader)
    assert failed["stage"] == operation
    assert failed["changed"] == bool(failed["changed_paths"])
    assert host.consumer_running
    current = snapshot(root, host)["bytes"]
    for preserved in ["var/log/auth.log", "var/log/syslog", "var/log/auth.log.1", "var/log/unrelated.log", "etc/logrotate.conf", "etc/logrotate.d/rsyslog"]:
        assert current[preserved] == before_bytes[preserved]
    host.producer = ProducerObservation(True, True)
    recovered = invoke(root, host, reader)
    assert recovered["stage"] == "complete"
    assert host.files["/var/log/auth.log"].gid == host.groups[reader].gid
    assert host.files["/var/log/syslog"].gid == host.groups[reader].gid
    operations = list(host.operations)
    converged = invoke(root, host, reader)
    assert converged == {"changed": False, "stage": "complete", "changed_paths": [], "producer_active": True}
    assert host.operations.count("restart") == operations.count("restart")


def test_valid_digest_metadata_only_repair_does_not_restart(tmp_path):
    root, host = make_root(tmp_path)
    assert invoke(root, host)["stage"] == "complete"
    host.files["/var/log/auth.log"] = FileFacts(gid=4, ino=host.files["/var/log/auth.log"].ino)
    restart_count = host.operations.count("restart")
    result = invoke(root, host)
    assert result["stage"] == "complete"
    assert host.operations.count("restart") == restart_count
    assert result["changed_paths"] == [
        "/var/lib/detection-engineering/stock-log-access/applied.json",
        "/var/log/auth.log",
    ]


def test_reapplication_invalidates_stale_digest_before_failed_restart(tmp_path):
    root, host = make_root(tmp_path)
    assert invoke(root, host)["stage"] == "complete"
    marker = root / "var/lib/detection-engineering/stock-log-access/applied.json"
    assert marker.is_file()
    (root / "etc/rsyslog.conf").write_bytes((PROFILE / "rsyslog.conf").read_bytes())
    host.restart_result = False
    host.restart_observation = True
    failed = invoke(root, host)
    assert failed["stage"] == "restart"
    assert failed["producer_active"] is True
    assert not marker.exists(), "failed reapplication retained an authoritative digest"


def test_marker_invalidation_directory_fsync_precedes_operational_mutation_and_retries(tmp_path, monkeypatch):
    helper = load_helper()
    root, host = make_root(tmp_path)
    assert invoke(root, host, helper=helper)["stage"] == "complete"
    marker = root / "var/lib/detection-engineering/stock-log-access/applied.json"
    assert marker.is_file()
    original = (PROFILE / "rsyslog.conf").read_bytes()
    (root / "etc/rsyslog.conf").write_bytes(original)
    baseline_gids = {path: host.files[path].gid for path in ["/var/log/auth.log", "/var/log/syslog"]}
    restart_count = host.operations.count("restart")
    real_fsync = helper.os.fsync
    failures = 2
    state_sync_calls = 0
    def fail_state_directory_fsync(fd):
        nonlocal failures, state_sync_calls
        info = helper.os.fstat(fd)
        if stat.S_ISDIR(info.st_mode) and helper.os.readlink(f"/proc/self/fd/{fd}").endswith("/stock-log-access"):
            state_sync_calls += 1
            if failures:
                failures -= 1
                raise OSError(errno.EIO, "injected state directory fsync failure")
        return real_fsync(fd)
    monkeypatch.setattr(helper.os, "fsync", fail_state_directory_fsync)
    first = invoke(root, host, helper=helper)
    assert first["stage"] == "invalidate_applied"
    assert first["changed_paths"] == ["/var/lib/detection-engineering/stock-log-access/applied.json"]
    assert not marker.exists()
    assert (root / "etc/rsyslog.conf").read_bytes() == original
    assert {path: host.files[path].gid for path in baseline_gids} == baseline_gids
    assert host.operations.count("restart") == restart_count
    second = invoke(root, host, helper=helper)
    assert second["stage"] == "invalidate_applied"
    assert second["changed_paths"] == []
    assert (root / "etc/rsyslog.conf").read_bytes() == original
    assert {path: host.files[path].gid for path in baseline_gids} == baseline_gids
    assert host.operations.count("restart") == restart_count
    assert state_sync_calls == 2
    recovered = invoke(root, host, helper=helper)
    assert recovered["stage"] == "complete"
    assert state_sync_calls >= 3


@pytest.mark.parametrize("defect", [
    "state_dir_symlink", "private_parent_symlink", "private_parent_mode", "state_dir_mode",
    "state_dir_owner", "lock_symlink", "lock_mode", "lock_hardlink", "lock_owner",
    "marker_symlink", "marker_mode", "marker_hardlink", "marker_owner",
])
def test_private_state_refuses_unsafe_existing_paths_without_following(tmp_path, defect):
    root, host = make_root(tmp_path)
    private_parent = root / "var/lib/detection-engineering"
    state_dir = private_parent / "stock-log-access"
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o755)
    victim_file = tmp_path / "victim-file"
    victim_file.write_text("do-not-touch")
    victim_file.chmod(0o644)
    if defect == "private_parent_symlink":
        private_parent.parent.mkdir(parents=True, exist_ok=True)
        private_parent.symlink_to(victim, target_is_directory=True)
    else:
        private_parent.mkdir(parents=True, exist_ok=True)
        private_parent.chmod(0o755 if defect == "private_parent_mode" else 0o700)
        if defect == "state_dir_symlink": state_dir.symlink_to(victim, target_is_directory=True)
        else: state_dir.mkdir(mode=0o700)
    if defect == "state_dir_mode": state_dir.chmod(0o755)
    if defect == "state_dir_owner": host.state_uid_overrides["/var/lib/detection-engineering/stock-log-access"] = 99
    if defect.startswith("lock_"):
        lock = state_dir / "lock"
        if defect == "lock_symlink": lock.symlink_to(victim_file)
        elif defect == "lock_hardlink": lock.hardlink_to(victim_file)
        else: lock.write_bytes(b"")
        if defect == "lock_mode": lock.chmod(0o644)
        if defect == "lock_owner": host.state_uid_overrides["/var/lib/detection-engineering/stock-log-access/lock"] = 99
    if defect.startswith("marker_"):
        marker = state_dir / "applied.json"
        if defect == "marker_symlink": marker.symlink_to(victim_file)
        elif defect == "marker_hardlink": marker.hardlink_to(victim_file)
        else: marker.write_text('{}')
        if defect == "marker_mode": marker.chmod(0o644)
        if defect == "marker_owner": host.state_uid_overrides["/var/lib/detection-engineering/stock-log-access/applied.json"] = 99
    victim_mode = victim.stat().st_mode
    victim_file_mode = victim_file.stat().st_mode
    result = invoke(root, host)
    assert result["stage"] == "preflight"
    assert not any(op.startswith(("group:", "publish:", "restart")) for op in host.operations)
    assert victim.stat().st_mode == victim_mode
    assert victim_file.stat().st_mode == victim_file_mode
    assert victim_file.read_text() == "do-not-touch"


@pytest.mark.parametrize("logical,operation", [
    ("/var/log/auth.log", "group_auth"), ("/var/log/syslog", "group_syslog"),
])
@pytest.mark.parametrize("already_desired", [False, True])
def test_group_checkpoint_rejects_replacement_without_mutating_new_object(tmp_path, logical, operation, already_desired):
    root, host = make_root(tmp_path)
    target_gid = host.groups["splunkfwd"].gid
    if already_desired:
        for source in ["/var/log/auth.log", "/var/log/syslog"]:
            host.files[source] = replace(host.files[source], gid=target_gid)
    path = root / logical.lstrip("/")
    replacement = b"replacement-object\n"
    replacement_gid = target_gid if already_desired else 4
    def swap():
        path.unlink()
        path.write_bytes(replacement)
        host.files[logical] = replace(host.files[logical], ino=host.files[logical].ino + 9000, gid=replacement_gid)
    host.callbacks[(operation, "before")] = swap
    result = invoke(root, host)
    assert result["stage"] == operation
    assert path.read_bytes() == replacement
    assert host.files[logical].gid == replacement_gid
    assert not any(op == f"group:{logical}:{target_gid}" for op in host.operations)
    assert not any(op.startswith(("publish:", "restart")) for op in host.operations)


def test_native_acl_errors_fail_closed_except_proven_absence(tmp_path, monkeypatch):
    helper = load_helper()
    host = helper.NativeHost()
    source = tmp_path / "source"
    source.write_text("x")
    def denied(*_args, **_kwargs):
        raise OSError(errno.EACCES, "denied")
    monkeypatch.setattr(helper.os, "getxattr", denied)
    with pytest.raises(helper.PolicyError):
        host.file_facts("/var/log/auth.log", source)
    def absent(*_args, **_kwargs):
        raise OSError(errno.ENODATA, "absent")
    monkeypatch.setattr(helper.os, "getxattr", absent)
    assert host.file_facts("/var/log/auth.log", source).extended_acl is False


def test_native_group_update_is_group_only_and_rejects_symlinked_parent(tmp_path, monkeypatch):
    helper = load_helper()
    host = helper.NativeHost()
    parent = tmp_path / "real"
    parent.mkdir()
    source = parent / "source"
    source.write_text("x")
    expected = host.file_facts("/var/log/auth.log", source)
    calls = []
    monkeypatch.setattr(helper.os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))
    host.set_group("/var/log/auth.log", source, expected.gid, expected)
    assert calls == [(-1, expected.gid)]
    calls.clear()
    alias = tmp_path / "alias"
    alias.symlink_to(parent, target_is_directory=True)
    with pytest.raises(helper.PolicyError):
        host.set_group("/var/log/auth.log", alias / "source", expected.gid, expected)
    assert calls == []


def test_native_group_update_fails_closed_on_descriptor_acl_error(tmp_path, monkeypatch):
    helper = load_helper()
    host = helper.NativeHost()
    source = tmp_path / "source"
    source.write_text("x")
    expected = host.file_facts("/var/log/auth.log", source)
    monkeypatch.setattr(helper.os, "getxattr", lambda *_a, **_k: (_ for _ in ()).throw(OSError(errno.EIO, "I/O error")))
    calls = []
    monkeypatch.setattr(helper.os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))
    with pytest.raises(helper.PolicyError):
        host.set_group("/var/log/auth.log", source, expected.gid, expected)
    assert calls == []


@pytest.mark.parametrize("second_pid,expected", [(410, True), (411, None)])
def test_native_observation_rechecks_systemd_mainpid_after_proc_reads(monkeypatch, second_pid, expected):
    helper = load_helper()
    host = helper.NativeHost()
    show = "\n".join([
        "LoadState=loaded", "ActiveState=active", "SubState=running", "MainPID=410",
        "ExecStart={ path=/usr/sbin/rsyslogd ; argv[]=/usr/sbin/rsyslogd -n -iNONE ; ignore_errors=no }",
        "DropInPaths=", "RootDirectory=", "RootImage=",
    ]) + "\n"
    calls = []
    def run(command, **_kwargs):
        calls.append(command)
        if len(calls) == 1:
            return SimpleNamespace(returncode=0, stdout=show)
        return SimpleNamespace(returncode=0, stdout=f"MainPID={second_pid}\n")
    monkeypatch.setattr(helper.subprocess, "run", run)
    real_read_text = helper.Path.read_text
    real_read_bytes = helper.Path.read_bytes
    monkeypatch.setattr(helper.Path, "read_text", lambda path, *a, **k: (
        "410 (rsyslogd) S " + " ".join(["0"] * 18) + " 9001 0\n"
        if str(path) == "/proc/410/stat" else real_read_text(path, *a, **k)
    ))
    monkeypatch.setattr(helper.Path, "read_bytes", lambda path, *a, **k: (
        b"/usr/sbin/rsyslogd\0-n\0-iNONE\0"
        if str(path) == "/proc/410/cmdline" else real_read_bytes(path, *a, **k)
    ))
    monkeypatch.setattr(helper.os, "readlink", lambda path: {
        "/proc/410/exe": "/usr/sbin/rsyslogd",
        "/proc/410/ns/mnt": "mnt:[1]",
        "/proc/self/ns/mnt": "mnt:[1]",
    }[str(path)])
    real_realpath = helper.os.path.realpath
    monkeypatch.setattr(helper.os.path, "realpath", lambda path: (
        "/" if str(path) == "/proc/410/root" else
        "/usr/sbin/rsyslogd" if str(path) == "/usr/sbin/rsyslogd" else real_realpath(path)
    ))
    observation = host.observe_producer("/usr/bin/systemctl", "/usr/sbin/rsyslogd")
    assert observation.active is expected
    assert len(calls) == 2
    assert calls[1][-1] == "--property=MainPID"


@pytest.mark.parametrize("operation,when,replaced", [
    ("publish_replace", "before", False),
    ("publish_replace", "after", True),
    ("publish_directory_fsync", "before", True),
])
def test_config_publication_reports_post_replace_partial_effects(tmp_path, operation, when, replaced):
    root, host = make_root(tmp_path)
    helper = load_helper()
    original = (root / "etc/rsyslog.conf").read_bytes()
    candidate = helper.render_candidate(original, "splunkfwd")
    host.fail_once(operation, when)
    result = invoke(root, host)
    assert result["stage"] == "publish_config"
    assert (root / "etc/rsyslog.conf").read_bytes() == (candidate if replaced else original)
    assert ("/etc/rsyslog.conf" in result["changed_paths"]) is replaced
    assert not (root / "var/lib/detection-engineering/stock-log-access/applied.json").exists()
    if replaced:
        assert host.files["/etc/rsyslog.conf"].ino >= 1000


@pytest.mark.parametrize("operation,when,replaced", [
    ("marker_replace", "before", False),
    ("marker_replace", "after", True),
    ("marker_directory_fsync", "before", True),
])
def test_marker_publication_failure_removes_authoritative_digest(tmp_path, operation, when, replaced):
    root, host = make_root(tmp_path)
    host.fail_once(operation, when)
    result = invoke(root, host)
    assert result["stage"] == "write_applied"
    marker = root / "var/lib/detection-engineering/stock-log-access/applied.json"
    assert not marker.exists()
    assert ("/var/lib/detection-engineering/stock-log-access/applied.json" in result["changed_paths"]) is replaced


@pytest.mark.parametrize("failure", [None, ("publish_replace", "before"), ("publish_replace", "after"), ("publish_directory_fsync", "before")])
def test_operational_parent_metadata_is_never_changed_by_publication(tmp_path, failure):
    root, host = make_root(tmp_path)
    parent = root / "etc"
    parent.chmod(0o751)
    before = parent.stat()
    if failure is not None:
        host.fail_once(*failure)
    invoke(root, host)
    after = parent.stat()
    assert (after.st_mode, after.st_uid, after.st_gid, after.st_ino) == (
        before.st_mode, before.st_uid, before.st_gid, before.st_ino,
    )


@pytest.mark.parametrize("context", ["config", "marker"])
@pytest.mark.parametrize("failure", ["fchmod", "fchown", "write", "flush", "file_fsync"])
def test_atomic_writer_cleans_owned_temp_on_every_early_failure(tmp_path, monkeypatch, context, failure):
    helper = load_helper()
    parent = tmp_path / context
    parent.mkdir(mode=0o751)
    target = parent / ("rsyslog.conf" if context == "config" else "applied.json")
    target.write_bytes(b"original\n")
    target.chmod(0o640 if context == "config" else 0o600)
    parent_before = parent.stat()
    directory_fd = helper.os.open(parent, helper.os.O_RDONLY | helper.os.O_DIRECTORY)
    real_fchmod, real_fchown = helper.os.fchmod, helper.os.fchown
    real_fsync, real_fdopen = helper.os.fsync, helper.os.fdopen
    def is_owned_temp(fd):
        try:
            return "/.stock-access-" in helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return False
    if failure == "fchmod":
        monkeypatch.setattr(helper.os, "fchmod", lambda fd, mode: (
            (_ for _ in ()).throw(OSError(errno.EIO, "injected fchmod failure"))
            if is_owned_temp(fd) else real_fchmod(fd, mode)
        ))
    if failure == "fchown":
        monkeypatch.setattr(helper.os, "fchown", lambda fd, uid, gid: (
            (_ for _ in ()).throw(OSError(errno.EIO, "injected fchown failure"))
            if is_owned_temp(fd) else real_fchown(fd, uid, gid)
        ))
    class FaultyStream:
        def __init__(self, stream): self.stream = stream
        def __enter__(self): return self
        def __exit__(self, *args): return self.stream.__exit__(*args)
        def fileno(self): return self.stream.fileno()
        def write(self, data):
            if failure == "write": raise OSError(errno.EIO, "injected write failure")
            return self.stream.write(data)
        def flush(self):
            if failure == "flush": raise OSError(errno.EIO, "injected flush failure")
            return self.stream.flush()
    if failure in {"write", "flush"}:
        monkeypatch.setattr(helper.os, "fdopen", lambda fd, *a, **k: FaultyStream(real_fdopen(fd, *a, **k)))
    if failure == "file_fsync":
        monkeypatch.setattr(helper.os, "fsync", lambda fd: (
            (_ for _ in ()).throw(OSError(errno.EIO, "injected file fsync failure"))
            if is_owned_temp(fd) else real_fsync(fd)
        ))
    try:
        with pytest.raises(OSError):
            helper._atomic_write_at(
                directory_fd, target.name, b"replacement\n", target.stat().st_mode & 0o777,
                owner=(helper.os.getuid(), helper.os.getgid()),
                replace_operation="test_replace", directory_operation="test_directory_fsync",
            )
    finally:
        helper.os.close(directory_fd)
    assert target.read_bytes() == b"original\n"
    assert list(parent.glob(".stock-access-*")) == []
    parent_after = parent.stat()
    assert (parent_after.st_mode, parent_after.st_uid, parent_after.st_gid, parent_after.st_ino) == (
        parent_before.st_mode, parent_before.st_uid, parent_before.st_gid, parent_before.st_ino,
    )


@pytest.mark.parametrize("context", ["config", "marker"])
def test_atomic_cleanup_failure_reports_exact_leftover_in_result(tmp_path, monkeypatch, context):
    helper = load_helper()
    root, host = make_root(tmp_path, generated=context == "marker")
    if context == "marker":
        target_gid = host.groups["splunkfwd"].gid
        for logical in ["/var/log/auth.log", "/var/log/syslog"]:
            host.files[logical] = replace(host.files[logical], gid=target_gid)
    real_fchmod, real_unlink = helper.os.fchmod, helper.os.unlink
    def is_owned_temp_fd(fd):
        try: return "/.stock-access-" in helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: return False
    monkeypatch.setattr(helper.os, "fchmod", lambda fd, mode: (
        (_ for _ in ()).throw(OSError(errno.EIO, "injected early publication failure"))
        if is_owned_temp_fd(fd) else real_fchmod(fd, mode)
    ))
    def fail_owned_cleanup(path, *args, **kwargs):
        if str(path).startswith(".stock-access-"):
            raise OSError(errno.EACCES, "injected cleanup failure")
        return real_unlink(path, *args, **kwargs)
    monkeypatch.setattr(helper.os, "unlink", fail_owned_cleanup)
    result = invoke(root, host, helper=helper)
    assert result["stage"] == ("publish_config" if context == "config" else "write_applied")
    assert "injected early publication failure" in result["error"]
    leftovers = list((root / ("etc" if context == "config" else "var/lib/detection-engineering/stock-log-access")).glob(".stock-access-*"))
    assert len(leftovers) == 1
    logical = "/" + str(leftovers[0].relative_to(root))
    assert result["cleanup_errors"] == [{
        "operation": "unlink",
        "resource": logical,
        "errno": errno.EACCES,
        "message": "[Errno 13] injected cleanup failure; removal unconfirmed",
    }]
    assert logical in result["changed_paths"]


def test_candidate_staging_cleans_owned_file_on_early_failure(tmp_path, monkeypatch):
    helper = load_helper()
    root, host = make_root(tmp_path)
    original = (root / "etc/rsyslog.conf").read_bytes()
    real_fchmod = helper.os.fchmod
    def fail_candidate_chmod(fd, mode):
        try: name = helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: name = ""
        if "/candidate-" in name:
            raise OSError(errno.EIO, "injected candidate staging failure")
        return real_fchmod(fd, mode)
    monkeypatch.setattr(helper.os, "fchmod", fail_candidate_chmod)
    result = invoke(root, host, helper=helper)
    assert result["stage"] == "preflight"
    state_dir = root / "var/lib/detection-engineering/stock-log-access"
    assert list(state_dir.glob("candidate-*")) == []
    assert (root / "etc/rsyslog.conf").read_bytes() == original
    assert not any(op.startswith(("group:", "publish:", "restart")) for op in host.operations)


@pytest.mark.parametrize("scenario,error_number", [
    ("fresh", errno.EACCES), ("converged", errno.EIO), ("prior_failure", errno.EACCES),
])
def test_main_reports_final_candidate_removal_failure_as_json(tmp_path, monkeypatch, capsys, scenario, error_number):
    helper = load_helper()
    root, host = make_root(tmp_path)
    if scenario == "converged":
        assert invoke(root, host, helper=helper)["stage"] == "complete"
        restart_count = host.operations.count("restart")
    elif scenario == "prior_failure":
        host.validator_accepts = False
    real_unlink = helper.os.unlink
    def fail_candidate(path, *args, **kwargs):
        if str(path).startswith("candidate-"):
            raise OSError(error_number, "injected final candidate unlink failure")
        return real_unlink(path, *args, **kwargs)
    monkeypatch.setattr(helper.os, "unlink", fail_candidate)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1
    assert result["producer_active"] is True
    assert len(result["cleanup_errors"]) == 1
    cleanup = result["cleanup_errors"][0]
    assert cleanup["operation"] == "unlink"
    assert cleanup["resource"].startswith("/var/lib/detection-engineering/stock-log-access/candidate-")
    assert cleanup["errno"] == error_number
    assert "unconfirmed" in cleanup["message"]
    assert cleanup["resource"] in result["changed_paths"]
    if scenario == "prior_failure":
        assert result["stage"] == "preflight"
        assert result["error"] == "native candidate validation failed"
        assert not (root / "var/lib/detection-engineering/stock-log-access/applied.json").exists()
    else:
        assert result["stage"] == "cleanup"
        assert "operational application completed" in result["error"]
        assert "applied marker retained" in result["error"]
        assert (root / "var/lib/detection-engineering/stock-log-access/applied.json").is_file()
    if scenario == "converged":
        assert host.operations.count("restart") == restart_count


def test_main_preserves_early_candidate_primary_and_cleanup_errors(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    root, host = make_root(tmp_path)
    real_fchmod, real_unlink = helper.os.fchmod, helper.os.unlink
    def candidate_fd(fd):
        try: return "/candidate-" in helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: return False
    monkeypatch.setattr(helper.os, "fchmod", lambda fd, mode: (
        (_ for _ in ()).throw(OSError(errno.EIO, "injected candidate write setup failure"))
        if candidate_fd(fd) else real_fchmod(fd, mode)
    ))
    def fail_candidate_cleanup(path, *args, **kwargs):
        if str(path).startswith("candidate-"):
            raise OSError(errno.EACCES, "injected candidate cleanup failure")
        return real_unlink(path, *args, **kwargs)
    monkeypatch.setattr(helper.os, "unlink", fail_candidate_cleanup)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1
    assert result["stage"] == "preflight"
    assert "candidate write setup failure" in result["error"]
    assert result["cleanup_errors"][0]["operation"] == "unlink"
    resource = result["cleanup_errors"][0]["resource"]
    assert resource.startswith("/var/lib/detection-engineering/stock-log-access/candidate-")
    assert resource in result["changed_paths"]


@pytest.mark.parametrize("failed_resources", [{"lock"}, {"directory"}, {"lock", "directory"}])
def test_main_attempts_lock_and_directory_close_once_after_success(tmp_path, monkeypatch, capsys, failed_resources):
    helper = load_helper()
    root, host = make_root(tmp_path)
    real_close = helper.os.close
    attempts = []
    all_final_closes = []
    def close_then_raise(fd):
        try: resource = helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: resource = ""
        kind = "lock" if resource.endswith("/lock") else "directory" if resource.endswith("/stock-log-access") else None
        if kind is not None:
            all_final_closes.append((fd, kind))
        if kind in failed_resources:
            attempts.append((fd, resource))
            real_close(fd)
            raise OSError(errno.EIO, "injected released-then-error close")
        return real_close(fd)
    monkeypatch.setattr(helper.os, "close", close_then_raise)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1 and result["stage"] == "cleanup"
    expected = []
    if "lock" in failed_resources: expected.append("/var/lib/detection-engineering/stock-log-access/lock")
    if "directory" in failed_resources: expected.append("/var/lib/detection-engineering/stock-log-access")
    assert [item["resource"] for item in result["cleanup_errors"]] == expected
    assert len(attempts) == len(failed_resources)
    assert len({fd for fd, _ in attempts}) == len(failed_resources)
    assert [kind for _, kind in all_final_closes] == ["lock", "directory"]
    assert all(result["changed_paths"].count(item["resource"]) == 0 for item in result["cleanup_errors"])


def test_partial_state_construction_preserves_flock_and_all_close_errors(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    root, host = make_root(tmp_path)
    monkeypatch.setattr(helper.fcntl, "flock", lambda *_a: (_ for _ in ()).throw(OSError(errno.EIO, "injected flock failure")))
    real_close = helper.os.close
    attempts = []
    def close_then_raise(fd):
        try: resource = helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: resource = ""
        if resource.endswith("/lock") or resource.endswith("/stock-log-access"):
            attempts.append((fd, resource))
            real_close(fd)
            raise OSError(errno.EACCES, "injected construction close failure")
        return real_close(fd)
    monkeypatch.setattr(helper.os, "close", close_then_raise)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1 and result["stage"] == "preflight"
    assert "injected flock failure" in result["error"]
    assert [item["resource"] for item in result["cleanup_errors"]] == [
        "/var/lib/detection-engineering/stock-log-access/lock",
        "/var/lib/detection-engineering/stock-log-access",
    ]
    assert len(attempts) == 2


def test_publication_primary_survives_parent_close_error(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    root, host = make_root(tmp_path)
    host.fail_once("publish_directory_fsync", "before")
    real_close = helper.os.close
    def close_etc_then_raise(fd):
        try: resource = helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: resource = ""
        if resource.endswith("/etc"):
            real_close(fd)
            raise OSError(errno.EIO, "injected publication parent close failure")
        return real_close(fd)
    monkeypatch.setattr(helper.os, "close", close_etc_then_raise)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1 and result["stage"] == "publish_config"
    assert "injected before publish_directory_fsync" in result["error"]
    assert result["cleanup_errors"][0]["operation"] == "close"
    assert result["cleanup_errors"][0]["resource"] == "/etc"


def test_marker_validation_primary_survives_marker_close_error(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    root, host = make_root(tmp_path)
    assert invoke(root, host, helper=helper)["stage"] == "complete"
    real_fstat, real_close = helper.os.fstat, helper.os.close
    marker_fds = set()
    def fail_marker_fstat(fd):
        try: resource = helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: resource = ""
        if resource.endswith("/applied.json"):
            marker_fds.add(fd)
            raise OSError(errno.EIO, "injected marker validation failure")
        return real_fstat(fd)
    def close_marker_then_raise(fd):
        if fd in marker_fds:
            real_close(fd)
            raise OSError(errno.EACCES, "injected marker close failure")
        return real_close(fd)
    monkeypatch.setattr(helper.os, "fstat", fail_marker_fstat)
    monkeypatch.setattr(helper.os, "close", close_marker_then_raise)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1 and result["stage"] == "preflight"
    assert "marker validation failure" in result["error"]
    assert result["cleanup_errors"][0]["resource"] == "/var/lib/detection-engineering/stock-log-access/applied.json"


def test_marker_publication_preserves_primary_and_failed_invalidation(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    root, host = make_root(tmp_path)
    host.fail_once("marker_directory_fsync", "before")
    real_unlink = helper.os.unlink
    def fail_marker_invalidation(path, *args, **kwargs):
        if str(path) == "applied.json":
            raise OSError(errno.EACCES, "injected failed marker invalidation")
        return real_unlink(path, *args, **kwargs)
    monkeypatch.setattr(helper.os, "unlink", fail_marker_invalidation)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1 and result["stage"] == "write_applied"
    assert "injected before marker_directory_fsync" in result["error"]
    assert result["cleanup_errors"][0]["operation"] == "unlink"
    assert result["cleanup_errors"][0]["resource"] == "/var/lib/detection-engineering/stock-log-access/applied.json"
    assert (root / "var/lib/detection-engineering/stock-log-access/applied.json").is_file()


def test_group_mutation_is_accounted_when_close_reports_error(tmp_path, capsys):
    helper = load_helper()
    root, host = make_root(tmp_path)
    host.group_close_error_for = "/var/log/auth.log"
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1 and result["stage"] == "group_auth"
    assert result["changed_paths"] == ["/var/log/auth.log"]
    assert host.files["/var/log/auth.log"].gid == host.groups["splunkfwd"].gid
    assert host.files["/var/log/syslog"].gid == 4


def test_early_candidate_primary_preserves_secondary_close_error(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    root, host = make_root(tmp_path)
    real_fchmod, real_close = helper.os.fchmod, helper.os.close
    candidate_fds = set()
    def fail_candidate_setup(fd, mode):
        try: resource = helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: resource = ""
        if "/candidate-" in resource:
            candidate_fds.add(fd)
            raise OSError(errno.EIO, "injected candidate primary")
        return real_fchmod(fd, mode)
    def close_candidate_then_raise(fd):
        if fd in candidate_fds:
            real_close(fd)
            raise OSError(errno.EACCES, "injected candidate close secondary")
        return real_close(fd)
    monkeypatch.setattr(helper.os, "fchmod", fail_candidate_setup)
    monkeypatch.setattr(helper.os, "close", close_candidate_then_raise)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1 and result["stage"] == "preflight"
    assert "candidate primary" in result["error"]
    assert result["cleanup_errors"][0]["operation"] == "close"
    assert result["cleanup_errors"][0]["resource"].startswith("/var/lib/detection-engineering/stock-log-access/candidate-")


def test_atomic_primary_preserves_temp_close_error_without_fake_path_change(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    root, host = make_root(tmp_path)
    real_fchmod, real_close = helper.os.fchmod, helper.os.close
    temp_fds = set()
    def fail_temp_setup(fd, mode):
        try: resource = helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: resource = ""
        if "/.stock-access-" in resource:
            temp_fds.add(fd)
            raise OSError(errno.EIO, "injected atomic primary")
        return real_fchmod(fd, mode)
    def close_temp_then_raise(fd):
        if fd in temp_fds:
            real_close(fd)
            raise OSError(errno.EACCES, "injected atomic close secondary")
        return real_close(fd)
    monkeypatch.setattr(helper.os, "fchmod", fail_temp_setup)
    monkeypatch.setattr(helper.os, "close", close_temp_then_raise)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1 and result["stage"] == "publish_config"
    assert "atomic primary" in result["error"]
    cleanup = result["cleanup_errors"][0]
    assert cleanup["resource"].startswith("/etc/.stock-access-")
    assert cleanup["resource"] not in result["changed_paths"]


def test_native_group_change_close_error_reports_accomplished_mutation(tmp_path, monkeypatch):
    helper = load_helper()
    host = helper.NativeHost()
    source = tmp_path / "source"
    source.write_text("x")
    expected = host.file_facts("/var/log/auth.log", source)
    changed = []
    monkeypatch.setattr(helper.os, "fchown", lambda fd, uid, gid: changed.append((uid, gid)))
    real_close = helper.os.close
    source_fd = None
    def close_source_then_raise(fd):
        nonlocal source_fd
        try: resource = helper.os.readlink(f"/proc/self/fd/{fd}")
        except OSError: resource = ""
        if resource.endswith("/source"):
            source_fd = fd
            real_close(fd)
            raise OSError(errno.EIO, "injected source close error")
        return real_close(fd)
    monkeypatch.setattr(helper.os, "close", close_source_then_raise)
    with pytest.raises(helper._OwnedOperationError) as raised:
        host.set_group("/var/log/auth.log", source, expected.gid, expected)
    assert changed == [(-1, expected.gid)]
    assert raised.value.changed_paths == ["/var/log/auth.log"]
    assert source_fd is not None


class NativeIdentityParsingHost:
    """Native getent parser with modeled privileged operations only."""

    def __init__(self, helper, model):
        self.native = helper.NativeHost()
        self.model = model

    def lookup_user(self, name, command):
        return self.native.lookup_user(name, command)

    def lookup_group(self, name, command):
        return self.native.lookup_group(name, command)

    def __getattr__(self, name):
        return getattr(self.model, name)


@pytest.mark.parametrize("malformed_field", ["passwd_uid", "passwd_gid", "group_gid"])
def test_main_rejects_malformed_native_identity_numbers_as_one_json(tmp_path, monkeypatch, capsys, malformed_field):
    helper = load_helper()
    root, model = make_root(tmp_path)
    host = NativeIdentityParsingHost(helper, model)
    before = snapshot(root, model)
    records = {
        ("passwd", "splunkfwd"): "splunkfwd:x:2201:2201::/nonexistent:/usr/sbin/nologin\n",
        ("group", "splunkfwd"): "splunkfwd:x:2201:\n",
        ("group", "root"): "root:x:0:\n",
        ("group", "adm"): "adm:x:4:\n",
    }
    if malformed_field == "passwd_uid":
        records[("passwd", "splunkfwd")] = "splunkfwd:x:not-decimal:2201::/nonexistent:/usr/sbin/nologin\n"
    elif malformed_field == "passwd_gid":
        records[("passwd", "splunkfwd")] = "splunkfwd:x:2201:not-decimal::/nonexistent:/usr/sbin/nologin\n"
    else:
        records[("group", "splunkfwd")] = "splunkfwd:x:not-decimal:\n"
    def getent(command, **_kwargs):
        assert command[0] == "/usr/bin/getent"
        return SimpleNamespace(returncode=0, stdout=records[(command[1], command[2])], stderr="")
    monkeypatch.setattr(helper.subprocess, "run", getent)
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 1
    assert result["stage"] == "preflight"
    assert "required account identity is missing" in result["error"]
    assert result["changed"] is False
    assert result["changed_paths"] == []
    assert snapshot(root, model) == before
    assert not any(op.startswith(("group:", "publish:", "restart")) for op in model.operations)


def test_main_accepts_valid_native_decimal_identity_records(tmp_path, monkeypatch, capsys):
    helper = load_helper()
    root, model = make_root(tmp_path)
    host = NativeIdentityParsingHost(helper, model)
    records = {
        ("passwd", "splunkfwd"): "splunkfwd:x:2201:2201::/nonexistent:/usr/sbin/nologin\n",
        ("group", "splunkfwd"): "splunkfwd:x:2201:\n",
        ("group", "root"): "root:x:0:\n",
        ("group", "adm"): "adm:x:4:\n",
    }
    monkeypatch.setattr(helper.subprocess, "run", lambda command, **_kwargs: SimpleNamespace(
        returncode=0, stdout=records[(command[1], command[2])], stderr="",
    ))
    code, result = invoke_main_json(helper, root, host, capsys)
    assert code == 0
    assert result["stage"] == "complete"
    assert model.files["/var/log/auth.log"].gid == 2201
    assert model.files["/var/log/syslog"].gid == 2201


def test_post_application_identity_drift_prevents_digest(tmp_path):
    root, host = make_root(tmp_path)
    host.observation_sequence = [
        ProducerObservation(True, True, 410, "410:9001"),
        ProducerObservation(True, True, 410, "410:9001"),
        ProducerObservation(None, False, 411, "411:9002"),
    ]
    result = invoke(root, host)
    assert result["stage"] == "verify"
    assert result["producer_active"] is None
    assert not (root / "var/lib/detection-engineering/stock-log-access/applied.json").exists()


def test_native_adapter_refuses_unprivileged_and_symlink_sources(tmp_path):
    helper = load_helper()
    host = helper.NativeHost()
    source = tmp_path / "source"
    source.write_text("x")
    facts = host.file_facts("/var/log/auth.log", source)
    assert facts is not None and facts.uid != 0
    with pytest.raises(helper.PolicyError):
        helper._safe_source(host, "/var/log/auth.log", source, {4, 2201})
    link = tmp_path / "link"
    link.symlink_to(source)
    link_facts = host.file_facts("/var/log/auth.log", link)
    assert link_facts is not None and link_facts.symlink
    with pytest.raises(helper.PolicyError):
        helper._safe_source(host, "/var/log/auth.log", link, {4, 2201})


def test_main_injects_model_and_emits_one_json_result(tmp_path, capsys):
    helper = load_helper()
    root, host = make_root(tmp_path)
    argv = [
        "--root", str(root), "--reader", "splunkfwd", "--profile-dir", str(PROFILE),
        "--dpkg-query", "/usr/bin/dpkg-query", "--getent", "/usr/bin/getent",
        "--systemctl", "/usr/bin/systemctl", "--rsyslogd", "/usr/sbin/rsyslogd",
        "--runuser", "/usr/sbin/runuser",
    ]
    assert helper.main(argv, host=host) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["stage"] == "complete"
