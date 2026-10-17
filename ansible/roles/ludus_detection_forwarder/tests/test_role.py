"""Stateful offline production-include tests for the Universal Forwarder role."""

from __future__ import annotations

import copy
import getpass
import hashlib
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from support import REPOSITORY_ROOT, run_production_include


ROLE = "ludus_detection_forwarder"
COMMON = [
    ("/var/log/auth.log", "de_linux", "linux:auth", ["_time", "host", "source", "sourcetype", "message"]),
    ("/var/log/syslog", "de_linux", "linux:system", ["_time", "host", "source", "sourcetype", "message"]),
    ("/var/log/laurel/audit.log", "de_linux", "linux:audit:laurel", ["_time", "host", "source", "sourcetype"]),
]
PROFILE = {
    "gitlab": [],
    "runner": [
        ("/var/log/detection-engineering/runner-registration.jsonl", "de_runner", "gitlab:runner:registration", ["_time", "host", "source", "sourcetype", "message"]),
    ],
    "workload": [],
}


def _executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\nset -eu\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def _gate(observed: dict, stops: list[int]) -> dict:
    return {
        "status": "VERIFIED",
        "source": {"url": "https://fixtures.invalid/explicitly-synthetic", "observed_at": "2026-10-17T00:00:00Z"},
        "observed": observed,
        "limitation": "Explicitly synthetic fixture; not deployment evidence.",
        "stops": stops,
    }


def _bootstrap_contract() -> dict:
    return _gate(
        {
            "version": "10.6.1.1",
            "build": "b2ae2962645c",
            "seed": {
                "path": "/opt/splunkforwarder/etc/system/local/user-seed.conf",
                "section": "user_info",
                "username_key": "USERNAME",
                "username": "admin",
                "password_key": "PASSWORD",
                "mode": "0600",
                "owner": "splunkfwd",
                "group": "splunkfwd",
            },
            "first_start": {
                "identity": "splunkfwd",
                "argv": ["start", "--accept-license", "--answer-yes", "--no-prompt"],
            },
            "boot_start": {
                "identity": "root",
                "argv": ["enable", "boot-start", "-user", "splunkfwd", "--accept-license", "--answer-yes", "--no-prompt"],
            },
            "unit": {
                "path": "/etc/systemd/system/SplunkForwarder.service",
                "service_name": "SplunkForwarder.service",
                "effective_user": "splunkfwd",
            },
        },
        [4, 8, 9, 10],
    )


def _inputs(profile: str) -> list[dict]:
    rows = COMMON + PROFILE[profile]
    return [
        {"path": path, "index": index, "sourcetype": sourcetype, "safe_fields": safe_fields}
        for path, index, sourcetype, safe_fields in rows
    ]


def _fixture(tmp_path: Path, profile: str = "workload") -> dict:
    root = tmp_path / "target"
    fake_bin = tmp_path / "bin"
    root.mkdir(); fake_bin.mkdir()
    calls = root / "calls"; calls.touch()
    package_state = root / "package-state"
    lifecycle = root / "lifecycle"; lifecycle.mkdir()
    readable_state = lifecycle / "readable"; readable_state.touch()
    artifact = root / "cache/splunkforwarder.deb"
    artifact.parent.mkdir(); artifact.write_bytes(b"explicitly synthetic Universal Forwarder package\n")
    unit = root / "etc/systemd/system/SplunkForwarder.service"
    seed = root / "opt/splunkforwarder/etc/system/local/user-seed.conf"
    logger = f"printf '%s\\n' \"$*\" >> {calls}"

    _executable(fake_bin / "dpkg-query", f"{logger}\n[ -f {package_state} ] && cat {package_state} || exit 1")
    _executable(fake_bin / "dpkg-deb", f'''{logger}
case "$3" in
  Package) printf '%s\\n' "${{FAKE_DEB_PACKAGE:-splunkforwarder}}" ;;
  Version) printf '%s\\n' "${{FAKE_DEB_VERSION:-10.6.1.1}}" ;;
  Architecture) printf '%s\\n' "${{FAKE_DEB_ARCH:-amd64}}" ;;
  *) exit 2 ;;
esac''')
    _executable(fake_bin / "dpkg", f"{logger}\nprintf 'install ok installed\\t10.6.1.1\\tamd64\\n' > {package_state}\ntouch {lifecycle}/package-installed")
    _executable(fake_bin / "splunk", f'''{logger}
[ -f {lifecycle}/package-installed ] || exit 40
case "$1" in
  start)
    [ -f {seed} ] && [ "$(stat -c %a {seed})" = 600 ] || exit 41
    touch {lifecycle}/bootstrapped ;;
  enable)
    [ -f {lifecycle}/bootstrapped ] || exit 42
    [ ! -f {lifecycle}/fail-unit ] || exit 44
    mkdir -p {unit.parent}; printf '[Unit]\\n[Service]\\nUser=splunkfwd\\n' > {unit}
    [ ! -f {lifecycle}/fail-marker ] || {{ mkdir -p {root}/var/lib/detection-engineering/forwarder-bootstrap.yml; chmod 000 {root}/var/lib/detection-engineering/forwarder-bootstrap.yml; }} ;;
  *) exit 43 ;;
esac''')
    _executable(fake_bin / "systemctl", f'''{logger}
[ -f {unit} ] || exit 50
[ -f {lifecycle}/bootstrapped ] || exit 51
case "$1" in
  restart|start) printf running > {lifecycle}/service ;;
  enable) printf enabled > {lifecycle}/enabled ;;
  is-active) [ -f {lifecycle}/service ] ;;
  is-enabled) [ -f {lifecycle}/enabled ] ;;
  show)
    [ "$2" = SplunkForwarder.service ] || exit 53
    [ "$3" = --property ] && [ "$5" = --value ] || exit 54
    case "$4" in
      User) if [ -f {lifecycle}/wrong-unit-user ]; then printf root; else printf splunkfwd; fi ;;
      FragmentPath) if [ -f {lifecycle}/wrong-unit-path ]; then printf /etc/systemd/system/other.service; else printf /etc/systemd/system/SplunkForwarder.service; fi ;;
      *) exit 55 ;;
    esac ;;
  *) exit 52 ;;
esac''')
    _executable(fake_bin / "id", f'''{logger}
case "$1" in
  -u) printf '%s\\n' {os.getuid()} ;;
  -g) printf '%s\\n' {os.getgid()} ;;
  *) exit 60 ;;
esac''')
    _executable(fake_bin / "runuser", f'''{logger}
[ "$1" = --user ] && [ "$2" = splunkfwd ] && [ "$3" = -- ] || exit 80
if [ "$4" = test ]; then
  [ "$5" = -r ] || exit 81
  inode=$(stat -c %i "$6")
  grep -Fqx "$6|$inode" {readable_state} || exit 82
  [ -f "$6" ] || exit 83
else
  shift 3
  exec "$@"
fi''')

    inputs = _inputs(profile)
    for item in inputs:
        actual = Path(str(root) + item["path"])
        actual.parent.mkdir(parents=True, exist_ok=True)
        actual.write_text('{"fixture":"explicitly synthetic"}\n', encoding="utf-8")
        actual.chmod(0o600)
        with readable_state.open("a", encoding="utf-8") as stream:
            stream.write(f"{actual}|{actual.stat().st_ino}\n")

    owner = getpass.getuser()
    variables = {
        "range_id": "synthetic-alpha",
        "detection_forwarder_artifact": {
            "version": "10.6.1.1", "build": "b2ae2962645c",
            "url": "https://fixtures.invalid/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "download_auth_required": False,
        },
        "detection_forwarder_download_auth_path": None,
        "detection_forwarder_profile": profile,
        "detection_forwarder_inputs": inputs,
        "detection_forwarder_bootstrap_contract": _bootstrap_contract(),
        "detection_splunk_receiver_host": "synthetic-alpha-splunk",
        "detection_splunk_receiver_port": 9997,
        "detection_forwarder_fixture_root": str(root),
        "detection_forwarder_fixture_mode": True,
        "detection_forwarder_artifact_path": str(artifact),
        "detection_forwarder_dpkg": str(fake_bin / "dpkg"),
        "detection_forwarder_dpkg_query": str(fake_bin / "dpkg-query"),
        "detection_forwarder_dpkg_deb": str(fake_bin / "dpkg-deb"),
        "detection_forwarder_cli": str(fake_bin / "splunk"),
        "detection_forwarder_systemctl": str(fake_bin / "systemctl"),
        "detection_forwarder_id": str(fake_bin / "id"),
        "detection_forwarder_runuser": str(fake_bin / "runuser"),
        "detection_forwarder_python": os.sys.executable,
        "detection_forwarder_file_owner": owner,
        "detection_forwarder_file_group": owner,
        "detection_forwarder_root_owner": owner,
        "detection_forwarder_root_group": owner,
    }
    return {"root": root, "bin": fake_bin, "calls": calls, "package_state": package_state,
            "lifecycle": lifecycle, "readable": readable_state, "variables": variables}


def _run(fixture: dict, **updates):
    variables = copy.deepcopy(fixture["variables"]); variables.update(updates)
    return run_production_include(ROLE, "main", variables, fixture["bin"])


def _calls(fixture: dict) -> list[str]:
    return fixture["calls"].read_text(encoding="utf-8").splitlines()


def _actual(fixture: dict, logical: str) -> Path:
    return Path(str(fixture["root"]) + logical)


def _parse_conf(text: str) -> dict[str, dict[str, str]]:
    parsed: dict[str, dict[str, str]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            parsed[section] = {}
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        parsed[section][key] = value
    return parsed


def _assert_no_mutation(fixture: dict) -> None:
    calls = _calls(fixture)
    assert not any(c.startswith("-i ") or c.startswith("start ") or c.startswith("enable ") or c.startswith("restart ") for c in calls)
    assert not _actual(fixture, "/var/lib/detection-engineering/forwarder-bootstrap.yml").exists()


def test_fresh_install_bootstraps_before_unit_service_and_cleans_seed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    result = _run(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = _calls(fixture)
    install = next(i for i, c in enumerate(calls) if c.startswith("-i "))
    start = next(i for i, c in enumerate(calls) if c.startswith("start "))
    boot = next(i for i, c in enumerate(calls) if c.startswith("enable boot-start"))
    restart = next(i for i, c in enumerate(calls) if c.startswith("restart "))
    assert install < start < boot < restart
    assert any(c == f"--user splunkfwd -- {fixture['bin'] / 'splunk'} start --accept-license --answer-yes --no-prompt" for c in calls)
    assert not _actual(fixture, "/opt/splunkforwarder/etc/system/local/user-seed.conf").exists()
    assert _actual(fixture, "/etc/systemd/system/SplunkForwarder.service").is_file()
    assert _actual(fixture, "/var/lib/detection-engineering/forwarder-bootstrap.yml").is_file()
    assert _actual(fixture, "/etc/detection-engineering/forwarder-install-provenance.yml").is_file()


def test_convergence_validates_marker_provenance_and_does_not_rebootstrap(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    first = _run(fixture); assert first.returncode == 0, first.stdout + first.stderr
    before = len(_calls(fixture))
    second = _run(fixture)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    later = _calls(fixture)[before:]
    assert not any(c.startswith("-i ") or c.startswith("start ") or c.startswith("enable boot-start") for c in later)


@pytest.mark.parametrize("profile", ["gitlab", "runner", "workload"])
def test_rendered_profiles_match_matrix_and_range_host(tmp_path: Path, profile: str) -> None:
    fixture = _fixture(tmp_path, profile)
    result = _run(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    rendered = _parse_conf(
        _actual(fixture, "/opt/splunkforwarder/etc/apps/detection_forwarder/local/inputs.conf").read_text()
    )
    assert rendered["default"] == {"host": f"synthetic-alpha-{profile}"}
    expected = fixture["variables"]["detection_forwarder_inputs"]
    assert len(expected) == {"gitlab": 3, "runner": 4, "workload": 3}[profile]
    assert set(rendered) == {"default"} | {f"monitor://{item['path']}" for item in expected}
    for item in expected:
        assert rendered[f"monitor://{item['path']}"] == {
            "disabled": "false",
            "index": item["index"],
            "sourcetype": item["sourcetype"],
        }
    outputs = _parse_conf(
        _actual(fixture, "/opt/splunkforwarder/etc/apps/detection_forwarder/local/outputs.conf").read_text()
    )
    assert outputs["tcpout"] == {"defaultGroup": "detection_receiver"}
    assert outputs["tcpout:detection_receiver"] == {"server": "synthetic-alpha-splunk:9997"}


def test_workload_forwarder_reads_only_native_linux_profile(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "workload")
    result = _run(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    rendered = _actual(fixture, "/opt/splunkforwarder/etc/apps/detection_forwarder/local/inputs.conf").read_text()
    assert "/var/log/laurel/audit.log" in rendered
    assert "linux:audit:laurel" in rendered
    assert "docker-daemon" not in rendered
    assert "/var/lib/docker" not in rendered
    assert "/var/log/containers" not in rendered
    assert "kubelet" not in rendered


@pytest.mark.parametrize("missing", range(3))
def test_omitting_any_common_source_fails_before_mutation(tmp_path: Path, missing: int) -> None:
    fixture = _fixture(tmp_path)
    inputs = fixture["variables"]["detection_forwarder_inputs"]
    result = _run(fixture, detection_forwarder_inputs=inputs[:missing] + inputs[missing + 1:])
    assert result.returncode != 0
    _assert_no_mutation(fixture)


@pytest.mark.parametrize("path", ["/tmp/auth.log", "/var/log/private/secret", "/var/log/auth.log.suffix"])
def test_arbitrary_or_suffix_substituted_source_fails(tmp_path: Path, path: str) -> None:
    fixture = _fixture(tmp_path)
    inputs = copy.deepcopy(fixture["variables"]["detection_forwarder_inputs"]); inputs[0]["path"] = path
    result = _run(fixture, detection_forwarder_inputs=inputs)
    assert result.returncode != 0
    _assert_no_mutation(fixture)


def test_absent_native_laurel_source_refuses_before_package_mutation(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _actual(fixture, "/var/log/laurel/audit.log").unlink()
    result = _run(fixture)
    assert result.returncode != 0
    _assert_no_mutation(fixture)


def test_obsolete_producer_contract_is_not_a_role_input(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "gitlab")
    result = _run(fixture, detection_forwarder_producer_contract={"unexpected": "ignored"})
    assert result.returncode == 0, result.stdout + result.stderr
    rendered = _actual(
        fixture, "/opt/splunkforwarder/etc/apps/detection_forwarder/local/inputs.conf"
    ).read_text()
    for obsolete in ("gitlab_access", "application_json", "audit_json", "audit-safe", "docker-daemon", "runner-service"):
        assert obsolete not in rendered
    assert not _actual(
        fixture, "/opt/splunkforwarder/etc/apps/detection_forwarder/local/producer-gaps.yml"
    ).exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("index", "de_wrong"),
        ("sourcetype", "linux:audit:safe"),
        ("safe_fields", ["native", "producer", "fields"]),
    ],
)
def test_exact_v1_input_shape_rejects_field_drift(tmp_path: Path, field: str, value: object) -> None:
    fixture = _fixture(tmp_path)
    inputs = copy.deepcopy(fixture["variables"]["detection_forwarder_inputs"])
    inputs[2][field] = value
    result = _run(fixture, detection_forwarder_inputs=inputs)
    assert result.returncode != 0
    _assert_no_mutation(fixture)


def test_matching_unmanaged_install_without_provenance_is_refused(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture["package_state"].write_text("install ok installed\t10.6.1.1\tamd64\n")
    (fixture["lifecycle"] / "package-installed").touch()
    result = _run(fixture)
    assert result.returncode != 0
    _assert_no_mutation(fixture)


@pytest.mark.parametrize("record", ["provenance", "marker"])
def test_tampered_managed_state_is_refused_not_existence_trusted(tmp_path: Path, record: str) -> None:
    fixture = _fixture(tmp_path)
    first = _run(fixture); assert first.returncode == 0, first.stdout + first.stderr
    path = _actual(fixture, "/etc/detection-engineering/forwarder-install-provenance.yml" if record == "provenance" else "/var/lib/detection-engineering/forwarder-bootstrap.yml")
    value = yaml.safe_load(path.read_text()); value["package"]["sha256"] = "0" * 64
    path.write_text(yaml.safe_dump(value)); before = len(_calls(fixture))
    result = _run(fixture)
    assert result.returncode != 0
    assert not any(c.startswith("restart ") or c.startswith("start ") or c.startswith("enable ") for c in _calls(fixture)[before:])


def test_producer_owned_readability_is_verified_as_nonroot_service_identity(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "runner")
    result = _run(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = _calls(fixture)
    actual_sources = [_actual(fixture, item["path"]) for item in fixture["variables"]["detection_forwarder_inputs"]]
    assert all(any(c == f"--user splunkfwd -- test -r {path}" for c in calls) for path in actual_sources)
    assert not any("setfacl" in c or "getfacl" in c for c in calls)


def test_replacement_inode_is_refused_without_producer_readability(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "runner")
    result = _run(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    source = _actual(fixture, "/var/log/auth.log")
    source.unlink()
    source.write_text("replacement inode\n", encoding="utf-8")
    source.chmod(0o600)
    before = len(_calls(fixture))
    result = _run(fixture)
    assert result.returncode != 0
    later = _calls(fixture)[before:]
    assert any(c == f"--user splunkfwd -- test -r {source}" for c in later)
    assert not any(c.startswith("restart ") or c.startswith("start ") or c.startswith("enable ") for c in later)


def test_seed_secret_never_enters_argv_query_stdout_and_is_removed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    result = _run(fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = result.stdout + result.stderr + "\n".join(_calls(fixture))
    assert "PASSWORD =" not in evidence
    assert "seed-passwd" not in evidence
    assert "?" not in fixture["variables"]["detection_forwarder_artifact"]["url"]
    assert not _actual(fixture, "/opt/splunkforwarder/etc/system/local/user-seed.conf").exists()


def test_failed_first_start_removes_seed_without_marker_or_unit(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    splunk = fixture["bin"] / "splunk"
    text = splunk.read_text().replace(
        'case "$1" in',
        f'[ ! -f {fixture["lifecycle"]}/reject-bootstrap ] || exit 44\ncase "$1" in',
    )
    splunk.write_text(text); splunk.chmod(0o755)
    (fixture["lifecycle"] / "reject-bootstrap").touch()
    result = _run(fixture)
    assert result.returncode != 0
    assert not _actual(fixture, "/opt/splunkforwarder/etc/system/local/user-seed.conf").exists()
    assert not _actual(fixture, "/var/lib/detection-engineering/forwarder-bootstrap.yml").exists()
    assert not _actual(fixture, "/etc/systemd/system/SplunkForwarder.service").exists()


@pytest.mark.parametrize("variable,value", [("FAKE_DEB_PACKAGE", "splunk"), ("FAKE_DEB_VERSION", "9.9.9"), ("FAKE_DEB_ARCH", "arm64")])
def test_downloaded_package_identity_mismatch_refuses_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variable: str, value: str) -> None:
    fixture = _fixture(tmp_path)
    monkeypatch.setenv(variable, value)
    result = _run(fixture)
    assert result.returncode != 0
    assert not any(c.startswith("-i ") for c in _calls(fixture))


def test_unknown_bootstrap_capability_refuses_before_mutation(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    contract = copy.deepcopy(fixture["variables"]["detection_forwarder_bootstrap_contract"])
    contract.update(status="BLOCKED", observed=None)
    result = _run(fixture, detection_forwarder_bootstrap_contract=contract)
    assert result.returncode != 0
    _assert_no_mutation(fixture)


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("seed", "path", "/tmp/user-seed.conf"),
        ("seed", "username", "root"),
        ("first_start", "identity", "root"),
        ("first_start", "argv", ["start", "--accept-license"]),
        ("boot_start", "identity", "splunkfwd"),
        ("boot_start", "argv", ["enable", "boot-start"]),
        ("unit", "path", "/etc/systemd/system/other.service"),
        ("unit", "effective_user", "root"),
    ],
)
def test_bootstrap_observation_binds_exact_role_owned_assumption(
    tmp_path: Path, section: str, key: str, value: object
) -> None:
    fixture = _fixture(tmp_path)
    contract = copy.deepcopy(fixture["variables"]["detection_forwarder_bootstrap_contract"])
    contract["observed"][section][key] = value
    result = _run(fixture, detection_forwarder_bootstrap_contract=contract)
    assert result.returncode != 0
    _assert_no_mutation(fixture)


def test_generated_unit_must_report_effective_nonroot_service_identity(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    (fixture["lifecycle"] / "wrong-unit-user").touch()
    result = _run(fixture)
    assert result.returncode != 0
    assert not _actual(fixture, "/var/lib/detection-engineering/forwarder-bootstrap.yml").exists()
    assert _actual(fixture, "/var/lib/detection-engineering/forwarder-bootstrap-in-progress.yml").is_file()


@pytest.mark.parametrize("failure", ["fail-unit", "wrong-unit-user", "wrong-unit-path", "fail-marker"])
def test_ambiguous_partial_bootstrap_refuses_retry_without_restarting(
    tmp_path: Path, failure: str
) -> None:
    fixture = _fixture(tmp_path)
    (fixture["lifecycle"] / failure).touch()
    first = _run(fixture)
    assert first.returncode != 0
    assert _actual(fixture, "/var/lib/detection-engineering/forwarder-bootstrap-in-progress.yml").is_file()
    (fixture["lifecycle"] / failure).unlink()
    before = len(_calls(fixture))
    second = _run(fixture)
    assert second.returncode != 0
    later = _calls(fixture)[before:]
    assert not any(c.startswith("start ") or c.startswith("enable boot-start") for c in later)


def test_root_or_caller_substituted_service_identity_is_refused(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    contract = copy.deepcopy(fixture["variables"]["detection_forwarder_bootstrap_contract"])
    contract["observed"]["service_user"] = "root"
    result = _run(
        fixture,
        detection_forwarder_bootstrap_contract=contract,
        detection_forwarder_service_user="root",
    )
    assert result.returncode != 0
    _assert_no_mutation(fixture)


def test_canonical_lifecycle_paths_cannot_be_substituted(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    result = _run(
        fixture,
        detection_forwarder_marker_path="/var/lib/detection-engineering/forwarder-bootstrap.yml.suffix",
    )
    assert result.returncode != 0
    _assert_no_mutation(fixture)


def test_missing_identity_probe_prerequisite_refuses_before_package_mutation(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    result = _run(fixture, detection_forwarder_runuser=str(tmp_path / "missing-runuser"))
    assert result.returncode != 0
    _assert_no_mutation(fixture)


def test_kernel_enforces_readability_as_distinct_nonroot_uid(tmp_path: Path) -> None:
    """Exercise production read probes with a real kernel UID transition."""

    if os.environ.get("DETECTION_FORWARDER_ACL_NAMESPACE") != "1":
        command = [
            "unshare", "--user",
            "--map-users", f"0:{os.getuid()}:1",
            "--map-users", "1000:100000:1",
            "--map-groups", f"0:{os.getgid()}:1",
            "--map-groups", "1000:100000:1",
            "env", "DETECTION_FORWARDER_ACL_NAMESPACE=1",
            os.sys.executable, "-m", "pytest", "-q",
            f"{Path(__file__).resolve()}::test_kernel_enforces_readability_as_distinct_nonroot_uid",
        ]
        result = subprocess.run(command, cwd=REPOSITORY_ROOT, text=True, capture_output=True, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        return

    fixture = _fixture(tmp_path, "runner")
    logger = f"printf '%s\\n' \"$*\" >> {fixture['calls']}"
    _executable(fixture["bin"] / "runuser", f'''{logger}
[ "$1" = --user ] && [ "$2" = splunkfwd ] && [ "$3" = -- ] || exit 80
if [ "$4" = test ]; then
  shift 3
  [ "$1" = test ] || exit 81
  shift
  exec /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups /usr/bin/test "$@"
fi
shift 3
exec "$@"''')
    boundary = fixture["root"]
    while boundary != Path("/tmp"):
        subprocess.run(["setfacl", "-m", "u:1000:x", str(boundary)], check=True)
        boundary = boundary.parent
    for item in fixture["variables"]["detection_forwarder_inputs"]:
        actual = _actual(fixture, item["path"])
        parent = actual.parent
        while parent != fixture["root"]:
            subprocess.run(["setfacl", "-m", "u:1000:x", str(parent)], check=True)
            parent = parent.parent
        subprocess.run(["setfacl", "-m", "u:1000:r", str(actual)], check=True)
    result = _run(fixture)
    assert result.returncode == 0, result.stdout + result.stderr


def test_uf_has_no_parsing_or_redaction_configuration() -> None:
    production = "\n".join(
        p.read_text(encoding="utf-8") for p in (REPOSITORY_ROOT / "ansible/roles" / ROLE).rglob("*")
        if p.is_file() and "tests" not in p.parts
    ).lower()
    for forbidden in (
        "props.conf", "transforms.conf", "sedcmd", "/var/lib/docker/containers",
        "/var/log/containers", "kubelet", "producer-gaps", "audit_dispatch",
        "gitlab_logs", "systemd_adapter", "setfacl", "getfacl",
    ):
        assert forbidden not in production
