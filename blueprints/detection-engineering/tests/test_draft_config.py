from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
UF_SHA256 = "c2ff5b4f53dce3f245231044291a9732a141099c24dabfe32d565e1487e4707e"
UF_URL = (
    "https://download.splunk.com/products/universalforwarder/releases/"
    "10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb"
)
COMMON_INPUTS = [
    {"path": "/var/log/auth.log", "index": "de_linux", "sourcetype": "linux:auth", "safe_fields": ["_time", "host", "source", "sourcetype", "message"]},
    {"path": "/var/log/syslog", "index": "de_linux", "sourcetype": "linux:system", "safe_fields": ["_time", "host", "source", "sourcetype", "message"]},
    {"path": "/var/log/laurel/audit.log", "index": "de_linux", "sourcetype": "linux:audit:laurel", "safe_fields": ["_time", "host", "source", "sourcetype"]},
]
EXPECTED_INPUTS = {
    "gitlab": COMMON_INPUTS,
    "runner": COMMON_INPUTS + [
        {"path": "/var/log/detection-engineering/runner-registration.jsonl", "index": "de_runner", "sourcetype": "gitlab:runner:registration", "safe_fields": ["_time", "host", "source", "sourcetype", "message"]}
    ],
    "workload": COMMON_INPUTS,
}


def _role_names(vm):
    return [entry if isinstance(entry, str) else entry["name"] for entry in vm["roles"]]


def test_canonical_range_is_populated_and_save_ready():
    text = (ROOT / "range-config.yml").read_text(encoding="utf-8")
    config = yaml.safe_load(text)
    render = config["ludus_extensions"]["detection_engineering_publication"]
    assert render["mode"] == "public-save"
    assert render["save_ready"] is True
    assert render["deployment_authorized"] is False
    assert "deployment_eligible" not in render
    vms = config["ludus"]
    assert len(vms) == 5
    assert [vm["vm_name"] for vm in vms] == [f"{{{{ range_id }}}}-{suffix}" for suffix in ("gitlab", "runner", "malcolm", "splunk", "workload")]
    assert [vm["ip_last_octet"] for vm in vms] == [11, 12, 13, 14, 15]
    assert all(vm["template"] == "debian-12-x64-server-template" for vm in vms)
    assert [(vm["ram_gb"], vm["cpus"], vm["vlan"]) for vm in vms] == [(8, 4, 10), (8, 4, 10), (64, 8, 10), (12, 4, 10), (16, 6, 10)]
    assert sum(vm["ram_gb"] for vm in vms) == 108
    assert sum(vm["cpus"] for vm in vms) == 26
    assert "config: range-config.yml" in (ROOT / "blueprint.yml").read_text(encoding="utf-8")
    assert all("testing" not in vm for vm in vms)
    for vm in (vms[0], vms[1], vms[3], vms[4]):
        assert vm["linux"]["packages"] == [
            "acl", "auditd", "ca-certificates", "curl", "gnupg", "logrotate", "python3", "rsyslog"
        ]
    assert "linux" in vms[2]
    assert vms[2]["linux"] is True
    assert vms[2]["role_vars"]["ludus_install_malcolm_user"] == "debian"
    assert vms[2]["role_vars"]["ludus_install_malcolm_install_dir"] == "/home/debian/Malcolm"
    assert vms[2]["role_vars"]["ludus_install_malcolm_venv_dir"] == "/home/debian/Malcolm/.venv"
    assert vms[2]["role_vars"]["ludus_install_malcolm_admin_username"] == "debian"
    assert vms[2]["role_vars"]["ludus_install_malcolm_admin_password"] == "debian"
    assert vms[3]["role_vars"]["detection_splunk_admin_username"] == "debian"
    assert vms[3]["role_vars"]["detection_splunk_admin_password"] == "debian"
    assert vms[4]["role_vars"]["detection_runtime_token_state"] == "present"
    assert vms[4]["role_vars"]["detection_workload_user"] == "debian"


def test_existing_debian_login_is_reused_without_login_password_mutation():
    repo = ROOT.parents[1]
    workload_defaults = yaml.safe_load(
        (repo / "ansible/roles/ludus_detection_workload/defaults/main.yml").read_text()
    )
    assert workload_defaults["detection_workload_user"] == "debian"
    assert workload_defaults["detection_workload_home"] == "/home/debian"
    workload_tasks = "\n".join(
        path.read_text() for path in (repo / "ansible/roles/ludus_detection_workload/tasks").glob("*.yml")
    )
    assert "--system, --create-home, --shell, /usr/sbin/nologin, {{ detection_workload_user }}" not in workload_tasks
    assert "password:" not in workload_tasks and "chpasswd" not in workload_tasks

    malcolm_defaults = yaml.safe_load(
        (repo / "ansible/roles/ludus_install_malcolm/defaults/main.yml").read_text()
    )
    assert malcolm_defaults["ludus_install_malcolm_user"] == "debian"
    assert malcolm_defaults["ludus_install_malcolm_install_dir"] == "/home/debian/Malcolm"
    malcolm_tasks = "\n".join(
        path.read_text() for path in (repo / "ansible/roles/ludus_install_malcolm/tasks").glob("*.yml")
    )
    assert "ansible.builtin.user" not in malcolm_tasks


def test_forwarder_artifact_and_profiles_are_correctly_bound():
    vms = {vm["hostname"].rsplit("-", 1)[-1]: vm for vm in yaml.safe_load((ROOT / "range-config.yml").read_text())["ludus"]}
    forwarder = {
        "version": "10.6.1.1",
        "build": "b2ae2962645c",
        "url": UF_URL,
        "sha256": UF_SHA256,
        "download_auth_required": False,
    }
    for profile in ("gitlab", "runner", "workload"):
        vars_ = vms[profile]["role_vars"]
        assert vars_["detection_forwarder_artifact"] == forwarder
        assert vars_["detection_forwarder_bootstrap_contract"]["status"] == "VERIFIED"
        assert vars_["detection_forwarder_bootstrap_contract"]["observed"]["unit"]["effective_user"] == "splunkfwd"
        assert vars_["detection_forwarder_profile"] == profile
        assert vars_["detection_forwarder_inputs"] == EXPECTED_INPUTS[profile]
    splunk_vars = vms["splunk"]["role_vars"]
    assert splunk_vars["detection_splunk_artifact"] == {
        "version": "10.6.1.1",
        "build": "b2ae2962645c",
        "url": "https://download.splunk.com/products/splunk/releases/10.6.1.1/linux/splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb",
        "sha256": "2d917d11d09f312e27f22280f7ad3536d4e1abff20a9726aeeb8b08cfb61c9db",
        "download_auth_required": False,
    }
    text = (ROOT / "range-config.yml").read_text()
    assert "splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb" in text
    assert all("c2ff5b4f53dce3f245231044291a9732a141099c24dabfe32d565e1487e4707e" not in str(vm["role_vars"].get("detection_splunk_artifact")) for vm in vms.values())


def test_pipeline_roles_and_peer_dependencies_are_not_misordered():
    vms = {vm["hostname"].rsplit("-", 1)[-1]: vm for vm in yaml.safe_load((ROOT / "range-config.yml").read_text())["ludus"]}
    expected = {
        "gitlab": ["ludus_detection_gitlab", "ludus_detection_forwarder_pipeline"],
        "runner": ["ludus_detection_runner", "ludus_detection_forwarder_pipeline"],
        "workload": ["ludus_detection_workload", "ludus_detection_forwarder_pipeline"],
        "splunk": ["ludus_detection_splunk"],
    }
    for name, expected_roles in expected.items():
        assert _role_names(vms[name]) == expected_roles
    runner_dep = vms["runner"]["roles"][0]["depends_on"]
    assert runner_dep == [{"vm_name": "{{ range_id }}-gitlab", "role": "ludus_detection_gitlab"}]
    workload_dep = vms["workload"]["roles"][0]["depends_on"]
    assert workload_dep == [{"vm_name": "{{ range_id }}-splunk", "role": "ludus_detection_splunk"}]
    for name in ("gitlab", "runner", "workload"):
        pipeline_dep = vms[name]["roles"][1]["depends_on"]
        assert pipeline_dep == [{"vm_name": "{{ range_id }}-splunk", "role": "ludus_detection_splunk"}]
    assert "ludus_detection_linux_logging" not in {role for vm in vms.values() for role in _role_names(vm)}
    assert "role_splunk_collector_linuxv" not in {role for vm in vms.values() for role in _role_names(vm)}
    assert all(not any(key.startswith("detection_firewall_") for key in vm["role_vars"]) for vm in vms.values())


def test_splunk_local_logging_is_role_internal_without_fake_role_var():
    text = (ROOT / "range-config.yml").read_text(encoding="utf-8")
    splunk = next(vm for vm in yaml.safe_load(text)["ludus"] if vm["hostname"].endswith("-splunk"))
    assert _role_names(splunk) == ["ludus_detection_splunk"]
    assert "detection_splunk_local_logging_order" not in splunk["role_vars"]
    role_main = (ROOT.parents[1] / "ansible/roles/ludus_detection_splunk/tasks/main.yml").read_text()
    assert role_main.index("Install verified Splunk Debian package") < role_main.index("Configure native Linux logging")
    assert role_main.index("Configure native Linux logging") < role_main.index("Bootstrap Splunk without credentials")
