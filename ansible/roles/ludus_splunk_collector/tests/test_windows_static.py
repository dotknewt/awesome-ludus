"""Static Windows collector contracts; never execute role or PowerShell code."""

from pathlib import Path
import copy
import configparser
import re
import unittest

import yaml
from jinja2 import Environment, StrictUndefined, meta
from ansible.plugins.filter.core import to_bool


ROLE = Path(__file__).resolve().parents[1]
WINDOWS = ROLE / "tasks/windows"
EXAMPLE = Path(__file__).resolve().parents[4] / "docs/examples/windows-splunk"
MSI_URL = (
    "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/"
    "windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi"
)
MSI_CHECKSUM = (
    "sha512:980658ef29a964e430ee7b601b170324185a2d93fcee83f55d992a522d20355dc"
    "784f2947839690b12265ba775f861810d610244c7cc978c65e20f588147f693"
)


def _yaml(path, default=None):
    if not path.exists():
        return default
    return yaml.safe_load(path.read_text()) or default


def _flatten(tasks):
    for task in tasks or []:
        yield task
        for section in ("block", "rescue", "always"):
            yield from _flatten(task.get(section, []))


def _module(task, name):
    aliases = {
        "template": ("ansible.windows.win_template", "community.windows.win_template", "win_template"),
        "file": ("ansible.windows.win_file", "community.windows.win_file", "win_file"),
        "uri": ("ansible.windows.win_uri", "community.windows.win_uri", "win_uri"),
        "stat": ("ansible.windows.win_stat", "community.windows.win_stat", "win_stat"),
        "assert": ("ansible.builtin.assert", "assert"),
        "acl": ("ansible.windows.win_acl", "community.windows.win_acl", "win_acl"),
        "acl_inheritance": ("ansible.windows.win_acl_inheritance", "community.windows.win_acl_inheritance", "win_acl_inheritance"),
        "get_url": ("ansible.windows.win_get_url", "community.windows.win_get_url", "win_get_url"),
        "package": ("ansible.windows.win_package", "community.windows.win_package", "win_package"),
        "powershell": ("ansible.windows.win_powershell", "community.windows.win_powershell", "win_powershell"),
        "service": ("ansible.windows.win_service", "community.windows.win_service", "win_service"),
        "copy": ("ansible.windows.win_copy", "community.windows.win_copy", "win_copy"),
    }
    for key in ("ansible.builtin." + name, name, *aliases.get(name, ())):
        if key in task:
            return task[key]
    return None


def _tasks():
    """Resolve only static Windows task imports; missing future files stay test failures."""
    entry = ROLE / "tasks/main.yml"

    def walk(tasks, origin, inherited_when=()):
        for original in tasks or []:
            task = copy.deepcopy(original)
            own_when = task.get("when", [])
            if isinstance(own_when, str):
                own_when = [own_when]
            task["_effective_when"] = [*inherited_when, *own_when]
            yield task
            for section in ("block", "rescue", "always"):
                yield from walk(task.get(section, []), origin, task["_effective_when"])
            imported = task.get("ansible.builtin.import_tasks", task.get("import_tasks"))
            if isinstance(imported, str) and "{{" not in imported:
                target = (origin.parent / imported).resolve()
                if target.exists() and target.is_relative_to(WINDOWS.resolve()):
                    yield from walk(_yaml(target, []), target, task["_effective_when"])

    return list(walk(_yaml(entry, []), entry)) if entry.exists() else []


def _windows_source():
    """Read only Windows-owned task/template/script sources and Windows handlers."""
    chunks = []
    for folder in (WINDOWS, ROLE / "files/windows"):
        if folder.exists():
            chunks.extend(p.read_text() for p in folder.rglob("*") if p.is_file())
    for name in ("windows-inputs.conf.j2", "windows-outputs.conf.j2", "windows-user-seed.conf.j2"):
        path = ROLE / "templates" / name
        if path.exists():
            chunks.append(path.read_text())
    handlers = _yaml(ROLE / "handlers/main.yml", []) or []
    for handler in _flatten(handlers):
        if "windows" in str(handler).lower() or "win_" in str(handler).lower():
            chunks.append(str(handler))
    return "\n".join(chunks)


def _script(task):
    module = _module(task, "powershell")
    return module.get("script", "") if isinstance(module, dict) else ""


def _module_name(task):
    for key in task:
        if key.startswith(("ansible.windows.", "community.windows.")):
            return key.rsplit(".", 1)[-1]
    return next((key for key in task if key.startswith("ansible.builtin.")), "")


class WindowsCollectorStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = _yaml(ROLE / "defaults/main.yml", {})
        cls.main = _yaml(ROLE / "tasks/main.yml", []) or []
        cls.tasks = _tasks()
        cls.source = _windows_source()

    def test_windows_defaults_are_verified_and_namespaced(self):
        expected = {
            "ludus_splunk_collector_windows_package_url": MSI_URL,
            "ludus_splunk_collector_windows_package_checksum": MSI_CHECKSUM,
            "ludus_splunk_collector_windows_version": "10.6.1.1",
            "ludus_splunk_collector_windows_msi_product_version": "10.6.1.1",
            "ludus_splunk_collector_windows_security_index": "winlogs",
            "ludus_splunk_collector_windows_sysmon_index": "sysmon",
            "ludus_splunk_collector_windows_silk_index": "etw",
        }
        for key, value in expected.items():
            with self.subTest(key=key):
                self.assertEqual(self.defaults.get(key), value)
        self.assertFalse(any("linux" in key for key in expected))
        self.assertEqual(self.defaults.get("ludus_splunk_collector_package_url", "").split("/")[-1],
                         "splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb")
        self.assertIn("ludus_splunk_collector_monitors", self.defaults)

    def test_standalone_example_orders_server_sysmon_and_collector_explicitly(self):
        config_path = EXAMPLE / "range-config.yml"
        requirements_path = EXAMPLE / "requirements.yml"
        self.assertTrue(config_path.is_file(), "missing standalone Windows/Splunk example")
        self.assertTrue(requirements_path.is_file(), "missing pinned Windows collections")
        config = yaml.safe_load(config_path.read_text())
        requirements = yaml.safe_load(requirements_path.read_text())
        server_vm = next(vm for vm in config["ludus"] if vm.get("linux") is True)
        windows_vm = next(vm for vm in config["ludus"] if "windows" in vm)
        server_roles = server_vm["roles"]
        windows_roles = windows_vm["roles"]
        self.assertEqual(server_roles[0], "ludus_splunk_server")
        self.assertIs(server_vm["role_vars"].get("ludus_splunk_server_accept_license"), True)
        self.assertIs(server_vm["role_vars"].get("ludus_splunk_server_receiver_enabled"), True)
        self.assertEqual(server_vm["role_vars"].get("ludus_splunk_server_receiver_port"), 9997)
        self.assertEqual(server_vm["role_vars"]["ludus_splunk_server_indexes"],
                         ["winlogs", "sysmon", "etw"])
        self.assertEqual([role if isinstance(role, str) else role["name"]
                          for role in windows_roles],
                         ["ludus_install_sysmon", "ludus_splunk_collector"])
        self.assertEqual(windows_roles[1]["depends_on"], [
            {"vm_name": server_vm["vm_name"], "role": "ludus_splunk_server"},
            {"vm_name": windows_vm["vm_name"], "role": "ludus_install_sysmon"},
        ])
        self.assertIn("ludus_splunk_server_indexes: [winlogs, sysmon, etw]",
                      config_path.read_text())
        self.assertEqual(config["ludus"][0]["roles"], server_roles)
        self.assertEqual(requirements, {"collections": [
            {"name": "ansible.windows", "version": "2.7.0"},
            {"name": "community.windows", "version": "2.3.0"},
        ]})
        readme = (EXAMPLE / "README.md").read_text().lower()
        for warning in ("unverified", "placeholder", "target server", "template"):
            self.assertIn(warning, readme)
        for forbidden in ("hec", "firewall", "tls", "blacklist1", "pstree"):
            self.assertNotIn(forbidden, config_path.read_text().lower())

        sysmon_harness_path = EXAMPLE.parents[2] / "ansible/roles/ludus_install_sysmon/tests/syntax.yml"
        self.assertTrue(sysmon_harness_path.is_file(), "missing Sysmon role syntax harness")
        harness = yaml.safe_load(sysmon_harness_path.read_text())[0]
        self.assertEqual([role if isinstance(role, str) else role.get("role")
                          for role in harness["roles"]], ["ludus_install_sysmon"])
        self.assertTrue(any("ansible.builtin.fail" in task for task in harness["pre_tasks"]))
        self.assertTrue(all("when" not in task for task in harness["pre_tasks"]))
        self.assertIn("sysmon_config_file", harness["vars"])
        self.assertIn("sysmon_download_latest", harness["vars"])

    def test_real_entrypoint_guards_platform_and_scopes_privilege(self):
        self.assertTrue(self.main, "missing real role entrypoint")
        imports = [task for task in self.tasks
                   if task.get("ansible.builtin.import_tasks", task.get("import_tasks")) is not None]
        import_paths = [task.get("ansible.builtin.import_tasks", task.get("import_tasks")) for task in imports]
        self.assertTrue(any(isinstance(path, str) and "windows" in path.lower() for path in import_paths),
                        "entrypoint must statically import the Windows branch")
        guarded_imports = [task for task in imports if isinstance(
            task.get("ansible.builtin.import_tasks", task.get("import_tasks")), str)
            and "windows" in task.get("ansible.builtin.import_tasks", task.get("import_tasks")).lower()]
        self.assertTrue(guarded_imports)
        self.assertTrue(any("win" in str(task.get("_effective_when", [])).lower() or
                            "windows" in str(task.get("_effective_when", [])).lower() for task in guarded_imports),
                        "Windows import must carry a Windows platform guard")
        linux_imports = [task for task in imports if task not in guarded_imports]
        self.assertTrue(linux_imports)
        self.assertTrue(any("ansible_system == 'linux'" in str(task.get("_effective_when", [])).lower()
                            for task in linux_imports), "existing Linux task branch must remain Linux-guarded")
        for name in ("validate.yml", "inspect.yml", "install.yml", "configure.yml"):
            self.assertTrue((WINDOWS / name).is_file(), f"missing Windows phase {name}")
        windows_text = "\n".join(p.read_text() for p in WINDOWS.rglob("*.y*ml")) if WINDOWS.exists() else ""
        self.assertRegex(windows_text, r"(?i)(?:ansible_distribution|ansible_os_family|ansible_distribution_major_version)")
        for release in ("2019", "2022", "2025", "5.1", "x64"):
            self.assertIn(release, windows_text)

    def test_preflight_identity_phase_order_and_fail_closed_recovery(self):
        joined = self.source.lower()
        for token in (
            "splunkuniversalforwarder", "splunkforwarder", "programdata", "schema_version",
            "bootstrappending", "ready", "reparse", "productversion", "sha512", "reboot_required",
        ):
            self.assertIn(token.lower(), joined)
        imported = [task.get("ansible.builtin.import_tasks", task.get("import_tasks")) for task in self.tasks]
        phases = ["validate.yml", "inspect.yml", "install.yml", "configure.yml"]
        phase_positions = [next((i for i, value in enumerate(imported) if value == phase), -1) for phase in phases]
        self.assertTrue(all(position >= 0 for position in phase_positions), "Windows phase imports are missing")
        self.assertEqual(phase_positions, sorted(phase_positions), "phase execution order must be validate, inspect, install, configure")
        for forbidden in ("USE_LOCAL_SYSTEM=1", "SPLUNKUSERNAME", "SPLUNKPASSWORD", "GENRANDOMPASSWORD=1"):
            self.assertNotIn(forbidden.lower(), joined)
        for required in ("AGREETOLICENSE=Yes", "LAUNCHSPLUNK=0", "GENRANDOMPASSWORD=0",
                         "PRIVILEGEBACKUP=0", "PRIVILEGESECURITY=0", "PRIVILEGEIMPERSONATE=0",
                         "GROUPPERFORMANCEMONITORUSERS=0"):
            self.assertIn(required.lower(), joined)
        for required_property in ("PRIVILEGEBACKUP", "PRIVILEGESECURITY", "PRIVILEGEIMPERSONATE"):
            self.assertIn(required_property.lower() + "=0", joined)
            self.assertNotIn(required_property.lower().replace("privilege", "privilege_"), joined)

    def test_seed_acl_readiness_and_reboot_failure_order(self):
        source = self.source.lower()
        for token in ("user-seed.conf", "no_log", "diff", "127.0.0.1", "passwd",
                      "nt service\\splunkforwarder", "securitydescriptor",
                      "savechanges", "deny", "sid"):
            self.assertIn(token.lower(), source)
        self.assertNotRegex(source, r"(?i)(?:localgroup|adsi|se_security_privilege|use_local_system\s*[:=]\s*['\"]?1)")
        self.assertNotRegex(source, r"(?im)^\s*(?:command|win_command|shell|win_shell):.*(?:password|hash)")
        tasks = self.tasks
        seed_writes = [i for i, task in enumerate(tasks) if _module(task, "template") is not None
                       and "user-seed.conf" in str(_module(task, "template"))]
        protected = [i for i, task in enumerate(tasks)
                     if "Set-Acl" in _script(task) and "user-seed.conf" in _script(task)]
        auth = [i for i, task in enumerate(tasks) if _module(task, "uri") is not None
                and "127.0.0.1" in str(_module(task, "uri"))]
        readiness = [i for i, task in enumerate(tasks)
                     if _module(task, "assert") is not None and "passwd" in str(_module(task, "assert"))]
        cleanup = [i for i, task in enumerate(tasks) if _module(task, "file") is not None
                   and _module(task, "file").get("state") == "absent"
                   and "user-seed.conf" in str(_module(task, "file"))]
        self.assertTrue(seed_writes, "missing protected fresh-install seed write")
        self.assertTrue(protected, "seed file ACL protection must be explicit before writing secret content")
        self.assertLess(max(protected), min(seed_writes))
        self.assertTrue(auth and readiness and cleanup, "missing authentication, passwd readiness, or cleanup task")
        self.assertLess(max(max(auth), max(readiness)), min(cleanup))
        self.assertTrue(any(task.get("no_log") is True and task.get("diff") is False for task in tasks
                            if _module(task, "template") is not None and "user-seed.conf" in str(task)),
                        "seed rendering must disable logs and diffs")
        eventlog_acl = next((_script(task) for task in tasks
                             if "Get-WinEvent -ListLog" in _script(task)
                             and "CommonAce" in _script(task)), "")
        self.assertTrue(eventlog_acl, "missing Event Log ACL planning script")
        self.assertRegex(eventlog_acl, r"(?i)AccessMask\s+-band\s+1")
        self.assertRegex(eventlog_acl, r"(?i)CommonAce\([\s\S]{0,200},\s*1,\s*\$sid")
        self.assertNotIn("FileSystemRights", eventlog_acl,
                         "Event Log READ mask is not an NTFS FileSystemRights value")

    def test_rendered_inputs_preserve_exact_three_channel_contract(self):
        path = ROLE / "templates/windows-inputs.conf.j2"
        self.assertTrue(path.is_file(), "missing actual Windows inputs template")
        environment = Environment(undefined=StrictUndefined)
        environment.filters["bool"] = to_bool
        template = environment.from_string(path.read_text())
        ast = environment.parse(path.read_text())
        undeclared = meta.find_undeclared_variables(ast)
        presence_vars = {name for name in undeclared if "silk" in name.lower() and
                         any(word in name.lower() for word in ("present", "exists", "available"))}
        self.assertTrue(presence_vars, "template must receive explicit Silk channel presence state")
        common = {name: "test-value" for name in undeclared}
        common.update({
            "ludus_splunk_collector_windows_security_index": "winlogs",
            "ludus_splunk_collector_windows_sysmon_index": "sysmon",
            "ludus_splunk_collector_windows_silk_index": "etw",
        })
        for name in presence_vars:
            common[name] = True
        rendered = template.render(common)
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string(rendered)
        self.assertEqual(parser["WinEventLog://Security"].get("renderXml"), "1")
        self.assertEqual(parser["WinEventLog://Security"].get("start_from"), "oldest")
        self.assertEqual(parser["WinEventLog://Security"].get("current_only"), "0")
        self.assertEqual(parser["WinEventLog://Security"].get("index"), "winlogs")
        self.assertFalse(any(key.lower().startswith("blacklist") for key in parser["WinEventLog://Security"]))
        sysmon = parser["WinEventLog://Microsoft-Windows-Sysmon/Operational"]
        self.assertEqual(sysmon.get("source"), "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
        self.assertEqual(sysmon.get("index"), "sysmon")
        silk = parser["WinEventLog://SilkService-Log"]
        self.assertEqual({k: silk.get(k) for k in ("disabled", "index", "sourcetype")},
                         {"disabled": "0", "index": "etw", "sourcetype": "json"})
        self.assertFalse(any(key.lower() in {"rendering", "current_only", "start_from"} for key in silk))
        for name in presence_vars:
            common[name] = False
        absent_rendered = template.render(common)
        absent = configparser.ConfigParser(interpolation=None, strict=True)
        absent.read_string(absent_rendered)
        absent_silk = absent["WinEventLog://SilkService-Log"]
        self.assertEqual({k: absent_silk.get(k) for k in ("disabled", "index", "sourcetype")},
                         {"disabled": "1", "index": "etw", "sourcetype": "json"})

    def test_channel_presence_inheritance_conflicts_hash_guard_and_safe_values(self):
        source = self.source
        lower = source.lower()
        for token in ("SilkService-Log", "warning", "hash", "inputs.conf", "outputs.conf", "notify"):
            self.assertIn(token.lower(), lower)
        self.assertNotRegex(source, r"(?im)^\s*(?:blacklist\d+|whitelist\d+)\s*=")
        self.assertNotRegex(source, r"(?i)(?:Sysmon|sysmon).*?(?:blacklist|whitelist)")
        self.assertNotIn("ludus_install_sysmon", source)
        # Inspect production validators in the Windows source; never substitute a test regex.
        self.assertRegex(lower, r"(?:fullmatch|\\z|\\a|\\$).*(?:index|channel|input|identifier)|(?:index|channel|input|identifier).*(?:fullmatch|\\z|\\$)")
        self.assertTrue("\\n" in lower or "\\r" in lower or "control" in lower,
                        "production input validation must explicitly reject newline/control characters")

    def test_powershell_inspection_avoids_readonly_home_and_exactly_checks_service_path(self):
        inspect_task = next((task for task in self.tasks if "inspect.yml" in str(
            task.get("ansible.builtin.import_tasks", task.get("import_tasks")))), None)
        self.assertIsNotNone(inspect_task, "missing Windows inspect phase import")
        inspect_scripts = [_script(task) for task in self.tasks if _script(task)]
        inspection_script = next((script for script in inspect_scripts if "Get-WinEvent" in script and "markerPath" in script), "")
        self.assertTrue(inspection_script, "missing production PowerShell inspection script")
        self.assertNotRegex(inspection_script, r"(?im)^\s*\$home\s*=")
        self.assertRegex(inspection_script, r"(?i)\$splunkhome\s*=")
        # Path acceptance must compare canonical executable paths, not substring or regex matches.
        path_checks = "\n".join(script for script in inspect_scripts if "PathName" in script)
        self.assertRegex(path_checks, r"(?i)GetFullPath")
        self.assertRegex(path_checks, r"(?i)-ieq")
        self.assertIn(r"C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe", path_checks)
        self.assertNotRegex(path_checks, r"(?i)PathName\s+-match|service_path\s+is\s+search")

    def test_executable_version_lookup_uses_established_splunk_home(self):
        inspect_script = next((_script(task) for task in self.tasks
                               if "Get-CimInstance Win32_Service" in _script(task)), "")
        self.assertTrue(inspect_script, "missing service inspection script")
        self.assertRegex(inspect_script, r"(?im)^\s*\$splunkHome\s*=")
        self.assertRegex(inspect_script, r"(?i)Test-Path\s+-LiteralPath\s+\$splunkHome\b")
        self.assertRegex(inspect_script,
                         r"(?i)Join-Path\s+\$splunkHome\s+'bin\\splunkd\.exe'")
        self.assertNotRegex(inspect_script, r"(?i)\$home\b")

    def test_pending_transition_is_result_gated_and_fresh_marker_is_reinspected(self):
        transition = next((task for task in self.tasks if "phase -ne 'pending'" in _script(task)), None)
        self.assertIsNotNone(transition, "missing explicit pending-to-bootstrapPending transition")
        gate = str(transition.get("when", ""))
        self.assertIn("ludus_splunk_collector_windows_phase", gate)
        self.assertRegex(gate, r"windows_package\s+is\s+defined")
        self.assertRegex(gate, r"windows_package\.skipped\s*\|\s*default\(false\)")
        self.assertIn("Get-Content", _script(transition))
        self.assertIn("$marker.phase", _script(transition))
        self.assertRegex(_script(transition), r"phase\s+-ne\s+'pending'")
        self.assertTrue(any(token in gate for token in ("reboot_required", "changed", "pending")))
        self.assertTrue(any("Get-Content" in _script(task) and "ownership.json" in _script(task)
                            and "schema_version" in _script(task) for task in self.tasks),
                        "ownership state must be re-read from the authoritative marker after install")

    def test_win_uri_retries_on_actual_status_code(self):
        auth_tasks = [task for task in self.tasks if _module(task, "uri") is not None
                      and "127.0.0.1" in str(_module(task, "uri"))]
        self.assertTrue(auth_tasks, "missing fresh loopback authentication")
        for task in auth_tasks:
            self.assertEqual(_module(task, "uri").get("status_code"), 200)
            self.assertIn("status_code", str(task.get("until", "")))
            self.assertNotRegex(str(task.get("until", "")), r"\.status\b")

    def test_checksum_contract_and_product_version_precede_install(self):
        downloads = [(i, task, _module(task, "get_url")) for i, task in enumerate(self.tasks)
                     if _module(task, "get_url") is not None]
        installs = [(i, task, _module(task, "package")) for i, task in enumerate(self.tasks)
                    if _module(task, "package") is not None]
        self.assertTrue(downloads, "missing Windows MSI download")
        self.assertTrue(installs, "missing Windows MSI install")
        for _, _, args in downloads:
            self.assertEqual(args.get("checksum_algorithm"), "sha512")
            checksum = str(args.get("checksum", ""))
            self.assertIn("ludus_splunk_collector_windows_package_checksum", checksum)
            self.assertIn("regex_replace('^sha512:', '')", checksum)
            bare_digest = self.defaults["ludus_splunk_collector_windows_package_checksum"].split(":", 1)[1]
            self.assertRegex(bare_digest, r"^[0-9a-f]{128}$")
        scripts = "\n".join(_script(task) for task in self.tasks)
        self.assertIn("ProductVersion", scripts)
        self.assertIn("UniversalForwarder", scripts)
        product_checks = [i for i, task in enumerate(self.tasks)
                          if "ProductVersion" in _script(task) and "MsiPath" in _script(task)]
        self.assertTrue(product_checks, "pinned MSI ProductVersion must be inspected before install")
        self.assertLess(max(i for i, _, _ in downloads), min(i for i, _, _ in installs))
        self.assertLess(min(product_checks), min(i for i, _, _ in installs),
                        "MSI ProductVersion must be verified before win_package mutation")

    def test_marker_schema_artifact_acl_hashes_and_readonly_reporting(self):
        source = self.source
        for field in ("schema_version", "artifact_url", "artifact_checksum", "artifact_version",
                      "service_name", "service_account", "inputs_sha256", "outputs_sha256", "phase"):
            self.assertIn(field, source)
        self.assertRegex(source, r"(?i)Get-Acl")
        self.assertRegex(source, r"(?i)Owner")
        self.assertRegex(source, r"(?i)\$entry\.acl\.Access\b")
        self.assertRegex(source, r"(?i)NT SERVICE\\SplunkForwarder")
        self.assertRegex(source, r"(?i)(?:remove|deny|not.*(?:write|modify)).{0,100}(?:service|SplunkForwarder)|(?:service|SplunkForwarder).{0,100}(?:write|modify).{0,100}(?:false|deny|absent)")
        inspect_tasks = [task for task in self.tasks if "Get-WinEvent" in _script(task) and "markerPath" in _script(task)]
        self.assertTrue(inspect_tasks)
        inspection_script = _script(inspect_tasks[0])
        all_source = "\n".join(_script(task) for task in self.tasks)
        assertion_text = "\n".join(str(_module(task, "assert")) for task in self.tasks)
        for field in ("schema_version", "artifact_url", "artifact_checksum", "artifact_version",
                      "service_name", "service_account", "inputs_sha256", "outputs_sha256", "phase"):
            self.assertIn("marker." + field, all_source + assertion_text,
                          "preflight/convergence must validate every authoritative marker field")
        self.assertIn("$Ansible.Failed", inspection_script)
        self.assertRegex(inspection_script,
                         r"(?i)\$markerAcl\s*=\s*Get-Acl\s+-LiteralPath\s+\$markerPath")
        self.assertRegex(inspection_script, r"(?i)IsInherited")
        self.assertRegex(inspection_script, r"(?i)FileSystemRights")
        self.assertRegex(inspection_script,
                         r"(?is)AccessControlType\s+-ne\s+'Allow'.{0,100}\$valid\s*=\s*\$false")
        self.assertRegex(inspection_script,
                         r"(?is)ruleSid\s+-notin\s+\$allowedOwners.{0,80}\$valid\s*=\s*\$false")
        self.assertTrue(any(task.get("changed_when") is False or "$Ansible.Changed = $false" in _script(task)
                            for task in inspect_tasks), "read-only inspection must report unchanged")
        ready_writers = [task for task in self.tasks if "inputs_sha256" in _script(task)
                         and "ownership.json" in _script(task)
                         and "Set-Content" in _script(task)]
        self.assertTrue(ready_writers)
        for task in ready_writers:
            script = _script(task)
            self.assertRegex(script, r"(?i)if\s*\(.*(?:-ne|-cne).*(?:inputs_sha256|outputs_sha256)")
            self.assertIn("$Ansible.Changed", script)
            self.assertRegex(script, r"(?is)if\s*\(.*(?:inputs_sha256|outputs_sha256).*?Set-Content")
            self.assertRegex(script, r"(?i)\$Ansible\.Changed\s*=\s*\$changed")

    def test_seed_acl_is_exclusive_and_protects_parent_before_secret_write(self):
        named = {task.get("name", ""): (i, task) for i, task in enumerate(self.tasks)}
        parent_acl_name = "Protect the seed parent using its inspected supported ACL"
        seed_acl_name = "Protect the seed file using its inspected supported ACL"
        self.assertIn(parent_acl_name, named)
        self.assertIn(seed_acl_name, named)
        _, parent_acl = named[parent_acl_name]
        _, seed_acl = named[seed_acl_name]
        template = next((i for i, task in enumerate(self.tasks)
                         if _module(task, "template") is not None
                         and "user-seed.conf" in str(_module(task, "template"))), None)
        self.assertIsNotNone(template)
        self.assertLess(named[parent_acl_name][0], named[seed_acl_name][0])
        self.assertLess(named[seed_acl_name][0], template)
        for task, expected_kind in ((parent_acl, "Directory"), (seed_acl, "File")):
            script = _script(task)
            for token in ("Get-Acl", "GetSecurityDescriptorSddlForm", "RawSecurityDescriptor",
                          "DiscretionaryAcl", "CommonAce", "IsCallback", "AccessDenied",
                          "Inherited", "AccessMask", "AceFlags", "SetAccessRuleProtection",
                          "Set-Acl", "FileSystemRights", "SecurityIdentifier", "ReparsePoint"):
                self.assertIn(token.lower(), script.lower(), f"{expected_kind} ACL lacks {token} validation")
            self.assertRegex(script, r"(?i)AceQualifier\s+-ne\s+.*AccessAllowed")
            self.assertRegex(script, r"(?i)if\s*\(.*IsCallback.*\).*throw")
            self.assertRegex(script, r"(?i)if\s*\(.*AccessDenied.*\).*throw")
            self.assertRegex(script, r"(?i)SetAccessRuleProtection\(\$true,\s*\$false\)")
            self.assertIn("Get-Acl -LiteralPath $Path" if expected_kind == "Directory"
                          else "Get-Acl -LiteralPath $path", script)
            self.assertNotIn("New-Object System.Security.AccessControl.DirectorySecurity", script)
            self.assertNotIn("New-Object System.Security.AccessControl.FileSecurity", script)
        parent_script = _script(parent_acl)
        seed_script = _script(seed_acl)
        self.assertIn("Get-SeedAclPlan $path 'Directory'", parent_script)
        self.assertIn("Get-SeedAclPlan $seed 'File'", parent_script,
                      "validate any existing seed before mutating the parent")
        self.assertIn("ReadAndExecute", parent_script)
        self.assertIn("$flags = if ($ExpectedKind -eq 'Directory') { 3 } else { 0 }", parent_script)
        self.assertIn("flags = $flags", parent_script)
        self.assertIn("FileSystemRights]::Read", seed_script)
        self.assertIn("FileSystemRights]::ReadAndExecute", parent_script)
        for script in (parent_script, seed_script):
            self.assertIn("FileSystemRights]::Synchronize", script,
                          "expected ACE masks must include .NET's implicit Synchronize right")
        self.assertIn("[int]$ace.AceFlags -ne 0", seed_script)
        self.assertIn("$parentExpected[$serviceSid] = [int]([System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor", seed_script)
        self.assertIn("$parentSeen.Count -ne 3", seed_script)

        # Existing resumable state is inspected before the install phase mutates MSI state.
        inspect_preflight = next((i, task) for i, task in enumerate(self.tasks)
                                 if task.get("name") == "Preflight existing bootstrap seed ACLs before installation")
        install = next(i for i, task in enumerate(self.tasks)
                       if task.get("ansible.builtin.import_tasks", task.get("import_tasks")) == "install.yml")
        self.assertLess(inspect_preflight[0], install)
        self.assertIn("bootstrapPending", str(inspect_preflight[1].get("when", "")))
        inspect_acl_script = _script(inspect_preflight[1])
        self.assertNotIn("$ludus_splunk_collector_windows_inspection", inspect_acl_script,
                         "Ansible register variables are not PowerShell variables")
        self.assertIn("Test-ExistingSeedAcl $parent 'Directory'", inspect_acl_script)
        self.assertIn("Test-ExistingSeedAcl $seed 'File'", inspect_acl_script)
        self.assertIn("FileSystemRights]::Synchronize", inspect_acl_script)
        for token in ("DiscretionaryAcl", "AccessDenied", "IsCallback", "CommonAce",
                      "SecurityIdentifier", "FileSystemRights", "ReparsePoint", "$unrelated.Count"):
            self.assertIn(token.lower(), _script(inspect_preflight[1]).lower())

        # A post-MSI preflight runs at configure entry before marker/Event Log mutation.
        configure_preflight = next((i, task) for i, task in enumerate(self.tasks)
                                   if task.get("name") == "Preflight newly installed seed paths before marker or Event Log changes")
        first_eventlog = next(i for i, task in enumerate(self.tasks) if "Get-WinEvent" in _script(task)
                              and "SaveChanges" in _script(task))
        marker_transition = next(i for i, task in enumerate(self.tasks)
                                 if "Fresh-install ownership transition" in _script(task))
        self.assertLess(configure_preflight[0], marker_transition)
        self.assertLess(configure_preflight[0], first_eventlog)
        for token in ("DiscretionaryAcl", "AccessDenied", "IsCallback", "CommonAce",
                      "SecurityIdentifier", "FileSystemRights", "ReparsePoint", "$unrelated.Count"):
            self.assertIn(token.lower(), _script(configure_preflight[1]).lower())
        self.assertIn("FileSystemRights]::Synchronize", _script(configure_preflight[1]))
        self.assertIn("ludus_splunk_collector_windows_package.skipped", str(configure_preflight[1].get("when", "")))

        # Both paths are rechecked before the secret-bearing template operation.
        final_check = next((i, task) for i, task in enumerate(self.tasks)
                           if task.get("name") == "Recheck seed parent and file ACLs immediately before secret rendering")
        self.assertLess(final_check[0], template)
        self.assertIn("Get-Acl", _script(final_check[1]))
        self.assertIn("user-seed.conf", _script(final_check[1]))
        self.assertIn("system\\local", _script(final_check[1]))
        self.assertIn("$unrelated.Count", _script(final_check[1]))
        final_script = _script(final_check[1])
        self.assertIn("Assert-ProtectedSeedAcl $parent 'Directory'", final_script)
        self.assertIn("Assert-ProtectedSeedAcl $seed 'File'", final_script)
        self.assertIn("FileSystemRights]::Synchronize", final_script)
        self.assertIn("SetAccessRuleProtection($true, $false)", parent_script)
        self.assertIn("$acl.SetAccessRule($rule)", parent_script)
        self.assertIn("$acl.SetAccessRule($rule)", seed_script)

    def test_collision_scan_is_boundary_aware_and_preserves_vendor_defaults(self):
        inspect_script = next((_script(task) for task in self.tasks
                               if "Get-WinEvent" in _script(task) and "markerPath" in _script(task)), "")
        self.assertTrue(inspect_script)
        self.assertNotIn("StartsWith($owned)", inspect_script)
        self.assertIn("inputs.conf", inspect_script)
        self.assertIn("outputs.conf", inspect_script)
        self.assertRegex(inspect_script, r"(?i)(?:OrdinalIgnoreCase|Path]::GetFullPath|relative)")
        self.assertRegex(inspect_script, r"(?i)system\\default")
        self.assertRegex(inspect_script, r"(?i)defaultGroup")
        self.assertRegex(inspect_script, r"(?i)ludus_collector")

    def test_windows_indexes_use_shared_lowercase_validator_contract(self):
        assertions = "\n".join(str(_module(task, "assert").get("that", ""))
                               for task in self.tasks if _module(task, "assert") is not None)
        for var in ("ludus_splunk_collector_windows_security_index",
                    "ludus_splunk_collector_windows_sysmon_index",
                    "ludus_splunk_collector_windows_silk_index"):
            self.assertIn(var, assertions)
            expressions = [line for line in assertions.splitlines() if var in line]
            self.assertTrue(any("[a-z][a-z0-9_]{0,79}" in line for line in expressions),
                            f"{var} must match the shared server index contract")
        for reserved in ("main", "history", "summary", "_internal", "_audit", "_introspection"):
            self.assertIn(reserved, assertions)


if __name__ == "__main__":
    unittest.main()
