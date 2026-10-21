"""Static contracts for the consolidated Splunk forwarder role."""

from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).resolve().parents[1]


def _yaml(path, default=None):
    if not path.is_file():
        return default
    return yaml.safe_load(path.read_text()) or default


def _flatten(tasks):
    for task in tasks or []:
        yield task
        for section in ("block", "rescue", "always"):
            yield from _flatten(task.get(section, []))


def _module(task, name):
    aliases = {
        "win_template": ("ansible.windows.win_template", "community.windows.win_template", "win_template"),
    }
    for key in (f"ansible.builtin.{name}", name, *aliases.get(name, ())):
        if key in task:
            return task[key]
    return None


class ConsolidatedForwarderStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = _yaml(ROLE / "defaults/main.yml", {})
        cls.entrypoint = _yaml(ROLE / "tasks/main.yml", []) or []
        cls.meta = _yaml(ROLE / "meta/main.yml", {})
        cls.windows_syntax = _yaml(ROLE / "tests/syntax-windows.yml", []) or []
        cls.tasks = [
            task
            for path in sorted((ROLE / "tasks").rglob("*.y*ml"))
            for task in _flatten(_yaml(path, []))
        ] if (ROLE / "tasks").is_dir() else []

    def test_role_identity_and_shared_forwarder_defaults_have_clean_namespace(self):
        self.assertEqual(self.meta.get("galaxy_info", {}).get("role_name"), "splunk_forwarder")
        self.assertEqual(self.meta.get("galaxy_info", {}).get("author"), "dotknewt")
        self.assertFalse((ROLE.parent / "linux_splunk_forwarder").exists())
        self.assertFalse((ROLE.parent / "windows_splunk_forwarder").exists())
        self.assertEqual(self.defaults.get("splunk_version"), "10.6.1.1")
        self.assertEqual(self.defaults.get("splunk_build"), "b2ae2962645c")
        self.assertIs(self.defaults.get("splunk_accept_license"), False)
        self.assertTrue(any(key.startswith("splunk_forwarder_") for key in self.defaults))
        self.assertFalse(any(key.startswith(("ludus_splunk_collector_", "splunk_uf_", "splunk_admin_"))
                             for key in self.defaults), "legacy public aliases must be removed")

    def test_dispatch_guards_platform_and_scopes_windows_privilege(self):
        windows_import = next((task for task in self.entrypoint
                               if task.get("ansible.builtin.import_tasks", task.get("import_tasks")) == "windows/main.yml"), None)
        self.assertIsNotNone(windows_import, "entrypoint must statically dispatch to the Windows implementation")
        self.assertIn("win32nt", str(windows_import.get("when", "")).lower(),
                      "Windows task import must be Windows guarded")
        self.assertIsNot(windows_import.get("become"), True,
                         "Windows dispatch must not escalate privileges")

        linux_block = next((task for task in self.entrypoint
                            if isinstance(task.get("block"), list)
                            and "linux" in str(task.get("when", "")).lower()), None)
        self.assertIsNotNone(linux_block, "Linux work must remain inside its Linux-guarded block")
        self.assertIs(linux_block.get("become"), True, "become must scope only the Linux block")
        self.assertTrue(any(task.get("ansible.builtin.import_tasks", task.get("import_tasks"))
                            for task in _flatten(linux_block.get("block", []))),
                        "Linux block must retain static task imports")

        platform_assert = next((task for task in self.entrypoint
                                if _module(task, "assert") is not None
                                and "ansible_system" in str(_module(task, "assert"))), None)
        self.assertIsNotNone(platform_assert, "unsupported platforms must fail through the supported-system assertion")
        self.assertIn("Win32NT", str(_module(platform_assert, "assert")))
        self.assertIn("Linux", str(_module(platform_assert, "assert")))

        windows_templates = []
        for path in (ROLE / "tasks").rglob("*.y*ml"):
            if "windows" in str(path).lower():
                for task in _flatten(_yaml(path, [])):
                    if "ansible.windows.win_template" in task:
                        windows_templates.append(task)
                        self.assertIn("windows-", str(_module(task, "win_template").get("src", "")))
                    self.assertFalse(task.get("become") is True,
                                     "Windows tasks must not use become")
        self.assertTrue(windows_templates, "Windows flow must use explicit Windows template names")

    def test_windows_syntax_fixture_uses_only_standalone_public_inputs(self):
        self.assertEqual(len(self.windows_syntax), 1)
        inputs = self.windows_syntax[0].get("vars", {})
        self.assertTrue(inputs)
        self.assertTrue(all(name.startswith(("splunk_",)) for name in inputs),
                        "Windows harness must use the shared/forwarder namespaces")
        self.assertFalse(any(name.startswith(("splunk_uf_", "ludus_splunk_collector_")) for name in inputs))

    def test_retained_windows_flow_uses_standalone_install_service_and_event_reader_tasks(self):
        windows_paths = [
            path for folder in ("tasks/windows", "handlers", "templates")
            if (ROLE / folder).is_dir()
            for path in (ROLE / folder).rglob("*") if path.is_file()
            and (folder != "templates" or path.name.startswith("windows-"))
        ]
        source = "\n".join(path.read_text() for path in windows_paths)
        for token in ("splunk_forwarder_", "win_get_url", "win_package", "win_service",
                      "Event Log Readers", "inputs.conf", "outputs.conf"):
            self.assertIn(token.lower(), source.lower(), f"retained Windows flow missing {token}")
        for removed in ("bootstrapPending", "ownership.json", "ludus_splunk_collector_windows_"):
            self.assertNotIn(removed.lower(), source.lower(), f"unfinished Windows logic remains: {removed}")

    def test_active_callers_use_global_shared_inputs_without_legacy_aliases(self):
        repo = ROLE.parents[2]
        expected_windows_inputs = {
            repo / "blueprints/threat-hunting/range-config.yml": {
                "WinEventLog://Security",
                "WinEventLog://Microsoft-Windows-Sysmon/Operational",
            },
            repo / "docs/examples/splunk-dev1/range-config.yml": {
                "WinEventLog://Security",
                "WinEventLog://Microsoft-Windows-Sysmon/Operational",
                "WinEventLog://Microsoft-Windows-PowerShell/Operational",
            },
            repo / "docs/examples/windows-splunk/range-config.yml": {
                "WinEventLog://Security",
                "WinEventLog://Microsoft-Windows-Sysmon/Operational",
            },
        }
        legacy = {"ludus_splunk_server_indexes", "splunk_server_indexes"}
        for path, expected_inputs in expected_windows_inputs.items():
            with self.subTest(path=path):
                config = _yaml(path, {})
                shared = config.get("global_role_vars", {})
                self.assertEqual(shared.get("splunk_version"), "10.6.1.1")
                self.assertEqual(shared.get("splunk_build"), "b2ae2962645c")
                self.assertIs(shared.get("splunk_accept_license"), True)
                self.assertEqual(shared.get("splunk_receiver_port"), 9997)
                self.assertTrue(shared.get("splunk_receiver_ip"))
                windows_vm = next(vm for vm in config.get("ludus", []) if "windows" in vm)
                windows_inputs = windows_vm.get("role_vars", {}).get("splunk_forwarder_inputs", [])
                self.assertEqual({entry.get("name") for entry in windows_inputs}, expected_inputs)
                for vm in config.get("ludus", []):
                    role_vars = vm.get("role_vars", {})
                    self.assertFalse(legacy & role_vars.keys(), "unsupported server index inputs remain")
                    self.assertFalse(any(key.startswith(("ludus_splunk_collector_", "splunk_uf_"))
                                         for key in role_vars),
                                     "caller-specific legacy public aliases remain")

    def test_both_forwarder_platforms_keep_existing_managed_paths(self):
        linux = "\n".join(path.read_text() for folder in (ROLE / "tasks", ROLE / "templates")
                           for path in folder.rglob("*") if path.is_file()
                           and "windows" not in path.parts
                           and not path.name.startswith("windows-"))
        self.assertIn("/opt/splunkforwarder/etc/apps/ludus_collector/local", linux)
        self.assertIn("ludus-managed.conf", linux)
        windows = "\n".join(path.read_text() for folder in (ROLE / "tasks/windows", ROLE / "templates")
                             for path in folder.rglob("*") if path.is_file()
                             and (folder.name != "templates" or path.name.startswith("windows-")))
        self.assertIn(r"\etc\system\local\inputs.conf", windows)
        self.assertIn(r"\etc\system\local\outputs.conf", windows)


if __name__ == "__main__":
    unittest.main()
