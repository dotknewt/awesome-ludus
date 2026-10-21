"""Static contracts for the retained standalone Windows task flow."""

from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).resolve().parents[1]


def _yaml(path, default=None):
    if not path.is_file():
        return default
    return yaml.safe_load(path.read_text()) or default


def _task_sequence(entry):
    def walk(tasks, origin):
        for task in tasks or []:
            yield task
            for section in ("block", "rescue", "always"):
                yield from walk(task.get(section, []), origin)
            imported = task.get("ansible.builtin.import_tasks", task.get("import_tasks"))
            if isinstance(imported, str) and "{{" not in imported:
                path = (origin.parent / imported).resolve()
                if path.is_file():
                    yield from walk(_yaml(path, []), path)

    return list(walk(_yaml(entry, []), entry)) if entry.is_file() else []


class WindowsForwarderStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = _yaml(ROLE / "defaults/main.yml", {})
        cls.tasks = _task_sequence(ROLE / "tasks/windows/main.yml")
        cls.inputs_template = (ROLE / "templates/windows-inputs.conf.j2").read_text()
        cls.outputs_template = (ROLE / "templates/windows-outputs.conf.j2").read_text()
        cls.handler = _yaml(ROLE / "handlers/main.yml", []) or []

    def test_standalone_defaults_and_input_driven_templates_are_retained(self):
        expected = {
            "splunk_version": "10.6.1.1",
            "splunk_build": "b2ae2962645c",
            "splunk_accept_license": False,
            "splunk_receiver_ip": "",
            "splunk_receiver_port": 9997,
            "splunk_forwarder_admin_user": "admin",
            "splunk_forwarder_install_dir": r"C:\Program Files\SplunkUniversalForwarder",
            "splunk_forwarder_start_service": True,
        }
        for key, value in expected.items():
            self.assertEqual(self.defaults.get(key), value)
        self.assertIn("splunk_forwarder_inputs", self.defaults)
        self.assertIn("splunk_forwarder_inputs", self.inputs_template)
        self.assertIn("input.index", self.inputs_template)
        self.assertIn("splunk_receiver_ip", self.outputs_template)
        self.assertNotIn("silk", self.inputs_template.lower())

    def test_shared_license_gate_namespaces_templates_and_persisted_windows_paths(self):
        self.assertEqual(self.defaults.get("splunk_version"), "10.6.1.1")
        self.assertEqual(self.defaults.get("splunk_build"), "b2ae2962645c")
        self.assertIs(self.defaults.get("splunk_accept_license"), False)
        self.assertEqual(self.defaults.get("splunk_receiver_port"), 9997)
        self.assertEqual(self.defaults.get("splunk_forwarder_admin_user"), "admin")
        self.assertFalse(any(key.startswith(("splunk_uf_", "ludus_splunk_collector_", "splunk_admin_"))
                             for key in self.defaults), "Windows legacy public aliases must be removed")
        self.assertTrue(any(key.startswith("splunk_forwarder_") for key in self.defaults))
        self.assertEqual(
            {value for key, value in self.defaults.items() if key.endswith("admin_password")},
            {"SplunkLab-ChangeMe1!", "Changeme1!"},
            "preserve both platform password defaults",
        )

        gates = [i for i, task in enumerate(self.tasks)
                 if task.get("ansible.builtin.assert", {}).get("that")
                 and "splunk_accept_license" in str(task["ansible.builtin.assert"]["that"])]
        mutations = [i for i, task in enumerate(self.tasks)
                     if any(module in task for module in (
                         "ansible.windows.win_service", "ansible.windows.win_stat",
                         "ansible.windows.win_file", "ansible.windows.win_powershell",
                         "ansible.windows.win_get_url", "ansible.windows.win_package",
                         "ansible.windows.win_group_membership", "ansible.windows.win_template",
                     ))]
        self.assertTrue(gates, "Windows task flow must explicitly assert shared license acceptance")
        self.assertTrue(mutations, "Windows mutation flow missing")
        self.assertLess(min(gates), min(mutations),
                        "Windows license gate must precede inspection, download, install, service, and config tasks")

        self.assertIn("splunk_forwarder_inputs", self.inputs_template)
        self.assertIn("splunk_receiver_ip", self.outputs_template)
        self.assertIn("splunk_receiver_port", self.outputs_template)
        install_dir = self.defaults.get("splunk_forwarder_install_dir", "")
        self.assertEqual(install_dir, r"C:\Program Files\SplunkUniversalForwarder")
        input_writer = next(task for task in self.tasks
                            if task.get("name") == "Create inputs.conf from template")
        output_writer = next(task for task in self.tasks
                             if task.get("name") == "Create outputs.conf from template")
        self.assertEqual(
            input_writer["ansible.windows.win_template"]["dest"],
            r"{{ splunk_forwarder_install_dir }}\etc\system\local\inputs.conf",
        )
        self.assertEqual(
            output_writer["ansible.windows.win_template"]["dest"],
            r"{{ splunk_forwarder_install_dir }}\etc\system\local\outputs.conf",
        )

    def test_download_install_event_readers_and_service_flow_uses_actual_tasks(self):
        module_names = [next((key for key in task
                              if key.startswith(("ansible.windows.", "ansible.builtin."))), "")
                        for task in self.tasks]
        self.assertIn("ansible.windows.win_get_url", module_names)
        self.assertIn("ansible.windows.win_package", module_names)
        self.assertIn("ansible.windows.win_group_membership", module_names)
        self.assertGreaterEqual(module_names.count("ansible.windows.win_service"), 3)

        token_download = next(i for i, task in enumerate(self.tasks)
                              if task.get("name") == "Download Splunk UF from splunk.com (with token)")
        no_token_download = next(i for i, task in enumerate(self.tasks)
                                 if task.get("name") == "Download Splunk UF from splunk.com (no token required)")
        install = next(i for i, task in enumerate(self.tasks)
                       if task.get("name") == "Install Splunk Universal Forwarder")
        membership = next(i for i, task in enumerate(self.tasks)
                          if task.get("name") == "Add SplunkForwarder service account to Event Log Readers")
        input_writer = next(i for i, task in enumerate(self.tasks)
                            if task.get("name") == "Create inputs.conf from template")
        output_writer = next(i for i, task in enumerate(self.tasks)
                             if task.get("name") == "Create outputs.conf from template")
        status = next(i for i, task in enumerate(self.tasks)
                      if task.get("name") == "Verify service is running")
        self.assertLess(max(token_download, no_token_download), install)
        self.assertLess(install, membership)
        self.assertLess(membership, input_writer)
        self.assertLess(input_writer, output_writer)
        self.assertLess(output_writer, status)
        self.assertEqual(self.tasks[input_writer]["ansible.windows.win_template"]["src"],
                         "windows-inputs.conf.j2")
        self.assertEqual(self.tasks[output_writer]["ansible.windows.win_template"]["src"],
                         "windows-outputs.conf.j2")
        self.assertTrue(any(task.get("name") == "Restart SplunkForwarder"
                            and "ansible.windows.win_service" in task for task in self.handler))


if __name__ == "__main__":
    unittest.main()
