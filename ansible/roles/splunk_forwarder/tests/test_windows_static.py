"""Static contracts for the retained standalone Windows task flow."""

from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).resolve().parents[1]


def _yaml(path, default=None):
    if not path.is_file():
        return default
    return yaml.safe_load(path.read_text()) or default


class WindowsForwarderStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = _yaml(ROLE / "defaults/main.yml", {})
        cls.tasks = _yaml(ROLE / "tasks/windows/main.yml", []) or []
        cls.inputs_template = (ROLE / "templates/windows-inputs.conf.j2").read_text()
        cls.outputs_template = (ROLE / "templates/windows-outputs.conf.j2").read_text()
        cls.handler = _yaml(ROLE / "handlers/main.yml", []) or []

    def test_standalone_defaults_and_input_driven_templates_are_retained(self):
        expected = {
            "splunk_uf_version": "9.3.2",
            "splunk_uf_build": "d8bb32809498",
            "splunk_uf_download_token": "",
            "splunk_uf_indexer": "",
            "splunk_uf_indexer_port": 9997,
            "splunk_uf_accept_license": True,
            "splunk_uf_start_service": True,
        }
        for key, value in expected.items():
            self.assertEqual(self.defaults.get(key), value)
        self.assertIn("splunk_uf_inputs", self.defaults)
        self.assertIn("splunk_uf_inputs", self.inputs_template)
        self.assertIn("input.index", self.inputs_template)
        self.assertIn("splunk_uf_indexer", self.outputs_template)
        self.assertNotIn("silk", self.inputs_template.lower())

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
