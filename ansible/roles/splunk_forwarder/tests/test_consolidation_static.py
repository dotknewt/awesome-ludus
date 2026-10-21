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

    def test_role_identity_and_both_public_default_apis_are_retained(self):
        self.assertEqual(self.meta.get("galaxy_info", {}).get("role_name"), "splunk_forwarder")
        self.assertEqual(self.meta.get("galaxy_info", {}).get("author"), "dotknewt")
        self.assertFalse((ROLE.parent / "linux_splunk_forwarder").exists())
        self.assertFalse((ROLE.parent / "windows_splunk_forwarder").exists())
        self.assertTrue(any(key.startswith("ludus_splunk_collector_")
                            for key in self.defaults), "Linux collector defaults/API missing")
        self.assertTrue(any(key.startswith("splunk_uf_")
                            for key in self.defaults), "standalone Windows splunk_uf_* defaults/API missing")
        self.assertFalse(any("windows" in key.lower() and key.startswith("ludus_splunk_collector_")
                             for key in self.defaults), "unfinished collector-prefixed Windows API remains")

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
        self.assertTrue(all(name.startswith("splunk_uf_") for name in inputs),
                        "Windows harness must supply only the splunk_uf_* API")

    def test_retained_windows_flow_uses_standalone_install_service_and_event_reader_tasks(self):
        windows_paths = [
            path for folder in ("tasks/windows", "handlers", "templates")
            if (ROLE / folder).is_dir()
            for path in (ROLE / folder).rglob("*") if path.is_file()
            and (folder != "templates" or path.name.startswith("windows-"))
        ]
        source = "\n".join(path.read_text() for path in windows_paths)
        for token in ("splunk_uf_", "win_get_url", "win_package", "win_service",
                      "Event Log Readers", "inputs.conf", "outputs.conf"):
            self.assertIn(token.lower(), source.lower(), f"retained Windows flow missing {token}")
        for removed in ("bootstrapPending", "ownership.json", "ludus_splunk_collector_windows_"):
            self.assertNotIn(removed.lower(), source.lower(), f"unfinished Windows logic remains: {removed}")


if __name__ == "__main__":
    unittest.main()
