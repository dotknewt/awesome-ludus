"""Static contracts for the shared Splunk server variable API."""

from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).resolve().parents[1]


def _yaml(path, default=None):
    if not path.is_file():
        return default
    return yaml.safe_load(path.read_text()) or default


def _module(task, name):
    return task.get(f"ansible.builtin.{name}", task.get(name))


def _flatten(tasks):
    for task in tasks or []:
        yield task
        for section in ("block", "rescue", "always"):
            yield from _flatten(task.get(section, []))


def _sequence(role):
    entry = role / "tasks/main.yml"

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


class SharedSplunkServerStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = _yaml(ROLE / "defaults/main.yml", {})
        cls.tasks = _sequence(ROLE)
        cls.templates = "\n".join(path.read_text() for path in (ROLE / "templates").rglob("*.*")
                                  if path.is_file())

    def test_shared_and_server_only_defaults_have_clean_namespaces(self):
        self.assertEqual(self.defaults.get("splunk_version"), "10.6.1.1")
        self.assertEqual(self.defaults.get("splunk_build"), "b2ae2962645c")
        self.assertIs(self.defaults.get("splunk_accept_license"), False)
        self.assertEqual(self.defaults.get("splunk_receiver_port"), 9997)
        self.assertTrue(any(key.startswith("splunk_server_") for key in self.defaults))
        legacy = {
            "splunk_download_token", "splunk_install_dir", "splunk_home",
            "splunk_admin_user", "splunk_admin_password", "splunk_web_port",
            "splunk_mgmt_port", "splunk_receiving_port", "splunk_license_file",
            "splunk_enable_boot_start", "splunk_disable_popups", "splunk_server_indexes",
        }
        self.assertFalse(legacy & self.defaults.keys(), "legacy aliases/unsupported index API must not remain")

    def test_server_license_gate_precedes_every_host_mutation(self):
        gates = [index for index, task in enumerate(self.tasks)
                 if _module(task, "assert") is not None
                 and "splunk_accept_license" in str(_module(task, "assert"))]
        mutation_modules = {"get_url", "unarchive", "template", "copy", "file", "command", "systemd", "systemd_service"}
        mutations = [index for index, task in enumerate(self.tasks)
                     if any(_module(task, module) is not None for module in mutation_modules)]
        self.assertTrue(gates, "server entrypoint must assert explicit shared license acceptance")
        self.assertTrue(mutations, "server mutation tasks missing")
        self.assertLess(min(gates), min(mutations), "server license gate must precede host mutation")

    def test_server_templates_and_persisted_seed_path_use_new_server_namespace(self):
        seed_template = (ROLE / "templates/user-seed.conf.j2").read_text()
        self.assertIn("splunk_server_admin_user", seed_template)
        self.assertIn("splunk_server_admin_password", seed_template)
        writers = [task for task in self.tasks if _module(task, "template") is not None]
        self.assertTrue(any(
            _module(task, "template").get("src") == "user-seed.conf.j2"
            and "splunk_server_home" in str(_module(task, "template").get("dest", ""))
            and str(_module(task, "template").get("dest", "")).endswith("etc/system/local/user-seed.conf")
            for task in writers
        ), "seed template writer must retain its persisted destination and use the new server home setting")
        self.assertIn("splunk_server_indexes", (ROLE / "README.md").read_text())
        self.assertIn("not supported", (ROLE / "README.md").read_text().lower())


if __name__ == "__main__":
    unittest.main()
