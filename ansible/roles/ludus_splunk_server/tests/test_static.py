"""Static checks over real YAML/Jinja artifacts; no host behavior is simulated."""

from pathlib import Path
import base64
import re
import unittest

import yaml
from jinja2 import Environment, StrictUndefined


ROLE = Path(__file__).resolve().parents[1]


def _flatten(tasks):
    for task in tasks:
        yield task
        yield from _flatten(task.get("block", []))


class SplunkServerStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
        cls.tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        cls.meta = yaml.safe_load((ROLE / "meta/main.yml").read_text())
        cls.template = (ROLE / "templates/user-seed.conf.j2").read_text()
        cls.flat_tasks = list(_flatten(cls.tasks))
        cls.by_name = {task["name"]: task for task in cls.flat_tasks if "name" in task}

    def _assertions(self, task_name):
        task = self.by_name[task_name]
        conditions = task["ansible.builtin.assert"]["that"]
        return [str(condition) for condition in conditions]

    def test_required_artifact_inputs_fail_closed(self):
        self.assertEqual(
            self.defaults["ludus_splunk_server_package_url"],
            "https://download.splunk.com/products/splunk/releases/10.6.1.1/linux/splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb",
        )
        self.assertEqual(
            self.defaults["ludus_splunk_server_package_checksum"],
            "sha512:f3f67f699fcd893ffd280b602a47215f5e7eb9b481cb242b08705a4db8ada489febb3fa49cb90f9bd1397603d9207ea5ac9bf59eec62f99d030c3f2ff738eb89",
        )
        self.assertEqual(self.defaults["ludus_splunk_server_version"], "10.6.1.1")
        self.assertIs(self.defaults["ludus_splunk_server_accept_license"], False)
        conditions = self._assertions("Validate non-secret platform and artifact inputs before mutation")
        self.assertTrue(any("is boolean" in condition for condition in conditions))
        self.assertTrue(any("ludus_splunk_server_accept_license" == condition for condition in conditions))
        self.assertIn('ansible_service_mgr == "systemd"', conditions)

    def test_role_metadata_declares_supported_platform(self):
        self.assertIn("Debian", [platform["name"] for platform in self.meta["galaxy_info"]["platforms"]])
        self.assertEqual([platform["versions"] for platform in self.meta["galaxy_info"]["platforms"]], [["trixie"]])
        self.assertEqual(self.meta["galaxy_info"]["min_ansible_version"], "2.16")
        self.assertEqual(self.meta["dependencies"], [])

    def test_command_module_values_are_valid_argv_mappings(self):
        for task in self.flat_tasks:
            if "ansible.builtin.command" in task:
                command = task["ansible.builtin.command"]
                self.assertIsInstance(command, dict, task["name"])
                self.assertIsInstance(command.get("argv"), list, task["name"])
                self.assertTrue(command["argv"], task["name"])

    def test_package_identity_uses_showformat_and_is_checked_before_mutation(self):
        metadata = self.by_name["Read package identity using dpkg-deb showformat fields"]["ansible.builtin.command"]["argv"]
        self.assertEqual(metadata[1], "-W")
        self.assertEqual(metadata[2], "--showformat=${Package}\\n${Version}\\n${Architecture}\\n")
        metadata_commands = [
            task["ansible.builtin.command"]
            for task in self.flat_tasks
            if "ansible.builtin.command" in task
            and task["ansible.builtin.command"]["argv"][0] in {"dpkg-query", "dpkg-deb"}
        ]
        self.assertEqual(len(metadata_commands), 3)
        self.assertTrue(all(command.get("expand_argument_vars") is False for command in metadata_commands))
        names = [task.get("name") for task in self.flat_tasks]
        self.assertLess(names.index("Require exact Enterprise package identity and version"), names.index("Create dedicated Splunk service group"))
        self.assertLess(names.index("Require exact Enterprise package identity and version"), names.index("Install the verified local package without an implicit upgrade path"))

    def test_real_jinja_template_preserves_safe_special_characters_without_lines(self):
        username = "admin.lab-1"
        password = "Lab! %+#=9pass"
        rendered = Environment(undefined=StrictUndefined).from_string(self.template).render(
            ludus_splunk_server_admin_username=username,
            ludus_splunk_server_admin_password=password,
        )
        self.assertEqual(rendered, f"[user_info]\nUSERNAME = {username}\nPASSWORD = {password}")
        credentials = self.by_name["Validate credentials without exposing assertion operands"]
        self.assertTrue(credentials["no_log"])
        self.assertIn("^[A-Za-z0-9_.-]+$", " ".join(self._assertions(credentials["name"])))
        self.assertIn("^[ -~]+$", " ".join(self._assertions(credentials["name"])))
        self.assertIn(".strip()", " ".join(self._assertions(credentials["name"])))
        trailing_backslash = next(item for item in self._assertions(credentials["name"]) if "endswith" in item)
        env = Environment(undefined=StrictUndefined)
        self.assertEqual(env.from_string("{{ " + trailing_backslash + " }}").render(ludus_splunk_server_admin_password="NoSlash123!"), "True")
        self.assertEqual(env.from_string("{{ " + trailing_backslash + " }}").render(ludus_splunk_server_admin_password="NoSlash123\\"), "False")

        env.tests["match"] = lambda value, pattern: re.match(pattern, value) is not None
        checks = [env.compile_expression(item) for item in self._assertions(credentials["name"])]

        def valid(username, password):
            context = {
                "ludus_splunk_server_admin_username": username,
                "ludus_splunk_server_admin_password": password,
            }
            return all(check(**context) for check in checks)

        self.assertTrue(valid(username, password))
        self.assertFalse(valid("admin]\nPASSWORD", password))
        self.assertFalse(valid(username, "Line1\nLine2!"))
        self.assertFalse(valid(username + "\n", password))
        self.assertFalse(valid(username, password + "\n"))
        self.assertFalse(valid(username, " leading8!"))
        self.assertFalse(valid(username, "NoSlash123\\"))

    def test_missing_optional_stat_fields_are_guarded_in_real_jinja(self):
        expressions = self._assertions("Validate installed package status and version")
        home_guard = next(item for item in expressions if "home.stat.get('islnk'" in item)
        unit_guard = next(item for item in expressions if "unit.stat.get('islnk'" in item)
        env = Environment(undefined=StrictUndefined)
        env.filters["bool"] = bool
        for expression in (home_guard, unit_guard):
            self.assertEqual(env.from_string("{{ " + expression + " }}").render(
                ludus_splunk_server_home={"stat": {}},
                ludus_splunk_server_unit={"stat": {}},
            ), "True")
        self.assertTrue(all(".stat.get(" in item for item in expressions if ".stat." in item))

    def test_package_status_and_identity_guards_precede_mutation(self):
        query = self.by_name["Query exact dpkg package status and version"]["ansible.builtin.command"]["argv"]
        self.assertIn("${db:Status-Status}", query[2])
        self.assertEqual(self.by_name["Query exact dpkg package status and version"]["failed_when"], "ludus_splunk_server_installed.rc not in [0, 1]")
        conditions = self._assertions("Validate installed package status and version")
        self.assertTrue(any("== 'installed'" in item for item in conditions))
        self.assertTrue(any("user_record.rc == 0" in item and "/usr/sbin/nologin" in item for item in conditions))
        names = [task.get("name") for task in self.flat_tasks]
        self.assertLess(names.index("Validate installed package status and version"), names.index("Create protected package cache directory"))
        self.assertLess(names.index("Reject an unrelated or root-run existing service"), names.index("Create protected package cache directory"))
        self.assertIn("not (ludus_splunk_server_unit.stat.get('islnk', false) | bool)", conditions)

    def test_fresh_tree_ownership_is_scoped_after_verified_install(self):
        names = [task.get("name") for task in self.flat_tasks]
        chown = self.by_name["Set ownership of the newly installed Splunk application tree"]["ansible.builtin.file"]
        self.assertEqual(chown["path"], "/opt/splunk")
        self.assertEqual(chown["owner"], "splunk")
        self.assertEqual(chown["group"], "splunk")
        self.assertTrue(chown["recurse"])
        self.assertLess(names.index("Install the verified local package without an implicit upgrade path"), names.index("Set ownership of the newly installed Splunk application tree"))
        self.assertLess(names.index("Set ownership of the newly installed Splunk application tree"), names.index("Create initial administrator seed only for an uninitialized instance"))

    def test_service_effective_identity_and_auth_readiness_are_checked(self):
        unit_guards = self._assertions("Require effective non-root vendor Splunk service identity")
        self.assertIn("ludus_splunk_server_effective_user.stdout == 'splunk'", unit_guards)
        self.assertIn("ludus_splunk_server_effective_group.stdout == 'splunk'", unit_guards)
        existing = self.by_name["Reject an unrelated or root-run existing service"]
        existing_guards = existing["ansible.builtin.assert"]["that"]
        self.assertTrue(any("existing_unit_fragment_stat.stat.get('islnk', false)" in item for item in existing_guards))
        self.assertTrue(any("regex_findall" in item for item in existing_guards))
        self.assertIn("--property=FragmentPath", self.by_name["Read existing systemd service fragment path"]["ansible.builtin.command"]["argv"])
        self.assertIn("Requires `ansible-core >= 2.16`", (ROLE / "README.md").read_text())

        env = Environment(undefined=StrictUndefined)
        env.filters["b64decode"] = lambda value: base64.b64decode(value).decode()
        env.filters["regex_findall"] = lambda value, pattern: re.findall(pattern, value)
        expected_lines = "[Service]\nExecStart=/opt/splunk/bin/splunk _internal_launch_under_systemd\n"
        spoofed_lines = [
            "[Service]\nExecStart=/tmp/evil _internal_launch_under_systemd /opt/splunk/bin/splunk\n",
            "[Service]\nExecStart=/opt/splunk/bin/splunk _internal_launch_under_systemd --extra\n",
            "[Service]\n# ExecStart=/opt/splunk/bin/splunk _internal_launch_under_systemd\n",
            "[Service]\nExecStart=/opt/splunk/bin/splunk _internal_launch_under_systemd\nExecStart=/opt/splunk/bin/splunk --bad\n",
        ]
        for task_name, content_var in (
            ("Reject an unrelated or root-run existing service", "ludus_splunk_server_existing_unit_content"),
            ("Require effective non-root vendor Splunk service identity", "ludus_splunk_server_effective_unit_content"),
        ):
            guard = next(item for item in self._assertions(task_name) if "regex_findall" in item)
            check_exec = env.compile_expression(guard)

            def exec_guard(lines):
                encoded = base64.b64encode(lines.encode()).decode()
                return check_exec(**{content_var: {"content": encoded}})

            self.assertTrue(exec_guard(expected_lines))
            for lines in spoofed_lines:
                self.assertFalse(exec_guard(lines))

        auth = self.by_name["Verify fresh administrator authentication over loopback management API"]
        uri = auth["ansible.builtin.uri"]
        self.assertEqual(uri["use_proxy"], False)
        self.assertEqual(uri["follow_redirects"], "none")
        self.assertEqual(uri["timeout"], 15)
        self.assertEqual(auth["retries"], 30)
        self.assertEqual(auth["delay"], 10)

    def test_seed_preserves_initialized_state_and_only_cleans_created_seed(self):
        seed_assertions = self._assertions("Reject an unmanaged seed for an uninitialized instance")
        self.assertTrue(any("passwd.stat.get('exists', false) or not" in item for item in seed_assertions))
        cleanup = self.by_name["Remove only the seed created successfully by this invocation"]
        self.assertIn("ludus_splunk_server_seed_created.changed", cleanup["when"])


if __name__ == "__main__":
    unittest.main()
