"""Static contracts for the optional Splunk receiver; no host is simulated."""

from pathlib import Path
import importlib.util
import unittest
import re

import yaml
from jinja2 import Environment, StrictUndefined


ROLE = Path(__file__).resolve().parents[1]


def _conditions(when):
    if when is None:
        return []
    return when if isinstance(when, list) else [when]


def _flatten(tasks, base_dir=None, inherited_when=()):
    base_dir = base_dir or (ROLE / "tasks")
    for task in tasks or []:
        effective_when = (*inherited_when, *_conditions(task.get("when")))
        module, args = _module(task)
        if module in {"ansible.builtin.import_tasks", "import_tasks"}:
            imported = args.get("file") if isinstance(args, dict) else args
            if isinstance(imported, str) and "{{" not in imported:
                path = base_dir / imported
                if path.is_file():
                    yield from _flatten(yaml.safe_load(path.read_text()), path.parent, effective_when)
            continue
        task = {**task, "__effective_when": list(effective_when)}
        yield task
        for key in ("block", "rescue", "always"):
            yield from _flatten(task.get(key, []), base_dir, effective_when)


def _module(task):
    return next(
        ((name, value) for name, value in task.items()
         if name.startswith("ansible.builtin.") or name == "import_tasks"),
        (None, None),
    )


class SplunkReceiverStaticContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
        cls.tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        cls.handlers = yaml.safe_load((ROLE / "handlers/main.yml").read_text()) if (ROLE / "handlers/main.yml").exists() else []
        cls.flat_tasks = list(_flatten(cls.tasks, ROLE / "tasks"))
        cls.flat_handlers = list(_flatten(cls.handlers, ROLE / "handlers"))

    def test_receiver_inputs_default_to_disabled_and_standard_port(self):
        self.assertIs(self.defaults.get("ludus_splunk_server_receiver_enabled"), False)
        self.assertEqual(self.defaults.get("ludus_splunk_server_receiver_port"), 9997)

    def test_receiver_inputs_are_validated_before_any_mutation(self):
        assertions = [
            task["ansible.builtin.assert"].get("that", [])
            for task in self.flat_tasks
            if "ansible.builtin.assert" in task
        ]
        receiver_conditions = [str(condition) for group in assertions for condition in group]
        enabled_checks = [item for item in receiver_conditions if "ludus_splunk_server_receiver_enabled" in item]
        port_checks = [item for item in receiver_conditions if "ludus_splunk_server_receiver_port" in item]
        self.assertTrue(any("is boolean" in item for item in enabled_checks))
        self.assertTrue(any("is integer" in item for item in port_checks))
        self.assertTrue(any("9997" not in item and "1" in item and "ludus_splunk_server_receiver_port" in item for item in port_checks))
        self.assertTrue(any("65535" in item for item in port_checks))
        self.assertTrue(any("8000" in item for item in port_checks))
        self.assertTrue(any("8089" in item for item in port_checks))

        validate_indexes = [
            index for index, task in enumerate(self.flat_tasks)
            if "ansible.builtin.assert" in task and any(
                "ludus_splunk_server_receiver_port" in str(item)
                for item in task["ansible.builtin.assert"].get("that", [])
            )
        ]
        mutation_indexes = [
            index for index, task in enumerate(self.flat_tasks)
            if _module(task)[0] in {
                "ansible.builtin.template", "ansible.builtin.copy", "ansible.builtin.file",
                "ansible.builtin.lineinfile", "ansible.builtin.blockinfile",
            }
        ]
        self.assertTrue(validate_indexes, "receiver validation must be a real assert task")
        self.assertTrue(mutation_indexes)
        self.assertLess(min(validate_indexes), min(mutation_indexes))

    def test_receiver_app_uses_dedicated_managed_splunktcp_config(self):
        config_paths = []
        for task in self.flat_tasks:
            module, args = _module(task)
            if module in {"ansible.builtin.template", "ansible.builtin.copy"} and isinstance(args, dict):
                config_paths.append(str(args.get("dest", "")))
        self.assertTrue(any(path.startswith("/opt/splunk/etc/apps/ludus_receiver/") for path in config_paths))

        rendered_configs = []
        for template_path in (ROLE / "templates").glob("*receiver*"):
            source = template_path.read_text()
            rendered_configs.append(Environment(undefined=StrictUndefined).from_string(source).render(
                ludus_splunk_server_receiver_port=9997,
            ))
        self.assertTrue(any("[splunktcp://9997]" in config for config in rendered_configs))
        self.assertTrue(any("disabled = 0" in config or "disabled=0" in config for config in rendered_configs))
        marker_tasks = [task for task in self.flat_tasks if
                        _module(task)[0] == "ansible.builtin.copy"
                        and isinstance(_module(task)[1], dict)
                        and ".ludus-splunk-server-owner" in str(_module(task)[1].get("dest", ""))]
        self.assertTrue(marker_tasks, "the app ownership marker must be created as a dedicated file")
        self.assertEqual(marker_tasks[0]["ansible.builtin.copy"].get("content"),
                         "ludus_splunk_server_receiver_v1\n")

    def test_existing_app_and_listener_are_checked_before_managed_changes(self):
        stats = []
        assertions = []
        mutators = []
        for index, task in enumerate(self.flat_tasks):
            module, args = _module(task)
            if module == "ansible.builtin.stat" and isinstance(args, dict):
                stats.append((index, args))
            if module == "ansible.builtin.assert":
                assertions.append((index, " ".join(map(str, args.get("that", [])))))
            if module in {"ansible.builtin.template", "ansible.builtin.copy", "ansible.builtin.file", "ansible.builtin.lineinfile", "ansible.builtin.blockinfile"}:
                mutators.append(index)

        receiver_stats = [(index, args) for index, args in stats
                          if "ludus_receiver" in str(args.get("path", "") + str(self.flat_tasks[index].get("loop", "")))]
        self.assertTrue(receiver_stats)
        self.assertTrue(all(args.get("follow") is False for _, args in receiver_stats))
        app_index = min(index for index, _ in receiver_stats)
        app_guards = [(index, text) for index, text in assertions if "ludus_splunk_server_receiver_app" in text]
        self.assertTrue(app_guards, "preflight must reject symlinked or unmanaged receiver state")
        self.assertLess(app_index, min(index for index, _ in app_guards))
        self.assertLess(max(index for index, _ in app_guards), min(mutators))
        guard_text = " ".join(text for _, text in app_guards).lower()
        self.assertIn("islnk", guard_text)
        self.assertTrue(any(token in guard_text for token in ("owner", "marker", "managed")))

    def test_cleanup_is_limited_to_marked_receiver_files_and_removes_stale_port(self):
        receiver_removals = []
        seed_removals = []
        for task in self.flat_tasks:
            module, args = _module(task)
            if module == "ansible.builtin.file" and isinstance(args, dict) and args.get("state") == "absent":
                if "/opt/splunk/etc/apps/ludus_receiver/" in str(args.get("path", "")):
                    receiver_removals.append((task, args))
                if args.get("path") == "/opt/splunk/etc/system/local/user-seed.conf":
                    seed_removals.append((task, args))
        self.assertTrue(receiver_removals)
        self.assertTrue(seed_removals, "existing seed cleanup must remain present")
        for task, _ in receiver_removals:
            self.assertTrue(task.get("__effective_when"), "owned-file cleanup must be gated by the ownership marker")
            condition = str(task["__effective_when"]).lower()
            self.assertIn("ludus_splunk_server_receiver_owned", condition)
        seed_task, seed_args = seed_removals[0]
        self.assertEqual(seed_args["state"], "absent")
        self.assertTrue(seed_task.get("when"), "seed cleanup remains conditional on successful bootstrap")
        marker_removals = [args for task, args in receiver_removals
                           if ".ludus-splunk-server-owner" in str(args.get("path", ""))]
        self.assertFalse(marker_removals, "retain the authoritative marker so repeated disabled runs remain safe")
        self.assertTrue(all(args.get("path") == "/opt/splunk/etc/apps/ludus_receiver/local/inputs.conf"
                            for _, args in receiver_removals))
        cleanup_conditions = [str(task["__effective_when"]) for task, _ in receiver_removals]
        self.assertTrue(all("ludus_splunk_server_receiver_owned" in condition for condition in cleanup_conditions))

        receiver_writes = [task for task in self.flat_tasks if any(
            part in str(_module(task)[1]) for part in ("ludus_receiver", "splunktcp")
        )]
        self.assertTrue(any(task.get("notify") for task in receiver_writes), "listener port changes must remove obsolete managed config")

    def test_disabled_receiver_does_not_apply_listener_or_restart_it(self):
        listener_tasks = [task for task in self.flat_tasks if
                          "ludus_receiver" in str(_module(task)[1])
                          or "ludus_splunk_server_receiver_port" in str(_module(task)[1])]
        self.assertTrue(listener_tasks)
        for task in listener_tasks:
            module, args = _module(task)
            if module in {"ansible.builtin.template", "ansible.builtin.copy", "ansible.builtin.file", "ansible.builtin.wait_for"}:
                conditions = str(task.get("__effective_when", []))
                if isinstance(args, dict) and args.get("state") == "absent":
                    self.assertIn("not ludus_splunk_server_receiver_enabled", conditions)
                    self.assertIn("ludus_splunk_server_receiver_owned", conditions)
                else:
                    self.assertTrue(conditions, task.get("name"))
                    self.assertIn("ludus_splunk_server_receiver_enabled", conditions)

        is_restart = lambda task: (_module(task)[0] == "ansible.builtin.systemd_service"
                                   and isinstance(_module(task)[1], dict)
                                   and _module(task)[1].get("state") == "restarted")
        task_restarts = [task for task in self.flat_tasks if is_restart(task)]
        handler_restarts = [task for task in self.flat_handlers if is_restart(task)]
        self.assertTrue(handler_restarts or task_restarts)
        for task in task_restarts:
            self.assertTrue(task.get("__effective_when"), "direct restart must be conditionally guarded")
        if handler_restarts:
            handler_names = {task.get("name") for task in handler_restarts}
            handler_names.update(task.get("listen") for task in handler_restarts)
            notified = {item for task in self.flat_tasks for item in _conditions(task.get("notify"))}
            self.assertTrue(handler_names & notified, "restart handler must be notified by changed config")

    def test_receiver_readiness_uses_configured_port_and_preserves_bootstrap_checks(self):
        waits = [task for task in self.flat_tasks if "ansible.builtin.wait_for" in task]
        receiver_waits = [task for task in waits if
                          "ludus_splunk_server_receiver_port" in str(task["ansible.builtin.wait_for"].get("port"))]
        self.assertTrue(receiver_waits)
        wait = receiver_waits[0]
        self.assertIn("ludus_splunk_server_receiver_port", str(wait["ansible.builtin.wait_for"].get("port")))
        self.assertIn("ludus_splunk_server_receiver_enabled", str(wait["__effective_when"]))
        modules = [_module(task)[0] for task in self.flat_tasks]
        self.assertIn("ansible.builtin.uri", modules)
        self.assertTrue(any("ansible.builtin.wait_for" == module and
                            isinstance(_module(task)[1], dict) and _module(task)[1].get("port") == 8000
                            for task, module in zip(self.flat_tasks, modules)),
                        "existing web listener readiness must remain present")

    def test_documentation_describes_opt_in_and_separate_client_example(self):
        readme = (ROLE / "README.md").read_text()
        snippets = [yaml.safe_load(match.group(1)) for match in re.finditer(r"```ya?ml\s*\n(.*?)\n```", readme, re.S)]

        def mappings(value):
            if isinstance(value, dict):
                yield value
                for child in value.values():
                    yield from mappings(child)
            elif isinstance(value, list):
                for child in value:
                    yield from mappings(child)

        documents = [mapping for snippet in snippets if snippet is not None for mapping in mappings(snippet)]
        self.assertTrue(any(mapping.get("ludus_splunk_server_receiver_enabled") is True
                            and mapping.get("ludus_splunk_server_receiver_port") == 9997
                            for mapping in documents), "server example must explicitly enable the listener and show its port")
        dependency_entries = [mapping["depends_on"] for mapping in documents if "depends_on" in mapping]
        self.assertTrue(dependency_entries, "client example must show Ludus depends_on ordering")
        self.assertTrue(any("ludus_splunk_server" in str(entry) for entry in dependency_entries))
        client = next(snippet for snippet in snippets if isinstance(snippet, list)
                      and any(isinstance(vm, dict) and vm.get("vm_name") == "splunk-client" for vm in snippet))
        client_vm = next(vm for vm in client if vm.get("vm_name") == "splunk-client")
        role_names = [role if isinstance(role, str) else role.get("name") for role in client_vm["roles"]]
        self.assertEqual(role_names, ["ludus_splunk_collector", "ludus_linux_logging"])
        client_vars = client_vm["role_vars"]
        self.assertEqual(client_vars, {
            "ludus_splunk_collector_receiver_host": "<splunk-server-address>",
            "ludus_splunk_collector_receiver_port": 9997,
            "ludus_splunk_collector_accept_license": True,
            "ludus_linux_logging_read_users": ["splunkfwd"],
        })
        self.assertIn("plaintext", readme.lower())

    def test_listener_header_parser_covers_cooked_raw_and_ssl_host_port_forms(self):
        parser_path = ROLE / "filter_plugins/receiver_listeners.py"
        spec = importlib.util.spec_from_file_location("receiver_listeners", parser_path)
        parser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(parser)
        configuration = """
[splunktcp://9997]
disabled = 1
[splunktcp://receiver.example.test:9998]
[splunktcp-ssl:9999]
[splunktcp-ssl://receiver.example.test:10000]
[tcp://0.0.0.0:10001]
[tcp-ssl://receiver.example.test:10002]
[splunktcp://[2001:db8::1]:10003]
[tcp://[2001:db8::2]:10004]
[monitor:///var/log/syslog]
"""
        self.assertEqual(parser.receiver_listener_ports(configuration), [
            "9997", "9998", "9999", "10000", "10001", "10002", "10003", "10004",
        ])

    def test_disabled_unmanaged_app_is_not_inspected_or_cleaned(self):
        ownership_assertions = [task for task in self.flat_tasks
                                if "ansible.builtin.assert" in task
                                and "ludus_splunk_server_receiver_owned" in str(task["ansible.builtin.assert"].get("that", []))]
        self.assertTrue(ownership_assertions)
        for task in ownership_assertions:
            self.assertIn("ludus_splunk_server_receiver_enabled", str(task.get("when")))

        scans = [task for task in self.flat_tasks if _module(task)[0] == "ansible.builtin.find"]
        config_reads = [task for task in self.flat_tasks if
                        _module(task)[0] == "ansible.builtin.slurp"
                        and "ludus_splunk_server_receiver_existing_input_configs" in str(task.get("loop", ""))]
        collision_asserts = [task for task in self.flat_tasks if
                             "ansible.builtin.assert" in task
                             and "item.content" in str(task["ansible.builtin.assert"].get("that", []))]
        self.assertTrue(scans)
        self.assertTrue(config_reads)
        self.assertTrue(collision_asserts)
        for task in scans + config_reads + collision_asserts:
            self.assertIn("ludus_splunk_server_receiver_enabled", str(task.get("__effective_when")))

        for task in self.flat_tasks:
            register = task.get("register", "")
            if "receiver" in register:
                self.assertTrue(register.startswith("ludus_splunk_server_receiver_"), register)


if __name__ == "__main__":
    unittest.main()
